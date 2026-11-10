"""The collector must preserve captured results even if detaching fails."""

from collections import Counter
from contextlib import ExitStack, contextmanager
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("_mixed_profile_lifecycle_entry", ROOT / "profile.py")
entry = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = entry
spec.loader.exec_module(entry)


@contextmanager
def capture_environment(detach_error=None):
    """One sample arrives, then the mocked target exits. No BPF is loaded."""
    order = []
    collector = mock.Mock(error="", stacks=Counter())
    builder = mock.Mock()
    bpf = mock.MagicMock()

    def poll(timeout):
        order.append("sample")
        collector.stacks[("native:main",)] += 1

    def detach(**kwargs):
        order.append("detach")
        if detach_error:
            raise RuntimeError(detach_error)

    bpf.ring_buffer_poll.side_effect = poll
    bpf.detach_perf_event.side_effect = detach
    bpf.cleanup.side_effect = lambda: order.append("cleanup")
    builder.close.side_effect = lambda: order.append("close")
    collector.drain.side_effect = lambda unused: order.append("drain")
    writer = mock.Mock(side_effect=lambda *unused: order.append("output"))

    bcc = ModuleType("bcc")
    bcc.BPF = mock.Mock(return_value=bpf)
    bcc.PerfType = SimpleNamespace(SOFTWARE=1)
    bcc.PerfSWConfig = SimpleNamespace(CPU_CLOCK=0)
    root = mock.MagicMock()
    root.__truediv__.return_value = root
    root.is_file.return_value = True
    namespace = SimpleNamespace(stat=lambda: SimpleNamespace(st_dev=1, st_ino=2))
    layout = SimpleNamespace(cflags=lambda: [], vm_ranges=())

    with ExitStack() as patches:
        patches.enter_context(mock.patch.dict(sys.modules, {"bcc": bcc}))
        patches.enter_context(mock.patch.object(entry.sys, "platform", "linux"))
        patches.enter_context(mock.patch.object(entry.platform, "machine", return_value="x86_64"))
        patches.enter_context(mock.patch.object(entry.shutil, "which", return_value="perl"))
        patches.enter_context(mock.patch.object(entry.signal, "signal"))
        patches.enter_context(mock.patch.object(entry, "process_start",
                                                side_effect=["start", "start", "start", None]))
        replacements = {
            "ROOT": root,
            "Path": lambda unused: namespace,
            "load_layout": lambda unused: layout,
            "MixedStackBuilder": mock.Mock(return_value=builder),
            "Collector": mock.Mock(return_value=collector),
            "read_stats": lambda unused: {"emitted": 1},
            "write_results": writer,
        }
        for name, value in replacements.items():
            patches.enter_context(mock.patch.object(entry, name, value))
        patches.enter_context(mock.patch.object(entry, "print", create=True))
        yield SimpleNamespace(order=order, bpf=bpf, builder=builder,
                              collector=collector, writer=writer)


class ProfileLifecycleTests(unittest.TestCase):
    def test_detach_failure_still_writes_captured_results_and_cleans_up(self):
        with capture_environment("detach failed") as capture:
            with self.assertRaisesRegex(RuntimeError, "detach failed"):
                entry.run(SimpleNamespace(pid=123))
            capture.bpf.cleanup.assert_called_once()
            capture.builder.close.assert_called_once()
            capture.collector.drain.assert_not_called()
            capture.writer.assert_called_once()
            self.assertEqual(capture.writer.call_args.args[1].stacks,
                             {("native:main",): 1})
            self.assertEqual(capture.order, ["sample", "detach", "cleanup", "close", "output"])

    def test_target_exit_stops_sampling_before_draining_and_writing(self):
        with capture_environment() as capture:
            self.assertEqual(entry.run(SimpleNamespace(pid=123)), 0)
            self.assertEqual(capture.order,
                             ["sample", "detach", "drain", "cleanup", "close", "output"])
            capture.writer.assert_called_once()


if __name__ == "__main__":
    unittest.main()
