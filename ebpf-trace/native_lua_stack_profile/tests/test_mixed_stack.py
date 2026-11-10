"""混合栈的顺序由 VM/CallInfo 对应关系决定，不依赖真实目标进程。"""

from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pylib import mixed_stack
from pylib.mixed_stack import MixedStackBuilder, merge_frames
from pylib.sample_events import C_FRAME, LUA_FRAME, LUA_DEPTH_LIMIT, LUA_NULL


def native(*root_first, status="complete", reason=""):
    frames = [SimpleNamespace(lookup_pc=pc, symbol=name, module="/tmp/test.so")
              for pc, name in root_first]
    return SimpleNamespace(frames=tuple(reversed(frames)), status=status,
                           stop_reason=reason)


def lua(line, fresh=False, source="@test.lua"):
    return SimpleNamespace(callstatus=4 if fresh else 0, kind=LUA_FRAME,
                           source=source, linedefined=line)


def c_frame():
    return SimpleNamespace(callstatus=2, kind=C_FRAME)


VM = ((100, 200),)


class MixedStackTests(unittest.TestCase):
    def test_multiple_lua_calls_expand_one_vm_frame(self):
        result = merge_frames(native((1, "main"), (110, "luaV_execute")),
                              (lua(20), lua(10, fresh=True)), 0, VM)
        self.assertEqual(result.status, "complete")
        self.assertEqual(result.frames, ("native:main", "native:luaV_execute",
                                         "lua:test.lua:10", "lua:test.lua:20"))

    def test_callback_interleaves_two_vm_segments(self):
        frames = (c_frame(), lua(40, fresh=True), c_frame(), lua(20), lua(10, fresh=True))
        result = merge_frames(
            native((1, "main"), (110, "luaV_execute"), (220, "cpp_call_lua"),
                   (120, "luaV_execute"), (230, "cpp_work"), (240, "native_work")),
            frames, 0, VM)
        self.assertEqual(result.status, "complete")
        self.assertEqual(result.frames, (
            "native:main", "native:luaV_execute", "lua:test.lua:10", "lua:test.lua:20",
            "native:cpp_call_lua", "native:luaV_execute", "lua:test.lua:40",
            "native:cpp_work", "native:native_work"))

    def test_recursive_lua_frames_are_preserved(self):
        result = merge_frames(native((110, "luaV_execute")),
                              (lua(10), lua(10), lua(10, fresh=True)), 0, VM)
        self.assertEqual(result.frames.count("lua:test.lua:10"), 3)

    def test_vm_frame_count_mismatch_keeps_native_only(self):
        result = merge_frames(native((1, "main")), (lua(10, fresh=True),), 0, VM)
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.frames, ("[mixed_partial]", "native:main"))
        self.assertIn("do not match", result.reason)

    def test_lua_truncation_does_not_invent_missing_frames(self):
        result = merge_frames(native((110, "luaV_execute")), (lua(10),),
                              LUA_DEPTH_LIMIT, VM)
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.lua_status, "partial")
        self.assertFalse(any(frame.startswith("lua:") for frame in result.frames))

    def test_native_partial_does_not_attach_lua_to_unproven_root(self):
        result = merge_frames(native((110, "luaV_execute"), status="partial",
                                     reason="snapshot exhausted"),
                              (lua(10, fresh=True),), 0, VM)
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.native_status, "partial")
        self.assertIn("snapshot exhausted", result.reason)

    def test_failed_native_unwind_is_visible(self):
        result = merge_frames(native(status="failed", reason="no frames"), (), LUA_NULL, VM)
        self.assertEqual(result.frames, ("[native_failed]",))
        self.assertEqual(result.status, "failed")

    def test_null_or_idle_state_is_normal_native_only(self):
        for flags in (0, LUA_NULL):
            result = merge_frames(native((1, "main")), (), flags, VM)
            self.assertEqual(result.status, "complete")
            self.assertEqual(result.lua_status, "none")
            self.assertEqual(result.frames, ("native:main",))

    def test_vm_anchors_use_addresses_not_symbol_names(self):
        result = merge_frames(native((1, "luaV_execute")), (), 0, VM)
        self.assertEqual(result.status, "complete")
        result = merge_frames(native((110, "unavailable")), (lua(10, fresh=True),), 0, VM)
        self.assertEqual(result.status, "complete")

    def test_missing_fresh_frame_is_partial(self):
        result = merge_frames(native((110, "luaV_execute")), (lua(10),), 0, VM)
        self.assertEqual(result.status, "partial")
        self.assertIn("no CIST_FRESH", result.reason)

    def test_folded_delimiters_in_frame_names_are_sanitized(self):
        result = merge_frames(native((110, "vm;symbol\n")),
                              (lua(10, fresh=True, source="@chunk;name\n"),), 0, VM)
        self.assertTrue(all(";" not in frame and "\n" not in frame for frame in result.frames))


class BufferedSnapshotTests(unittest.TestCase):
    """目标已退出时仍应使用启动时的 ELF，对 ring 中旧快照正常解栈。"""

    def setUp(self):
        self.module = mixed_stack._unwind_module()
        self.unwinder = object.__new__(self.module.DwarfUnwinder)
        self.unwinder.pid = 123
        self.unwinder._dwfl = 1
        self.unwinder._map_error = ""
        self.unwinder._mappings = ("initial executable mapping",)
        self.unwinder._frame_cb = None

        def frames(*args):
            self.unwinder._frames.append(self.module.Frame(1, 1, "main"))
            return 0

        self.unwinder._lib = SimpleNamespace(dwfl_getthread_frames=frames)
        self.backend = SimpleNamespace(Snapshot=self.module.Snapshot,
                                       DwarfUnwinder=lambda *args, **kwargs: self.unwinder)
        self.sample = SimpleNamespace(sequence=1, pid=123, tid=123, regs=(0,) * 17,
                                      stack_base=0, stack=b"", native_flags=0, native_error=0,
                                      lua_frames=(), lua_flags=LUA_NULL)

    def build_after(self, state):
        with patch.object(mixed_stack, "_unwind_module", return_value=self.backend), \
                patch.object(mixed_stack, "_process_identity", create=True,
                             side_effect=[("R", 100), state]), \
                patch.object(self.module, "_maps", return_value=()) as maps:
            builder = MixedStackBuilder(123, VM)
            result = builder.build(self.sample)
        return result, maps

    def test_zombie_empty_maps_does_not_destroy_buffered_snapshot(self):
        result, maps = self.build_after(("Z", 100))
        self.assertEqual(result.status, "complete")
        self.assertEqual(result.frames, ("native:main",))
        maps.assert_not_called()

    def test_missing_process_uses_saved_elf(self):
        result, maps = self.build_after(None)
        self.assertEqual(result.status, "complete")
        maps.assert_not_called()

    def test_reused_pid_does_not_validate_against_new_process_maps(self):
        result, maps = self.build_after(("R", 200))
        self.assertEqual(result.status, "complete")
        maps.assert_not_called()

    def test_alive_process_mapping_changes_still_fail(self):
        result, maps = self.build_after(("R", 100))
        self.assertEqual(result.status, "failed")
        self.assertIn("module mappings changed", result.reason)
        maps.assert_called_once_with(123)

    def test_previous_mapping_error_cannot_be_bypassed_after_exit(self):
        self.unwinder._map_error = "previous module mappings changed"
        result, maps = self.build_after(("Z", 100))
        self.assertEqual(result.status, "failed")
        self.assertIn("previous module mappings changed", result.reason)
        maps.assert_not_called()

    def test_old_unwind_call_still_validates_maps_by_default(self):
        snapshot = self.module.Snapshot(1, 123, 123, (0,) * 17, 0, b"")
        with patch.object(self.module, "_maps", return_value=()):
            result = self.unwinder.unwind(snapshot)
        self.assertEqual(result.status, "failed")
        self.assertIn("module mappings changed", result.stop_reason)

    def test_process_identity_handles_parentheses_in_comm(self):
        stat = "123 (worker ) name) R " + " ".join(["0"] * 18 + ["987", "0"])
        with patch.object(Path, "read_text", return_value=stat):
            self.assertEqual(mixed_stack._process_identity(123), ("R", 987))


if __name__ == "__main__":
    unittest.main()
