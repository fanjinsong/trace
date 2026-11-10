#!/usr/bin/env python3
"""Sample one profile_test process at 49 Hz and write a mixed CPU flame graph."""

import argparse
from collections import Counter
import ctypes
from datetime import datetime
from pathlib import Path
import platform
import shutil
import signal
import sys
from zoneinfo import ZoneInfo

from pylib.flamegraph import render_flamegraph
from pylib.lua_layout import load_layout
from pylib.mixed_stack import MixedStackBuilder
from pylib.sample_events import STATS_NAMES, decode_event


ROOT = Path(__file__).resolve().parent
SAMPLE_HZ = 49


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-p", "--pid", type=int, required=True, help="profile_test PID")
    args = parser.parse_args(argv)
    if args.pid <= 0:
        parser.error("--pid must be positive")
    return args


def process_start(pid):
    """Include start time to distinguish an exited target from a reused PID."""
    try:
        fields = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
    except (FileNotFoundError, ProcessLookupError):
        return None
    return None if fields[0] == "Z" else fields[19]


class Collector:
    def __init__(self, builder):
        self.builder = builder
        self.stacks = Counter()
        self.statuses = Counter()
        self.reasons = Counter()
        self.error = ""
        self.received = False

    def record(self, context, data, size):
        self.received = True
        try:
            sample = decode_event(ctypes.string_at(data, size))
            result = self.builder.build(sample)
            self.stacks[result.frames or ("[empty_stack]",)] += 1
            self.statuses[result.status] += 1
            if result.reason:
                self.reasons[result.reason] += 1
            if "module mappings changed" in result.reason:
                self.error = result.reason
        except Exception as exc:
            self.statuses["sample_error"] += 1
            self.reasons[str(exc)] += 1
        return 0

    def drain(self, bpf):
        # Called only after all sampling events have been detached.
        while True:
            self.received = False
            bpf.ring_buffer_consume()
            if not self.received:
                break


def read_stats(bpf):
    table = bpf["stats"]
    return {name: sum(int(getattr(value, "value", value))
                      for value in table[ctypes.c_int(index)])
            for index, name in enumerate(STATS_NAMES)}


def write_results(pid, collector, stats, perl, flamegraph):
    output = ROOT / "profile-output"
    output.mkdir(exist_ok=True)
    stamp = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y%m%d-%H%M%S-%f")
    base = output / ("%d-%s" % (pid, stamp))
    folded = base.with_suffix(".folded")
    svg = base.with_suffix(".svg")
    with folded.open("w", encoding="utf-8") as stream:
        for frames, count in sorted(collector.stacks.items()):
            stream.write("%s %d\n" % (";".join(frames), count))

    print("BPF: " + ", ".join("%s=%d" % item for item in stats.items()))
    print("Stacks: " + ", ".join("%s=%d" % item for item in collector.statuses.items()))
    for reason, count in collector.reasons.most_common(10):
        print("  %d: %s" % (count, reason))
    print("Folded: " + str(folded))
    if not collector.stacks:
        print("No stack samples; SVG was not generated.", file=sys.stderr)
        return
    render_flamegraph(folded, svg, pid=pid, perl=perl, script=flamegraph)
    print("SVG: " + str(svg))


def run(args):
    if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise RuntimeError("this profiler requires x86-64 Linux or WSL2")
    try:
        from bcc import BPF, PerfType, PerfSWConfig
    except ImportError as exc:
        raise RuntimeError("install python3-bpfcc and use /usr/bin/python3") from exc
    perl = shutil.which("perl")
    flamegraph = ROOT / "flamegraph" / "flamegraph.pl"
    if not perl or not flamegraph.is_file():
        raise RuntimeError("Perl and the flamegraph submodule are required; "
                           "run git submodule update --init --recursive")
    identity = process_start(args.pid)
    if identity is None:
        raise RuntimeError("target process is not running")
    layout = load_layout(args.pid)
    namespace = Path("/proc/self/ns/pid").stat()
    cflags = layout.cflags() + ["-DTARGET_PID=%d" % args.pid,
                               "-DPIDNS_DEV=%dULL" % namespace.st_dev,
                               "-DPIDNS_INO=%dULL" % namespace.st_ino]
    builder = MixedStackBuilder(args.pid, layout.vm_ranges)
    collector = Collector(builder)
    bpf = None
    attached = False
    started = False
    stopping = False
    old_handlers = {}
    error = None
    stats = {}

    def stop(signum, frame):
        nonlocal stopping
        stopping = True

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.signal(signum, stop)
        bpf = BPF(src_file=str(ROOT / "pylib" / "bcc.c"), cflags=cflags)
        bpf["events"].open_ring_buffer(collector.record)
        if process_start(args.pid) != identity:
            raise RuntimeError("target exited while preparing the profiler")
        if not stopping:
            bpf.attach_perf_event(ev_type=PerfType.SOFTWARE, ev_config=PerfSWConfig.CPU_CLOCK,
                                  fn_name="sample", sample_freq=SAMPLE_HZ)
            attached = started = True
            print("Sampling PID %d at %d Hz; Ctrl+C to write the flame graph." %
                  (args.pid, SAMPLE_HZ), file=sys.stderr, flush=True)
        while started and not stopping and process_start(args.pid) == identity:
            bpf.ring_buffer_poll(100)
            if collector.error:
                raise RuntimeError(collector.error)
    except (Exception, KeyboardInterrupt) as exc:
        error = exc
    finally:
        # A cleanup failure must not prevent writing stacks already collected.
        try:
            if attached:
                bpf.detach_perf_event(ev_type=PerfType.SOFTWARE, ev_config=PerfSWConfig.CPU_CLOCK)
                attached = False
        except Exception as exc:
            error = error or exc
        if started and not attached:
            try:
                collector.drain(bpf)
            except Exception as exc:
                error = error or exc
        if started:
            try:
                stats = read_stats(bpf)
            except Exception as exc:
                error = error or exc
        try:
            if bpf is not None:
                bpf.cleanup()
        except Exception as exc:
            error = error or exc
        try:
            builder.close()
        except Exception as exc:
            error = error or exc
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
    if started:
        write_results(args.pid, collector, stats, perl, flamegraph)
    if error is not None:
        raise RuntimeError(str(error) or "capture interrupted") from error
    return 0


def main(argv=None):
    args = arguments(argv)
    try:
        return run(args)
    except (Exception, KeyboardInterrupt) as exc:
        print("profile: %s" % (str(exc) or "interrupted"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
