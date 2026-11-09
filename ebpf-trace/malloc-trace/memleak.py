#!/usr/bin/env python3
"""记录 malloc/free 事件，在按下 Ctrl+C 后对尚未释放的分配进行解栈。"""

import argparse
from collections import Counter
import ctypes
import ctypes.util
from pathlib import Path
import platform
import signal
import sys

from dwarf_unwind import DwarfUnwinder, UnwindResult
from events import (
    AllocationState, FREE, HEADER, LIFECYCLE_SIZE, MALLOC, MAX_SNAPSHOT_BYTES, ProtocolError,
    SAMPLE_LENGTH_OFFSET, SAMPLE_PREFIX_SIZE, decode_event,
)


MALLOC_BUFFER_MB = 64
FREE_BUFFER_MB = 4
MAX_FRAMES = 127
RECORD_BATCH_SIZE = 1000


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-p", "--pid", type=int, required=True, help="target native x86-64 PID")
    parser.add_argument("--obj", default="c", help="glibc library name or path containing malloc/free")
    parser.add_argument("--stack-bytes", type=int, default=16384, help="maximum stack snapshot bytes, 1..32768")
    args = parser.parse_args(argv)
    if args.pid <= 0:
        parser.error("--pid must name a running process")
    if not 1 <= args.stack_bytes <= MAX_SNAPSHOT_BYTES:
        parser.error("--stack-bytes must be between 1 and 32768")
    return args


def dependencies():
    if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise RuntimeError("this tracer requires native x86-64 Linux (WSL2 is supported)")
    if not ctypes.util.find_library("dw"):
        raise RuntimeError("libdw is missing; install the elfutils libdw runtime")
    try:
        from bcc import BPF
    except ImportError as exc:
        raise RuntimeError("BCC Python bindings are missing (Debian: python3-bpfcc)") from exc
    return BPF


class Tracer:
    def __init__(self, bpf):
        self.bpf = bpf
        self.records = []
        self._new_records = 0
        self._last_compacted_sequence = 0
        self._record_received = False
        self.state = None
        self.last_error = ""
        bpf["malloc_events"].open_ring_buffer(self._record)
        bpf["free_events"].open_ring_buffer(self._record)

    def _copy_record(self, data, size):
        if size < LIFECYCLE_SIZE:
            raise ProtocolError("invalid event size")
        kind = ctypes.c_uint32.from_address(data).value
        sequence = ctypes.c_uint64.from_address(data + 8).value
        address = ctypes.c_uint64.from_address(data + HEADER.size).value
        if kind not in (MALLOC, FREE):
            raise ProtocolError("unknown event kind: %s" % kind)
        # free 和没有栈快照的 malloc 都是固定大小的小记录。
        used_size = size
        if size != LIFECYCLE_SIZE:
            if kind != MALLOC or size < SAMPLE_PREFIX_SIZE:
                raise ProtocolError("invalid event size")
            length = ctypes.c_uint32.from_address(data + SAMPLE_LENGTH_OFFSET).value
            used_size = SAMPLE_PREFIX_SIZE + length
            if length > MAX_SNAPSHOT_BYTES or used_size > size:
                raise ProtocolError("snapshot length exceeds record size")
        return sequence, kind, address, ctypes.string_at(data, used_size)

    def _record(self, context, data, size):
        self._record_received = True
        try:
            self.records.append(self._copy_record(data, size))
            self._new_records += 1
            if self._new_records >= RECORD_BATCH_SIZE:
                self._compact_records()
        except Exception as exc:
            self.last_error = str(exc)
        return 0

    def _compact_records(self):
        """只压缩序号连续的部分，缺口及其后的记录原样保留。"""
        self._new_records = 0
        self.records.sort(key=lambda record: record[0])
        live = {}
        last_sequence = self._last_compacted_sequence
        pending = []
        for index, record in enumerate(self.records):
            sequence, kind, address, _ = record
            # 旧的存活记录已处理过；只要求新增部分从上次进度起连续。
            if sequence > last_sequence:
                if sequence != last_sequence + 1:
                    pending = self.records[index:]
                    break
                last_sequence = sequence
            # 先移除旧状态，再按需插入，使剩余记录也保持最新分配的序号顺序。
            live.pop(address, None)
            if kind == MALLOC:
                live[address] = record
        self.records = list(live.values()) + pending
        self._last_compacted_sequence = last_sequence

    def drain(self):
        # 清理会改变 records 长度，需通过本轮是否收到回调判断 ring 是否读完。
        while True:
            self._record_received = False
            self.bpf.ring_buffer_consume()
            if not self._record_received:
                return

    def finish(self, unwinder):
        """卸载探针并读完缓冲区后，配对事件，仅对尚未释放的分配进行解栈。"""
        if self.state is not None:
            return self.state
        self._compact_records()
        self.state = AllocationState()
        for _, _, _, data in self.records:
            try:
                self.state.apply(decode_event(data))
            except ProtocolError as exc:
                self.last_error = str(exc)
        self.records.clear()

        for allocation in self.state.live.values():
            if allocation.snapshot is None:
                continue
            try:
                allocation.result = unwinder.unwind(allocation.snapshot)
            except Exception as exc:
                allocation.result = UnwindResult((), "failed", "unwind error: %s" % exc)
        return self.state

    def report(self, pid):
        if self.state is None:
            raise RuntimeError("finish capture before reporting")
        allocations = list(self.state.live.values())
        total_bytes = sum(item.size for item in allocations)
        print("PID %d: %d bytes in %d outstanding mallocs (observed since attach)" %
              (pid, total_bytes, len(allocations)))
        groups = {}
        for allocation in allocations:
            result = allocation.result
            frames = result.frames if result else ()
            status = result.status if result else "unknown"
            reason = result.stop_reason if result else "stack snapshot unavailable"
            # 按完整的调用地址序列归类，避免把同一函数内不同调用点的栈合并。
            # 同时区分解栈状态，避免将不完整的解栈结果与完整结果归为一组。
            key = (tuple((frame.module, frame.lookup_pc) for frame in frames), status)
            if key not in groups:
                groups[key] = {"bytes": 0, "count": 0, "frames": frames,
                               "status": status, "reasons": Counter()}
            group = groups[key]
            group["bytes"] += allocation.size
            group["count"] += 1
            group["reasons"][reason] += 1
        for group in sorted(groups.values(), key=lambda item: item["bytes"], reverse=True):
            print("  %d bytes in %d allocations [%s]" %
                  (group["bytes"], group["count"], group["status"]))
            if group["status"] != "complete":
                for reason, count in group["reasons"].most_common():
                    print("    %d allocations: %s" % (count, reason))
            for frame in group["frames"]:
                detail = "0x%x" % frame.lookup_pc
                if frame.symbol:
                    detail += " " + frame.symbol
                if frame.module:
                    detail += " [%s]" % frame.module
                if frame.location:
                    detail += " at " + frame.location
                print("    " + detail)
        if self.last_error:
            print("  last error: " + self.last_error)


def run(args):
    BPF = dependencies()
    with open("/proc/%d/exe" % args.pid, "rb") as executable:
        header = executable.read(20)
    if header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != 62:
        raise RuntimeError("target must be a native little-endian x86-64 ELF process")

    # 提前定位并持有 ELF 文件，实际解栈在停止采集后进行。
    unwinder = DwarfUnwinder(args.pid, max_frames=MAX_FRAMES)
    namespace = Path("/proc/self/ns/pid").stat()
    cflags = [
        "-DTARGET_PID=%d" % args.pid, "-DSTACK_MAX_BYTES=%d" % args.stack_bytes,
        "-DPIDNS_DEV=%dULL" % namespace.st_dev, "-DPIDNS_INO=%dULL" % namespace.st_ino,
        "-DMALLOC_PAGES=%d" % (MALLOC_BUFFER_MB * 256),
        "-DFREE_PAGES=%d" % (FREE_BUFFER_MB * 256),
    ]
    bpf = None
    tracer = None
    attached = []
    old_handlers = {}
    started = False
    stopping = False

    def stop(signum, frame):
        nonlocal stopping
        stopping = True

    try:
        bpf = BPF(src_file=str(Path(__file__).with_name("memleak.bpf.c")), cflags=cflags)
        tracer = Tracer(bpf)
        # 先挂载 free 探针，再开始捕获新的分配事件。
        bpf.attach_uprobe(name=args.obj, sym="free", fn_name="trace_free_enter", pid=args.pid)
        attached.append((False, "free"))
        bpf.attach_uretprobe(name=args.obj, sym="malloc", fn_name="trace_malloc_exit", pid=args.pid)
        attached.append((True, "malloc"))
        bpf.attach_uprobe(name=args.obj, sym="malloc", fn_name="trace_malloc_enter", pid=args.pid)
        attached.append((False, "malloc"))
        for signum in (signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.signal(signum, stop)
        started = True
        print("Tracing PID %d; press Ctrl+C to stop and unwind." % args.pid, file=sys.stderr, flush=True)
        while not stopping and Path("/proc/%d" % args.pid).exists():
            bpf.ring_buffer_poll(100)
    finally:
        try:
            if bpf is not None:
                detached = True
                for is_return, symbol in reversed(attached):
                    detach = bpf.detach_uretprobe if is_return else bpf.detach_uprobe
                    try:
                        detach(name=args.obj, sym=symbol, pid=args.pid)
                    except Exception as exc:
                        detached = False
                        tracer.last_error = "probe detach failed: %s" % exc
                if started:
                    # 卸载成功后读完剩余事件；卸载失败时避免等待持续写入的 ring。
                    if detached:
                        tracer.drain()
                    tracer.finish(unwinder)
                    tracer.report(args.pid)
        finally:
            try:
                if bpf is not None:
                    bpf.cleanup()
            finally:
                unwinder.close()
                for signum, handler in old_handlers.items():
                    signal.signal(signum, handler)
    return 0


def main(argv=None):
    args = arguments(argv)
    try:
        return run(args)
    except (Exception, KeyboardInterrupt) as exc:
        print("memleak: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
