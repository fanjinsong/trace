"""使用寄存器快照和已复制的用户栈数据，离线执行 x86-64 DWARF 栈回溯。

仅使用 libdw 公开的 libdwfl 接口，不通过 ptrace 附加目标进程，
内存读取回调也不会读取目标当前的 /proc/PID/mem。回溯需要可访问的 ELF 文件
和稳定的 /proc/PID/maps 布局；遇到 JIT 或模块映射变化时会明确报告不支持，
避免猜测调用栈。
"""

from __future__ import annotations

import ctypes as ct
import ctypes.util
import os
import platform
import re
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple


@dataclass(frozen=True)
class Frame:
    pc: int
    lookup_pc: int
    symbol: str = ""
    module: str = ""
    location: str = ""


@dataclass(frozen=True)
class UnwindResult:
    frames: Tuple[Frame, ...]
    status: str
    stop_reason: str


@dataclass(frozen=True)
class Snapshot:
    alloc_id: int
    pid: int
    tid: int
    # AMD64 DWARF 寄存器顺序：AX、DX、CX、BX、SI、DI、BP、SP、R8..R15、IP。
    regs: Tuple[int, ...]
    stack_base: int
    stack: bytes
    flags: int = 0
    read_error: int = 0


@dataclass(frozen=True)
class _Mapping:
    start: int
    end: int
    permissions: str
    offset: int
    device: str
    inode: int
    path: str


_P = ct.c_void_p
_U64 = ct.c_uint64
_NEXT_THREAD = ct.CFUNCTYPE(ct.c_int, _P, _P, ct.POINTER(_P))
_MEMORY_READ = ct.CFUNCTYPE(ct.c_bool, _P, _U64, ct.POINTER(_U64), _P)
_INITIAL_REGS = ct.CFUNCTYPE(ct.c_bool, _P, _P)
_FRAME_CALLBACK = ct.CFUNCTYPE(ct.c_int, _P, _P)
_FIND_DEBUG = ct.CFUNCTYPE(ct.c_int, _P, ct.POINTER(_P), ct.c_char_p,
                         _U64, ct.c_char_p, ct.c_char_p, ct.c_uint32, ct.POINTER(_P))


class _Callbacks(ct.Structure):
    # 用 void* 保存函数地址，直接使用 libdw 提供的标准回调，
    # 无需在 Python 中为这些参数繁多的 ABI 定义对应函数。
    _fields_ = [(name, _P) for name in (
        "find_elf", "find_debuginfo", "section_address", "debuginfo_path")]


class _ThreadCallbacks(ct.Structure):
    # 保留完整 ABI 布局；get_thread 置空，libdwfl 通过 next_thread 获取快照的 TID。
    _fields_ = [
        ("next_thread", _NEXT_THREAD),
        ("get_thread", _P),
        ("memory_read", _MEMORY_READ),
        ("set_initial_registers", _INITIAL_REGS),
        ("detach", _P),
        ("thread_detach", _P),
    ]


def _decode(value: Optional[bytes]) -> str:
    return value.decode("utf-8", "replace") if value else ""


def _maps(pid: int) -> Tuple[_Mapping, ...]:
    result = []
    with open("/proc/%d/maps" % pid, encoding="utf-8", errors="surrogateescape") as stream:
        for line in stream:
            fields = line.rstrip("\n").split(None, 5)
            if len(fields) < 6 or not fields[5].startswith("/"):
                continue
            start, end = (int(value, 16) for value in fields[0].split("-", 1))
            path = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[5])
            result.append(_Mapping(start, end, fields[1], int(fields[2], 16),
                                   fields[3], int(fields[4]), path))
    # 忽略匿名栈、堆的增长，以及调试器自身创建的只读 ELF 映射。
    # 只关注可执行映射，代码的加载和卸载会使其发生变化。
    return tuple(m for m in result if "x" in m.permissions)


def _elf_base(descriptor: int, mapping: _Mapping) -> int:
    """根据可执行 PT_LOAD 段的映射，计算传给 dwfl_report_elf 的 BASE。

    仅用 Mapping.start - mapping.offset 无法适配所有 ELF 布局。
    当 add_p_vaddr=false 时，BASE 是最低 PT_LOAD 虚拟地址向下按页对齐后，
    对应的运行时绝对地址，不能一律当作加载偏移量。
    """
    header = os.pread(descriptor, 64, 0)
    phoff = struct.unpack_from("<Q", header, 32)[0]
    phsize, phcount = struct.unpack_from("<HH", header, 54)
    loads = []
    for index in range(phcount):
        data = os.pread(descriptor, phsize, phoff + index * phsize)
        if len(data) < 56:
            raise ValueError("truncated ELF program header")
        kind, flags, offset, vaddr, _, file_size, _, _ = struct.unpack_from("<IIQQQQQQ", data)
        if kind == 1:
            loads.append((flags, offset, vaddr, file_size))
    page_size = os.sysconf("SC_PAGE_SIZE")
    page_mask = ~(page_size - 1)
    minimum_vaddr = min(vaddr & page_mask for _, _, vaddr, _ in loads)
    for flags, offset, vaddr, file_size in loads:
        if flags & 1 and (offset & page_mask) <= mapping.offset < offset + file_size:
            bias = mapping.start - (vaddr + mapping.offset - offset)
            return bias + minimum_vaddr
    raise ValueError("executable mapping does not match an ELF PT_LOAD")


class DwarfUnwinder:
    """在主线程中，用一个 libdwfl 会话依次回溯单个进程的快照。

    ELF 映射变化后不再解栈，因为旧快照没有记录所属的映射版本，
    无法安全地按新布局解析。
    """

    def __init__(self, pid: int, max_frames: int = 127):
        if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
            raise RuntimeError("DWARF unwinding requires native Linux x86-64")
        if pid <= 0 or max_frames <= 0:
            raise ValueError("pid and max_frames must be positive")
        self.pid = pid
        self.max_frames = max_frames
        self._dwfl = None
        self._snapshot = None
        self._frames = []
        self._callback_error = ""
        self._memory_error = ""
        self._map_error = ""
        # 同一会话内按地址复用查询结果，关闭时清空，不维护 LRU 淘汰规则。
        self._symbol_cache = {}
        self._cfi_cache = {}
        try:
            self._lib = ct.CDLL(ctypes.util.find_library("dw") or "libdw.so.1")
        except OSError as exc:
            raise RuntimeError("libdw.so.1 is required (Debian/Ubuntu: libdw1)") from exc
        self._libc = ct.CDLL(None)
        self._libc.free.argtypes = [_P]
        self._libc.free.restype = None
        self._libc.strdup.argtypes = [ct.c_char_p]
        self._libc.strdup.restype = _P
        self._bind()
        self._mappings = _maps(pid)
        self._callbacks = _Callbacks()
        # 自定义回调只查找本地调试文件，避免 libdwfl 通过 debuginfod 联网查询，
        # 并校验 .gnu_debuglink 指向的独立调试文件。
        self._debug_cb = _FIND_DEBUG(self._find_debug)
        self._callbacks.find_debuginfo = ct.cast(self._debug_cb, _P)
        self._callbacks.section_address = ct.cast(self._lib.dwfl_offline_section_address, _P)
        # 保持这些回调对象的引用，直到 dwfl_end 调用完成。
        # 线程回调描述当前快照的目标 TID，不会创建 Python 线程。
        self._next_cb = _NEXT_THREAD(self._next_thread)
        self._memory_cb = _MEMORY_READ(self._read_memory)
        self._regs_cb = _INITIAL_REGS(self._initial_registers)
        self._frame_cb = _FRAME_CALLBACK(self._visit_frame)
        self._thread_callbacks = _ThreadCallbacks(
            self._next_cb, None, self._memory_cb, self._regs_cb, None, None)
        self._dwfl = self._lib.dwfl_begin(ct.byref(self._callbacks))
        if not self._dwfl:
            raise RuntimeError("dwfl_begin: " + self._error())
        try:
            self._report_modules()
            if not self._lib.dwfl_attach_state(self._dwfl, None, pid,
                                               ct.byref(self._thread_callbacks), None):
                raise RuntimeError("dwfl_attach_state: " + self._error())
        except BaseException:
            self.close()
            raise

    def _bind(self):
        signatures = {
            "dwfl_begin": (_P, [ct.POINTER(_Callbacks)]),
            "dwfl_end": (None, [_P]),
            "dwfl_report_begin": (None, [_P]),
            "dwfl_report_elf": (_P, [_P, ct.c_char_p, ct.c_char_p, ct.c_int, _U64, ct.c_bool]),
            "dwfl_report_end": (ct.c_int, [_P, _P, _P]),
            "dwfl_attach_state": (ct.c_bool, [_P, _P, ct.c_int, ct.POINTER(_ThreadCallbacks), _P]),
            "dwfl_getthread_frames": (ct.c_int, [_P, ct.c_int, _FRAME_CALLBACK, _P]),
            "dwfl_thread_state_registers": (ct.c_bool, [_P, ct.c_int, ct.c_uint, ct.POINTER(_U64)]),
            "dwfl_frame_pc": (ct.c_bool, [_P, ct.POINTER(_U64), ct.POINTER(ct.c_bool)]),
            "dwfl_addrmodule": (_P, [_P, _U64]),
            "dwfl_module_addrname": (ct.c_char_p, [_P, _U64]),
            "dwfl_module_getsrc": (_P, [_P, _U64]),
            "dwfl_lineinfo": (ct.c_char_p, [_P, ct.POINTER(_U64), ct.POINTER(ct.c_int),
                                            ct.POINTER(ct.c_int), ct.POINTER(_U64), ct.POINTER(_U64)]),
            "dwfl_module_eh_cfi": (_P, [_P, ct.POINTER(_U64)]),
            "dwfl_module_dwarf_cfi": (_P, [_P, ct.POINTER(_U64)]),
            "dwarf_cfi_addrframe": (ct.c_int, [_P, _U64, ct.POINTER(_P)]),
            "dwfl_errmsg": (ct.c_char_p, [ct.c_int]),
        }
        try:
            for name, (return_type, arguments) in signatures.items():
                function = getattr(self._lib, name)
                function.restype = return_type
                function.argtypes = arguments
        except AttributeError as exc:
            raise RuntimeError("installed libdw lacks the required public unwind interface") from exc

    def _error(self) -> str:
        return _decode(self._lib.dwfl_errmsg(-1)) or "unknown libdw error"

    def _report_modules(self):
        self._lib.dwfl_report_begin(self._dwfl)
        groups = {}
        for mapping in self._mappings:
            groups.setdefault((mapping.device, mapping.inode, mapping.path), []).append(mapping)
        loaded = 0
        for (device, inode, path), mappings in groups.items():
            # 通过 /proc/PID/root，可按目标进程的挂载命名空间解析路径。
            candidates = ["/proc/%d/root%s" % (self.pid, path), path]
            descriptor = None
            for candidate in candidates:
                try:
                    descriptor = os.open(candidate, os.O_RDONLY | os.O_CLOEXEC)
                    info = os.fstat(descriptor)
                    identity = os.pread(descriptor, 20, 0)
                    expected_device = tuple(int(value, 16) for value in device.split(":"))
                    if (info.st_ino != inode
                            or (os.major(info.st_dev), os.minor(info.st_dev)) != expected_device
                            or identity[:6] != b"\x7fELF\x02\x01"
                            or len(identity) < 20 or struct.unpack_from("<H", identity, 18)[0] != 62):
                        os.close(descriptor)
                        descriptor = None
                        continue
                    break
                except OSError:
                    if descriptor is not None:
                        os.close(descriptor)
                    descriptor = None
            if descriptor is None:
                continue
            try:
                bases = {_elf_base(descriptor, mapping) for mapping in mappings}
                for base in bases:
                    module_fd = os.dup(descriptor)
                    module = self._lib.dwfl_report_elf(self._dwfl, os.fsencode(path),
                                                       os.fsencode(path), module_fd, base, False)
                    if not module:
                        os.close(module_fd)  # 只有调用成功时，库才会接管该文件描述符。
                        continue
                    loaded += 1
            finally:
                os.close(descriptor)
        if self._lib.dwfl_report_end(self._dwfl, None, None) != 0:
            raise RuntimeError("dwfl_report_end: " + self._error())
        if not loaded:
            raise RuntimeError("no readable native x86-64 ELF modules found for PID %d" % self.pid)

    def _next_thread(self, dwfl, argument, thread_argument):
        try:
            if self._snapshot is None or thread_argument[0]:
                return 0
            thread_argument[0] = 1
            return self._snapshot.tid
        except Exception as exc:
            self._callback_error = "thread callback: %s" % exc
            return -1

    def _find_debug(self, module, userdata, module_name, base, file_name,
                    debuglink_file, debuglink_crc, output_name):
        """只打开 CRC 匹配的本地 debuglink 调试文件，不访问服务器。"""
        descriptor = None
        try:
            if not file_name or not debuglink_file:
                return -1  # 不使用此回调仍可读取 ELF 内嵌的 .debug_info。
            filename = os.fsdecode(file_name)
            debuglink = os.fsdecode(debuglink_file)
            if os.path.basename(debuglink) != debuglink:
                return -1
            directory = os.path.dirname(filename)
            candidates = [os.path.join(directory, debuglink),
                          os.path.join(directory, ".debug", debuglink),
                          os.path.join("/usr/lib/debug", directory.lstrip("/"), debuglink)]
            for candidate in candidates:
                for location in ("/proc/%d/root%s" % (self.pid, candidate), candidate):
                    try:
                        descriptor = os.open(location, os.O_RDONLY | os.O_CLOEXEC)
                        crc = 0
                        while True:
                            data = os.read(descriptor, 65536)
                            if not data:
                                break
                            crc = zlib.crc32(data, crc)
                        if crc != debuglink_crc:
                            os.close(descriptor)
                            descriptor = None
                            continue
                        os.lseek(descriptor, 0, os.SEEK_SET)
                        name = self._libc.strdup(os.fsencode(location))
                        if not name:
                            os.close(descriptor)
                            return -1
                        output_name[0] = name
                        return descriptor  # 库会接管文件描述符和动态分配的文件名内存。
                    except OSError:
                        if descriptor is not None:
                            os.close(descriptor)
                        descriptor = None
            return -1
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            return -1

    def _initial_registers(self, thread, argument):
        try:
            values = (_U64 * 17)(*self._snapshot.regs)
            return self._lib.dwfl_thread_state_registers(thread, 0, 17, values)
        except Exception as exc:
            self._callback_error = "register callback: %s" % exc
            return False

    def _read_memory(self, dwfl, address, result, argument):
        try:
            sample = self._snapshot
            offset = address - sample.stack_base
            if offset < 0 or offset + 8 > len(sample.stack):
                self._memory_error = "snapshot range exhausted at 0x%x" % address
                return False
            result[0] = struct.unpack_from("<Q", sample.stack, offset)[0]
            return True
        except Exception as exc:
            self._callback_error = "memory callback: %s" % exc
            return False

    def _has_cfi(self, module, pc: int) -> bool:
        key = (module, pc)
        if key in self._cfi_cache:
            return self._cfi_cache[key]
        for name in ("dwfl_module_eh_cfi", "dwfl_module_dwarf_cfi"):
            bias = _U64()
            cache = getattr(self._lib, name)(module, ct.byref(bias))
            if not cache or pc < bias.value:
                continue
            frame = _P()
            if self._lib.dwarf_cfi_addrframe(cache, pc - bias.value, ct.byref(frame)) == 0:
                self._libc.free(frame)
                self._cfi_cache[key] = True
                return True
        self._cfi_cache[key] = False
        return False

    def _symbolize(self, module, pc: int, lookup_pc: int) -> Frame:
        key = (pc, lookup_pc)
        if key in self._symbol_cache:
            return self._symbol_cache[key]
        path = next((mapping.path for mapping in self._mappings
                     if mapping.start <= lookup_pc < mapping.end), "")
        symbol = _decode(self._lib.dwfl_module_addrname(module, lookup_pc))
        location = ""
        line = self._lib.dwfl_module_getsrc(module, lookup_pc)
        if line:
            line_number = ct.c_int()
            filename = self._lib.dwfl_lineinfo(line, None, ct.byref(line_number), None, None, None)
            if filename and line_number.value > 0:
                location = "%s:%d" % (_decode(filename), line_number.value)
        frame = Frame(pc, lookup_pc, symbol, path, location)
        self._symbol_cache[key] = frame
        return frame

    def _visit_frame(self, state, argument):
        try:
            pc = _U64()
            activation = ct.c_bool()
            if not self._lib.dwfl_frame_pc(state, ct.byref(pc), ct.byref(activation)):
                self._callback_error = "frame PC unavailable: " + self._error()
                return 1
            if not pc.value:
                return 0
            lookup_pc = pc.value if activation.value else pc.value - 1
            module = self._lib.dwfl_addrmodule(self._dwfl, lookup_pc)
            if not module:
                self._frames.append(Frame(pc.value, lookup_pc))
                self._callback_error = "unknown ELF module or uretprobe trampoline at 0x%x" % lookup_pc
                return 1
            self._frames.append(self._symbolize(module, pc.value, lookup_pc))
            # 缺少 CFI 时，libdwfl 可能退回到架构相关的帧指针回溯。
            # 这里仅允许使用 DWARF，因此缺少 CFI 就停止。
            if not self._has_cfi(module, lookup_pc):
                self._callback_error = "no DWARF CFI at 0x%x" % lookup_pc
                return 1
            if len(self._frames) >= self.max_frames:
                self._callback_error = "maximum frame depth reached"
                return 1
            return 0
        except Exception as exc:
            self._callback_error = "frame callback: %s" % exc
            return 1

    def unwind(self, snapshot: Snapshot, *, process_exited: bool = False) -> UnwindResult:
        """process_exited 仅用于调用方已确认原目标退出后的缓冲快照。

        此时继续使用会话持有的 ELF 和旧映射；已有映射错误仍然不可绕过。
        """
        if self._dwfl is None:
            raise RuntimeError("unwinder is closed")
        if snapshot.pid != self.pid:
            return UnwindResult((), "failed", "snapshot PID does not match the ELF session")
        if len(snapshot.regs) != 17 or snapshot.regs[7] != snapshot.stack_base:
            return UnwindResult((), "failed", "invalid x86-64 registers or stack base")
        if self._map_error:
            return UnwindResult((), "failed", self._map_error)
        if not process_exited:
            try:
                current = _maps(self.pid)
            except OSError as exc:
                # 进程退出后，已打开的 ELF 文件描述符仍然有效。
                # 此时也不会再产生新映射，避免将新布局混入旧快照。
                if Path("/proc/%d" % self.pid).exists():
                    return UnwindResult((), "failed", "cannot validate module mappings: %s" % exc)
            else:
                if current != self._mappings:
                    self._map_error = "module mappings changed; restart capture to establish a new ELF layout"
                    return UnwindResult((), "failed", self._map_error)
        self._snapshot = snapshot
        self._frames = []
        self._callback_error = ""
        self._memory_error = ""
        try:
            result = self._lib.dwfl_getthread_frames(
                self._dwfl, snapshot.tid, self._frame_cb, None)
            frames = tuple(self._frames)
            reason = self._callback_error or self._memory_error
            if not reason and result != 0:
                reason = self._error()
            if reason:
                return UnwindResult(frames, "partial" if frames else "failed", reason)
            if not frames:
                return UnwindResult((), "failed", "no frames recovered")
            return UnwindResult(frames, "complete", "end of DWARF call chain")
        finally:
            self._snapshot = None

    def close(self):
        if self._dwfl is not None:
            self._lib.dwfl_end(self._dwfl)
            self._dwfl = None
            self._symbol_cache.clear()
            self._cfi_cache.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
