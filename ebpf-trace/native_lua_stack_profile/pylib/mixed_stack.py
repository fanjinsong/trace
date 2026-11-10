"""由同一次采样的 native 快照和 Lua CallInfo 构造 root -> leaf 混合栈。"""

from __future__ import annotations

import ctypes
import ctypes.util
from dataclasses import dataclass
from functools import lru_cache
import importlib.util
from pathlib import Path
import sys

from .sample_events import (
    C_FRAME, LUA_FRAME, LUA_NULL, LUA_PARTIAL, CIST_C, CIST_FRESH,
)


@dataclass(frozen=True)
class MixedResult:
    frames: tuple[str, ...]
    status: str
    reason: str
    native_status: str
    lua_status: str


def _clean(text):
    """分号是 folded 栈分隔符，不能出现在单个帧名中。"""
    return str(text).replace(";", ":").replace("\n", " ").replace("\r", " ")


@lru_cache(maxsize=1)
def _demangler():
    path = ctypes.util.find_library("stdc++")
    if not path:
        return None
    try:
        library = ctypes.CDLL(path)
        function = getattr(library, "__cxa_demangle")
        function.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p,
                             ctypes.POINTER(ctypes.c_int)]
        function.restype = ctypes.c_void_p
        free = ctypes.CDLL(None).free
        free.argtypes = [ctypes.c_void_p]
        free.restype = None
        return function, free
    except (OSError, AttributeError):
        return None


@lru_cache(maxsize=4096)
def _demangle(name):
    if not name.startswith("_Z"):
        return name
    functions = _demangler()
    if functions is None:
        return name
    function, free = functions
    status = ctypes.c_int()
    pointer = function(name.encode("utf-8"), None, None, ctypes.byref(status))
    try:
        if pointer and status.value == 0:
            return ctypes.string_at(pointer).decode("utf-8", "replace")
        return name
    finally:
        if pointer:
            free(pointer)


def _native_label(frame):
    if frame.symbol:
        name = _demangle(frame.symbol)
    else:
        module = Path(frame.module).name or "unknown"
        name = "%s@0x%x" % (module, frame.lookup_pc)
    return "native:" + _clean(name)


def _lua_label(frame):
    source = frame.source
    if source.startswith("@"):
        source = source[1:]
    return "lua:%s:%d" % (_clean(source or "unknown"), frame.linedefined)


def _lua_segments(frames):
    """Lua->Lua 共用一个 VM 帧；CIST_FRESH 开始下一次 native VM 调用。"""
    segments = []
    current = None
    for frame in reversed(frames):
        if frame.callstatus & CIST_C:
            if frame.kind != C_FRAME:
                raise ValueError("Lua frame kind disagrees with CIST_C")
            current = None
            continue
        if frame.kind != LUA_FRAME:
            raise ValueError("C frame kind disagrees with CIST_C")
        if frame.callstatus & CIST_FRESH:
            current = []
            segments.append(current)
        if current is None:
            raise ValueError("Lua execution segment has no CIST_FRESH frame")
        current.append(_lua_label(frame))
    return segments


def merge_frames(native, lua_frames, lua_flags, vm_ranges):
    """纯合并逻辑：native 和 Lua 输入均为 leaf -> root，输出为 root -> leaf。"""
    native_frames = tuple(reversed(native.frames))
    labels = tuple(_native_label(frame) for frame in native_frames)
    lua_status = "partial" if lua_flags & LUA_PARTIAL else "complete"
    if not lua_frames and not lua_flags & LUA_PARTIAL:
        lua_status = "none"

    def partial(reason):
        marker = "[native_failed]" if not native_frames else "[mixed_partial]"
        status = "failed" if not native_frames else "partial"
        return MixedResult((marker,) + labels, status, reason,
                           native.status, lua_status)

    if native.status != "complete":
        return partial("native unwind: " + native.stop_reason)
    if lua_flags & LUA_PARTIAL:
        return partial("Lua snapshot flags: 0x%x" % lua_flags)
    if lua_flags & LUA_NULL and lua_frames:
        return partial("null Lua state has active frames")
    try:
        segments = _lua_segments(lua_frames)
    except ValueError as exc:
        return partial(str(exc))

    anchors = [index for index, frame in enumerate(native_frames)
               if any(start <= frame.lookup_pc < end for start, end in vm_ranges)]
    if len(anchors) != len(segments):
        return partial("native VM frames (%d) do not match Lua segments (%d)" %
                       (len(anchors), len(segments)))

    insertions = dict(zip(anchors, segments))
    result = []
    for index, label in enumerate(labels):
        result.append(label)
        result.extend(insertions.get(index, ()))
    return MixedResult(tuple(result), "complete", "", native.status, lua_status)


def _unwind_module():
    """复用已有 DWARF 实现，唯一模块名避免与 malloc 的事件模块混淆。"""
    name = "_native_lua_profile_dwarf_unwind"
    if name not in sys.modules:
        path = Path(__file__).resolve().parents[2] / "malloc-trace" / "dwarf_unwind.py"
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load DWARF unwinder: " + str(path))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module  # dataclasses 需要先找到所属模块。
        previous_bytecode = sys.dont_write_bytecode
        try:
            # Keep this adapter from creating files in the sibling example.
            sys.dont_write_bytecode = True
            spec.loader.exec_module(module)
        except Exception:
            del sys.modules[name]
            raise
        finally:
            sys.dont_write_bytecode = previous_bytecode
    return sys.modules[name]


def _process_identity(pid):
    """返回状态和 starttime；comm 可含空格及括号，不能直接 split 整行。"""
    try:
        text = Path("/proc/%d/stat" % pid).read_text(encoding="utf-8")
    except (FileNotFoundError, ProcessLookupError):
        return None
    fields = text.rpartition(")")[2].split()
    if len(fields) < 20:
        raise RuntimeError("invalid /proc/%d/stat" % pid)
    return fields[0], int(fields[19])


class MixedStackBuilder:
    def __init__(self, pid, vm_ranges, max_frames=127):
        identity = _process_identity(pid)
        if identity is None or identity[0] in ("Z", "X", "x"):
            raise RuntimeError("target process has already exited")
        self.pid = pid
        self._start_time = identity[1]
        self._exited = False
        self.vm_ranges = tuple(vm_ranges)
        module = _unwind_module()
        self._snapshot = module.Snapshot
        self._unwinder = module.DwarfUnwinder(pid, max_frames=max_frames)

    def build(self, sample):
        snapshot = self._snapshot(
            sample.sequence, sample.pid, sample.tid, sample.regs,
            sample.stack_base, sample.stack, sample.native_flags, sample.native_error)
        if not self._exited:
            identity = _process_identity(self.pid)
            self._exited = (identity is None or identity[0] in ("Z", "X", "x")
                            or identity[1] != self._start_time)
        # zombie 的 maps 可能为空；PID 重用后的新 maps 也不属于本次旧快照。
        native = self._unwinder.unwind(snapshot, process_exited=self._exited)
        return merge_frames(native, sample.lua_frames, sample.lua_flags, self.vm_ranges)

    def close(self):
        self._unwinder.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
