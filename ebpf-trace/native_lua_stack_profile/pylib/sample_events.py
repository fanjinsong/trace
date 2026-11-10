"""Wire format for one simultaneous native/Lua stack sample."""

from dataclasses import dataclass
import struct
from typing import Tuple


VERSION = 1
STACK_BYTES = 16384
MAX_LUA_FRAMES = 64
SOURCE_BYTES = 128

READ_FAULT = 1
LIMIT = 2
LUA_NULL = 1
LUA_READ_FAULT = 2
LUA_INVALID = 4
LUA_DEPTH_LIMIT = 8
LUA_SOURCE_TRUNCATED = 16
LUA_PARTIAL = LUA_READ_FAULT | LUA_INVALID | LUA_DEPTH_LIMIT | LUA_SOURCE_TRUNCATED

LUA_FRAME = 1
C_FRAME = 2
CIST_C = 2
CIST_FRESH = 4

STATS_NAMES = (
    "target_samples", "kernel_skipped", "emitted", "dropped",
    "native_read_fault", "lua_partial",
)

HEADER = struct.Struct("<IIQQIIIIIiQQII17Q")
FRAME = struct.Struct("<QQQIIiI128s")
STACK_OFFSET = HEADER.size + FRAME.size * MAX_LUA_FRAMES
EVENT_SIZE = STACK_OFFSET + STACK_BYTES


class ProtocolError(ValueError):
    """A record does not match the BPF/Python ABI."""


@dataclass(frozen=True)
class LuaFrame:
    ci: int
    callstatus: int
    kind: int
    proto: int
    c_function: int
    source: str
    linedefined: int


@dataclass(frozen=True)
class Sample:
    sequence: int
    timestamp_ns: int
    pid: int
    tid: int
    cpu: int
    regs: Tuple[int, ...]
    stack_base: int
    stack: bytes
    native_flags: int
    native_error: int
    lua_state: int
    lua_flags: int
    # Captured from L->ci towards base_ci: leaf to root, excluding base_ci.
    lua_frames: Tuple[LuaFrame, ...]


def decode_event(payload: bytes) -> Sample:
    if len(payload) != EVENT_SIZE:
        raise ProtocolError("unexpected sample size: %d" % len(payload))
    fields = HEADER.unpack_from(payload)
    (version, size, sequence, timestamp, pid, tid, cpu, length,
     native_flags, native_error, stack_base, state, count, lua_flags) = fields[:14]
    regs = tuple(fields[14:])
    if version != VERSION or size != EVENT_SIZE:
        raise ProtocolError("unsupported sample version or ABI size")
    if not sequence or not pid or tid != pid:
        raise ProtocolError("invalid sample identity")
    if length > STACK_BYTES or count > MAX_LUA_FRAMES:
        raise ProtocolError("sample length exceeds its capacity")
    if native_flags & ~(READ_FAULT | LIMIT) or lua_flags & ~(LUA_NULL | LUA_PARTIAL):
        raise ProtocolError("unknown sample flags")
    if regs[7] != stack_base or stack_base + length >= 1 << 64:
        raise ProtocolError("invalid native stack range")
    if native_flags & LIMIT and length != STACK_BYTES:
        raise ProtocolError("native LIMIT disagrees with stack length")
    if lua_flags & LUA_NULL and (state or count or lua_flags != LUA_NULL):
        raise ProtocolError("inconsistent null Lua state")

    frames = []
    for index in range(count):
        ci, proto, c_function, callstatus, kind, line, reserved, source = FRAME.unpack_from(
            payload, HEADER.size + index * FRAME.size)
        if not ci or reserved or kind not in (LUA_FRAME, C_FRAME):
            raise ProtocolError("invalid Lua frame")
        if bool(callstatus & CIST_C) != (kind == C_FRAME):
            raise ProtocolError("Lua frame kind disagrees with callstatus")
        if kind == LUA_FRAME and (not proto or c_function or line < 0):
            raise ProtocolError("invalid Lua function frame")
        if kind == C_FRAME and (not c_function or proto):
            raise ProtocolError("invalid Lua C function frame")
        frames.append(LuaFrame(ci, callstatus, kind, proto, c_function,
                               source.split(b"\0", 1)[0].decode("utf-8", "replace"), line))
    return Sample(sequence, timestamp, pid, tid, cpu, regs, stack_base,
                  payload[STACK_OFFSET:STACK_OFFSET + length], native_flags,
                  native_error, state, lua_flags, tuple(frames))
