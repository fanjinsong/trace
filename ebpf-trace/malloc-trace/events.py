"""解码采集到的记录，并按全局序号顺序重放 malloc/free 事件。"""

from dataclasses import dataclass
import struct
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from dwarf_unwind import Snapshot


MALLOC = 1
FREE = 2
READ_FAULT = 1
LIMIT = 2
KNOWN_FLAGS = READ_FAULT | LIMIT

# 两个环形缓冲区共用全局 sequence；对于 MALLOC，它同时也是分配 ID。
HEADER = struct.Struct("<IIQII")
LIFECYCLE_BODY = struct.Struct("<QQ")
SAMPLE_BODY = struct.Struct("<Q17QIIIi")
LIFECYCLE_SIZE = HEADER.size + LIFECYCLE_BODY.size
SAMPLE_PREFIX_SIZE = LIFECYCLE_SIZE + SAMPLE_BODY.size
SAMPLE_LENGTH_OFFSET = LIFECYCLE_SIZE + struct.calcsize("<Q17QI")
MAX_SNAPSHOT_BYTES = 32768


class ProtocolError(ValueError):
    """记录不符合传输格式或内存分配生命周期的顺序约定。"""


@dataclass(frozen=True)
class Event:
    kind: int
    sequence: int
    pid: int
    tid: int

    @property
    def alloc_id(self) -> int:
        # FREE 的序号只标识本次释放事件，不代表被释放内存的分配 ID。
        return self.sequence if self.kind == MALLOC else 0


@dataclass(frozen=True)
class AllocationEvent(Event):
    address: int
    size: int
    snapshot: Optional["Snapshot"] = None


def decode_event(payload: bytes) -> AllocationEvent:
    """解码完整记录，或仅包含记录有效前缀的副本。

    header.size 保存预留的完整记录大小。未使用的栈容量和对齐填充无需复制，
    因此 len(payload) 可以小于该大小。
    """
    payload = bytes(payload)
    if len(payload) < HEADER.size:
        raise ProtocolError("record is shorter than its header")
    kind, wire_size, sequence, pid, tid = HEADER.unpack_from(payload)
    if kind not in (MALLOC, FREE):
        raise ProtocolError("unknown event kind: %s" % kind)
    if sequence == 0:
        raise ProtocolError("event sequence must be nonzero")
    if len(payload) < LIFECYCLE_SIZE:
        raise ProtocolError("record is shorter than its allocation fields")
    address, size = LIFECYCLE_BODY.unpack_from(payload, HEADER.size)
    if address == 0:
        raise ProtocolError("allocation address must be nonzero")
    common = (kind, sequence, pid, tid, address, size)
    if wire_size == LIFECYCLE_SIZE:
        if len(payload) != LIFECYCLE_SIZE:
            raise ProtocolError("invalid basic record length")
        if kind == FREE and size != 0:
            raise ProtocolError("free record has a nonzero allocation size")
        return AllocationEvent(*common)
    if kind != MALLOC or len(payload) < SAMPLE_PREFIX_SIZE:
        raise ProtocolError("invalid allocation record length")
    values = SAMPLE_BODY.unpack_from(payload, LIFECYCLE_SIZE)
    stack_base, regs = values[0], tuple(values[1:18])
    max_bytes, length, flags, read_error = values[18:22]
    if not 1 <= max_bytes <= MAX_SNAPSHOT_BYTES:
        raise ProtocolError("snapshot byte limit is outside supported bounds")
    if wire_size != SAMPLE_PREFIX_SIZE + ((max_bytes + 7) & ~7):
        raise ProtocolError("sample record capacity does not match its wire length")
    if length > max_bytes or flags & ~KNOWN_FLAGS:
        raise ProtocolError("invalid snapshot length or flags")
    if flags & LIMIT and length != max_bytes:
        raise ProtocolError("snapshot limit flag disagrees with captured length")
    if regs[7] != stack_base or stack_base + max_bytes > 1 << 64:
        raise ProtocolError("invalid snapshot stack base")
    used_size = SAMPLE_PREFIX_SIZE + length
    if len(payload) not in (wire_size, used_size):
        raise ProtocolError("sample record is truncated or has trailing data")
    # 延迟导入，避免仅导入事件协议时就导入或创建解栈器。
    try:
        from .dwarf_unwind import Snapshot
    except ImportError:
        from dwarf_unwind import Snapshot
    snapshot = Snapshot(sequence, pid, tid, regs, stack_base,
                        payload[SAMPLE_PREFIX_SIZE:used_size], flags, read_error)
    return AllocationEvent(*common, snapshot)


@dataclass
class Allocation:
    alloc_id: int
    pid: int
    tid: int
    address: int
    size: int
    snapshot: Optional["Snapshot"] = None
    result: Optional[Any] = None


class AllocationState:
    """重放已排序的事件，仅为尚未释放的分配保留原始栈快照。"""

    def __init__(self):
        self.live = {}
        self._last_sequence = 0

    def apply(self, event: Event) -> None:
        if not isinstance(event, AllocationEvent) or event.kind not in (MALLOC, FREE):
            raise ProtocolError("allocation state accepts only malloc/free records")
        if event.sequence <= self._last_sequence:
            raise ProtocolError("allocation state requires increasing event sequences")
        self._last_sequence = event.sequence
        key = (event.pid, event.address)
        if event.kind == FREE:
            self.live.pop(key, None)
            return
        self.live[key] = Allocation(event.alloc_id, event.pid, event.tid,
                                    event.address, event.size,
                                    snapshot=event.snapshot)
