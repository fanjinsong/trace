"""Read the target's ELF addresses and Lua 5.4 layout; never guess offsets.

``Layout.cflags()`` supplies LUA_STATE_SLOT, SIZE_STACKVALUE, and the OFF_*
macros listed in FIELDS below. Paths are resolved through /proc/PID/root and
checked against the mapped device/inode before reading symbols or DWARF.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import re


# Member paths include the union's .p member, not the temporary realloc offset.
FIELDS = {
    "OFF_LUA_STATE_CI": ("lua_State", "ci"),
    "OFF_LUA_STATE_BASE_CI": ("lua_State", "base_ci"),
    "OFF_LUA_STATE_STACK": ("lua_State", "stack", "p"),
    "OFF_LUA_STATE_STACK_LAST": ("lua_State", "stack_last", "p"),
    "OFF_CALLINFO_FUNC": ("CallInfo", "func", "p"),
    "OFF_CALLINFO_PREVIOUS": ("CallInfo", "previous"),
    "OFF_CALLINFO_CALLSTATUS": ("CallInfo", "callstatus"),
    "OFF_STACKVALUE_VAL": ("StackValue", "val"),
    "OFF_TVALUE_VALUE": ("TValue", "value_"),
    "OFF_TVALUE_TT": ("TValue", "tt_"),
    "OFF_VALUE_GC": ("Value", "gc"),
    "OFF_VALUE_F": ("Value", "f"),
    "OFF_LCLOSURE_P": ("LClosure", "p"),
    "OFF_CCLOSURE_F": ("CClosure", "f"),
    "OFF_PROTO_SOURCE": ("Proto", "source"),
    "OFF_PROTO_LINEDEFINED": ("Proto", "linedefined"),
    "OFF_TSTRING_CONTENTS": ("TString", "contents"),
}


@dataclass(frozen=True)
class Layout:
    exe_path: str
    lib_path: str
    state_slot: int
    offsets: dict
    vm_ranges: tuple

    def cflags(self):
        return ["-DLUA_STATE_SLOT=%dULL" % self.state_slot] + [
            "-D%s=%d" % item for item in sorted(self.offsets.items())
        ]


@dataclass(frozen=True)
class _Mapping:
    start: int
    end: int
    permissions: str
    offset: int
    device: tuple
    inode: int
    path: str


def _maps(pid):
    result = []
    for line in Path("/proc/%d/maps" % pid).read_text().splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6 or not fields[5].startswith("/"):
            continue
        start, end = (int(value, 16) for value in fields[0].split("-"))
        path = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[5])
        result.append(_Mapping(start, end, fields[1], int(fields[2], 16),
                               tuple(int(part, 16) for part in fields[3].split(":")),
                               int(fields[4]), path))
    return tuple(result)


def _same_file(info, mapping):
    return (info.st_ino == mapping.inode and
            (os.major(info.st_dev), os.minor(info.st_dev)) == mapping.device)


def _elf(stream):
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise RuntimeError("pyelftools is required (Debian: python3-pyelftools)") from exc
    elf = ELFFile(stream)
    if elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_X86_64":
        raise RuntimeError("target and Lua library must be little-endian x86-64 ELF files")
    return elf


def _symbol(elf, name):
    for section_name in (".symtab", ".dynsym"):
        section = elf.get_section_by_name(section_name)
        if section is not None:
            for symbol in section.get_symbol_by_name(name) or ():
                if symbol["st_shndx"] != "SHN_UNDEF" and symbol["st_size"] > 0:
                    return symbol
    raise RuntimeError("ELF symbol %s is missing; use the unstripped profiling build" % name)


def _load_bias(elf, mappings):
    page_size = os.sysconf("SC_PAGE_SIZE")
    page_mask = ~(page_size - 1)
    biases = set()
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not segment["p_flags"] & 1:
            continue
        file_start = segment["p_offset"] & page_mask
        file_end = (segment["p_offset"] + segment["p_filesz"] + page_size - 1) & page_mask
        virtual_start = segment["p_vaddr"] & page_mask
        for mapping in mappings:
            if "x" in mapping.permissions and file_start <= mapping.offset < file_end:
                biases.add(mapping.start - virtual_start - (mapping.offset - file_start))
    if len(biases) != 1:
        raise RuntimeError("cannot determine a unique ELF load bias from executable mappings")
    return biases.pop()


def _name(die):
    attribute = die.attributes.get("DW_AT_name")
    return attribute.value.decode("utf-8", "replace") if attribute else ""


class _Types:
    def __init__(self, elf):
        if not elf.has_dwarf_info():
            raise RuntimeError("Lua library has no DWARF; rebuild it with debug information")
        self.types = {}
        for unit in elf.get_dwarf_info().iter_CUs():
            for die in unit.iter_DIEs():
                if die.tag not in ("DW_TAG_structure_type", "DW_TAG_union_type"):
                    continue
                if "DW_AT_byte_size" in die.attributes and _name(die):
                    self.types.setdefault(_name(die), die)

    def find(self, name):
        try:
            return self.types[name]
        except KeyError as exc:
            raise RuntimeError("Lua DWARF type %s is missing" % name) from exc

    @staticmethod
    def _concrete(die):
        while die.tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type",
                          "DW_TAG_restrict_type"):
            die = die.get_DIE_from_attribute("DW_AT_type")
        return die

    def offset(self, type_name, *members):
        die = self.find(type_name)
        offset = 0
        for member_name in members:
            die = self._concrete(die)
            member = next((child for child in die.iter_children()
                           if child.tag == "DW_TAG_member" and _name(child) == member_name), None)
            if member is None:
                raise RuntimeError("Lua DWARF member %s.%s is missing" % (type_name, member_name))
            location = member.attributes.get("DW_AT_data_member_location")
            if location is None and die.tag == "DW_TAG_union_type":
                value = 0
            elif location is not None and isinstance(location.value, int):
                value = location.value
            else:
                raise RuntimeError("Lua member %s.%s has a nonconstant DWARF offset" %
                                   (type_name, member_name))
            offset += value
            die = member.get_DIE_from_attribute("DW_AT_type")
        return offset


def _lua_offsets(elf):
    """Also usable for checking a built library without starting a target."""
    identity = _symbol(elf, "lua_ident")
    section = elf.get_section(identity["st_shndx"])
    start = identity["st_value"] - section["sh_addr"]
    text = section.data()[start:start + identity["st_size"]]
    if b"Lua 5.4" not in text:
        raise RuntimeError("this sampler supports the repository's Lua 5.4 build")
    types = _Types(elf)
    offsets = {macro: types.offset(*path) for macro, path in FIELDS.items()}
    offsets["SIZE_STACKVALUE"] = types.find("StackValue").attributes["DW_AT_byte_size"].value
    if offsets["SIZE_STACKVALUE"] != 16:
        raise RuntimeError("unsupported Lua StackValue layout; expected the default 64-bit build")
    return offsets


def load_layout(pid):
    """Resolve a single-threaded profile_test and its one loaded Lua library.

    Coroutine/yield support requires tracking the active state separately; a
    global main-state pointer cannot provide that information automatically.
    """
    process = Path("/proc/%d" % pid)
    tasks = {int(task.name) for task in (process / "task").iterdir()}
    if tasks != {pid}:
        raise RuntimeError("this sampler requires a single-threaded process PID (the main TID)")
    mappings = _maps(pid)
    exe_path = os.readlink(process / "exe")
    with (process / "exe").open("rb") as stream:
        executable_mappings = tuple(mapping for mapping in mappings
                                    if _same_file(os.fstat(stream.fileno()), mapping))
        elf = _elf(stream)
        symbol = _symbol(elf, "g_lua_state")
        if symbol["st_size"] != 8:
            raise RuntimeError("g_lua_state must be an exported 64-bit lua_State pointer")
        state_slot = _load_bias(elf, executable_mappings) + symbol["st_value"]
        if not any(mapping.start <= state_slot and state_slot + 8 <= mapping.end
                   and "r" in mapping.permissions for mapping in executable_mappings):
            raise RuntimeError("g_lua_state is outside the target's readable ELF mappings")

    libraries = {mapping.path for mapping in mappings
                 if Path(mapping.path).name == "liblua.so" or
                 Path(mapping.path).name.startswith("liblua.so.")}
    if len(libraries) != 1:
        raise RuntimeError("expected exactly one mapped liblua.so from the profiling build")
    lib_path = libraries.pop()
    library_mappings = tuple(mapping for mapping in mappings if mapping.path == lib_path)
    with (process / "root" / lib_path.lstrip("/")).open("rb") as stream:
        if not all(_same_file(os.fstat(stream.fileno()), mapping) for mapping in library_mappings):
            raise RuntimeError("mapped Lua library was replaced; restart the target before profiling")
        elf = _elf(stream)
        bias = _load_bias(elf, library_mappings)
        vm = _symbol(elf, "luaV_execute")
        vm_start = bias + vm["st_value"]
        offsets = _lua_offsets(elf)
        vm_ranges = ((vm_start, vm_start + vm["st_size"]),)
    if _maps(pid) != mappings:
        raise RuntimeError("target mappings changed while resolving Lua layout; retry capture")
    return Layout(exe_path, lib_path, state_slot, offsets, vm_ranges)
