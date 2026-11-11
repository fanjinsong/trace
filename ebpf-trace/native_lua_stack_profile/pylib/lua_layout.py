"""读取目标进程的 ELF 地址和 Lua 5.4 内存布局，不猜测偏移量。

ELF 符号给出文件中的链接虚拟地址，/proc/PID/maps 提供实际装载位置；
两者结合可处理 PIE/ASLR。Lua 结构成员的字节偏移则从库内的 DWARF
调试信息提取，避免依赖采样器本机头文件或手工维护的布局常量。

``Layout.cflags()`` 提供 LUA_STATE_SLOT、SIZE_STACKVALUE 和下方 FIELDS 中列出的
OFF_* 宏。通过 /proc/PID/root 解析共享库路径，并在读取符号或 DWARF 信息前，
核对文件的设备号和 inode 是否与内存映射一致。
"""

from dataclasses import dataclass
import os
from pathlib import Path
import re


# 将 BPF 使用的偏移宏映射到 DWARF 中的类型名和逐层成员路径。
# 例如 ("lua_State", "stack", "p") 表示 stack.p 相对 lua_State 起点的字节偏移。
# stack、stack_last 和 func 使用 StkIdRel 联合体中的指针成员 .p；
# 同一联合体的 .offset 成员仅在 Lua 栈重新分配期间保存临时相对偏移。
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
    """保存目标进程的地址及布局，供 BPF 编译和用户态混合栈合并使用。"""

    exe_path: str  # /proc/PID/exe 指向的可执行文件路径，用于标识目标程序。
    lib_path: str  # maps 中记录的 Lua 库路径，相对于目标进程的根目录。
    state_slot: int  # g_lua_state 变量的运行时地址，该地址处存放 lua_State*。
    offsets: dict  # OFF_* 成员偏移及 SIZE_STACKVALUE，单位均为字节。
    vm_ranges: tuple  # luaV_execute 的运行时地址区间，采用左闭右开形式。

    def cflags(self):
        """将状态指针槽地址和 DWARF 布局转换为 BCC/BPF 的 -D 编译参数。

        LUA_STATE_SLOT 使用 ULL 后缀，保留完整的 64 位用户态地址；
        其余宏按名称排序，保证相同布局生成的参数顺序一致。
        vm_ranges 由用户态合并逻辑使用，不属于这些编译参数。
        """
        return ["-DLUA_STATE_SLOT=%dULL" % self.state_slot] + [
            "-D%s=%d" % item for item in sorted(self.offsets.items())
        ]


@dataclass(frozen=True)
class _Mapping:
    """表示 /proc/PID/maps 中一条带绝对文件路径的内存映射记录。"""

    start: int  # 目标进程中的映射起始虚拟地址，包含该地址。
    end: int  # 映射结束虚拟地址，不包含该地址。
    permissions: str  # maps 原始权限字符串，例如 r-xp 或 rw-p。
    offset: int  # 映射起点对应的文件字节偏移，并非内存地址。
    device: tuple  # 文件所在设备的 (主设备号, 次设备号)。
    inode: int  # 文件的 inode，与 device 共同用于核对文件身份。
    path: str  # 还原八进制转义后的路径，保留 maps 中的其他内容。


def _maps(pid):
    """读取目标进程的文件映射快照，按 maps 原始顺序返回 _Mapping 元组。

    只保留带绝对路径的记录，跳过匿名映射以及 [heap]、[stack]、[vdso]
    等特殊记录。地址、文件偏移和设备号按十六进制解析，inode 按十进制解析。
    返回值可用于文件身份匹配、装载偏移计算，以及解析前后的映射比较。
    """
    result = []
    for line in Path("/proc/%d/maps" % pid).read_text().splitlines():
        # 前五列是固定字段，最多拆分五次，避免将路径中的空格继续拆开。
        fields = line.split(None, 5)
        if len(fields) != 6 or not fields[5].startswith("/"):
            continue
        start, end = (int(value, 16) for value in fields[0].split("-"))
        # maps 可能将路径中的换行等字符写成 \012 形式，匹配前先还原。
        path = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[5])
        result.append(_Mapping(start, end, fields[1], int(fields[2], 16),
                               tuple(int(part, 16) for part in fields[3].split(":")),
                               int(fields[4]), path))
    return tuple(result)


def _same_file(info, mapping):
    """比较 stat/fstat 结果与映射的设备号、inode，判断是否指向同一文件。

    路径相同不代表文件相同，例如原路径可能已被另一个构建产物替换；
    inode 也需要结合设备号比较，不能单独作为跨设备的文件标识。
    此处只核对文件身份，不校验文件内容是否曾被原地改写。
    """
    return (info.st_ino == mapping.inode and
            (os.major(info.st_dev), os.minor(info.st_dev)) == mapping.device)


def _elf(stream):
    """用 pyelftools 解析二进制流，并限定为采样器支持的小端 x86-64 ELF。

    可执行文件和 Lua 共享库都经过这一检查。缺少依赖或架构不兼容时
    抛出 RuntimeError；返回的 ELFFile 后续仍需访问流，由调用方保持其打开。
    """
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise RuntimeError("pyelftools is required (Debian: python3-pyelftools)") from exc
    elf = ELFFile(stream)
    if elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_X86_64":
        raise RuntimeError("target and Lua library must be little-endian x86-64 ELF files")
    return elf


def _symbol(elf, name):
    """查找已定义且大小大于零的 ELF 符号，优先使用 .symtab，再查 .dynsym。

    完整符号表可包含未导出的内部符号，动态符号表提供后备来源。
    跳过未定义的外部引用和大小为零的符号，因为后续需要符号实际占用范围。
    返回值的 st_value 是 ELF 链接虚拟地址，尚未加上目标进程的装载偏移。
    """
    for section_name in (".symtab", ".dynsym"):
        section = elf.get_section_by_name(section_name)
        if section is not None:
            for symbol in section.get_symbol_by_name(name) or ():
                if symbol["st_shndx"] != "SHN_UNDEF" and symbol["st_size"] > 0:
                    return symbol
    raise RuntimeError("ELF symbol %s is missing; use the unstripped profiling build" % name)


def _load_bias(elf, mappings):
    """根据可执行 PT_LOAD 段和文件映射，推导唯一的 ELF 运行时装载偏移。

    mappings 应只包含同一 ELF 文件的映射。对每个文件偏移匹配的可执行映射，
    先算出映射起点在 ELF 中对应的链接虚拟地址，再与实际映射地址相减：
        bias = mapping.start - (virtual_start + mapping.offset - file_start)
    其中 virtual_start 和 file_start 分别是段虚拟地址和文件偏移向下页对齐的值。
    文件偏移差用于处理映射从段内其他页面开始的情况，不能直接把映射起点当作 bias。

    符号运行时地址 = bias + st_value；这同时适用于 PIE/共享库和普通可执行文件。
    所有匹配产生的候选值必须恰好只有一个，否则拒绝使用不确定的地址。
    """
    page_size = os.sysconf("SC_PAGE_SIZE")
    page_mask = ~(page_size - 1)
    biases = set()
    for segment in elf.iter_segments():
        # p_flags 的最低位是 PF_X；只用可执行的可装载段推导地址对应关系。
        if segment["p_type"] != "PT_LOAD" or not segment["p_flags"] & 1:
            continue
        # maps 以页为单位描述映射，因此段的文件区间也要扩展到页边界。
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
    """读取 DWARF 调试信息条目（DIE）的名称，缺少名称时返回空字符串。

    名称字节按 UTF-8 解码，无法解码的内容用替代字符表示，避免扫描因此中断。
    """
    attribute = die.attributes.get("DW_AT_name")
    return attribute.value.decode("utf-8", "replace") if attribute else ""


class _Types:
    """索引 Lua 库中的 DWARF 结构体、联合体定义，并解析嵌套成员偏移。"""

    def __init__(self, elf):
        """扫描所有编译单元，为有名称且有字节大小的类型建立名称索引。

        缺少 DWARF 时立即报错，避免退回猜测布局。要求 DW_AT_byte_size
        可过滤没有大小信息的前置声明；同名类型保留首次遇到的定义。
        """
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
        """按名称返回已索引的类型 DIE，缺失时报告所需的 Lua 类型名称。"""
        try:
            return self.types[name]
        except KeyError as exc:
            raise RuntimeError("Lua DWARF type %s is missing" % name) from exc

    @staticmethod
    def _concrete(die):
        """沿 DW_AT_type 剥离 typedef 和 const/volatile/restrict 类型包装。

        这些包装不改变底层成员布局；解析成员前先定位实际类型。
        不剥离指针类型，也不进行指针解引用。
        """
        while die.tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type",
                          "DW_TAG_restrict_type"):
            die = die.get_DIE_from_attribute("DW_AT_type")
        return die

    def offset(self, type_name, *members):
        """返回嵌套成员相对根类型起点的累计字节偏移。

        例如 offset("lua_State", "stack", "p") 依次查找 stack 和 p，
        累加每层成员相对其直接所属类型的偏移，得到 lua_State.stack.p 的位置。
        每一步只查当前类型的直接成员，不跨指针访问其他对象。

        只接受整数常量形式的 DW_AT_data_member_location；联合体成员缺少该
        属性时按共享起点 0 处理。成员缺失或偏移需要 DWARF 表达式计算时立即报错。
        """
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
                # 联合体各成员共享起始地址，DWARF 可以省略值为零的位置属性。
                value = 0
            elif location is not None and isinstance(location.value, int):
                value = location.value
            else:
                raise RuntimeError("Lua member %s.%s has a nonconstant DWARF offset" %
                                   (type_name, member_name))
            offset += value
            # 下一层成员属于当前成员的类型，而非最初传入的根类型。
            die = member.get_DIE_from_attribute("DW_AT_type")
        return offset


def _lua_offsets(elf):
    """从 Lua ELF 的版本标识和 DWARF 提取 BPF 所需的布局常量。

    先检查 lua_ident 的内容包含 Lua 5.4，再解析 FIELDS 中的所有成员路径，
    并补充 StackValue 的字节大小。版本字符串只是初步筛选，不能替代实际的
    类型、成员及大小检查；当前采样器要求默认 64 位布局中 StackValue 为 16 字节。
    返回宏名称到整数值的字典，也可直接用于检查构建产物，无需启动目标进程。
    """
    identity = _symbol(elf, "lua_ident")
    section = elf.get_section(identity["st_shndx"])
    # st_value 和 sh_addr 都是链接虚拟地址，相减得到符号在节数据中的字节位置。
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
    """为单线程 profile_test 目标解析采样所需的运行时地址和 Lua 内存布局。

    pid 必须是目标进程的主线程 ID，调用方还需有读取相应 /proc 文件及 ELF
    文件的权限。目标应提供 g_lua_state 符号，并加载唯一一份可识别的 liblua.so
    或 liblua.so.*；Lua 库必须保留所需符号和 DWARF 调试信息。

    处理流程：检查线程集合并保存映射快照；定位可执行文件中的 g_lua_state；
    根据目标根目录打开实际映射的 Lua 库；解析 luaV_execute 地址范围及结构布局；
    最后重读映射，拒绝使用解析期间发生可见映射变化的结果。

    返回 Layout，其中 state_slot 是全局指针变量本身的地址，并非 lua_State
    对象地址；BPF 每次采样时才从该地址读取当前指针。offsets 用于读取对象字段，
    vm_ranges 用于在用户态识别 native 栈中的 Lua VM 帧并合并 Lua 调用链。

    支持协程和 yield 需要单独跟踪当前活动的 Lua 状态；
    全局主状态指针无法自动提供这一信息。

    不满足显式校验时抛出 RuntimeError，文件访问及 ELF/DWARF 解析异常向上传递。
    本函数不暂停目标；前后快照比较只能发现两次读取间可见的文件映射差异，
    不能保证线程、映射或 Lua 状态在函数返回后继续保持不变。
    """
    process = Path("/proc/%d" % pid)

    # 1. task 目录列出各线程 TID。集合必须恰好为 {pid}，同时限定单线程目标
    #    及主线程 PID；当前采样方案只使用一个全局主 Lua 状态指针。
    tasks = {int(task.name) for task in (process / "task").iterdir()}
    if tasks != {pid}:
        raise RuntimeError("this sampler requires a single-threaded process PID (the main TID)")

    # 2. 保存文件映射快照。exe_path 记录可执行文件路径，读取内容则直接打开
    #    /proc/PID/exe，以访问目标正在执行的文件，而非重新按路径查找同名文件。
    mappings = _maps(pid)
    exe_path = os.readlink(process / "exe")
    with (process / "exe").open("rb") as stream:
        # 一个 ELF 通常有多段映射；按打开文件的设备号和 inode 收集全部匹配项。
        # 此处 executable_mappings 表示主可执行文件的映射，也包含其只读、可写段。
        executable_mappings = tuple(mapping for mapping in mappings
                                    if _same_file(os.fstat(stream.fileno()), mapping))
        elf = _elf(stream)
        symbol = _symbol(elf, "g_lua_state")
        # 在已限定的 x86-64 环境中，lua_State* 槽位应占 8 字节。
        # 这只检查符号大小，并不从 DWARF 验证变量的 C 类型。
        if symbol["st_size"] != 8:
            raise RuntimeError("g_lua_state must be an exported 64-bit lua_State pointer")

        # 3. 将符号链接地址换算为运行时地址，处理主程序的 PIE/ASLR。
        #    state_slot 相当于 &g_lua_state；该槽位内保存的值才是 lua_State*。
        state_slot = _load_bias(elf, executable_mappings) + symbol["st_value"]
        # 整个 8 字节槽位必须落在主文件某个可读映射内，避免仅起点有效或跨越边界。
        if not any(mapping.start <= state_slot and state_slot + 8 <= mapping.end
                   and "r" in mapping.permissions for mapping in executable_mappings):
            raise RuntimeError("g_lua_state is outside the target's readable ELF mappings")

    # 4. 根据库文件名筛选路径。集合将同一库的多个段合并为一个候选路径；
    #    没有候选或有多个不同路径时，都无法为当前方案选定唯一的 Lua 库。
    libraries = {mapping.path for mapping in mappings
                 if Path(mapping.path).name == "liblua.so" or
                 Path(mapping.path).name.startswith("liblua.so.")}
    if len(libraries) != 1:
        raise RuntimeError("expected exactly one mapped liblua.so from the profiling build")
    lib_path = libraries.pop()
    library_mappings = tuple(mapping for mapping in mappings if mapping.path == lib_path)

    # 5. 从目标根目录解释库的绝对路径，兼容目标与采样器处于不同根目录或
    #    挂载命名空间的情况。去掉开头的 /，避免 Path 拼接丢弃 /proc/PID/root。
    with (process / "root" / lib_path.lstrip("/")).open("rb") as stream:
        # 必须先核对打开文件与所有同路径映射的身份，再读取其符号和调试信息。
        # 路径若已被新的库文件替换，旧进程的内存布局不能用新文件来解释。
        if not all(_same_file(os.fstat(stream.fileno()), mapping) for mapping in library_mappings):
            raise RuntimeError("mapped Lua library was replaced; restart the target before profiling")
        elf = _elf(stream)
        bias = _load_bias(elf, library_mappings)

        # 6. 确定 Lua VM 执行函数的运行时区间，供混合栈合并时识别 native VM 帧。
        #    结束地址不包含在区间内；外层元组允许下游按多个区间的接口统一处理。
        vm = _symbol(elf, "luaV_execute")
        vm_start = bias + vm["st_value"]
        # 从这份已核对身份的实际 Lua 库提取偏移，而不依赖本机 Lua 头文件。
        offsets = _lua_offsets(elf)
        vm_ranges = ((vm_start, vm_start + vm["st_size"]),)

    # 7. 再读一次文件映射，检测解析期间可见的装载、卸载或权限/地址变化。
    #    _maps 不包含匿名映射；此比较也无法发现变化后又恢复成原样的情况。
    if _maps(pid) != mappings:
        raise RuntimeError("target mappings changed while resolving Lua layout; retry capture")

    # 所有信息核对完成后再交给调用方，分别用于 BPF 编译参数和用户态栈合并。
    return Layout(exe_path, lib_path, state_slot, offsets, vm_ranges)
