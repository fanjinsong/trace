# Native / Lua 混合栈采样

`profile_test` 持续执行 Lua → C++ → Lua 回调 → C++ 调用链。
`profile.py` 对它进行 49 Hz 的用户态 on-CPU 采样，停止时生成火焰图。

## 构建与运行

需要 x86-64 Linux 或 WSL2、CMake、C/C++ 编译器。当前 Debian 13 环境的依赖
安装和构建命令如下：

```bash
sudo apt-get install python3-bpfcc python3-pyelftools libdw1t64 perl
git submodule update --init --recursive
cmake -S . -B build
cmake --build build -j
./build/profile_test
```

BCC 还需要当前内核支持 BPF、perf event 和 ring buffer，并能找到适用的内核头文件。
程序启动时打印 PID。在另一个终端执行：

```bash
sudo /usr/bin/python3 profile.py --pid <PID>
```

在**采集器终端**按 Ctrl+C，或目标进程退出后，采集器停止 perf 事件、排空
ring buffer，并在 `profile-output/` 写出 `.folded` 和 `.svg`。SIGTERM 也会
正常收尾；SIGKILL 无法执行收尾操作。目标进程可以继续运行。
没有收到有效栈样本时仅写出 folded 文件，并说明未生成 SVG。

49 Hz 是每 CPU 的软件时钟采样频率，目标休眠或被抢占时不会产生它的样本。
内核态现场跳过并单独计数，图中权重是用户态样本数。

## 采集和合并

- `main.cpp` 导出 `g_lua_state`，创建后发布指针，关闭前清空。
- `pylib/lua_layout.py` 处理 PIE/ASLR，从目标实际加载的 Lua ELF/DWARF
  提取结构偏移；因此目标和 `liblua.so` 应保留当前构建的符号、调试信息。
- `pylib/bcc.c` 在同一次回调内保存寄存器、从 RSP 起最多 16 KiB 的 native
  原始栈，以及最多 64 个 Lua/C CallInfo。Lua source 字符串当场复制，
  Python 不事后读取可能已经变化的 Lua 堆。
- native 解栈直接复用 `../malloc-trace/dwarf_unwind.py` 的 libdwfl 实现，
  保持 malloc/free 采集流程不变。仅使用事件里的寄存器和栈快照恢复调用链。
- `pylib/mixed_stack.py` 按 `CIST_FRESH` 切分 Lua 执行段，插入对应的 native
  `luaV_execute` 帧之后；其余 native 帧保留，C CallInfo 不重复生成 C++ 帧。
- Lua 帧标签为 `lua:source:函数定义行`，native 标签尽可能使用解码后的
  C++ 函数名。Lua Proto 没有稳定名称字段，当前不推断函数名或精确执行行。
- Python 持续解栈并按最终调用栈计数，随后释放原始快照；停止时调用官方
  `flamegraph/flamegraph.pl` 生成 SVG，输出目录已被 Git 忽略。
- 火焰图中 Lua 帧统一为绿色，native 帧使用稳定的暖色配色；图上方附有颜色说明。
  配色由临时 palette 文件提供，不修改 FlameGraph 子模块。

达到 16 KiB 上限或读到栈映射末端，都不代表调用链一定完整或不完整，
最终以 DWARF 解栈结果为准。因而 `native_read_fault` 也可能出现在最终
解栈为 `complete` 的样本中。
读取失败、深度截断、Lua 更新中间状态或 VM 段无法对齐时，样本明确标记为
`mixed_partial` / `native_failed`，不会强行拼接。终端同时报告丢样与失败原因。

第一版支持当前 Lua 5.4 子模块、主线程和唯一主 state；不覆盖 coroutine、
yield、debug hooks、JIT 或运行中加载/卸载代码模块。全局主 state 不能自动
代表协程；采集器启动时拒绝多线程目标。发现代码映射变化时停止采集。

## Python 合并逻辑检查

```bash
/usr/bin/python3 -m unittest discover -s tests -v
```

这些测试覆盖 Lua 多层调用、递归、C++ 回调和不完整样本的合并顺序，
不依赖内核 BPF 权限。
