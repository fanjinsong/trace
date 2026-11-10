# eBPF 学习测试

## 项目

- [malloc-trace](./malloc-trace/)：使用 BCC 跟踪 `malloc/free`，通过 DWARF 解栈汇总未释放的内存及其分配调用栈。
- [native_lua_stack_profile](./native_lua_stack_profile/)：使用 BCC 以 49 Hz 采集 native/Lua 混合调用栈，并生成以绿色标识 Lua 帧的火焰图。
