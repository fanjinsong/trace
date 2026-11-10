extern "C" {
#include "lauxlib.h"
}

namespace {

lua_Integer native_work(lua_Integer seed) {
    lua_Unsigned value = static_cast<lua_Unsigned>(seed);
    for (lua_Unsigned i = 0; i < 20000; ++i) {
        value = (value * 33 + i) % 1000003;
    }
    return static_cast<lua_Integer>(value);
}

int cpp_work(lua_State* L) {
    const lua_Integer seed = luaL_checkinteger(L, 1);
    lua_pushinteger(L, native_work(seed));
    return 1;
}

int cpp_call_lua(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    const lua_Integer value = luaL_checkinteger(L, 2);
    lua_pushvalue(L, 1);
    lua_pushinteger(L, value);
    // 回调错误由 main 中最外层的 lua_pcall 统一处理。
    lua_call(L, 1, 1);
    return 1;
}

}  // namespace

void register_lua_api(lua_State* L) {
    const luaL_Reg methods[] = {
        {"work", cpp_work},
        {"call_lua", cpp_call_lua},
        {nullptr, nullptr},
    };
    luaL_newlib(L, methods);
    lua_setglobal(L, "cpp");
}
