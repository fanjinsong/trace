#include <csignal>
#include <cstdio>
#include <unistd.h>

extern "C" {
#include "lauxlib.h"
#include "lualib.h"

// The profiler resolves this symbol, then reads the pointer at each sample.
lua_State* g_lua_state = nullptr;
}

void register_lua_api(lua_State* L);

namespace {

volatile std::sig_atomic_t running = 1;

void stop(int) {
    running = 0;
}

void print_lua_error(lua_State* L) {
    const char* message = lua_tostring(L, -1);
    std::fprintf(stderr, "Lua error: %s\n", message ? message : "non-string error");
}

}  // namespace

int main(int argc, char* argv[]) {
    const char* script = argc > 1 ? argv[1] : PROFILE_TEST_SCRIPT;
    g_lua_state = luaL_newstate();
    lua_State* L = g_lua_state;
    if (!L) {
        std::fprintf(stderr, "Failed to create Lua state\n");
        return 1;
    }

    luaL_openlibs(L);
    register_lua_api(L);
    if (luaL_dofile(L, script) != LUA_OK) {
        print_lua_error(L);
        g_lua_state = nullptr;
        lua_close(L);
        return 1;
    }
    lua_settop(L, 0);

    std::signal(SIGINT, stop);
    std::signal(SIGTERM, stop);
    std::printf("profile_test pid=%ld, script=%s (Ctrl+C to stop)\n",
                static_cast<long>(getpid()), script);
    std::fflush(stdout);

    int exit_code = 0;
    while (running) {
        lua_getglobal(L, "profile_entry");
        if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
            print_lua_error(L);
            exit_code = 1;
            break;
        }
    }

    g_lua_state = nullptr;
    lua_close(L);
    return exit_code;
}
