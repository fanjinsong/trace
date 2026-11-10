local function lua_work(value)
    for i = 1, 2000 do
        value = (value * 33 + i) % 1000003
    end
    return value
end

local function lua_callback(value)
    local result = lua_work(value)
    result = cpp.work(result)
    return result + 1
end

local function lua_stage_two(value)
    local result = cpp.work(value)
    result = cpp.call_lua(lua_callback, result)
    return result + 1
end

local function lua_stage_one(value)
    local result = lua_stage_two(value)
    return result + 1
end

function profile_entry()
    local result = lua_stage_one(1)
    -- 返回前保留一次运算，避免 Lua 尾调用折叠测试栈。
    return result + 1
end
