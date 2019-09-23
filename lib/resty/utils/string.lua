local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local C = ffi.C
local setmetatable = setmetatable

ffi.cdef[[
typedef unsigned char u_char;
u_char * ngx_hex_dump(u_char *dst, const u_char *src, size_t len);
]]

local str_type = ffi.typeof("uint8_t[?]")

local _M = { _VERSION = '0.0.1' }
local mt = { __index = _M }

function _M.tohex(s)
    if not s then
        return nil
    end

    local len = #s
    local buf_len = len * 2
    local buf = ffi_new(str_type, buf_len)
    C.ngx_hex_dump(buf, s, len)
    return ffi_str(buf, buf_len)
end

return _M