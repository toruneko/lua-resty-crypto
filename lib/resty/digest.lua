-- Copyright (C) by Jianhao Dai (Toruneko)

local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local C = ffi.C
local setmetatable = setmetatable

local digest = {
    md5 = require "resty.digest.md5",
    sm3 = require "resty.digest.sm3",
    sha1 = require "resty.digest.sha1",
    sha224 = require "resty.digest.sha224",
    sha256 = require "resty.digest.sha256",
    sha384 = require "resty.digest.sha384",
    sha512 = require "resty.digest.sha512",
}

ffi.cdef[[
typedef unsigned char u_char;
u_char * ngx_hex_dump(u_char *dst, const u_char *src, size_t len);
]]

local str_type = ffi.typeof("uint8_t[?]")

local _M = { _VERSION = '0.0.1' }
local mt = { __index = _M }

local function tohex(s)
    if not s then
        return nil
    end

    local len = #s
    local buf_len = len * 2
    local buf = ffi_new(str_type, buf_len)
    C.ngx_hex_dump(buf, s, len)
    return ffi_str(buf, buf_len)
end

function mt.__call(self, s)
    local dg = self.dg
    if dg:update(s) == 1 then
        return tohex(dg:final())
    end
end

function _M.new(algorithm)
    local dg = digest[algorithm]
    if not dg then
        return nil, "digest algorithm not found"
    end

    return setmetatable({dg = dg.new()}, mt)
end

function _M.update(self, s)
    return self.dg:update(s)
end

function _M.final(self)
    return self.dg:final()
end

function _M.reset(self)
    return self.dg:reset()
end

function _M.to_hex(s)
    return tohex(s)
end

return _M