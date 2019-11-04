-- Copyright (C) by Jianhao Dai (Toruneko)
local ffi = require "ffi"
local bit = require "bit"
local rshift = bit.rshift
local band = bit.band
local C = ffi.C
local tonumber = tonumber

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
unsigned long OpenSSL_version_num(void);
]]

function _M.version()
    return tonumber(C.OpenSSL_version_num())
end

function _M.major_version()
    return band(rshift(tonumber(C.OpenSSL_version_num()), 28), 0xF)
end

function _M.minor_version()
    return band(rshift(tonumber(C.OpenSSL_version_num()), 20), 0xFF)
end

function _M.patch_version()
    return band(rshift(tonumber(C.OpenSSL_version_num()), 4), 0xFFFF)
end

return _M