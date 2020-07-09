-- Copyright (C) by Jianhao Dai (Toruneko)

local ffi = require "ffi"

local _M = { _VERSION = '0.0.1' }

local ffi_gc = ffi.gc
local C = ffi.C

ffi.cdef [[
void CRYPTO_free(void *ptr, const char *file, int line);
]]

local function openssl_free(ptr)
    C.CRYPTO_free(ptr, "", 0)
end

function _M.free(str)
    ffi_gc(str, openssl_free)
end

return _M



