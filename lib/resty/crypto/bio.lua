-- Copyright (C) by Jianhao Dai (Toruneko)

local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local ffi_null = ffi.null
local C = ffi.C

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
typedef struct bio_st BIO;
typedef struct bio_method_st BIO_METHOD;

BIO_METHOD *BIO_s_mem(void);
BIO * BIO_new(BIO_METHOD *type);
void BIO_vfree(BIO *a);
int	BIO_puts(BIO *bp,const char *buf);
int BIO_read(BIO *b, void *data, int len);
long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
]]

local char_ptr = ffi.typeof("char[?]")
local BIO_CTRL_PENDING = 10

function _M.new(data, method)
    if not method then
        method = C.BIO_s_mem()
    end

    local bio = C.BIO_new(method)
    if bio == ffi_null then
        return nil, ERR.get_error()
    end
    ffi_gc(bio, C.BIO_vfree)

    if data then
        local len = C.BIO_puts(bio, data)
        if len < 0 then
            return nil, ERR.get_error()
        end
    end
    return bio
end

function _M.puts(bio, data)
    if not data then
        return
    end

    local len = C.BIO_puts(bio, data)
    if len < 0 then
        return nil, ERR.get_error()
    end
    return bio
end

function _M.read(bio)
    local len = C.BIO_ctrl(bio, BIO_CTRL_PENDING, 0, ffi_null)
    if len <= 0 then
        return nil, ERR.get_error()
    end

    local data = ffi_new(char_ptr, len)
    if C.BIO_read(bio, data, len) <= 0 then
        return nil, ERR.get_error()
    end

    return ffi_str(data, len)
end

return _M