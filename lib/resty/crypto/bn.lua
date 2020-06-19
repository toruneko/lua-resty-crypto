-- Copyright (C) by Jianhao Dai (Toruneko)

local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_str = ffi.string
local ffi_null = ffi.null

local C = ffi.C

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
typedef struct bignum_ctx BN_CTX;
typedef struct bignum_st BIGNUM;
typedef unsigned long BN_ULONG;
typedef struct bn_gencb_st BN_GENCB;
BIGNUM *BN_new(void);
void BN_free(BIGNUM *a);
int BN_set_word(BIGNUM *a, BN_ULONG w);

char *BN_bn2hex(const BIGNUM *a);
int BN_hex2bn(BIGNUM **a, const char *str);
]]

local BIGNUM_ptr = ffi.typeof("BIGNUM*[?]")
local const_char_ptr = ffi.typeof("const char *")

local function BN_free(bn)
    ffi_gc(bn, C.BN_free)
end

local function BN_new()
    local bn = C.BN_new()
    if bn == ffi_null then
        return nil, ERR.get_error()
    end
    BN_free(bn)
    return bn
end

function _M.new()
    return BN_new()
end

function _M.free(bn)
    return BN_free(bn)
end

function _M.set_word(bn, word)
    if C.BN_set_word(bn, word) <= 0 then
        return false, ERR.get_error()
    end
    return true
end

function _M.bn2hex(bn)
    return ffi_str(C.BN_bn2hex(bn))
end

function _M.hex2bn(hex)
    local bn, err = BN_new()
    if not bn then
        return nil, err
    end
    local bignum = ffi_new(BIGNUM_ptr, 1)
    bignum[0] = bn
    if C.BN_hex2bn(bignum, ffi_new(const_char_ptr, hex)) > 0 then
        return bignum[0]
    end
    return nil, ERR.get_error()
end

return _M