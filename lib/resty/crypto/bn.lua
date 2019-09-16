-- Copyright (C) by Jianhao Dai (Toruneko)

local ffi = require "ffi"
local ffi_gc = ffi.gc
local C = ffi.C

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
typedef struct bignum_st BIGNUM;
BIGNUM *BN_new(void);
void BN_free(BIGNUM *a);
typedef unsigned long BN_ULONG;
int BN_set_word(BIGNUM *a, BN_ULONG w);
typedef struct bn_gencb_st BN_GENCB;
]]

local function BN_free(bn)
    ffi_gc(bn, C.BN_free)
end

local function BN_new()
    local bn = C.BN_new()
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
    return C.BN_set_word(bn, word)
end

return _M