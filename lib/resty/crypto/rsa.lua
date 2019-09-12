-- Copyright (C) by Jianhao Dai (Toruneko)

local ffi = require "ffi"
local ffi_gc = ffi.gc
local C = ffi.C

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
typedef struct rsa_st RSA;
RSA *RSA_new(void);
void RSA_free(RSA *rsa);

typedef struct bignum_st BIGNUM;
BIGNUM *BN_new(void);
void BN_free(BIGNUM *a);
typedef unsigned long BN_ULONG;
int BN_set_word(BIGNUM *a, BN_ULONG w);
typedef struct bn_gencb_st BN_GENCB;
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
]]

local function RSA_free(rsa)
    ffi_gc(rsa, C.RSA_free)
end

local function RSA_new()
    local rsa = C.RSA_new()
    RSA_free(rsa)
    return rsa
end

local function BN_free(bn)
    ffi_gc(bn, C.BN_free)
end

local function BN_new()
    local bn = C.BN_new()
    BN_free(bn)
    return bn
end

function _M.new()
    return RSA_new()
end

function _M.free(rsa)
    RSA_free(rsa)
end

function _M.BN_new()
    return BN_new()
end

function _M.BN_free(bn)
    return BN_free(bn)
end

return _M