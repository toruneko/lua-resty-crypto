-- Copyright (C) by Thought Foundry Inc.

local EVP = require "resty.crypto.evp"
local str = require "resty.utils.string"

local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local ffi_gc = ffi.gc
local C = ffi.C
local setmetatable = setmetatable

ffi.cdef[[
const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
const EVP_MD *EVP_sm3(void);

typedef struct hmac_ctx_st HMAC_CTX;
HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);

int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len);
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
]]

local _M = { _VERSION = '0.03' }
local mt = { __index = _M }

local sm3_support = pcall(function() C.EVP_sm3() end)

local buf = ffi_new("unsigned char[64]")
local res_len = ffi_new("unsigned int[1]")
local hash = {
    md5 = C.EVP_md5(),
    sha1 = C.EVP_sha1(),
    sha224 = C.EVP_sha224(),
    sha256 = C.EVP_sha256(),
    sha384 = C.EVP_sha384(),
    sha512 = C.EVP_sha512(),
    sm3 = sm3_support and C.EVP_sm3() or nil
}
_M.hash = hash

function mt.__call(self, s)
    if not self:reset() then
        return nil
    end
    if self:update(s) then
        return str.tohex(self:final())
    end
end

function _M.new(key, _hash)
    local ctx = C.HMAC_CTX_new()
    ffi_gc(ctx, C.HMAC_CTX_free)

    local _hash = _hash or hash.md5

    if C.HMAC_Init_ex(ctx, key, #key, _hash, nil) == 0 then
        return nil
    end

    return setmetatable({ _ctx = ctx }, mt)
end

function _M.update(self, s)
    return C.HMAC_Update(self._ctx, s, #s) == 1
end

function _M.final(self)
    if C.HMAC_Final(self._ctx, buf, res_len) == 1 then
        return ffi_str(buf, res_len[0])
    end

    return nil
end

function _M.reset(self)
    return C.HMAC_Init_ex(self._ctx, nil, 0, nil, nil) == 1
end

function _M.tohex(s)
    return str.tohex(s)
end

return _M