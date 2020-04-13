-- Copyright (C) by Thought Foundry Inc.

require "resty.crypto.evp"
local str = require "resty.utils.string"

local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local ffi_null = ffi.null
local ffi_gc = ffi.gc
local C = ffi.C
local setmetatable = setmetatable

ffi.cdef[[
typedef struct hmac_ctx_st HMAC_CTX;
HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);

int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len);
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
]]

local _M = { _VERSION = '0.03' }
local mt = { __index = _M }

local buf = ffi_new("unsigned char[64]")
local res_len = ffi_new("unsigned int[1]")

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
    if ctx == ffi_null then
        return nil
    end
    ffi_gc(ctx, C.HMAC_CTX_free)

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