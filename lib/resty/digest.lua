-- Copyright (C) by Jianhao Dai (Toruneko)

local EVP = require "resty.crypto.evp"
local ERR = require "resty.crypto.error"
local HMAC = require "resty.digest.hmac"
local SM3 = require "resty.digest.sm3"

local ffi = require "ffi"
local str = require "resty.utils.string"
local setmetatable = setmetatable
local C = ffi.C

ffi.cdef [[
const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
const EVP_MD *EVP_sm3(void);
]]

local _M = { _VERSION = '0.0.1' }
local mt = { __index = _M }

local sm3_support = pcall(function() C.EVP_sm3() end)

local hash = {
    md5 = C.EVP_md5(),
    sha1 = C.EVP_sha1(),
    sha224 = C.EVP_sha224(),
    sha256 = C.EVP_sha256(),
    sha384 = C.EVP_sha384(),
    sha512 = C.EVP_sha512(),
    sm3 = sm3_support and C.EVP_sm3() or SM3,
}

function mt.__call(self, s)
    if not self:reset() then
        return nil
    end
    if self:update(s) then
        return str.tohex(self:final())
    end
end

function _M.new(name, key)
    local md = hash[name] and hash[name] or EVP.get_digestbyname(name)

    if not md then
        return nil, "Unknown message digest"
    end

    -- sm3 compac for openssl 1.1.0
    if name == "sm3" and not sm3_support then
        return setmetatable({ md = md.new() }, mt)
    end

    -- hmac mode if key exists
    if key then
        return setmetatable({ md = HMAC.new(key, md) }, mt)
    end

    local md_ctx, err = EVP.MD_CTX_new()
    if not md_ctx then
        return nil, err
    end

    if EVP.DigestInit(md_ctx, md) ~= 1 then
        return nil, ERR.get_error()
    end

    return setmetatable({
        md = md,
        md_ctx = md_ctx
    }, mt)
end

function _M.update(self, s)
    if not self.md_ctx then
        return self.md:update(s)
    end
    return EVP.DigestUpdate(self.md_ctx, s) == 1
end

function _M.final(self)
    if not self.md_ctx then
        return self.md:final()
    end
    return EVP.DigestFinal(self.md_ctx)
end

function _M.reset(self)
    if not self.md_ctx then
        return self.md:reset()
    end
    return true
end

function _M.tohex(s)
    return str.tohex(s)
end

return _M