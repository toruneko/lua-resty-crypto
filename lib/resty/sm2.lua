-- Copyright (C) by Jianhao Dai (Toruneko)

local EC = require "resty.crypto.ec"
local EVP = require "resty.crypto.evp"
local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local C = ffi.C

local setmetatable = setmetatable

local _M = { _VERSION = '0.0.1' }
local mt = { __index = _M }

ffi.cdef [[
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);
]]

local NID_SM2 = 1172

function _M.new(opts)
    local eckey, err = EC.KEY_new_by_curve_name(NID_SM2)
    if not eckey then
        return nil, err
    end

    local is_pub = false

    if opts.public_key then
        if EC.KEY_set_public_key(eckey, opts.public_key) == 0 then
            return nil, ERR.get_error()
        end
        is_pub = true
    elseif opts.private_key then
        if EC.KEY_set_private_key(eckey, opts.private_key) == 0 then
            return nil, ERR.get_error()
        end
    else
        return nil, "public_key or private_key not found"
    end

    -- EVP_PKEY
    local pkey, err = EVP.PKEY_new()
    if not pkey then
        return nil, err
    end

    if C.EVP_PKEY_set1_EC_KEY(pkey, eckey) == 0 then
        return nil, ERR.get_error()
    end

    --EVP_PKEY_CTX
    local ctx, err = EVP.PKEY_CTX_new(pkey)
    if not ctx then
        return nil, err
    end

    -- md_ctx init for sign or verify; if signature algorithm is seted
    local md = opts.algorithm and EVP.get_digestbyname(opts.algorithm)
    if opts.algorithm and not md then
        return nil, "Unknown message digest"
    end

    return setmetatable({
        pkey = pkey,
        _encrypt_ctx = is_pub and ctx or nil,
        _decrypt_ctx = not is_pub and ctx or nil,
        is_pub = is_pub,
        md = md,
    }, mt)
end

function _M.generate_key()
    local eckey, err = EC.KEY_new_by_curve_name(NID_SM2)
    if not eckey then
        return nil, nil, err
    end
    if EC.KEY_generate_key(eckey) == 0 then
        return nil, nil, ERR.get_error()
    end
    local prvkey, err = EC.KEY_get0_private_key(eckey)
    if not prvkey then
        return nil, nil, err
    end
    local pubkey, err = EC.KEY_get0_public_key(eckey)
    if not pubkey then
        return nil, nil, err
    end

    return pubkey, prvkey
end
--
--function _M.decrypt(self, str)
--    local ctx = self._decrypt_ctx
--    if not ctx then
--        return nil, "not inited for decrypt"
--    end
--
--    return EVP.PKEY_decrypt(ctx, str)
--end
--
--function _M.encrypt(self, str)
--    local ctx = self._encrypt_ctx
--    if not ctx then
--        return nil, "not inited for encrypt"
--    end
--
--    return EVP.PKEY_encrypt(ctx, str)
--end

function _M.sign(self, str)
    if self.is_pub then
        return nil, "not inited for sign"
    end

    local md_ctx = EVP.MD_CTX_new()

    if EVP.DigestInit(md_ctx, self.md) <= 0 then
        return nil, ERR.get_error()
    end

    if EVP.DigestUpdate(md_ctx, str) <= 0 then
        return nil, ERR.get_error()
    end

    return EVP.SignFinal(md_ctx, self.pkey)
end

function _M.verify(self, str, sig)
    if not self.is_pub then
        return nil, "not inited for verify"
    end

    local md_ctx = EVP.MD_CTX_new()

    if EVP.DigestInit(md_ctx, self.md) <= 0 then
        return nil, ERR.get_error()
    end

    if EVP.DigestUpdate(md_ctx, str) <= 0 then
        return nil, ERR.get_error()
    end

    return EVP.VerifyFinal(md_ctx, self.pkey, sig)
end

return _M