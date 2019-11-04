-- Copyright (C) by Jianhao Dai (Toruneko)

local EC = require "resty.crypto.ec"
local EVP = require "resty.crypto.evp"
local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local ffi_cast = ffi.cast
local C = ffi.C

local setmetatable = setmetatable

local _M = { _VERSION = '0.0.1' }
local mt = { __index = _M }

ffi.cdef [[
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);
int EVP_PKEY_set_alias_type(EVP_PKEY *pkey, int type);
]]

local void_ptr = ffi.typeof("void *")

local NID_SM2 = 1172
local EVP_PKEY_SM2 = NID_SM2

local EVP_PKEY_ALG_CTRL = 0x1000
local EVP_PKEY_CTRL_SET1_ID = EVP_PKEY_ALG_CTRL + 11

function _M.new(opts)
    local eckey, err = EC.KEY_new_by_curve_name(NID_SM2)
    if not eckey then
        return nil, err
    end

    local is_pub = true
    if opts.private_key then
        if EC.KEY_set_private_key(eckey, opts.private_key) == 0 then
            return nil, ERR.get_error()
        end
        is_pub = false
    end

    if EC.KEY_set_public_key(eckey, opts.public_key) == 0 then
        return nil, ERR.get_error()
    end

    -- EVP_PKEY
    local pkey, err = EVP.PKEY_new()
    if not pkey then
        return nil, err
    end

    if C.EVP_PKEY_set1_EC_KEY(pkey, eckey) == 0 then
        return nil, ERR.get_error()
    end

    C.EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)

    --EVP_PKEY_CTX
    local pkey_ctx, err = EVP.PKEY_CTX_new(pkey)
    if not pkey_ctx then
        return nil, err
    end

    local id = opts.id or "default sm2 ID"
    EVP.PKEY_CTX_ctrl(pkey_ctx, -1, -1, EVP_PKEY_CTRL_SET1_ID, #id, ffi_cast(void_ptr, id))

    local init_func = is_pub and EVP.PKEY_encrypt_init
            or EVP.PKEY_decrypt_init
    if init_func(pkey_ctx) <= 0 then
        return nil, ERR.get_error()
    end

    -- md_ctx init for sign or verify
    local md = opts.algorithm and EVP.get_digestbyname(opts.algorithm)
    if opts.algorithm and not md then
        return nil, "Unknown message digest"
    end

    return setmetatable({
        pkey = pkey,
        pkey_ctx = pkey_ctx,
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

function _M.decrypt(self, str)
    if self.is_pub then
        return nil, "not inited for decrypt"
    end

    return EVP.PKEY_decrypt(self.pkey_ctx, str)
end

function _M.encrypt(self, str)
    if not self.is_pub then
        return nil, "not inited for encrypt"
    end

    return EVP.PKEY_encrypt(self.pkey_ctx, str)
end

function _M.sign(self, str)
    if self.is_pub then
        return nil, "not inited for sign"
    end
    local md_ctx = EVP.MD_CTX_new(self.pkey_ctx)

    if EVP.DigestSignInit(md_ctx, self.md, self.pkey) <= 0 then
        return nil, ERR.get_error()
    end

    return EVP.DigestSign(md_ctx, str)
end

function _M.verify(self, str, sig)
    if not self.is_pub then
        return nil, "not inited for verify"
    end

    local md_ctx = EVP.MD_CTX_new(self.pkey_ctx)

    if EVP.DigestVerifyInit(md_ctx, self.md, self.pkey) <= 0 then
        return nil, ERR.get_error()
    end

    return EVP.DigestVerify(md_ctx, str, sig)
end

return _M