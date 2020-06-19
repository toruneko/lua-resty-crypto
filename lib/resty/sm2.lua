-- Copyright (C) by Jianhao Dai (Toruneko)

local EC = require "resty.crypto.ec"
local EVP = require "resty.crypto.evp"
local PEM = require "resty.crypto.pem"
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

local function read_private_key(private_key, private_pass, pemformat)
    if not pemformat then
        return private_key
    end
    local prv_eckey, err = PEM.PEM_read_bio_ECPrivateKey(private_key, private_pass)
    if not prv_eckey then
        return nil, err
    end
    local key, err = EC.KEY_get0_private_key(prv_eckey)
    if not key then
        return nil, err
    end
    return key
end

local function read_public_key(public_key, public_pass, pemformat)
    if not pemformat then
        return public_key
    end
    local pub_eckey, err = PEM.read_bio_EC_PUBKEY(public_key, public_pass)
    if not pub_eckey then
        return nil, err
    end
    local key, err = EC.KEY_get0_public_key(pub_eckey)
    if not key then
        return nil, err
    end
    return key
end

function _M.new(opts, pemformat)
    local eckey, err = EC.KEY_new_by_curve_name(NID_SM2)
    if not eckey then
        return nil, err
    end

    local is_pub = true
    if opts.private_key then
        local private_key, err = read_private_key(opts.private_key, opts.private_pass, pemformat)
        if not private_key then
            return nil, err
        end
        local ok, err = EC.KEY_set_private_key(eckey, private_key)
        if not ok then
            return nil, err
        end
        is_pub = false
    end

    local public_key, err = read_public_key(opts.public_key, opts.public_pass, pemformat)
    if not public_key then
        return nil, err
    end
    local ok, err = EC.KEY_set_public_key(eckey, public_key)
    if not ok then
        return nil, err
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
    local ok, err = EVP.PKEY_CTX_ctrl(pkey_ctx, -1, -1, EVP_PKEY_CTRL_SET1_ID, #id, ffi_cast(void_ptr, id))
    if not ok then
        return nil, err
    end

    local init_func = is_pub and EVP.PKEY_encrypt_init
            or EVP.PKEY_decrypt_init
    local ok, err = init_func(pkey_ctx)
    if not ok then
        return nil, err
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

function _M.generate_eckey()
    local eckey, err = EC.KEY_new_by_curve_name(NID_SM2)
    if not eckey then
        return nil, nil, err
    end
    local ok, err = EC.KEY_generate_key(eckey)
    if not ok then
        return nil, nil, err
    end

    local public_key, err = PEM.write_bio_EC_PUBKEY(eckey)
    if not public_key then
        return nil, nil, err
    end

    local private_key, err = PEM.write_bio_ECPrivateKey(eckey)
    if not private_key then
        return nil, nil, err
    end

    return public_key, private_key
end

function _M.generate_key()
    local eckey, err = EC.KEY_new_by_curve_name(NID_SM2)
    if not eckey then
        return nil, nil, err
    end
    local ok, err = EC.KEY_generate_key(eckey)
    if not ok then
        return nil, nil, err
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
    local md_ctx, err = EVP.MD_CTX_new(self.pkey_ctx)
    if not md_ctx then
        return nil, err
    end

    local ok, err = EVP.DigestSignInit(md_ctx, self.md, self.pkey)
    if not ok then
        return nil, err
    end

    return EVP.DigestSign(md_ctx, str)
end

function _M.verify(self, str, sig)
    if not self.is_pub then
        return nil, "not inited for verify"
    end

    local md_ctx, err = EVP.MD_CTX_new(self.pkey_ctx)
    if not md_ctx then
        return nil, err
    end

    local ok, err = EVP.DigestVerifyInit(md_ctx, self.md, self.pkey)
    if not ok then
        return nil, err
    end

    return EVP.DigestVerify(md_ctx, str, sig)
end

return _M