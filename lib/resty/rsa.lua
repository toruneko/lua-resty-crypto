-- Copyright (C) by Zhu Dejiang (doujiang24)
-- Copyright (C) by Zexuan Luo (spacewander)
-- Copyright (C) by Jianhao Dai (Toruneko)

local VERSION = require "resty.crypto.version"
local EVP = require "resty.crypto.evp"
local RSA = require "resty.crypto.rsa"
local PEM = require "resty.crypto.pem"
local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_copy = ffi.copy
local C = ffi.C
local setmetatable = setmetatable

local _M = { _VERSION = '1.0.0' }
local mt = { __index = _M }

local OPENSSL_1_1_256 = 269488143

local PADDING = {
    RSA_PKCS1_PADDING = 1, -- RSA_size - 11
    RSA_SSLV23_PADDING = 2, -- RSA_size - 11
    RSA_NO_PADDING = 3, -- RSA_size
    RSA_PKCS1_OAEP_PADDING = 4, -- RSA_size - 42
}
_M.PADDING = PADDING

local KEY_TYPE = {
    PKCS1 = "PKCS#1",
    PKCS8 = "PKCS#8",
}
_M.KEY_TYPE = KEY_TYPE

ffi.cdef [[
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key);
]]

local unsigned_char_ptr = ffi.typeof("unsigned char[?]")

local EVP_PKEY_ALG_CTRL = 0x1000
local EVP_PKEY_CTRL_RSA_PADDING = EVP_PKEY_ALG_CTRL + 1
local NID_rsaEncryption = 6
local EVP_PKEY_RSA = NID_rsaEncryption

function _M.new(_, opts)
    local key, read_func, is_pub, md

    if opts.public_key then
        key = opts.public_key
        if opts.key_type == KEY_TYPE.PKCS8 then
            read_func = PEM.read_RSA_PUBKEY
        else
            read_func = PEM.read_RSAPublicKey
        end
        is_pub = true

    elseif opts.private_key then
        key = opts.private_key
        read_func = PEM.read_RSAPrivateKey

    else
        return nil, "public_key or private_key not found"
    end

    local pass
    if opts.password then
        local plen = #opts.password
        pass = ffi_new(unsigned_char_ptr, plen + 1)
        ffi_copy(pass, opts.password, plen)
    end

    local rsa, err = read_func(key, pass)
    if not rsa then
        return nil, err
    end

    -- EVP_PKEY
    local pkey, err = EVP.PKEY_new()
    if not pkey then
        return nil, err
    end

    if C.EVP_PKEY_set1_RSA(pkey, rsa) == 0 then
        return nil, ERR.get_error()
    end

    --EVP_PKEY_CTX
    local ctx, err = EVP.PKEY_CTX_new(pkey)
    if not ctx then
        return nil, err
    end

    -- md_ctx init for sign or verify; if signature algorithm is seted
    if opts.algorithm then
        md = EVP.get_digestbyname(opts.algorithm)
        if md == nil then
            return nil, "Unknown message digest"
        end
    end

    -- ctx init for encrypt or decrypt
    -- default for encrypt/decrypt if nothing is set
    if opts.padding or not opts.digest then
        local init_func = is_pub and EVP.PKEY_encrypt_init
                or EVP.PKEY_decrypt_init
        local ok, err = init_func(ctx)
        if not ok then
            return nil, err
        end

        local ok, err = EVP.PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_PADDING,
            opts.padding or PADDING.RSA_PKCS1_PADDING, nil)
        if not ok then
            return nil, err
        end
    end

    return setmetatable({
        pkey = pkey,
        _encrypt_ctx = is_pub and ctx or nil,
        _decrypt_ctx = not is_pub and ctx or nil,
        is_pub = is_pub,
        md = md,
    }, mt)
end

function _M.generate_key(bits, pkcs8)
    local rsa, err = RSA.new()
    if not rsa then
        return nil, nil, err
    end
    local ok, err = RSA.generate_key(rsa, bits)
    if not ok then
        return nil, nil, err
    end

    local pub_write_func
    if pkcs8 == true then
        pub_write_func = PEM.write_RSA_PUBKEY
    else
        pub_write_func = PEM.write_RSAPublicKey
    end

    local public_key, err = pub_write_func(rsa)
    if not public_key then
        return nil, nil, err
    end

    local priv_write_func
    if pkcs8 == true then
        local pk, err = EVP.PKEY_new(rsa)
        if not pk then
            return nil, nil, err
        end
        if C.EVP_PKEY_set1_RSA(pk, rsa) == 0 then
            return nil, nil, ERR.get_error()
        end
        rsa = pk
        priv_write_func = PEM.write_PKCS8PrivateKey
    else
        priv_write_func = PEM.write_RSAPrivateKey
    end

    local private_key, err = priv_write_func(rsa)
    if not private_key then
        return nil, nil, err
    end

    return public_key, private_key
end

function _M.decrypt(self, str)
    local ctx = self._decrypt_ctx
    if not ctx then
        return nil, "not inited for decrypt"
    end

    return EVP.PKEY_decrypt(ctx, str)
end

function _M.encrypt(self, str)
    local ctx = self._encrypt_ctx
    if not ctx then
        return nil, "not inited for encrypt"
    end

    return EVP.PKEY_encrypt(ctx, str)
end

function _M.sign(self, str)
    if self.is_pub then
        return nil, "not inited for sign"
    end

    if VERSION.version() >= OPENSSL_1_1_256 then
        local md_ctx, err = EVP.MD_CTX_new(self._decrypt_ctx)
        if not md_ctx then
            return nil, err
        end
        local ok, err = EVP.DigestSignInit(md_ctx, self.md, self.pkey)
        if not ok then
            return nil, err
        end
        return EVP.DigestSign(md_ctx, str)
    end

    local md_ctx, err = EVP.MD_CTX_new()
    if not md_ctx then
        return nil, err
    end

    local ok, err = EVP.DigestInit(md_ctx, self.md)
    if not ok then
        return nil, err
    end

    local ok, err = EVP.DigestUpdate(md_ctx, str)
    if not ok then
        return nil, err
    end

    return EVP.SignFinal(md_ctx, self.pkey)
end

function _M.verify(self, str, sig)
    if not self.is_pub then
        return nil, "not inited for verify"
    end

    if VERSION.version() >= OPENSSL_1_1_256 then
        local md_ctx, err = EVP.MD_CTX_new(self._encrypt_ctx)
        if not md_ctx then
            return nil, err
        end
        local ok, err = EVP.DigestVerifyInit(md_ctx, self.md, self.pkey)
        if not ok then
            return nil, err
        end
        return EVP.DigestVerify(md_ctx, str, sig)
    end

    local md_ctx, err = EVP.MD_CTX_new()
    if not md_ctx then
        return nil, err
    end

    local ok, err = EVP.DigestInit(md_ctx, self.md)
    if not ok then
        return nil, err
    end

    local ok, err = EVP.DigestUpdate(md_ctx, str)
    if not ok then
        return nil, err
    end

    return EVP.VerifyFinal(md_ctx, self.pkey, sig)
end


return _M