-- Copyright (C) by Zhu Dejiang (doujiang24)
-- Copyright (C) by Zexuan Luo (spacewander)
-- Copyright (C) by Jianhao Dai (Toruneko)

local EVP = require "resty.crypto.evp"
local PEM = require "resty.crypto.pem"
local BN = require "resty.crypto.bn"
local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local ffi_gc = ffi.gc
local C = ffi.C
local setmetatable = setmetatable

local _M = { _VERSION = '1.0.0' }
local mt = { __index = _M }


local PADDING = {
    RSA_PKCS1_PADDING = 1,  -- RSA_size - 11
    RSA_SSLV23_PADDING = 2, -- RSA_size - 11
    RSA_NO_PADDING = 3,     -- RSA_size
    RSA_PKCS1_OAEP_PADDING = 4, -- RSA_size - 42
}
_M.PADDING = PADDING

local KEY_TYPE = {
    PKCS1 = "PKCS#1",
    PKCS8 = "PKCS#8",
}
_M.KEY_TYPE = KEY_TYPE

ffi.cdef[[
typedef struct rsa_st RSA;
RSA *RSA_new(void);
void RSA_free(RSA *rsa);
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);

int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
        unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen);

int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen);


int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const unsigned char *in, int inl);
int EVP_SignFinal(EVP_MD_CTX *ctx,unsigned char *sig,unsigned int *s,
                  EVP_PKEY *pkey);
int EVP_VerifyFinal(EVP_MD_CTX *ctx,unsigned char *sigbuf, unsigned int siglen,
                    EVP_PKEY *pkey);
]]

local unsigned_char_ptr = ffi.typeof("unsigned char[?]")
local unsigned_int_ptr = ffi.typeof("unsigned int[?]")
local size_t_ptr = ffi.typeof("size_t[?]")

local EVP_PKEY_ALG_CTRL = 0x1000
local EVP_PKEY_CTRL_RSA_PADDING = EVP_PKEY_ALG_CTRL + 1
local NID_rsaEncryption = 6
local EVP_PKEY_RSA = NID_rsaEncryption

local function RSA_free(rsa)
    ffi_gc(rsa, C.RSA_free)
end

local function RSA_new()
    local rsa = C.RSA_new()
    RSA_free(rsa)
    return rsa
end

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
    local pkey, err = EVP.PKEY_new(rsa)
    if not pkey then
        return nil, err
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
        local init_func = is_pub and C.EVP_PKEY_encrypt_init
                or C.EVP_PKEY_decrypt_init
        if init_func(ctx) <= 0 then
            return nil, ERR.get_error()
        end

        if C.EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_PADDING,
            opts.padding or PADDING.RSA_PKCS1_PADDING, nil) <= 0 then
            return ERR.get_error()
        end
    end

    local size = EVP.PKEY_size(pkey)
    return setmetatable({
        pkey = pkey,
        size = size,
        buf = ffi_new(unsigned_char_ptr, size),
        _encrypt_ctx = is_pub and ctx or nil,
        _decrypt_ctx = not is_pub and ctx or nil,
        is_pub = is_pub,
        md = md,
    }, mt)
end

function _M.generate_key(bits, pkcs8)
    local rsa = RSA_new()
    local bn = BN.new()

    -- Set public exponent to 65537
    if BN.set_word(bn, 65537) ~= 1 then
        return nil, ERR.get_error()
    end

    -- Generate key
    if C.RSA_generate_key_ex(rsa, bits, bn, nil) ~= 1 then
        return nil, ERR.get_error()
    end

    local pub_write_func
    if pkcs8 == true then
        pub_write_func = PEM.write_RSA_PUBKEY
    else
        pub_write_func = PEM.write_RSAPublicKey
    end

    local public_key, err = pub_write_func(rsa)
    if not public_key then
        return nil, err
    end

    local priv_write_func
    if pkcs8 == true then
        local pk, err = EVP.PKEY_new(rsa)
        if not pk then
            return nil, err
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

    local len = ffi_new(size_t_ptr, 1)
    if C.EVP_PKEY_decrypt(ctx, nil, len, str, #str) <= 0 then
        return nil, ERR.get_error()
    end

    local buf = self.buf
    if C.EVP_PKEY_decrypt(ctx, buf, len, str, #str) <= 0 then
        return nil, ERR.get_error()
    end

    return ffi_str(buf, len[0])
end


function _M.encrypt(self, str)
    local ctx = self._encrypt_ctx
    if not ctx then
        return nil, "not inited for encrypt"
    end

    local len = ffi_new(size_t_ptr, 1)
    if C.EVP_PKEY_encrypt(ctx, nil, len, str, #str) <= 0 then
        return nil, ERR.get_error()
    end

    local buf = self.buf
    if C.EVP_PKEY_encrypt(ctx, buf, len, str, #str) <= 0 then
        return nil, ERR.get_error()
    end

    return ffi_str(buf, len[0])
end


function _M.sign(self, str)
    if self.is_pub then
        return nil, "not inited for sign"
    end

    local md_ctx = EVP.MD_CTX_new()

    if C.EVP_DigestInit(md_ctx, self.md) <= 0 then
        return nil, ERR.get_error()
    end

    if C.EVP_DigestUpdate(md_ctx, str, #str) <= 0 then
        return nil, ERR.get_error()
    end

    local buf = self.buf
    local len = ffi_new(unsigned_int_ptr, 1)
    if C.EVP_SignFinal(md_ctx, self.buf, len, self.pkey) <= 0 then
        return nil, ERR.get_error()
    end

    return ffi_str(buf, len[0])
end


function _M.verify(self, str, sig)
    if not self.is_pub then
        return nil, "not inited for verify"
    end

    local md_ctx = EVP.MD_CTX_new()

    if C.EVP_DigestInit(md_ctx, self.md) <= 0 then
        return nil, ERR.get_error()
    end

    if C.EVP_DigestUpdate(md_ctx, str, #str) <= 0 then
        return nil, ERR.get_error()
    end

    local siglen = #sig
    local buf = siglen <= self.size and self.buf
            or ffi_new(unsigned_char_ptr, siglen)
    ffi_copy(buf, sig, siglen)
    if C.EVP_VerifyFinal(md_ctx, buf, siglen, self.pkey) <= 0 then
        return nil, ERR.get_error()
    end

    return true
end


return _M