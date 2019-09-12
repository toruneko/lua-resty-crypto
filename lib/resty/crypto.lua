-- Copyright (C) by Jianhao Dai (Toruneko)
-- Copyright (C) by Yichun Zhang (agentzh)

local EVP = require "resty.crypto.evp"
local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local ffi_copy = ffi.copy
local C = ffi.C
local setmetatable = setmetatable
local type = type

local _M = { _VERSION = '0.0.1' }
local mt = { __index = _M }

ffi.cdef[[
const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_sha(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);

int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
        ENGINE *impl, unsigned char *key, const unsigned char *iv);

int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
        const unsigned char *in, int inl);

int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
        ENGINE *impl, unsigned char *key, const unsigned char *iv);

int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
        const unsigned char *in, int inl);

int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

int EVP_BytesToKey(const EVP_CIPHER *type,const EVP_MD *md,
        const unsigned char *salt, const unsigned char *data, int datal,
        int count, unsigned char *key,unsigned char *iv);

typedef unsigned char u_char;
u_char * ngx_hex_dump(u_char *dst, const u_char *src, size_t len);
]]

local str_type = ffi.typeof("uint8_t[?]")

local hash
hash = {
    md5 = C.EVP_md5(),
    sha1 = C.EVP_sha1(),
    sha224 = C.EVP_sha224(),
    sha256 = C.EVP_sha256(),
    sha384 = C.EVP_sha384(),
    sha512 = C.EVP_sha512()
}
_M.hash = hash

function _M.new(key, salt, _cipher, _hash, hash_rounds)
    local encrypt_ctx, err = EVP.CIPHER_CTX_new()
    if not encrypt_ctx then
        return nil, err
    end

    local decrypt_ctx, err = EVP.CIPHER_CTX_new()
    if not decrypt_ctx then
        return nil, err
    end

    if not _cipher then
        return nil, "no cipher"
    end

    local _hash = _hash or hash.md5
    local hash_rounds = hash_rounds or 1
    local _cipherLength = _cipher.size / 8
    local gen_key = ffi_new("unsigned char[?]",_cipherLength)
    local gen_iv = ffi_new("unsigned char[?]",_cipherLength)

    if type(_hash) == "table" then
        if not _hash.iv or #_hash.iv ~= 16 then
            return nil, "bad iv"
        end

        if _hash.method then
            local tmp_key = _hash.method(key)

            if #tmp_key ~= _cipherLength then
                return nil, "bad key length"
            end

            ffi_copy(gen_key, tmp_key, _cipherLength)

        elseif #key ~= _cipherLength then
            return nil, "bad key length"

        else
            ffi_copy(gen_key, key, _cipherLength)
        end

        ffi_copy(gen_iv, _hash.iv, 16)

    else
        if salt and #salt ~= 8 then
            return nil, "salt must be 8 characters or nil"
        end

        if C.EVP_BytesToKey(_cipher.method, _hash, salt, key, #key,
            hash_rounds, gen_key, gen_iv)
                ~= _cipherLength
        then
            return nil, ERR.get_error()
        end
    end

    if C.EVP_EncryptInit_ex(encrypt_ctx, _cipher.method, nil,
        gen_key, gen_iv) == 0 or
            C.EVP_DecryptInit_ex(decrypt_ctx, _cipher.method, nil,
                gen_key, gen_iv) == 0 then
        return nil, ERR.get_error()
    end

    return setmetatable({
        _encrypt_ctx = encrypt_ctx,
        _decrypt_ctx = decrypt_ctx
    }, mt)
end


function _M.encrypt(self, s)
    local s_len = #s
    local max_len = s_len + 16
    local buf = ffi_new("unsigned char[?]", max_len)
    local out_len = ffi_new("int[1]")
    local tmp_len = ffi_new("int[1]")
    local ctx = self._encrypt_ctx

    if C.EVP_EncryptInit_ex(ctx, nil, nil, nil, nil) == 0 then
        return nil, ERR.get_error()
    end

    if C.EVP_EncryptUpdate(ctx, buf, out_len, s, s_len) == 0 then
        return nil, ERR.get_error()
    end

    if C.EVP_EncryptFinal_ex(ctx, buf + out_len[0], tmp_len) == 0 then
        return nil, ERR.get_error()
    end

    return ffi_str(buf, out_len[0] + tmp_len[0])
end


function _M.decrypt(self, s)
    local s_len = #s
    local buf = ffi_new("unsigned char[?]", s_len)
    local out_len = ffi_new("int[1]")
    local tmp_len = ffi_new("int[1]")
    local ctx = self._decrypt_ctx

    if C.EVP_DecryptInit_ex(ctx, nil, nil, nil, nil) == 0 then
        return nil, ERR.get_error()
    end

    if C.EVP_DecryptUpdate(ctx, buf, out_len, s, s_len) == 0 then
        return nil, ERR.get_error()
    end

    if C.EVP_DecryptFinal_ex(ctx, buf + out_len[0], tmp_len) == 0 then
        return nil, ERR.get_error()
    end

    return ffi_str(buf, out_len[0] + tmp_len[0])
end

function _M.to_hex(s)
    local len = #s
    local buf_len = len * 2
    local buf = ffi_new(str_type, buf_len)
    C.ngx_hex_dump(buf, s, len)
    return ffi_str(buf, buf_len)
end

return _M