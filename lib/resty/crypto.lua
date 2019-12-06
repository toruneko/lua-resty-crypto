-- Copyright (C) by Jianhao Dai (Toruneko)
-- Copyright (C) by Yichun Zhang (agentzh)

local EVP = require "resty.crypto.evp"
local ERR = require "resty.crypto.error"
local str = require "resty.utils.string"

local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local ffi_null = ffi.null
local C = ffi.C
local setmetatable = setmetatable

local _M = { _VERSION = '0.0.4' }
local mt = { __index = _M }

ffi.cdef [[
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
]]

local unsigned_char_ptr = ffi.typeof("unsigned char[?]")
local int_ptr = ffi.typeof("int[?]")

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

    local _hash = EVP.get_digestbyname(_hash or "md5")
    if _hash == ffi_null then
        _hash = EVP.get_digestbyname("md5")
    end
    local hash_rounds = hash_rounds or 1
    local _cipherLength = _cipher.size / 8
    local gen_key = ffi_new(unsigned_char_ptr, _cipherLength)
    local gen_iv = ffi_new(unsigned_char_ptr, _cipherLength)

    if salt and #salt ~= 8 then
        return nil, "salt must be 8 characters or nil"
    end

    if C.EVP_BytesToKey(_cipher.method, _hash, salt, key, #key, hash_rounds, gen_key, gen_iv) ~= _cipherLength then
        return nil, ERR.get_error()
    end

    if C.EVP_EncryptInit_ex(encrypt_ctx, _cipher.method, nil, gen_key, gen_iv) == 0
            or C.EVP_DecryptInit_ex(decrypt_ctx, _cipher.method, nil, gen_key, gen_iv) == 0 then
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
    local buf = ffi_new(unsigned_char_ptr, max_len)
    local out_len = ffi_new(int_ptr, 1)
    local tmp_len = ffi_new(int_ptr, 1)
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
    local buf = ffi_new(unsigned_char_ptr, s_len)
    local out_len = ffi_new(int_ptr, 1)
    local tmp_len = ffi_new(int_ptr, 1)
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

function _M.tohex(s)
    return str.tohex(s)
end

return _M