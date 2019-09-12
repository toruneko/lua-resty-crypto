-- Copyright (C) by Jianhao Dai (Toruneko)

local RSA = require "resty.crypto.rsa"
local X509 = require "resty.crypto.x509"
local BIO = require "resty.crypto.bio"
local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local ffi_gc = ffi.gc
local ffi_null = ffi.null
local C = ffi.C

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);

RSA * PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **rsa, pem_password_cb *cb, void *u);
RSA * PEM_read_bio_RSAPublicKey(BIO *bp, RSA **rsa, pem_password_cb *cb, void *u);
RSA * PEM_read_bio_RSA_PUBKEY(BIO *bp, RSA **rsa, pem_password_cb *cb, void *u);

int PEM_write_bio_RSAPrivateKey(BIO *bp, RSA *x, const EVP_CIPHER *enc,
                                unsigned char *kstr, int klen,
                                pem_password_cb *cb, void *u);
int PEM_write_bio_RSAPublicKey(BIO *bp, RSA *x);
int PEM_write_bio_PKCS8PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
                                  char *kstr, int klen, pem_password_cb *cb,
                                  void *u);
int PEM_write_bio_RSA_PUBKEY(BIO *bp, RSA *x);


X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
]]

local function PEM_read_RSA_Key(read_function, key, pass)
    local bio, err = BIO.new(key)
    if not bio then
        return nil, err
    end

    local rsa = read_function(bio, ffi_null, ffi_null, pass)
    if rsa == ffi_null then
        return nil, ERR.get_error()
    end
    ffi_gc(rsa, RSA.free)

    return rsa
end

local function PEM_write_RSA_PublicKey(write_function, rsa)
    local bp, err = BIO.new()
    if not bp then
        return nil, err
    end

    if write_function(bp, rsa) ~= 1 then
        return nil, ERR.get_error()
    end

    local public_key, err = BIO.read(bp)
    if not public_key then
        return nil, err
    end

    return public_key
end

local function PEM_write_RSA_PrivateKey(write_function, rsa)
    local bp, err = BIO.new()
    if not bp then
        return nil, err
    end

    if write_function(bp, rsa, ffi_null, ffi_null, 0, ffi_null, ffi_null) ~= 1 then
        return nil, ERR.get_error()
    end

    local private_key, err = BIO.read(bp)
    if not private_key then
        return nil, err
    end

    return private_key
end

function _M.read_RSAPrivateKey(key, pass)
    return PEM_read_RSA_Key(C.PEM_read_bio_RSAPrivateKey, key, pass)
end

function _M.read_RSAPublicKey(key, pass)
    return PEM_read_RSA_Key(C.PEM_read_bio_RSAPublicKey, key, pass)
end

function _M.read_RSA_PUBKEY(key, pass)
    return PEM_read_RSA_Key(C.PEM_read_bio_RSA_PUBKEY, key, pass)
end

function _M.write_RSAPublicKey(rsa)
    return PEM_write_RSA_PublicKey(C.PEM_write_bio_RSAPublicKey, rsa)
end

function _M.write_RSA_PUBKEY(rsa)
    return PEM_write_RSA_PublicKey(C.PEM_write_bio_RSA_PUBKEY, rsa)
end

function _M.write_RSAPrivateKey(rsa)
    return PEM_write_RSA_PrivateKey(C.PEM_write_bio_RSAPrivateKey, rsa)
end

function _M.write_PKCS8PrivateKey(pkey)
    return PEM_write_RSA_PrivateKey(C.PEM_write_bio_PKCS8PrivateKey, pkey)
end

function _M.read_X509(cert, pass)
    local bio, err = BIO.new(cert)
    if not bio then
        return nil, err
    end

    local x509 = C.PEM_read_bio_X509(bio, ffi_null, ffi_null, pass)
    if x509 == ffi_null then
        return nil, ERR.get_error()
    end
    ffi_gc(x509, X509.free)

    return x509
end

return _M