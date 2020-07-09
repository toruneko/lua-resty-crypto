-- Copyright (C) by Jianhao Dai (Toruneko)

local X509 = require "resty.crypto.x509"
local RSA = require "resty.crypto.rsa"
local EC = require "resty.crypto.ec"
local BIO = require "resty.crypto.bio"
local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local ffi_gc = ffi.gc
local ffi_null = ffi.null
local C = ffi.C

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);

int PEM_write_bio_PKCS8PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
                                  char *kstr, int klen,
                                  pem_password_cb *cb, void *u);

//X509
int PEM_write_bio_X509(BIO *bp, X509 *x509);
X509 *PEM_read_bio_X509(BIO *bp, X509 **x509, pem_password_cb *cb, void *u);

// RSA
int PEM_write_bio_RSA_PUBKEY(BIO *bp, RSA *rsa);
RSA *PEM_read_bio_RSA_PUBKEY(BIO *bp, RSA **rsa, pem_password_cb *cb, void *u);
int PEM_write_bio_RSAPrivateKey(BIO *bp, RSA *rsa, const EVP_CIPHER *enc,
                               unsigned char *kstr, int klen,
                               pem_password_cb *cb, void *u);
RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **rsa, pem_password_cb *cb, void *u);
int PEM_write_bio_RSAPublicKey(BIO *bp, const RSA *rsa);
RSA *PEM_read_bio_RSAPublicKey(BIO *bp, RSA **rsa, pem_password_cb *cb, void *u);

// EC_KEY
int PEM_write_bio_EC_PUBKEY(BIO *bp, EC_KEY *eckey);
EC_KEY *PEM_read_bio_EC_PUBKEY(BIO *bp, EC_KEY **eckey, pem_password_cb *cb, void *u);
int PEM_write_bio_ECPrivateKey(BIO *bp, EC_KEY *eckey, const EVP_CIPHER *enc,
                               unsigned char *kstr, int klen,
                               pem_password_cb *cb, void *u);
EC_KEY *PEM_read_bio_ECPrivateKey(BIO *bp, EC_KEY **eckey, pem_password_cb *cb, void *u);
]]

local function PEM_read_Key(d2i, key, pass, gc_meth)
    local bio, err = BIO.new(key)
    if not bio then
        return nil, err
    end

    local x = d2i(bio, ffi_null, ffi_null, pass)
    if x == ffi_null then
        return nil, ERR.get_error()
    end
    gc_meth(x)

    return x
end

local function PEM_write_PublicKey(i2d, x)
    local bp, err = BIO.new()
    if not bp then
        return nil, err
    end

    if i2d(bp, x) ~= 1 then
        return nil, ERR.get_error()
    end

    local public_key, err = BIO.read(bp)
    if not public_key then
        return nil, err
    end

    return public_key
end

local function PEM_write_PrivateKey(i2d, x)
    local bp, err = BIO.new()
    if not bp then
        return nil, err
    end

    if i2d(bp, x, ffi_null, ffi_null, 0, ffi_null, ffi_null) ~= 1 then
        return nil, ERR.get_error()
    end

    local private_key, err = BIO.read(bp)
    if not private_key then
        return nil, err
    end

    return private_key
end

function _M.write_X509(x509)
    return PEM_write_PublicKey(C.PEM_write_bio_X509, x509)
end

function _M.read_X509(cert, pass)
    return PEM_read_Key(C.PEM_read_bio_X509, cert, pass, X509.free)
end

function _M.write_RSA_PUBKEY(rsa)
    return PEM_write_PublicKey(C.PEM_write_bio_RSA_PUBKEY, rsa)
end

function _M.read_RSA_PUBKEY(key, pass)
    return PEM_read_Key(C.PEM_read_bio_RSA_PUBKEY, key, pass, RSA.free)
end

function _M.write_RSAPrivateKey(rsa)
    return PEM_write_PrivateKey(C.PEM_write_bio_RSAPrivateKey, rsa)
end

function _M.read_RSAPrivateKey(key, pass)
    return PEM_read_Key(C.PEM_read_bio_RSAPrivateKey, key, pass, RSA.free)
end

function _M.write_RSAPublicKey(rsa)
    return PEM_write_PublicKey(C.PEM_write_bio_RSAPublicKey, rsa)
end

function _M.read_RSAPublicKey(key, pass)
    return PEM_read_Key(C.PEM_read_bio_RSAPublicKey, key, pass, RSA.free)
end

function _M.write_PKCS8PrivateKey(pkey)
    return PEM_write_PrivateKey(C.PEM_write_bio_PKCS8PrivateKey, pkey)
end

function _M.write_bio_EC_PUBKEY(eckey)
    return PEM_write_PublicKey(C.PEM_write_bio_EC_PUBKEY, eckey)
end

function _M.read_bio_EC_PUBKEY(eckey, pass)
    return PEM_read_Key(C.PEM_read_bio_EC_PUBKEY, eckey, pass, EC.KEY_free)
end

function _M.write_bio_ECPrivateKey(eckey)
    return PEM_write_PrivateKey(C.PEM_write_bio_ECPrivateKey, eckey)
end

function _M.PEM_read_bio_ECPrivateKey(eckey, pass)
    return PEM_read_Key(C.PEM_read_bio_ECPrivateKey, eckey, pass, EC.KEY_free)
end

return _M