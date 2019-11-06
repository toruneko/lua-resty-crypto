-- Copyright (C) by Jianhao Dai (Toruneko)

local EVP = require "resty.crypto.evp"
local BIO = require "resty.crypto.bio"
local X509 = require "resty.crypto.x509"
local PEM = require "resty.crypto.pem"
local ERR = require "resty.crypto.error"
local STACK = require "resty.crypto.stack"

local bit = require "bit"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_cast = ffi.cast
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local ffi_null = ffi.null
local C = ffi.C
local bor = bit.bor
local setmetatable = setmetatable
local type = type
local ipairs = ipairs

local CMS_NO_CONTENT_VERIFY = 0x4
local CMS_NO_ATTR_VERIFY = 0x8
local CMS_NOATTR = 0x100
local CMS_DEBUG_DECRYPT = 0x20000

local _M = { _VERSION = '0.0.2' }
local mt = { __index = _M }

ffi.cdef [[
//cipher Functions
const EVP_CIPHER *EVP_des_cbc(void);
const EVP_CIPHER *EVP_des_cfb(void);
const EVP_CIPHER *EVP_des_ecb(void);
const EVP_CIPHER *EVP_des_ofb(void);
const EVP_CIPHER *EVP_des_ede(void);
const EVP_CIPHER *EVP_des_ede_cbc(void);
const EVP_CIPHER *EVP_des_ede_cfb(void);
const EVP_CIPHER *EVP_des_ede_ofb(void);
const EVP_CIPHER *EVP_des_ede3(void);
const EVP_CIPHER *EVP_des_ede3_cbc(void);
const EVP_CIPHER *EVP_des_ede3_cfb(void);
const EVP_CIPHER *EVP_des_ede3_ofb(void);

//CMS Functions
typedef struct CMS_ContentInfo_st CMS_ContentInfo;
CMS_ContentInfo *CMS_ContentInfo_new();
void *CMS_ContentInfo_free(CMS_ContentInfo *cms);
int i2d_CMS_ContentInfo(CMS_ContentInfo *a, unsigned char **pp);
CMS_ContentInfo *d2i_CMS_ContentInfo(CMS_ContentInfo **a, unsigned char **pp,
                                     long length);
CMS_ContentInfo *PEM_read_bio_CMS(BIO *bp, CMS_ContentInfo **a, pem_password_cb *cb, void *u);

CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey,
                          struct stack_st_X509 *certs, BIO *data,
                          unsigned int flags);
CMS_ContentInfo *CMS_encrypt(struct stack_st_X509 *certs, BIO *in,
                             const EVP_CIPHER *cipher, unsigned int flags);
int CMS_verify(CMS_ContentInfo *cms, struct stack_st_X509 *certs,
               X509_STORE *store, BIO *dcont, BIO *out, unsigned int flags);
int CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pkey, X509 *cert,
                BIO *dcont, BIO *out, unsigned int flags);
]]

function _M.new(opts)
    local cms = {}

    if opts.private_key then
        local rsa, err = PEM.read_RSAPrivateKey(opts.private_key)
        if not rsa then
            return nil, err
        end
        local pkey, err = EVP.PKEY_new(rsa)
        if not pkey then
            return nil, err
        end
        cms.pkey = pkey
    end

    if opts.sign_cert then
        local pcert, err = PEM.read_X509(opts.sign_cert)
        if not pcert then
            return nil, err
        end
        cms.signcert = pcert
    end

    if opts.cert then
        local cert, err = PEM.read_X509(opts.cert)
        if not cert then
            return nil, err
        end
        cms.cert = cert
    end

    if opts.root_cert then
        if type(opts.root_cert) ~= "table" then
            opts.root_cert = { opts.root_cert }
        end
        local rcert = {}
        for _, cert in ipairs(opts.root_cert) do
            local x509, err = PEM.read_X509(cert)
            if not x509 then
                return nil, err
            end
            rcert[#rcert + 1] = x509
        end
        local store, err = X509.STORE_new(rcert)
        if not store then
            return nil, err
        end
        cms.store = store
    end

    if opts.cipher and opts.method then
        local func = "EVP_" .. opts.cipher .. "_" .. opts.method
        if not C[func] then
            return nil, "no cipher on method"
        end
        cms.cipher = C[func]()
    else
        cms.cipher = C.EVP_des_ede3_cbc()
    end

    return setmetatable(cms, mt)
end

function _M.i2d_CMS_ContentInfo(self, cms)
    local str = ffi_new("unsigned char*[1]")
    local str_len = C.i2d_CMS_ContentInfo(cms, str)
    if str_len == 0 then
        return nil, ERR.get_error()
    end

    return ffi_str(str[0], str_len)
end

function _M.d2i_CMS_ContentInfo(self, data)
    local enc_data = ffi_new("unsigned char*[1]")
    enc_data[0] = ffi_cast("unsigned char*", data)
    local cms = C.d2i_CMS_ContentInfo(ffi_null, enc_data, #data)
    if cms == ffi_null then
        return nil, ERR.get_error()
    end
    ffi_gc(cms, C.CMS_ContentInfo_free)

    return cms
end

function _M.PEM_read_CMS(self, data, pass)
    local data_in, err = BIO.new(data)
    if not data_in then
        return nil, err
    end

    local cms = C.PEM_read_bio_CMS(data_in, ffi_null, ffi_null, pass)
    if cms == ffi_null then
        return nil, ERR.get_error()
    end
    ffi_gc(cms, C.CMS_ContentInfo_free)

    return cms
end

function _M.CMS_sign(self, data_in, flags)
    local cms = C.CMS_sign(self.signcert, self.pkey, ffi_null, data_in, flags)
    if cms == ffi_null then
        return nil, ERR.get_error()
    end
    return cms
end

function _M.CMS_encrypt(self, data_in, flags)
    local certs = STACK.X509_new({ self.cert })
    local cms = C.CMS_encrypt(certs, data_in, self.cipher, flags)
    if cms == ffi_null then
        return nil, ERR.get_error()
    end
    return cms
end

function _M.CMS_verify(self, cms, flags)
    local out = BIO.new()
    local certs = STACK.X509_new({ self.cert })
    if C.CMS_verify(cms, certs, self.store, ffi_null, out, flags) == 0 then
        return nil, ERR.get_error()
    end
    return out
end

function _M.CMS_decrypt(self, cms, flags)
    local out = BIO.new()
    if C.CMS_decrypt(cms, self.pkey, self.signcert, ffi_null, out, flags) == 0 then
        return nil, ERR.get_error()
    end
    return out
end

function _M.sign(self, data)
    if not data then
        return nil, "no plain data"
    end

    local data_in, err = BIO.new(data)
    if not data_in then
        return nil, err
    end

    local cms, err = self:CMS_sign(data_in, CMS_NOATTR)
    if not cms then
        return nil, err
    end

    local signed, err = self:i2d_CMS_ContentInfo(cms)
    if not signed then
        return nil, err
    end

    return signed
end

function _M.encrypt(self, data)
    if not data then
        return nil, "no plain data"
    end

    local data_in, err = BIO.new(data)
    if not data_in then
        return nil, err
    end

    local cms, err = self:CMS_encrypt(data_in, 0)
    if not cms then
        return nil, err
    end

    local encryped, err = self:i2d_CMS_ContentInfo(cms)
    if not encryped then
        return nil, err
    end

    return encryped
end

function _M.verify(self, data)
    if not data then
        return nil, "no cihper data"
    end

    local cms, err = self:d2i_CMS_ContentInfo(data)
    if not cms then
        return nil, err
    end

    local out, err = self:CMS_verify(cms, bor(CMS_NO_ATTR_VERIFY, CMS_NO_CONTENT_VERIFY))
    if not out then
        return nil, err
    end

    local verified, err = BIO.read(out)
    if not verified then
        return nil, err
    end

    return verified
end

function _M.decrypt(self, data)
    if not data then
        return nil, "no chiper data"
    end

    local cms, err = self:d2i_CMS_ContentInfo(data)
    if not cms then
        return nil, err
    end

    local out, err = self:CMS_decrypt(cms, CMS_DEBUG_DECRYPT)
    if not out then
        return nil, err
    end

    local decryped, err = BIO.read(out)
    if not decryped then
        return nil, err
    end

    return decryped
end

return _M