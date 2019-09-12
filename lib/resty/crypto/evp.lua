-- Copyright (C) by Jianhao Dai (Toruneko)

local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
//	EVP digest routines
typedef struct engine_st ENGINE;
typedef struct asn1_type_st ASN1_TYPE;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st {
    int nid;
    int block_size;
    int key_len;
    int iv_len;
    unsigned long flags;
    int (*init) (EVP_CIPHER_CTX *ctx, const unsigned char *key,
                 const unsigned char *iv, int enc);
    int (*do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
    int (*cleanup) (EVP_CIPHER_CTX *);
    int ctx_size;
    int (*set_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    int (*get_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    int (*ctrl) (EVP_CIPHER_CTX *, int type, int arg, void *ptr);
    void *app_data;
} EVP_CIPHER;

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new();
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a);

//	EVP digest routines
typedef struct env_md_st EVP_MD;
typedef struct env_md_ctx_st EVP_MD_CTX;

const EVP_MD *EVP_get_digestbyname(const char *name);

/* EVP_MD_CTX methods for OpenSSL < 1.1.0 */
EVP_MD_CTX *EVP_MD_CTX_create(void);
void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);

/* EVP_MD_CTX methods for OpenSSL >= 1.1.0 */
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

//  private key allocation functions
typedef struct evp_pkey_st EVP_PKEY;
EVP_PKEY *EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *key);
int EVP_PKEY_size(EVP_PKEY *pkey);
typedef struct rsa_st RSA;
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key);

//  public key algorithm context functions
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2);
]]


local evp_md_ctx_new
local evp_md_ctx_free
if not pcall(function () return C.EVP_MD_CTX_create end) then
    evp_md_ctx_new = C.EVP_MD_CTX_new
    evp_md_ctx_free = C.EVP_MD_CTX_free
else
    evp_md_ctx_new = C.EVP_MD_CTX_create
    evp_md_ctx_free = C.EVP_MD_CTX_destroy
end

function _M.CIPHER_CTX_new()
    local cipher_ctx = C.EVP_CIPHER_CTX_new()
    if cipher_ctx == nil then
        return nil, "no memory"
    end

    ffi_gc(cipher_ctx, C.EVP_CIPHER_CTX_free)

    return cipher_ctx
end

function _M.MD_CTX_new()
    local md_ctx = evp_md_ctx_new()
    ffi_gc(md_ctx, evp_md_ctx_free)
    return md_ctx
end

function _M.get_digestbyname(algorithm)
    return C.EVP_get_digestbyname(algorithm)
end

function _M.PKEY_new(rsa)
    local pkey = C.EVP_PKEY_new()
    ffi_gc(pkey, C.EVP_PKEY_free)
    if rsa then
        if C.EVP_PKEY_set1_RSA(pkey, rsa) == 0 then
            return nil, ERR.get_error()
        end
    end
    return pkey
end

function _M.PKEY_size(pkey)
    return C.EVP_PKEY_size(pkey)
end

function _M.PKEY_CTX_new(pkey)
    local ctx = C.EVP_PKEY_CTX_new(pkey, nil)
    if not ctx then
        return nil, ERR.get_error()
    end
    ffi_gc(ctx, C.EVP_PKEY_CTX_free)
    return ctx
end

return _M