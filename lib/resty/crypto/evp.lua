-- Copyright (C) by Jianhao Dai (Toruneko)

local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local ffi_null = ffi.null

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

//  private key allocation functions
typedef struct evp_pkey_st EVP_PKEY;
EVP_PKEY *EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *key);
int EVP_PKEY_size(EVP_PKEY *pkey);

//  public key algorithm context functions
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2);

//	EVP digest routines
typedef struct env_md_st EVP_MD;
typedef struct env_md_ctx_st EVP_MD_CTX;
const EVP_MD *EVP_get_digestbyname(const char *name);
const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx);
int EVP_MD_size(const EVP_MD *md);

/* EVP_MD_CTX methods for OpenSSL < 1.1.0 */
EVP_MD_CTX *EVP_MD_CTX_create(void);
void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);

/* EVP_MD_CTX methods for OpenSSL >= 1.1.0 */
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

void EVP_MD_CTX_set_pkey_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx);

// PKEY encrypt
int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
        unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen);

//PKEY decrypt
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
                     unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen);

// Digest Sign & Verify
// openssl 1.1.0
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const unsigned char *in, int inl);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int EVP_SignFinal(EVP_MD_CTX *ctx,unsigned char *sig,unsigned int *s,
                  EVP_PKEY *pkey);
int EVP_VerifyFinal(EVP_MD_CTX *ctx,unsigned char *sigbuf, unsigned int siglen,
                    EVP_PKEY *pkey);

// openssl 1.1.1
int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                    const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret,
                size_t *siglen, const unsigned char *tbs,
                size_t tbslen);
int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                      const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
                  size_t siglen, const unsigned char *tbs, size_t tbslen);
]]

local unsigned_char_ptr = ffi.typeof("unsigned char[?]")
local unsigned_int_ptr = ffi.typeof("unsigned int[?]")
local size_t_ptr = ffi.typeof("size_t[?]")

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
        return nil, ERR.get_error()
    end
    ffi_gc(cipher_ctx, C.EVP_CIPHER_CTX_free)

    return cipher_ctx
end

function _M.MD_CTX_new(pkey_ctx)
    local md_ctx = evp_md_ctx_new()
    if md_ctx == ffi_null then
        return nil, ERR.get_error()
    end
    ffi_gc(md_ctx, evp_md_ctx_free)
    if pkey_ctx then
        -- openssl 1.1.1
        C.EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx)
    end
    return md_ctx
end

function _M.get_digestbyname(algorithm)
    local md = C.EVP_get_digestbyname(algorithm)
    if md == ffi_null then
        return nil
    end
    return md
end

function _M.PKEY_new()
    local pkey = C.EVP_PKEY_new()
    if pkey == ffi_null then
        return nil, ERR.get_error()
    end
    ffi_gc(pkey, C.EVP_PKEY_free)
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

function _M.PKEY_CTX_ctrl(ctx, keytype, optype, cmd, p1, p2)
    if C.EVP_PKEY_CTX_ctrl(ctx, keytype, optype, cmd, p1, p2) <= 0 then
        return false, ERR.get_error()
    end
    return true
end

function _M.PKEY_encrypt_init(ctx)
    if C.EVP_PKEY_encrypt_init(ctx) <= 0 then
        return false, ERR.get_error()
    end
    return true
end

function _M.PKEY_encrypt(ctx, str)
    local len = ffi_new(size_t_ptr, 1)
    local ret = C.EVP_PKEY_encrypt(ctx, nil, len, str, #str)
    if ret <= 0 then
        return nil, ERR.get_error()
    end

    local buf = ffi_new(unsigned_char_ptr, len[0])
    if C.EVP_PKEY_encrypt(ctx, buf, len, str, #str) <= 0 then
        return nil, ERR.get_error()
    end

    return ffi_str(buf, len[0])
end

function _M.PKEY_decrypt_init(ctx)
    if C.EVP_PKEY_decrypt_init(ctx) <= 0 then
        return false, ERR.get_error()
    end
    return true
end

function _M.PKEY_decrypt(ctx, str)
    local len = ffi_new(size_t_ptr, 1)
    if C.EVP_PKEY_decrypt(ctx, nil, len, str, #str) <= 0 then
        return nil, ERR.get_error()
    end

    local buf = ffi_new(unsigned_char_ptr, len[0])
    if C.EVP_PKEY_decrypt(ctx, buf, len, str, #str) <= 0 then
        return nil, ERR.get_error()
    end

    return ffi_str(buf, len[0])
end

function _M.DigestInit(md_ctx, md)
    if C.EVP_DigestInit_ex(md_ctx, md, ffi_null) <= 0 then
        return false, ERR.get_error()
    end
    return true
end

function _M.DigestUpdate(md_ctx, str)
    if C.EVP_DigestUpdate(md_ctx, str, #str) <= 0 then
        return false, ERR.get_error()
    end
    return true
end

function _M.DigestFinal(md_ctx)
    local md = C.EVP_MD_CTX_md(md_ctx)
    local size = C.EVP_MD_size(md)
    local buf = ffi_new(unsigned_char_ptr, size)
    local len = ffi_new(unsigned_int_ptr, 1)
    if C.EVP_DigestFinal_ex(md_ctx, buf, len) <= 0 then
        return nil, ERR.get_error()
    end

    return ffi_str(buf, len[0])
end

function _M.SignFinal(md_ctx, pkey)
    local size = C.EVP_PKEY_size(pkey)
    local buf = ffi_new(unsigned_char_ptr, size)
    local len = ffi_new(unsigned_int_ptr, 1)
    if C.EVP_SignFinal(md_ctx, buf, len, pkey) <= 0 then
        return nil, ERR.get_error()
    end

    return ffi_str(buf, len[0])
end

function _M.VerifyFinal(md_ctx, pkey, sig)
    local siglen = #sig
    local size = C.EVP_PKEY_size(pkey)
    local buf = siglen <= size and ffi_new(unsigned_char_ptr, size)
            or ffi_new(unsigned_char_ptr, siglen)
    ffi_copy(buf, sig, siglen)
    if C.EVP_VerifyFinal(md_ctx, buf, siglen, pkey) <= 0 then
        return false, ERR.get_error()
    end

    return true
end

function _M.DigestSignInit(md_ctx, md, pkey)
    if C.EVP_DigestSignInit(md_ctx, ffi_null, md, ffi_null, pkey) <= 0 then
        return false, ERR.get_error()
    end
    return true
end

function _M.DigestSign(md_ctx, str)
    local siglen = ffi_new(size_t_ptr, 1)
    if C.EVP_DigestSign(md_ctx, ffi_null, siglen, ffi_null, 0) <= 0 then
        return nil, ERR.get_error()
    end

    local sigret = ffi_new(unsigned_char_ptr, siglen[0])
    if C.EVP_DigestSign(md_ctx, sigret, siglen, str, #str) <= 0 then
        return nil, ERR.get_error()
    end
    return ffi_str(sigret, siglen[0])
end

function _M.DigestVerifyInit(md_ctx, md, pkey)
    if C.EVP_DigestVerifyInit(md_ctx, ffi_null, md, ffi_null, pkey) <= 0 then
        return false, ERR.get_error()
    end
    return true
end

function _M.DigestVerify(md_ctx, str, sig)
    if C.EVP_DigestVerify(md_ctx, sig, #sig, str, #str) <= 0 then
        return false, ERR.get_error()
    end
    return true
end

return _M