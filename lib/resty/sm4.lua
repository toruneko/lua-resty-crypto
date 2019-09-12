-- Copyright (C) by Jianhao Dai (Toruneko)

require "resty.crypto.evp"

local bit = require "bit"
local ffi = require "ffi"
local bor = bit.bor
local band = bit.band
local bxor = bit.bxor
local lshift = bit.lshift
local rshift = bit.rshift
local ffi_new = ffi.new
local ffi_cast = ffi.cast
local ffi_str = ffi.string
local ffi_copy = ffi.copy
local ffi_null = ffi.null
local C = ffi.C
local tonumber = tonumber
local setmetatable = setmetatable

local _M = { _VERSION = '0.0.1' }
local mt = { __index = _M }

local EVP_CIPHER_CTX_FLAG_WRAP_ALLOW = 0x1
local EVP_CIPH_WRAP_MODE = 0x10002
local EVP_CIPH_CUSTOM_IV = 0x10
local EVP_CIPH_FLAG_CUSTOM_CIPHER = 0x100000
local EVP_CIPH_ALWAYS_CALL_INIT = 0x20
local EVP_CIPH_CTRL_INIT = 0x40
local EVP_CIPH_FLAG_DEFAULT_ASN1 = 0x1000
local SMS4_WRAP_FLAGS = bor(EVP_CIPH_WRAP_MODE, EVP_CIPH_CTRL_INIT,
    EVP_CIPH_CUSTOM_IV, EVP_CIPH_FLAG_CUSTOM_CIPHER,
    EVP_CIPH_ALWAYS_CALL_INIT, EVP_CIPH_FLAG_DEFAULT_ASN1)

ffi.cdef [[
typedef struct {
	uint32_t rk[32];
} sms4_key_t;

typedef struct {
    union {
        double align;
        sms4_key_t ks;
    } ks;
    /* Indicates if IV has been set */
    unsigned char *iv;
} EVP_SMS4_WRAP_CTX;

typedef void (*block128_f) (const unsigned char in[16],
                            unsigned char out[16], const void *key);

void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags);
void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx);
unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx);
size_t CRYPTO_128_wrap_pad(void *key, const unsigned char *icv,
                           unsigned char *out, const unsigned char *in,
                           size_t inlen, block128_f block);
size_t CRYPTO_128_unwrap_pad(void *key, const unsigned char *icv,
                             unsigned char *out, const unsigned char *in,
                             size_t inlen, block128_f block);
size_t CRYPTO_128_wrap(void *key, const unsigned char *icv,
                       unsigned char *out, const unsigned char *in,
                       size_t inlen, block128_f block);
size_t CRYPTO_128_unwrap(void *key, const unsigned char *icv,
                         unsigned char *out, const unsigned char *in,
                         size_t inlen, block128_f block);
]]

local function get32(pc, n)
    return bor(lshift(pc[n], 24), lshift(pc[n + 1], 16), lshift(pc[n + 2], 8), pc[n + 3])
end

local function put32(st, ct, n)
    ct[n] = band(rshift(st, 24), 0xFF)
    ct[n + 1] = band(rshift(st, 16), 0xFF)
    ct[n + 2] = band(rshift(st, 8), 0xFF)
    ct[n + 3] = band(st, 0xFF)
end

-- S(x,n): 32比特循环左移n比特运算
local function S(x, n)
    return bor(lshift(x, n), rshift(x, 32 - n))
end

-- 系统参数 FK
local FK = ffi.new("uint32_t[4]", { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC })

-- 固定参数 CK
local CK = ffi.new("uint32_t[32]", {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
})

-- Sbox
local Sbox = ffi.new("uint32_t[256]", {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
})

-- 非线性变换τ
local function P(a)
    return bxor(lshift(Sbox[rshift(a, 24)], 24),
        lshift(Sbox[band(rshift(a, 16), 0xFF)], 16),
        lshift(Sbox[band(rshift(a, 8), 0xFF)], 8),
        Sbox[band(a, 0xFF)])
end

-- 线性变换 𝐿
local function L(b)
    return bxor(b, S(b, 2), S(b, 10), S(b, 18), S(b, 24))
end

-- 合成置换 T
local function T(a)
    return L(P(a))
end

-- 轮函数 F
local function F(x0, x1, x2, x3, rk)
    return bxor(x0, T(bxor(x1, x2, x3, rk)))
end

-- 线性变换 𝐿′
local function L1(b)
    return bxor(b, S(b, 13), S(b, 23))
end

-- 密钥扩展算法 T′
local function T1(a)
    return L1(P(a))
end

-- 密钥扩展算法 F′
local function F1(x0, x1, x2, x3, rk)
    return bxor(x0, T1(bxor(x1, x2, x3, rk)))
end

local function SMS4_Init(key)
    local K = ffi_new("uint32_t[4]")
    K[0] = bxor(get32(key, 0), FK[0])
    K[1] = bxor(get32(key, 4), FK[1])
    K[2] = bxor(get32(key, 8), FK[2])
    K[3] = bxor(get32(key, 12), FK[3])

    local rk = ffi_new("uint32_t[32]")
    for i = 0, 8 - 1, 1 do
        local j = 4 * i
        K[0] = F1(K[0], K[1], K[2], K[3], CK[j])
        K[1] = F1(K[1], K[2], K[3], K[0], CK[j + 1])
        K[2] = F1(K[2], K[3], K[0], K[1], CK[j + 2])
        K[3] = F1(K[3], K[0], K[1], K[2], CK[j + 3])

        rk[j], rk[j + 1], rk[j + 2], rk[j + 3] = K[0], K[1], K[2], K[3]
    end

    return rk
end

local function SMS4_Update_block(rk, _in, _out, enc)
    local X = ffi_new("uint32_t[4]")
    X[0] = get32(_in, 0)
    X[1] = get32(_in, 4)
    X[2] = get32(_in, 8)
    X[3] = get32(_in, 12)

    for i = 0, 8 - 1, 1 do
        local j = 4 * i
        X[0] = F(X[0], X[1], X[2], X[3], rk[enc and j + 0 or 31 - j])
        X[1] = F(X[1], X[2], X[3], X[0], rk[enc and j + 1 or 30 - j])
        X[2] = F(X[2], X[3], X[0], X[1], rk[enc and j + 2 or 29 - j])
        X[3] = F(X[3], X[0], X[1], X[2], rk[enc and j + 3 or 28 - j])
    end
    X[0], X[1], X[2], X[3] = X[3], X[2], X[1], X[0]

    put32(X[0], _out, 0)
    put32(X[1], _out, 4)
    put32(X[2], _out, 8)
    put32(X[3], _out, 12)
end

local function sms4_encrypt(_in, _out, key)
    local sms4key = ffi_cast("sms4_key_t*", key)
    SMS4_Update_block(sms4key.rk, _in, _out, true)
end

local function sms4_decrypt(_in, _out, key)
    local sms4key = ffi_cast("sms4_key_t*", key)
    SMS4_Update_block(sms4key.rk, _in, _out, false)
end

local function sms4_wrap_init_key(ctx, key, iv, enc)
    local cipher_data = C.EVP_CIPHER_CTX_get_cipher_data(ctx)
    local wctx = ffi_cast("EVP_SMS4_WRAP_CTX*", cipher_data)
    if iv == ffi_null and key == ffi_null then
        return 1
    end

    if key ~= ffi_null then
        wctx.ks.ks.rk = SMS4_Init(key)
        if iv == ffi_null then
            wctx.iv = ffi_null
        end
    end

    if iv ~= ffi_null then
        ffi_copy(C.EVP_CIPHER_CTX_iv_noconst(ctx), iv, C.EVP_CIPHER_CTX_iv_length(ctx))
        wctx.iv = C.EVP_CIPHER_CTX_iv_noconst(ctx)
    end

    return 1
end

local function sms4_wrap_cipher(ctx, _out, _in, inlen)
    local cipher_data = C.EVP_CIPHER_CTX_get_cipher_data(ctx)
    local wctx = ffi_cast("EVP_SMS4_WRAP_CTX*", cipher_data)

    -- SMS4 wrap with padding has IV length of 4, without padding 8
    local pad = C.EVP_CIPHER_CTX_iv_length(ctx) == 4

    -- No final operation so always return zero length
    if _in == ffi_null then
        return 0
    end
    -- Input length must always be non-zero
    if tonumber(inlen) == 0 then
        return -1
    end
    -- If decrypting need at least 16 bytes and multiple of 8
    if C.EVP_CIPHER_CTX_encrypting(ctx) == 0 and (tonumber(inlen) < 16 or band(tonumber(inlen), 0x7) ~= 0) then
        return -1
    end

    -- If not padding input must be multiple of 8
    if not pad and band(tonumber(inlen), 0x7) ~= 0 then
        return -1
    end

    if _out == ffi_null then
        if C.EVP_CIPHER_CTX_encrypting(ctx) == 1 then
            -- If padding round up to multiple of 8
            if pad then
                inlen = (tonumber(inlen) + 7) / 8 * 8;
            end
            --  8 byte prefix
            return inlen + 8
        else
            -- If not padding output will be exactly 8 bytes smaller than
            -- input. If padding it will be at least 8 bytes smaller but we
            -- don't know how much.
            return inlen - 8
        end
    end

    local rv = 0
    local ks = ffi_new("sms4_key_t[1]", { wctx.ks.ks })
    if pad then
        if C.EVP_CIPHER_CTX_encrypting(ctx) == 1 then
            rv = C.CRYPTO_128_wrap_pad(ks, wctx.iv, _out, _in, inlen, ffi_cast("block128_f", sms4_encrypt))
        else
            rv = C.CRYPTO_128_unwrap_pad(ks, wctx.iv, _out, _in, inlen, ffi_cast("block128_f", sms4_decrypt))
        end
    else
        if C.EVP_CIPHER_CTX_encrypting(ctx) == 1 then
            rv = C.CRYPTO_128_wrap(ks, wctx.iv, _out, _in, inlen, ffi_cast("block128_f", sms4_encrypt))
        else
            rv = C.CRYPTO_128_unwrap(ks, wctx.iv, _out, _in, inlen, ffi_cast("block128_f", sms4_decrypt))
        end
    end

    return tonumber(rv) ~= 0 and tonumber(rv) or -1;
end

local function sms4_ctrl(ctx, type, arg, ptr)
    C.EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW)
    return 1
end

function _M.cipher(_cipher, _size)
    local cipher = ffi_new("EVP_CIPHER[1]")
    cipher[0].nid = 1161
    cipher[0].block_size = 8
    cipher[0].key_len = 16
    cipher[0].iv_len = 4
    cipher[0].flags = SMS4_WRAP_FLAGS
    cipher[0].init = sms4_wrap_init_key
    cipher[0].do_cipher = sms4_wrap_cipher
    cipher[0].cleanup = ffi_null
    cipher[0].ctx_size = ffi.sizeof("EVP_SMS4_WRAP_CTX")
    cipher[0].set_asn1_parameters = ffi_null
    cipher[0].get_asn1_parameters = ffi_null
    cipher[0].ctrl = sms4_ctrl
    cipher[0].app_data = ffi_null

    local _cipher = _cipher or "cbc"
    return { size = 128, cipher = _cipher, method = cipher }
end

function _M.new(self, key)
    local rk = SMS4_Init(ffi_new("const unsigned char[16]", key))
    return setmetatable({ rk = rk }, mt)
end

function _M.encrypt(self, block)
    local _in = ffi_new("const unsigned char[16]", block)
    local _out = ffi_new("unsigned char[16]")

    SMS4_Update_block(self.rk, _in, _out, true)

    return ffi_str(_out)
end

function _M.decrypt(self, block)
    local _in = ffi_new("const unsigned char[16]", block)
    local _out = ffi_new("unsigned char[16]")

    SMS4_Update_block(self.rk, _in, _out, false)

    return ffi_str(_out)
end

return _M