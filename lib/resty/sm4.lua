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
local ffi_null = ffi.null
local ffi_copy = ffi.copy
local ffi_sizeof = ffi.sizeof
local C = ffi.C
local tonumber = tonumber
local setmetatable = setmetatable

local _M = { _VERSION = '0.0.3' }
local mt = { __index = _M }

local BLOCK_SIZE = 16
local EVP_MAXCHUNK = lshift(1, (64 * 8 - 2))

ffi.cdef [[
typedef struct SM4_KEY_st {
    uint32_t rk[32];
} SM4_KEY;

typedef struct {
    SM4_KEY ks;
} EVP_SM4_KEY;

typedef void (*block128_f) (const unsigned char in[16],
                            unsigned char out[16], const void *key);

const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx);
unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx);
unsigned char *EVP_CIPHER_CTX_buf_noconst(EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_num(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num);

void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], block128_f block);
void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], block128_f block);

void CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], int *num,
                           int enc, block128_f block);

void CRYPTO_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16], int *num,
                           block128_f block);

void CRYPTO_ctr128_encrypt(const unsigned char *in, unsigned char *out,
                           size_t len, const void *key,
                           unsigned char ivec[16],
                           unsigned char ecount_buf[16], unsigned int *num,
                           block128_f block);

// openssl 1.1.1
const EVP_CIPHER *EVP_sm4_cbc(void);
const EVP_CIPHER *EVP_sm4_ecb(void);
const EVP_CIPHER *EVP_sm4_cfb128(void);
const EVP_CIPHER *EVP_sm4_ofb(void);
const EVP_CIPHER *EVP_sm4_ctr(void);
]]

local unsigned_char_ptr = ffi.typeof("unsigned char[?]")
local uint32_t_ptr = ffi.typeof("uint32_t[?]")
local int_ptr = ffi.typeof("int[?]")
local EVP_SM4_KEY_ptr = ffi.typeof("EVP_SM4_KEY*")
local SM4_KEY_ptr = ffi.typeof("SM4_KEY*")
local block128_f = ffi.typeof("block128_f")

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
local FK = ffi_new("const uint32_t[4]", { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC })

-- 固定参数 CK
local CK = ffi_new("const uint32_t[32]", {
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
local Sbox = ffi_new("const uint32_t[256]", {
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
    return bor(lshift(Sbox[rshift(a, 24)], 24),
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
    local K = ffi_new(uint32_t_ptr, 4)
    K[0] = bxor(get32(key, 0), FK[0])
    K[1] = bxor(get32(key, 4), FK[1])
    K[2] = bxor(get32(key, 8), FK[2])
    K[3] = bxor(get32(key, 12), FK[3])

    local rk = ffi_new(uint32_t_ptr, 32)
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
    local X = ffi_new(uint32_t_ptr, 4)
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

local function sm4_encrypt(_in, _out, key)
    local sms4key = ffi_cast(SM4_KEY_ptr, key)
    SMS4_Update_block(sms4key.rk, _in, _out, true)
end

local function sm4_decrypt(_in, _out, key)
    local sms4key = ffi_cast(SM4_KEY_ptr, key)
    SMS4_Update_block(sms4key.rk, _in, _out, false)
end

local function sm4_init_key(ctx, key, iv, enc)
    local cipher_data = C.EVP_CIPHER_CTX_get_cipher_data(ctx)
    local ks = ffi_cast(EVP_SM4_KEY_ptr, cipher_data)
    local rk = SMS4_Init(key)
    ffi_copy(ks.ks.rk, rk, ffi_sizeof(rk))
    return 1
end

local function sm4_ecb_encrypt(_in, _out, key, enc)
    if enc == 1 then
        sm4_encrypt(_in, _out, key)
    else
        sm4_decrypt(_in, _out, key)
    end
end

local function sm4_cbc_encrypt(_in, _out, len, key, ivec, enc)
    if enc == 1 then
        C.CRYPTO_cbc128_encrypt(_in, _out, len, key, ivec, ffi_cast(block128_f, sm4_encrypt))
    else
        C.CRYPTO_cbc128_decrypt(_in, _out, len, key, ivec, ffi_cast(block128_f, sm4_decrypt))
    end
end

local function sm4_cfb128_encrypt(_in, _out, len, key, ivec, num, enc)
    C.CRYPTO_cfb128_encrypt(_in, _out, len, key, ivec, num, enc, ffi_cast(block128_f, sm4_encrypt))
end

local function sm4_ofb128_encrypt(_in, _out, len, key, ivec, num)
    C.CRYPTO_ofb128_encrypt(_in, _out, len, key, ivec, num, ffi_cast(block128_f, sm4_encrypt))
end

local function sm4_ecb_cipher(ctx, _out, _in, inl)
    local cipher = C.EVP_CIPHER_CTX_cipher(ctx)
    local cipher_data = C.EVP_CIPHER_CTX_get_cipher_data(ctx)
    local dat = ffi_cast(EVP_SM4_KEY_ptr, cipher_data)
    local bl = cipher.block_size
    if (inl < bl) then
        return 1
    end
    inl = tonumber(inl - bl);
    for i = 0, inl, bl do
        sm4_ecb_encrypt(_in + i, _out + i, dat.ks, C.EVP_CIPHER_CTX_encrypting(ctx))
    end

    return 1
end

local function sm4_cbc_cipher(ctx, _out, _in, inl)
    local cipher_data = C.EVP_CIPHER_CTX_get_cipher_data(ctx)
    local dat = ffi_cast(EVP_SM4_KEY_ptr, cipher_data)

    while inl >= EVP_MAXCHUNK do
        sm4_cbc_encrypt(_in, _out, EVP_MAXCHUNK, dat.ks,
            C.EVP_CIPHER_CTX_iv_noconst(ctx), C.EVP_CIPHER_CTX_encrypting(ctx))
        inl = inl - EVP_MAXCHUNK
        _in = _in + EVP_MAXCHUNK
        _out = _out + EVP_MAXCHUNK
    end
    if inl > 0 then
        sm4_cbc_encrypt(_in, _out, inl, dat.ks,
            C.EVP_CIPHER_CTX_iv_noconst(ctx), C.EVP_CIPHER_CTX_encrypting(ctx))
    end
    return 1
end

local function sm4_cfb128_cipher(ctx, _out, _in, inl)
    local cipher_data = C.EVP_CIPHER_CTX_get_cipher_data(ctx)
    local dat = ffi_cast(EVP_SM4_KEY_ptr, cipher_data)

    local chunk = EVP_MAXCHUNK
    if inl < chunk then
        chunk = inl
    end
    while inl > 0 and inl >= chunk do
        local num = ffi_new(int_ptr, 1, { C.EVP_CIPHER_CTX_num(ctx) })
        sm4_cfb128_encrypt(_in, _out, chunk, dat.ks,
            C.EVP_CIPHER_CTX_iv_noconst(ctx), num, C.EVP_CIPHER_CTX_encrypting(ctx))
        C.EVP_CIPHER_CTX_set_num(ctx, num[0])
        inl = inl - chunk
        _in = _in + chunk
        _out = _out + chunk
        if inl < chunk then
            chunk = inl
        end
    end
    return 1
end

local function sm4_ofb128_cipher(ctx, _out, _in, inl)
    local cipher_data = C.EVP_CIPHER_CTX_get_cipher_data(ctx)
    local dat = ffi_cast(EVP_SM4_KEY_ptr, cipher_data)

    while inl >= EVP_MAXCHUNK do
        local num = ffi_new(int_ptr, 1, { C.EVP_CIPHER_CTX_num(ctx) })
        sm4_ofb128_encrypt(_in, _out, EVP_MAXCHUNK, dat.ks, C.EVP_CIPHER_CTX_iv_noconst(ctx), num)
        C.EVP_CIPHER_CTX_set_num(ctx, num[0])
        inl = inl - EVP_MAXCHUNK
        _in = _in + EVP_MAXCHUNK
        _out = _out + EVP_MAXCHUNK
    end
    if inl > 0 then
        local num = ffi_new(int_ptr, 1, { C.EVP_CIPHER_CTX_num(ctx) })
        sm4_ofb128_encrypt(_in, _out, inl, dat.ks, C.EVP_CIPHER_CTX_iv_noconst(ctx), num)
        C.EVP_CIPHER_CTX_set_num(ctx, num[0])
    end
    return 1
end

local function sm4_ctr_cipher(ctx, _out, _in, inl)
    local cipher_data = C.EVP_CIPHER_CTX_get_cipher_data(ctx)
    local dat = ffi_cast(EVP_SM4_KEY_ptr, cipher_data)

    local num = ffi_new(int_ptr, 1, { C.EVP_CIPHER_CTX_num(ctx) })

    C.CRYPTO_ctr128_encrypt(_in, _out, inl, dat.ks,
        C.EVP_CIPHER_CTX_iv_noconst(ctx),
        C.EVP_CIPHER_CTX_buf_noconst(ctx), num,
        ffi_cast(block128_f, sm4_encrypt))

    C.EVP_CIPHER_CTX_set_num(ctx, num[0])

    return 1
end

local function defs_cipher(nid, block_size, key_len, iv_len, flags, do_cipher)
    local cipher = ffi_new("EVP_CIPHER[?]", 1)
    cipher[0].nid = nid
    cipher[0].block_size = block_size
    cipher[0].key_len = key_len
    cipher[0].iv_len = iv_len
    cipher[0].flags = flags
    cipher[0].init = sm4_init_key
    cipher[0].do_cipher = do_cipher
    cipher[0].cleanup = ffi_null
    cipher[0].ctx_size = ffi_sizeof("EVP_SM4_KEY")
    cipher[0].set_asn1_parameters = ffi_null
    cipher[0].get_asn1_parameters = ffi_null
    cipher[0].ctrl = ffi_null
    cipher[0].app_data = ffi_null
    return cipher
end

-- openssl 1.1.1
local support = pcall(function() C.EVP_sm4_ecb() end)
local ciphers = {
    ecb = support and C.EVP_sm4_ecb() or defs_cipher(1133, 16, 16, 16, 0x1, sm4_ecb_cipher),
    cbc = support and C.EVP_sm4_cbc() or defs_cipher(1134, 16, 16, 16, 0x2, sm4_cbc_cipher),
    ofb = support and C.EVP_sm4_ofb() or defs_cipher(1135, 16, 16, 16, 0x4, sm4_ofb128_cipher),
    cfb = support and C.EVP_sm4_cfb128() or defs_cipher(1137, 16, 16, 16, 0x3, sm4_cfb128_cipher),
    ctr = support and C.EVP_sm4_ctr() or defs_cipher(1139, 1, 16, 16, 0x5, sm4_ctr_cipher)
}

function _M.cipher(_cipher)
    local _cipher = _cipher or "ecb"
    if ciphers[_cipher] then
        return { size = 128, cipher = _cipher, method = ciphers[_cipher] }
    else
        return nil
    end
end

function _M.new(self, key)
    local rk = SMS4_Init(ffi_new(unsigned_char_ptr, BLOCK_SIZE, key))
    return setmetatable({ rk = rk }, mt)
end

function _M.encrypt(self, block)
    local _in = ffi_new(unsigned_char_ptr, BLOCK_SIZE, block)
    local _out = ffi_new(unsigned_char_ptr, BLOCK_SIZE)

    SMS4_Update_block(self.rk, _in, _out, true)

    return ffi_str(_out)
end

function _M.decrypt(self, block)
    local _in = ffi_new(unsigned_char_ptr, BLOCK_SIZE, block)
    local _out = ffi_new(unsigned_char_ptr, BLOCK_SIZE)

    SMS4_Update_block(self.rk, _in, _out, false)

    return ffi_str(_out)
end

return _M