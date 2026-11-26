-- Copyright (C) by Yichun Zhang (agentzh)
-- Copyright (C) by Jianhao Dai (Toruneko)

require "resty.crypto.evp"

local ffi = require "ffi"
local C = ffi.C

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
const EVP_CIPHER *EVP_aes_128_ecb(void);
const EVP_CIPHER *EVP_aes_128_cbc(void);
const EVP_CIPHER *EVP_aes_128_cfb1(void);
const EVP_CIPHER *EVP_aes_128_cfb8(void);
const EVP_CIPHER *EVP_aes_128_cfb128(void);
const EVP_CIPHER *EVP_aes_128_ofb(void);
const EVP_CIPHER *EVP_aes_128_ctr(void);
const EVP_CIPHER *EVP_aes_192_ecb(void);
const EVP_CIPHER *EVP_aes_192_cbc(void);
const EVP_CIPHER *EVP_aes_192_cfb1(void);
const EVP_CIPHER *EVP_aes_192_cfb8(void);
const EVP_CIPHER *EVP_aes_192_cfb128(void);
const EVP_CIPHER *EVP_aes_192_ofb(void);
const EVP_CIPHER *EVP_aes_192_ctr(void);
const EVP_CIPHER *EVP_aes_256_ecb(void);
const EVP_CIPHER *EVP_aes_256_cbc(void);
const EVP_CIPHER *EVP_aes_256_cfb1(void);
const EVP_CIPHER *EVP_aes_256_cfb8(void);
const EVP_CIPHER *EVP_aes_256_cfb128(void);
const EVP_CIPHER *EVP_aes_256_ofb(void);
const EVP_CIPHER *EVP_aes_256_ctr(void);
]]

local sizes = { [128] = true, [192] = true, [256] = true }
local modes = { ecb = true, cbc = true, cfb1 = true, cfb8 = true,
                cfb128 = true, ofb = true, ctr = true }

function _M.cipher(_cipher, _size)
    local _size = _size or 128
    local _cipher = _cipher or "cbc"
    if not sizes[_size] or not modes[_cipher] then
        return nil
    end
    local func = "EVP_aes_" .. _size .. "_" .. _cipher
    return { size = _size, cipher = _cipher, method = C[func]() }
end

return _M
