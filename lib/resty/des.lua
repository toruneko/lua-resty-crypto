-- Copyright (C) by Jianhao Dai (Toruneko)

require "resty.crypto.evp"

local ffi = require "ffi"
local C = ffi.C

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
const EVP_CIPHER *EVP_des_cbc(void);
const EVP_CIPHER *EVP_des_cfb64(void);
const EVP_CIPHER *EVP_des_ecb(void);
const EVP_CIPHER *EVP_des_ofb(void);
const EVP_CIPHER *EVP_des_ede(void);
const EVP_CIPHER *EVP_des_ede_cbc(void);
const EVP_CIPHER *EVP_des_ede_cfb64(void);
const EVP_CIPHER *EVP_des_ede_ofb(void);
const EVP_CIPHER *EVP_des_ede3(void);
const EVP_CIPHER *EVP_des_ede3_cbc(void);
const EVP_CIPHER *EVP_des_ede3_cfb64(void);
const EVP_CIPHER *EVP_des_ede3_ofb(void);
]]

local modes = {
    cbc = "cbc", cfb = "cfb64", ecb = "ecb", ofb = "ofb",
    ede = "ede", ede_cbc = "ede_cbc", ede_cfb = "ede_cfb64", ede_ofb = "ede_ofb",
    ede3 = "ede3", ede3_cbc = "ede3_cbc", ede3_cfb = "ede3_cfb64", ede3_ofb = "ede3_ofb",
}

function _M.cipher(_cipher)
    local _cipher = _cipher or "cbc"
    local mode = modes[_cipher]
    if not mode then
        return nil
    end
    local size = _cipher:sub(1, 4) == "ede3" and 192
            or _cipher:sub(1, 3) == "ede" and 128 or 64
    return { size = size, cipher = _cipher, method = C["EVP_des_" .. mode]() }
end

return _M
