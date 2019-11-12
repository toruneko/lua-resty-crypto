-- Copyright (C) by Jianhao Dai (Toruneko)

require "resty.crypto.evp"

local ffi = require "ffi"
local C = ffi.C

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
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
]]

function _M.cipher(_cipher)
    local _cipher = _cipher or "cbc"
    local func = "EVP_des_" .. _cipher
    if C[func] then
        return { size = 128, cipher = _cipher, method = C[func]() }
    else
        return nil
    end
end

return _M
