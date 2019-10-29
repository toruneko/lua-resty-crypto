-- Copyright (C) by Jianhao Dai (Toruneko)
local ffi = require "ffi"

local _M = { _VERSION = '0.0.1' }
local mt = { __index = _M }

ffi.cdef[[
int sm2_sign(const unsigned char *dgst, int dgstlen,
             unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);

int sm2_verify(const unsigned char *dgst, int dgstlen,
               const unsigned char *sig, int siglen, EC_KEY *eckey);

int sm2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                        size_t *ct_size);

int sm2_plaintext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                       size_t *pt_size);

int sm2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *msg,
                size_t msg_len,
                uint8_t *ciphertext_buf, size_t *ciphertext_len);

int sm2_decrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len);
]]

local NID_SM2 = 1172

function _M.new(prvkey, pubkey)

end