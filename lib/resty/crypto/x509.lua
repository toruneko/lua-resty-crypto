-- Copyright (C) by Jianhao Dai (Toruneko)

local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local ffi_gc = ffi.gc
local ffi_null = ffi.null
local C = ffi.C
local type = type
local ipairs = ipairs

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
typedef struct x509_st X509;
typedef struct x509_store_st X509_STORE;

X509 *X509_new(void);
void X509_free(X509 *x509);

X509_STORE *X509_STORE_new(void);
void X509_STORE_free(X509_STORE *v);
int X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
]]

local function X509_free(x509)
    ffi_gc(x509, C.X509_free)
end

local function X509_new()
    local x509 = C.X509_new()
    if x509 == ffi_null then
        return nil, ERR.get_error()
    end
    X509_free(x509)
    return x509
end

function _M.new()
    return X509_new()
end

function _M.free(x509)
    X509_free(x509)
end

function _M.STORE_new(cert)
    if not cert then
        return nil, "no cert"
    end

    local ctx = C.X509_STORE_new()
    if ctx == ffi_null then
        return nil, ERR.get_error()
    end
    ffi_gc(ctx, C.X509_STORE_free)

    if type(cert) ~= "table" then
        cert = { cert }
    end
    for _, x509 in ipairs(cert) do
        if C.X509_STORE_add_cert(ctx, x509) == 0 then
            return nil, ERR.get_error()
        end
    end

    return ctx
end

return _M