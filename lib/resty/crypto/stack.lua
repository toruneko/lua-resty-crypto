-- Copyright (C) by Jianhao Dai (Toruneko)

local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local ffi_cast = ffi.cast
local ffi_gc = ffi.gc
local ffi_null = ffi.null
local C = ffi.C
local ipairs = ipairs

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
typedef struct stack_st OPENSSL_STACK;

OPENSSL_STACK *OPENSSL_sk_new_null(void);
void OPENSSL_sk_free(OPENSSL_STACK *st);
int OPENSSL_sk_push(OPENSSL_STACK *st, void *data);
]]

local function sk_new(type, items)
    if not items and type(items) ~= "table" then
        return nil
    end

    local stack = C.OPENSSL_sk_new_null()
    if stack == ffi_null then
        return nil, ERR.get_error()
    end
    ffi_gc(stack, C.OPENSSL_sk_free)

    for _, item in ipairs(items) do
        C.OPENSSL_sk_push(stack, item)
    end

    return ffi_cast("struct stack_st_" .. type .. " *", ffi_cast("intptr_t", stack))
end

function _M.X509_new(certs)
    return sk_new("X509", certs)
end

return _M