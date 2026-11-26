-- Copyright (C) by Jianhao Dai (Toruneko)

local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local ffi_cast = ffi.cast
local ffi_gc = ffi.gc
local ffi_null = ffi.null
local C = ffi.C
local type = type
local ipairs = ipairs

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
typedef struct stack_st OPENSSL_STACK;
struct stack_st_X509;

OPENSSL_STACK *OPENSSL_sk_new_null(void);
void OPENSSL_sk_free(OPENSSL_STACK *st);
int OPENSSL_sk_push(OPENSSL_STACK *st, void *data);
]]

local function sk_new(st, items)
    if type(items) ~= "table" then
        return nil, "items must be a table"
    end

    local stack = C.OPENSSL_sk_new_null()
    if stack == ffi_null then
        return nil, ERR.get_error()
    end
    ffi_gc(stack, C.OPENSSL_sk_free)

    local refs = { stack }
    for _, item in ipairs(items) do
        if C.OPENSSL_sk_push(stack, item) <= 0 then
            return nil, ERR.get_error()
        end
        refs[#refs + 1] = item
    end

    -- Keep the original pointer and certificate references alive after casting.
    local typed_stack = ffi_cast("struct stack_st_" .. st .. " *", stack)
    return ffi_gc(typed_stack, function()
        ffi_gc(refs[1], nil)
        C.OPENSSL_sk_free(refs[1])
    end)
end

function _M.X509_new(certs)
    return sk_new("X509", certs)
end

return _M
