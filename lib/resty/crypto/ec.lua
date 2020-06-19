-- Copyright (C) by Jianhao Dai (Toruneko)

local BN = require "resty.crypto.bn"
local ERR = require "resty.crypto.error"

local ffi = require "ffi"
local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_null = ffi.null
local ffi_str = ffi.string
local C = ffi.C
local tonumber = tonumber

local _M = { _VERSION = '0.0.1' }

ffi.cdef [[
typedef struct ec_group_st EC_GROUP;
typedef struct ec_point_st EC_POINT;
typedef struct ec_key_st EC_KEY;
typedef struct {
    int nid;
    const char *comment;
} EC_builtin_curve;
typedef enum {
    POINT_CONVERSION_COMPRESSED = 2,
    POINT_CONVERSION_UNCOMPRESSED = 4,
    POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;

size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);

// EC_KEY
EC_KEY *EC_KEY_new_by_curve_name(int nid);
void EC_KEY_free(EC_KEY *key);
int EC_KEY_generate_key(EC_KEY *key);
int EC_KEY_check_key(const EC_KEY *key);
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);
int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv);
const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key);
int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key);

point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *key);
char *EC_POINT_point2hex(const EC_GROUP *group, const EC_POINT *p,
                         point_conversion_form_t form, BN_CTX *ctx);
EC_POINT *EC_POINT_hex2point(const EC_GROUP *group, const char *hex,
                             EC_POINT *p, BN_CTX *ctx);
]]

local EC_builtin_curve_ptr = ffi.typeof("EC_builtin_curve[?]")
local const_char_ptr = ffi.typeof("const char *")

function _M.get_builtin_curves()
    local size_t = C.EC_get_builtin_curves(ffi_null, 0)
    if size_t > 0 then
        local curvers = ffi_new(EC_builtin_curve_ptr, tonumber(size_t))
        if C.EC_get_builtin_curves(curvers, size_t) > 0 then
            return curvers, size_t
        end
    end
    return nil, "no builtin curvers"
end

function _M.KEY_new_by_curve_name(nid)
    local eckey = C.EC_KEY_new_by_curve_name(nid)
    if eckey == ffi_null then
        return nil, "curver not found"
    end
    ffi_gc(eckey, C.EC_KEY_free)

    return eckey
end

function _M.KEY_free(eckey)
    ffi_gc(eckey, C.EC_KEY_free)
end

function _M.KEY_generate_key(eckey)
    if  C.EC_KEY_generate_key(eckey) == 1 then
        return C.EC_KEY_check_key(eckey) == 1
    end
    return false, ERR.get_error()
end

function _M.KEY_check_key(eckey)
    return C.EC_KEY_check_key(eckey) == 1
end

function _M.KEY_get0_private_key(eckey)
    local bn = C.EC_KEY_get0_private_key(eckey)
    if bn == ffi_null then
        return nil, "no private key"
    end
    return BN.bn2hex(bn)
end

function _M.KEY_set_private_key(eckey, prv)
    local bn = BN.hex2bn(prv)
    if bn and C.EC_KEY_set_private_key(eckey, bn) == 1 then
        return true
    end
    return false, ERR.get_error()
end

function _M.KEY_get0_public_key(eckey)
    local point = C.EC_KEY_get0_public_key(eckey)
    if point == ffi_null then
        return nil, "no private key"
    end
    local group = C.EC_KEY_get0_group(eckey)
    if group == ffi_null then
        return nil, "no group"
    end
    local conv = C.EC_KEY_get_conv_form(eckey)
    local hex = C.EC_POINT_point2hex(group, point, conv, ffi_null)
    return ffi_str(hex)
end

function _M.KEY_set_public_key(eckey, pub)
    local group = C.EC_KEY_get0_group(eckey)
    if group == ffi_null then
        return false, ERR.get_error()
    end
    local str = ffi_new(const_char_ptr, pub)
    local point = C.EC_POINT_hex2point(group, str, ffi_null, ffi_null)
    if point == ffi_null then
        return false, ERR.get_error()
    end
    if C.EC_KEY_set_public_key(eckey, point) <= 0 then
        return false, ERR.get_error()
    end
    return true
end

return _M