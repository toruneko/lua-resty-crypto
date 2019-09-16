-- Copyright (C) by Jianhao Dai (Toruneko)

local bit = require "bit"
local ffi = require "ffi"
local bor = bit.bor
local band = bit.band
local bxor = bit.bxor
local bnot = bit.bnot
local lshift = bit.lshift
local rshift = bit.rshift
local tohex = bit.tohex
local ffi_new = ffi.new
local ffi_cast = ffi.cast
local tab_concat = table.concat
local setmetatable = setmetatable

local _M = { _VERSION = '0.0.1' }
local mt = { __index = _M }

local ok, new_tab = pcall(require, "table.new")
if not ok then
    new_tab = function(narr, nrec) return {} end
end

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

-- 置换函数 P0
local function P0(x)
    return bxor(x, S(x, 9), S(x, 17))
end

-- 置换函数 P1
local function P1(x)
    return bxor(x, S(x, 15), S(x, 23))
end

-- 布尔函数FF(X,Y,Z)
local FF1 = function(x, y, z)
    return bxor(x, y, z)
end
local FF2 = function(x, y, z)
    return bor(band(x, y), band(x, z), band(y, z))
end
local FF = new_tab(64, 0)
for i = 1, 16, 1 do
    FF[i] = FF1
end
for i = 17, 64, 1 do
    FF[i] = FF2
end

-- 布尔函数GG(X,Y,Z)
local GG1 = function(x, y, z)
    return bxor(x, y, z)
end
local GG2 = function(x, y, z)
    return bor(band(x, y), band(bnot(x), z))
end
local GG = new_tab(64, 0)
for i = 1, 16, 1 do
    GG[i] = GG1
end
for i = 17, 64, 1 do
    GG[i] = GG2
end

-- 常量 T
local T = ffi.new("const uint32_t[64]", {
    0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb, 0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
    0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce, 0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
    0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
    0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
    0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53, 0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d,
    0x879d8a7a, 0x0f3b14f5, 0x1e7629ea, 0x3cec53d4, 0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43,
    0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
    0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
})
-- 常量 T
--local T = ffi.new("uint32_t[64]")
--for i = 1, 16, 1 do
--    local j = i - 1
--    T[j] = S(0x79cc4519, j)
--end
--for i = 17, 64, 1 do
--    local j = i - 1
--    T[j] = S(0x7a879d8a, band(j, 0x1f))
--end

-- 填充
local sm3_padding = ffi.new("const uint32_t[64]", {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
})

local function SM3_Init(ctx)
    -- 高有效位
    ctx.hLen = 0
    -- 低有效位
    ctx.lLen = 0
    -- 初始值
    ctx.iv = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    }
    -- 填充块
    ctx.block = ffi_new("uint32_t[64]", {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    })
end

local function SM3_Update_block(ctx, block, offset)
    if not offset then
        offset = 0
    end

    local W = ffi_new("uint32_t[68]")
    local WP = ffi_new("uint32_t[64]")

    for i = 1, 16, 1 do
        local j = i - 1
        W[j] = get32(block, offset + lshift(j, 2))
    end

    for i = 17, 68, 1 do
        local j = i - 1
        W[j] = bxor(P1(bxor(W[j - 16], W[j - 9], S(W[j - 3], 15))), S(W[j - 13], 7), W[j - 6])
    end

    local A = ctx.iv[1]
    local B = ctx.iv[2]
    local C = ctx.iv[3]
    local D = ctx.iv[4]
    local E = ctx.iv[5]
    local F = ctx.iv[6]
    local G = ctx.iv[7]
    local H = ctx.iv[8]

    for i = 1, 64, 1 do
        local j = i - 1
        WP[j] = bxor(W[j], W[j + 4])

        local A12 = S(A, 12)
        local SS1 = S(A12 + E + T[j], 7)
        local SS2 = bxor(SS1, A12)
        local TT1 = FF[i](A, B, C) + D + SS2 + WP[j]
        local TT2 = GG[i](E, F, G) + H + SS1 + W[j]
        D = C
        C = S(B, 9)
        B = A
        A = TT1
        H = G
        G = S(F, 19)
        F = E
        E = P0(TT2)
    end

    ctx.iv[1] = bxor(ctx.iv[1], A)
    ctx.iv[2] = bxor(ctx.iv[2], B)
    ctx.iv[3] = bxor(ctx.iv[3], C)
    ctx.iv[4] = bxor(ctx.iv[4], D)
    ctx.iv[5] = bxor(ctx.iv[5], E)
    ctx.iv[6] = bxor(ctx.iv[6], F)
    ctx.iv[7] = bxor(ctx.iv[7], G)
    ctx.iv[8] = bxor(ctx.iv[8], H)
end

local function SM3_Update(ctx, data, len)
    if len <= 0 then
        return 0
    end

    local left = band(ctx.lLen, 0x3f)
    local fill = 64 - left
    local offset = 0

    ctx.lLen = ctx.lLen + len;
    ctx.lLen = band(ctx.lLen, 0xFFFFFFFF);

    if ctx.lLen < len then
        ctx.hLen = ctx.hLen + 1;
    end

    if left > 0 and len >= fill then
        for i = 1, fill, 1 do
            local j = i - 1
            ctx.block[left + j] = data[j]
        end
        SM3_Update_block(ctx, ctx.block, 0)
        offset = fill
        len = len - fill
        left = 0
    end

    while len >= 64 do
        SM3_Update_block(ctx, data, offset)
        offset = offset + 64
        len = len - 64
    end

    if len > 0 then
        for i = 1, len, 1 do
            local j = i - 1
            ctx.block[left + j] = data[offset + j]
        end
    end

    return 1
end

local function SM3_Final(ctx, digest)
    local msglen = ffi_new("uint32_t[8]", { 0, 0, 0, 0, 0, 0, 0, 0 })
    local high = bor(rshift(ctx.lLen, 29), lshift(ctx.hLen, 3))
    local low = lshift(ctx.lLen, 3)
    put32(high, msglen, 0)
    put32(low, msglen, 4)

    local last = band(ctx.lLen, 0x3F)
    local padn = (last < 56) and (56 - last) or (120 - last)

    if SM3_Update(ctx, sm3_padding, padn) ~= 1 then
        return 0
    end

    if SM3_Update(ctx, msglen, 8) ~= 1 then
        return 0
    end

    for i = 1, 8, 1 do
        digest[i] = tohex(ctx.iv[i])
    end

    return 1
end

function _M.new(self)
    local ctx = new_tab(0, 4)
    SM3_Init(ctx)

    return setmetatable({ _ctx = ctx }, mt)
end

function _M.update(self, s)
    return SM3_Update(self._ctx, ffi_cast("unsigned char*", s), #s)
end

function _M.final(self)
    local digest = new_tab(8, 0)

    if SM3_Final(self._ctx, digest) == 1 then
        return tab_concat(digest)
    end
end

function _M.reset(self)
    SM3_Init(self._ctx)
end

return _M