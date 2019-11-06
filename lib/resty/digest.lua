-- Copyright (C) by Jianhao Dai (Toruneko)

local str = require "resty.utils.string"
local setmetatable = setmetatable

local digest = {
    md5 = require "resty.digest.md5",
    sm3 = require "resty.digest.sm3",
    sha1 = require "resty.digest.sha1",
    sha224 = require "resty.digest.sha224",
    sha256 = require "resty.digest.sha256",
    sha384 = require "resty.digest.sha384",
    sha512 = require "resty.digest.sha512",
}

local _M = { _VERSION = '0.0.1' }
local mt = { __index = _M }

function mt.__call(self, s)
    local hash = self.hash
    if not hash:reset() then
        return nil
    end
    if hash:update(s) then
        return str.tohex(hash:final())
    end
end

function _M.new(algorithm)
    local hash = digest[algorithm]
    if not hash then
        return nil, "digest algorithm not found"
    end

    return setmetatable({ hash = hash.new() }, mt)
end

function _M.update(self, s)
    return self.hash:update(s)
end

function _M.final(self)
    return self.hash:final()
end

function _M.reset(self)
    return self.hash:reset()
end

function _M.tohex(s)
    return str.tohex(s)
end

return _M