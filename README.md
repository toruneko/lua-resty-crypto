## Common crypto functions

### Digests
```lua
local resty_digest = require "resty.digest"
local sm3 = resty_digest.new("sm3")
sm3:update("abc")
ngx.say(sm3:final())
```

### Crypto
```lua
local resty_crypto = require "resty.crypto"
local resty_sm4 = require "resty.sm4"
local sm4, err = resty_crypto.new("secret", nil, resty_sm4.cipher())
if not sm4 then
    error(err)
end
local enc_data, err = sm4:encrypt("abc")
if err then
    error(err)
end
ngx.say(sm4:decrypt(enc_data))
```