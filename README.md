## Common crypto functions

### support
- asymmetric: `sm2`, `rsa`, `cms`
- symmetric: `sm4`, `aes`, `hmac`
- digest: `sm3`, `md5`, `sha`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`

## Examples
### Digests
```lua
local resty_digest = require "resty.digest"
local sm3 = resty_digest.new("sm3")
sm3:update("abc")
ngx.say(sm3:final())
ngx.say(sm3("abcabcabc"))
```

### Crypto

#### SM4
`require "resty.sm4".cipher(_cipher, _size)`

`cipher`: `ecb(default)`, `cbc`, `ofb`, `cfb`, `ctr`

`size`: `128-bit`

```lua
local resty_crypto = require "resty.crypto"
local resty_sm4 = require "resty.sm4"
local sm4, err = resty_crypto.new("secret", nil, resty_sm4.cipher("ecb", 128))
if not sm4 then
    error(err)
end
local enc_data, err = sm4:encrypt("abc")
if err then
    error(err)
end
ngx.say(sm4:decrypt(enc_data))
```

#### AES

`require "resty.aes".cipher(_cipher, _size)`

`cipher`: `ecb`, `cbc(default)`, `cfb1`, `cfb8`, `cfb128`, `ofb`, `ctr`

`size`: `128-bit(default)`, `192-bit`, `256-bit`

```lua
local resty_crypto = require "resty.crypto"
local resty_aes = require "resty.aes"
local aes, err = resty_crypto.new("secret", nil, resty_aes.cipher("cbc", 128))
if not aes then
    error(err)
end
local enc_data, err = aes:encrypt("abc")
if err then
    error(err)
end
ngx.say(aes:decrypt(enc_data))
```

#### HMAC

`resty_hmac.hash`: `md5`, `sm3`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`

```lua
local resty_hmac = require "resty.digest.hmac"
local hmac = resty_hmac.new("secret", resty_hmac.hash.md5)
hmac:update("abc")
ngx.say(hmac:final())
ngx.say(hmac("abcabcabc"))
```

