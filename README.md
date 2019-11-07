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

`hash`: `md5`, `sm3`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`

OR
```lua
local resty_digest = require "resty.digest"
local hmac = resty_digest.new("sha1", "secret")
hmac:update("abc")
ngx.say(hmac:final())
ngx.say(hmac("abcabcabc"))
```

#### SM2

```lua
local resty_sm2 = require "resty.sm2"
-- generator an eckey
local pubkey, prvkey = resty_sm2.generate_key()
-- new instance with sm3 hash algorithm
-- will be sign and decrypt mode when private key set.
local sm2, _ = resty_sm2.new({
    private_key = prvkey,
    public_key = pubkey,
    algorithm = "sm3",
    id = "toruneko@outlook.com"
})
sm2:sign(data)
sm2:decrypt(data)

-- will be verify and encrypt mode when private key not key
local sm2, _ = resty_sm2.new({
    public_key = pubkey,
    algorithm = "sm3",
    id = "toruneko@outlook.com"
})
sm2:verify(data)
sm2:encrypt(data)
```

#### RSA
```lua
local resty_rsa = require "resty.rsa"
local pubkey, prvkey = resty_rsa.generate_key(2048)

-- will be sign and decrypt mode when only private key set.
local rsa, _ = resty_rsa.new({
    private_key = prvkey,
    algorithm = "sha1",
    padding = resty_rsa.PADDING.RSA_PKCS1_PADDING
})
rsa:sign(data)
rsa:decrypt(data)

-- will be verify and encrypt mode when only public key set.
local rsa, _ = resty_rsa.new({
    public_key = pubkey,
    algorithm = "sha1",
    padding = resty_rsa.PADDING.RSA_PKCS1_PADDING
})
rsa:verify(data)
rsa:encrypt(data)
```
