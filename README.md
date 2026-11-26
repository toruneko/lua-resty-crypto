# lua-resty-crypto

Common cryptographic functions for OpenResty / ngx_lua, implemented with LuaJIT FFI on top of the OpenSSL library linked into your OpenResty build.

## Features

| Category   | Algorithms / operations |
| ---------- | ----------------------- |
| Digest     | `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sm3`, plus any digest exposed by OpenSSL (for example `sha3-256`) |
| MAC        | `HMAC` with any supported digest |
| Symmetric  | `AES-128/192/256`, `SM4-128`, `DES` and 2-key/3-key Triple DES |
| Asymmetric | `RSA` (PKCS#1 v1.5, OAEP, no padding), `SM2` |
| Message    | `CMS` (PKCS#7) signing/verification and encryption/decryption |

## Requirements

- OpenResty (or nginx with ngx_lua) built with LuaJIT.
- The OpenSSL library linked into OpenResty.
- OpenSSL 1.1.1+ is recommended. Native `SM3` and `SM4` are used when available; this library also ships Lua fallbacks for the `SM3` digest and `SM4` cipher modes. `HMAC-SM3` and `SM2` require native OpenSSL support.
- Linux.

## Installation

With the OpenResty Package Manager:

```bash
opm get toruneko/lua-resty-crypto
```

From source:

```bash
git clone https://github.com/toruneko/lua-resty-crypto.git
cd lua-resty-crypto
make install LUA_VERSION=5.1
```

The files are installed under `$(PREFIX)/lib/lua/$(LUA_VERSION)/resty`, with `PREFIX` defaulting to `/usr/local`. If you install to a custom location, add it to `lua_package_path`:

```nginx
lua_package_path "/path/to/lua/lib/?.lua;;";
```

## Usage

The examples below are meant to run inside `content_by_lua_block` (or any other ngx_lua context).

### Digest

```lua
local digest = require "resty.digest"

local md = assert(digest.new("sha256"))
md:update("abc")

local raw = assert(md:final())     -- binary digest
ngx.say(digest.tohex(raw))         -- hex-encoded digest
ngx.say(md("abc"))                 -- shorthand: resets, hashes and returns hex
```

`digest.new(name[, key])` also accepts any digest name known to OpenSSL. When `key` is provided, the instance works in HMAC mode:

```lua
local digest = require "resty.digest"

local mac = assert(digest.new("sha256", "secret"))
mac:update("abc")
ngx.say(mac.tohex(mac:final()))
ngx.say(mac("abc"))
```

Use `update()` + `final()` for streaming data. `final()` returns raw bytes; `tohex()` and the `__call` shorthand return lowercase hex. The fallback `SM3` implementation supports plain hashing only, so `HMAC-SM3` needs OpenSSL with native SM3.

### Symmetric encryption

Create a cipher descriptor with one of the cipher modules, then pass it to `resty.crypto`:

```lua
local crypto = require "resty.crypto"

local instance, err = crypto.new(key, salt, cipher, kdf_hash, kdf_rounds)
```

| Parameter     | Description |
| ------------- | ----------- |
| `key`         | Passphrase used to derive the key and IV. |
| `salt`        | Optional 8-byte salt. Must be exactly 8 bytes when provided. |
| `cipher`      | Cipher descriptor returned by `aes.cipher()`, `sm4.cipher()` or `des.cipher()`. |
| `kdf_hash`    | Digest used by `EVP_BytesToKey` (default `md5`). |
| `kdf_rounds`  | Number of KDF rounds (default `1`). |

The returned instance provides:

- `instance:encrypt(plain)` → ciphertext, or `nil, err`
- `instance:decrypt(ciphertext)` → plaintext, or `nil, err`

Ciphertext is binary. Hex-encode it with `crypto.tohex()` or base64-encode it before sending over text protocols.

| Module        | Modes | Key size (bits) |
| ------------- | ----- | --------------- |
| `resty.aes`   | `cbc` (default), `ecb`, `cfb1`, `cfb8`, `cfb128`, `ofb`, `ctr` | `128` (default), `192`, `256` |
| `resty.sm4`   | `ecb` (default), `cbc`, `ofb`, `cfb`, `ctr` | `128` |
| `resty.des`   | `cbc` (default), `cfb`, `ecb`, `ofb`, `ede`, `ede_cbc`, `ede_cfb`, `ede_ofb`, `ede3`, `ede3_cbc`, `ede3_cfb`, `ede3_ofb` | `64` / `128` / `192`, selected automatically by mode |

Example with AES-256-CBC:

```lua
local crypto = require "resty.crypto"
local aes = require "resty.aes"

local cipher = assert(aes.cipher("cbc", 256))
local instance = assert(crypto.new("secret", "01234567", cipher))

local encrypted = assert(instance:encrypt("hello"))
ngx.say(crypto.tohex(encrypted))
ngx.say(assert(instance:decrypt(encrypted)))   -- hello
```

Pass the same salt and cipher when decrypting. Examples for the other algorithms:

```lua
-- SM4-CBC
local sm4 = assert(require("resty.crypto").new(
    "secret", nil, require("resty.sm4").cipher("cbc")))

-- 3-key Triple DES CBC
local des = assert(require("resty.crypto").new(
    "secret", nil, require("resty.des").cipher("ede3_cbc")))
```

Notes:

- Modes such as CBC, CFB, OFB and CTR do not authenticate data. Pair encryption with HMAC if integrity is required.
- An instance holds OpenSSL cipher contexts that are reset on every call. Do not share one instance between coroutines that encrypt or decrypt concurrently; create one instance per operation or worker-local cache entry.

### RSA

```lua
local rsa = require "resty.rsa"

-- PKCS#1 PEM output
local public_pem, private_pem = assert(rsa.generate_key(2048))

-- Pass true to generate PKCS#8 (SPKI / PKCS#8) PEM output instead
-- local public_pem, private_pem = assert(rsa.generate_key(2048, true))
```

`rsa.new(opts)` accepts:

| Option        | Description |
| ------------- | ----------- |
| `public_key`  | PEM-encoded public key. |
| `private_key` | PEM-encoded private key. |
| `password`    | Passphrase for an encrypted private key. |
| `algorithm`   | Digest used for `sign` / `verify`, for example `sha256`. |
| `padding`     | One of `rsa.PADDING.*`; defaults to `RSA_PKCS1_PADDING`. |
| `key_type`    | `rsa.KEY_TYPE.PKCS8` when the public key is SPKI (`-----BEGIN PUBLIC KEY-----`); the default is PKCS#1 (`-----BEGIN RSA PUBLIC KEY-----`). |

An instance is either a public-key instance or a private-key instance:

- `public_key` only: `encrypt()` and `verify()`
- `private_key` only: `decrypt()` and `sign()`

Sign and verify:

```lua
local signer = assert(rsa.new({
    private_key = private_pem,
    algorithm = "sha256",
}))
local verifier = assert(rsa.new({
    public_key = public_pem,
    algorithm = "sha256",
}))

local signature = assert(signer:sign("message"))
ngx.say(verifier:verify("message", signature))   -- true
```

Encrypt and decrypt (both sides must use the same padding):

```lua
local encrypter = assert(rsa.new({
    public_key = public_pem,
    padding = rsa.PADDING.RSA_PKCS1_OAEP_PADDING,
}))
local decrypter = assert(rsa.new({
    private_key = private_pem,
    padding = rsa.PADDING.RSA_PKCS1_OAEP_PADDING,
}))

local encrypted = assert(encrypter:encrypt("message"))
ngx.say(assert(decrypter:decrypt(encrypted)))   -- message
```

Maximum plaintext length for a modulus of `k` bytes:

| Padding | Maximum plaintext |
| ------- | ----------------- |
| `RSA_PKCS1_PADDING`, `RSA_SSLV23_PADDING` | `k - 11` |
| `RSA_PKCS1_OAEP_PADDING` | `k - 42` (with SHA-1) |
| `RSA_NO_PADDING` | exactly `k` |

### SM2

```lua
local sm2 = require "resty.sm2"

-- Raw key material, usable directly with sm2.new()
local public_key, private_key = assert(sm2.generate_key())

local signer = assert(sm2.new({
    private_key = private_key,
    public_key = public_key,
    algorithm = "sm3",
    id = "1234567812345678",
}))
local verifier = assert(sm2.new({
    public_key = public_key,
    algorithm = "sm3",
    id = "1234567812345678",
}))

local signature = assert(signer:sign("message"))
ngx.say(verifier:verify("message", signature))   -- true

local encrypted = assert(verifier:encrypt("message"))
ngx.say(assert(signer:decrypt(encrypted)))       -- message
```

`sm2.generate_eckey()` returns PEM-encoded keys instead. Pass `true` as the second argument to `sm2.new()` to parse them as PEM:

```lua
local public_pem, private_pem = assert(sm2.generate_eckey())

local instance = assert(sm2.new({
    private_key = private_pem,
    public_key = public_pem,
    algorithm = "sm3",
    id = "1234567812345678",
}, true))
```

`sm2.new(opts[, pemformat])` accepts:

| Option         | Description |
| -------------- | ----------- |
| `public_key`   | Raw EC public key or PEM string. Required in both modes. |
| `private_key`  | Raw EC private key or PEM string. When present, the instance is in sign/decrypt mode. |
| `algorithm`    | Digest used by `sign` / `verify`, for example `sm3`, `sha256` or `sha3-256`. |
| `id`           | SM2 user ID. The signer and verifier must use the same value. Defaults to `default sm2 ID`; set it explicitly for interoperability. |
| `private_pass` | Passphrase for an encrypted private key when `pemformat` is `true`. |
| `public_pass`  | Passphrase for an encrypted public key when `pemformat` is `true`. |

Mode rules:

- `private_key` present: `sign()` and `decrypt()`
- only `public_key` present: `verify()` and `encrypt()`

### CMS (PKCS#7)

```lua
local cms = require "resty.cms"

local instance = assert(cms.new({
    private_key = private_pem,   -- signer/recipient private key
    sign_cert   = cert_pem,      -- signing certificate
    cert        = cert_pem,      -- recipient certificate
    root_cert   = ca_pem,        -- trusted root certificate(s), string or array
}))

local signed = assert(instance:sign("plain text"))
ngx.say(instance:verify(signed))             -- plain text

local encrypted = assert(instance:encrypt("plain text"))
ngx.say(instance:decrypt(encrypted))         -- plain text
```

`cms.new(opts)` accepts:

| Option        | Description |
| ------------- | ----------- |
| `private_key` | PEM-encoded RSA private key. |
| `sign_cert`   | PEM-encoded signing certificate. |
| `cert`        | PEM-encoded recipient certificate. |
| `root_cert`   | Trusted root certificate, or an array of certificates, used during verification. |
| `cipher`      | AES cipher descriptor or native OpenSSL cipher pointer. Defaults to AES-128-CBC. |

`sign()` and `encrypt()` return PEM-encoded CMS data; `verify()` and `decrypt()` accept that PEM data and return the plaintext. For DER/PEM conversion, the lower-level helpers are available:

```lua
local info = assert(instance:PEM_read_CMS(signed))
local der  = assert(instance:i2d_CMS_ContentInfo(info))
local info = assert(instance:d2i_CMS_ContentInfo(der))
local pem  = assert(instance:PEM_write_CMS(info))
```

### Error handling

Constructors and operations return `nil, err` on failure, so always check the first return value:

```lua
local instance, err = crypto.new(key, salt, cipher)
if not instance then
    ngx.log(ngx.ERR, "failed to init cipher: ", err)
    return
end
```

RSA and SM2 `verify()` return `true` for a valid signature and `false` for an invalid one (or `nil, err` if verification cannot be performed). CMS `verify()` returns the recovered plaintext, or `nil, err` when the content cannot be verified.

## Testing

The test suite uses [Test::Nginx](https://github.com/openresty/test-nginx):

```bash
# Requires Test::Nginx, prove and OpenResty
make test

# Use a custom OpenResty installation
make test OPENRESTY_PREFIX=/usr/local/openresty

# Alternatively, when Test::Nginx::Socket::Lua is already installed
prove -r t
```

The `make test` target expects a sibling checkout of `test-nginx` at `../test-nginx` and an OpenResty installation at `$(OPENRESTY_PREFIX)` (default `/usr/local/openresty-debug`). To run the suite under Valgrind and check for definite leaks:

```bash
bash test_with_valgrind.sh
```

## Documentation

- [SM3 cryptographic hash algorithm (PDF, Chinese)](docs/SM3杂凑密码算法.pdf)
- [SM4 block cipher algorithm (PDF, Chinese)](docs/SM4分组密码算法.pdf)

## License

[MIT](LICENSE)
