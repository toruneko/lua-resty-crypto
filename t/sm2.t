
use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

$ENV{TEST_NGINX_CWD} = cwd();

no_long_string();

our $HttpConfig = <<'_EOC_';
    lua_package_path '$TEST_NGINX_CWD/lib/?.lua;$TEST_NGINX_CWD/t/?.lua;;';
_EOC_

run_tests();

__DATA__

=== TEST 1: SM2 sign & verify
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_sm2 = require "resty.sm2"
            local resty_str = require "resty.utils.string"
            local pubkey, prvkey = resty_sm2.generate_key()
            local data = "ssssssssss"
            local digests = {"sm3", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"}
            for _, digest in ipairs(digests) do
                local sm2_for_sign, err = resty_sm2.new({
                    private_key = prvkey,
                    public_key = pubkey,
                    algorithm = digest,
                    id = "toruneko@outlook.com"
                })
                if err then
                    ngx.log(ngx.ERR, "init:", err)
                end
                local signed, err = sm2_for_sign:sign(data)
                if err then
                    ngx.log(ngx.ERR, "sign:", err)
                end
                local sm2_for_verify, err = resty_sm2.new({
                    public_key = pubkey,
                    algorithm = digest,
                    id = "toruneko@outlook.com"
                })
                local ok , err = sm2_for_verify:verify(data, signed)
                if err then
                    ngx.log(ngx.ERR, "verify:", err)
                end
                ngx.say(digest .. ":" .. tostring(ok))
            end
        }
    }
--- request
GET /t
--- response_body
sm3:true
sha1:true
sha224:true
sha256:true
sha384:true
sha512:true
sha3-224:true
sha3-256:true
sha3-384:true
sha3-512:true
--- error_code: 200
--- no_error_log
[error]



=== TEST 2: SM2 encrypt & decrypt
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_sm2 = require "resty.sm2"
            local resty_str = require "resty.utils.string"
            local pubkey, prvkey = resty_sm2.generate_key()
            local data = "ssssssssss"
            local sm2_for_enc, err = resty_sm2.new({
                public_key = pubkey,
                algorithm = "sm3",
                id = "toruneko@outlook.com"
            })
            if err then
                ngx.log(ngx.ERR, "init:", err)
            end
            local enc_data, err = sm2_for_enc:encrypt(data)
            if err then
                ngx.log(ngx.ERR, "encrypt:", err)
            end
            local sm2_for_dec, err = resty_sm2.new({
                private_key = prvkey,
                public_key = pubkey,
                algorithm = "sm3",
                id = "toruneko@outlook.com"
            })
            local ok , err = sm2_for_dec:decrypt(enc_data)
            if err then
                ngx.log(ngx.ERR, "decrypt:", err)
            end
            ngx.say(tostring(ok))
        }
    }
--- request
GET /t
--- response_body
ssssssssss
--- error_code: 200
--- no_error_log
[error]