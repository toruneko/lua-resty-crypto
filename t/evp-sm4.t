
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

=== TEST 1: SM4 ecb evp cipher
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_crypto = require "resty.crypto"
            local resty_sm4 = require "resty.sm4"
            local cipher = resty_sm4.cipher("ecb", 128)
            local sm4, err = resty_crypto.new("secret", nil, cipher)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local enc_data, err = sm4:encrypt("abc")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(sm4:decrypt(enc_data))
        }
    }
--- request
GET /t
--- response_body
abc
--- error_code: 200
--- no_error_log
[error]



=== TEST 2: SM4 cbc evp cipher
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_crypto = require "resty.crypto"
            local resty_sm4 = require "resty.sm4"
            local cipher = resty_sm4.cipher("cbc", 128)
            local sm4, err = resty_crypto.new("secret", nil, cipher)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local enc_data, err = sm4:encrypt("abc")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(sm4:decrypt(enc_data))
        }
    }
--- request
GET /t
--- response_body
abc
--- error_code: 200
--- no_error_log
[error]



=== TEST 3: SM4 ofb evp cipher
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_crypto = require "resty.crypto"
            local resty_sm4 = require "resty.sm4"
            local cipher = resty_sm4.cipher("ofb", 128)
            local sm4, err = resty_crypto.new("secret", nil, cipher)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local enc_data, err = sm4:encrypt("abc")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(sm4:decrypt(enc_data))
        }
    }
--- request
GET /t
--- response_body
abc
--- error_code: 200
--- no_error_log
[error]



=== TEST 5: SM4 ctr evp cipher
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_crypto = require "resty.crypto"
            local resty_sm4 = require "resty.sm4"
            local cipher = resty_sm4.cipher("ctr", 128)
            local sm4, err = resty_crypto.new("secret", nil, cipher)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local enc_data, err = sm4:encrypt("abc")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(sm4:decrypt(enc_data))
        }
    }
--- request
GET /t
--- response_body
abc
--- error_code: 200
--- no_error_log
[error]



=== TEST 1: SM4 evp cipher
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_crypto = require "resty.crypto"
            local resty_sm4 = require "resty.sm4"
            local cipher = resty_sm4.cipher("ecb", 128)
            local sm4, err = resty_crypto.new("secret", nil, cipher)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local enc_data, err = sm4:encrypt("abc")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(sm4:decrypt(enc_data))
        }
    }
--- request
GET /t
--- response_body
abc
--- error_code: 200
--- no_error_log
[error]

