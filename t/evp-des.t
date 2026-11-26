use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(2);
plan tests => repeat_each() * (3 * blocks());

$ENV{TEST_NGINX_CWD} = cwd();
our $HttpConfig = <<'_EOC_';
    lua_package_path '$TEST_NGINX_CWD/lib/?.lua;;';
_EOC_

no_long_string();
run_tests();

__DATA__

=== TEST 1: DES and triple DES use their actual key lengths
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local des = require "resty.des"
            local crypto = require "resty.crypto"
            for _, mode in ipairs({"cbc", "cfb", "ecb", "ofb", "ede", "ede_cbc", "ede_cfb", "ede_ofb", "ede3", "ede3_cbc", "ede3_cfb", "ede3_ofb"}) do
                local cipher = assert(des.cipher(mode))
                local instance = assert(crypto.new("secret", nil, cipher))
                local plain = "hello" .. string.char(0) .. "world"
                ngx.say(mode, ":", instance:decrypt(assert(instance:encrypt(plain))) == plain)
            end
        }
    }
--- request
GET /t
--- response_body
cbc:true
cfb:true
ecb:true
ofb:true
ede:true
ede_cbc:true
ede_cfb:true
ede_ofb:true
ede3:true
ede3_cbc:true
ede3_cfb:true
ede3_ofb:true
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: Invalid DES selection returns nil
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            ngx.say(require("resty.des").cipher("invalid") == nil)
        }
    }
--- request
GET /t
--- response_body
true
--- error_code: 200
--- no_error_log
[error]
