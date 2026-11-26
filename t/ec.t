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

=== TEST 1: Exported public points remain owned by their EC key
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local ec = require "resty.crypto.ec"
            local key = assert(ec.KEY_new_by_curve_name(1172))
            assert(ec.KEY_generate_key(key))
            local public = assert(ec.KEY_get0_public_key(key))
            collectgarbage("collect")
            ngx.say(ec.KEY_check_key(key))
            ngx.say(ec.KEY_get0_public_key(key) == public)
            collectgarbage("collect")
            ngx.say(ec.KEY_check_key(key))
        }
    }
--- request
GET /t
--- response_body
true
true
true
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: BIGNUM rejects empty and partially valid hexadecimal input
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local bn = require "resty.crypto.bn"
            ngx.say(bn.hex2bn("") == nil)
            ngx.say(bn.hex2bn("ABinvalid") == nil)
        }
    }
--- request
GET /t
--- response_body
true
true
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: Parsed BIGNUM remains alive through garbage collection
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local bn = require "resty.crypto.bn"
            local number = assert(bn.hex2bn("DEADBEEF"))
            collectgarbage("collect")
            ngx.say(bn.bn2hex(number))
        }
    }
--- request
GET /t
--- response_body
DEADBEEF
--- error_code: 200
--- no_error_log
[error]
