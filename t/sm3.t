
use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

$ENV{TEST_NGINX_CWD} = cwd();

no_long_string();

our $HttpConfig = <<'_EOC_';
    lua_package_path '$TEST_NGINX_CWD/lib/?.lua;;';
_EOC_

run_tests();

__DATA__

=== TEST 1: SM3 abc
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_digest = require "resty.digest"
            local sm3 = resty_digest.new("sm3")
            sm3:update("abc")
            ngx.say(sm3:final())
        }
    }
--- request
GET /t
--- response_body
66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
--- error_code: 200
--- no_error_log
[error]



=== TEST 2: SM3 512bit
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_digest = require "resty.digest"
            local sm3 = resty_digest.new("sm3")
            sm3:update("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
            ngx.say(sm3:final())
        }
    }
--- request
GET /t
--- response_body
debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
--- error_code: 200
--- no_error_log
[error]
