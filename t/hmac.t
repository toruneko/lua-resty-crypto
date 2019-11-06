
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

=== TEST 1: HMAC abc
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_hmac = require "resty.digest.hmac"
            local hmac = resty_hmac.new("hmac", resty_hmac.hash.sha1)
            hmac:update("abc")
            ngx.say(hmac.tohex(hmac:final()))
        }
    }
--- request
GET /t
--- response_body
140c02829ead7449c6548e586d7c56bbb3a85306
--- error_code: 200
--- no_error_log
[error]



=== TEST 2: HMAC 512bit
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_hmac = require "resty.digest.hmac"
            local hmac = resty_hmac.new("hmac", resty_hmac.hash.sha1)
            hmac:update("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
            ngx.say(hmac.tohex(hmac:final()))
        }
    }
--- request
GET /t
--- response_body
4f5fa62a1ace53c7386b3133a17bcc95ae8b9a9c
--- error_code: 200
--- no_error_log
[error]



=== TEST 3: HMAC function
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_hmac = require "resty.digest.hmac"
            local hmac = resty_hmac.new("hmac", resty_hmac.hash.sha1)
            ngx.say(hmac("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"))
        }
    }
--- request
GET /t
--- response_body
4f5fa62a1ace53c7386b3133a17bcc95ae8b9a9c
--- error_code: 200
--- no_error_log
[error]
