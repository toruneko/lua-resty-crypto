
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

=== TEST 1: SM4 encrypt block
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_sm4 = require "resty.sm4"
            local sm4 = resty_sm4:new({0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10})
            local bytes = sm4:encrypt({0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10})
            local data = {}
            for i = 1, 16, 1 do
                data[i] = string.format("%02x", string.byte(bytes, i))
            end
            ngx.say(table.concat(data, " "))
        }
    }
--- request
GET /t
--- response_body
68 1e df 34 d2 06 96 5e 86 b3 e9 4f 53 6e 42 46
--- error_code: 200
--- no_error_log
[error]



=== TEST 2: SM4 decrypt block
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_sm4 = require "resty.sm4"
            local sm4 = resty_sm4:new({0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10})
            local bytes = sm4:decrypt({0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46})
            local data = {}
            for i = 1, 16, 1 do
                data[i] = string.format("%02x", string.byte(bytes, i))
            end
            ngx.say(table.concat(data, " "))
        }
    }
--- request
GET /t
--- response_body
01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
--- error_code: 200
--- no_error_log
[error]
