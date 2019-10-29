
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

=== TEST 1: SM2 encoder
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resty_sm2 = require "resty.sm2"
            local resty_str = require "resty.utils.string"
            local data = "ssssssssss"
            local sm2_for_sign, err = resty_sm2.new({
                private_key = "10C9308C5D192CC41C064F7407A846B58ADABEB709EDA4EF77AC0B44767AB329",
                algorithm = "sha1",
            })
            local signed, err = sm2_for_sign:sign(data)
            local sm2_for_verify, err = resty_sm2.new({
                public_key = "044EA5AF846E8CDD6740AE49E44119F70D0EE771BD24EA6F6C921E17A7AA15E6AC7A9D79DB60DAEB8A71122C815A056DDC1DEE46213179EE734DA9F3FA81BCC70F",
                algorithm = "sha1",
            })
            local ok , err = sm2_for_verify:verify(data, signed)
            ngx.say(ok)
        }
    }
--- request
GET /t
--- response_body
true
--- error_code: 200
--- no_error_log
[error]

