
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

=== TEST 1: AES evp cipher
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local ffi = require "ffi"
            local EC = require "resty.crypto.ec"
            local eckey = EC.KEY_new_by_curve_name(1172)
            EC.KEY_generate_key(eckey)
            EC.KEY_set_private_key(eckey, "10C9308C5D192CC41C064F7407A846B58ADABEB709EDA4EF77AC0B44767AB329")
            EC.KEY_set_public_key(eckey, "044EA5AF846E8CDD6740AE49E44119F70D0EE771BD24EA6F6C921E17A7AA15E6AC7A9D79DB60DAEB8A71122C815A056DDC1DEE46213179EE734DA9F3FA81BCC70F")
            local prvkey, err = EC.KEY_get0_private_key(eckey)
            ngx.log(ngx.ERR, prvkey)
            local pubkey, err = EC.KEY_get0_public_key(eckey)
            ngx.log(ngx.ERR, pubkey)
        }
    }
--- request
GET /t
--- response_body
abc
--- error_code: 200
--- no_error_log
[error]

