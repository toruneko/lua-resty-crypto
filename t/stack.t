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

=== TEST 1: Certificate stack and its elements survive garbage collection
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local ffi = require "ffi"
            local pem = require "resty.crypto.pem"
            local stack = require "resty.crypto.stack"
            ffi.cdef[[
                int OPENSSL_sk_num(const OPENSSL_STACK *st);
                void *OPENSSL_sk_value(const OPENSSL_STACK *st, int idx);
                int X509_cmp(const X509 *a, const X509 *b);
            ]]
            local f = assert(io.open("$TEST_NGINX_CWD/t/fixtures/cms-cert.pem"))
            local cert = f:read("*a")
            f:close()
            local items = {assert(pem.read_X509(cert))}
            local certs = assert(stack.X509_new(items))
            items[1] = nil
            collectgarbage("collect")
            local raw = ffi.cast("OPENSSL_STACK *", certs)
            ngx.say(ffi.C.OPENSSL_sk_num(raw))
            local value = ffi.cast("X509 *", ffi.C.OPENSSL_sk_value(raw, 0))
            ngx.say(ffi.C.X509_cmp(value, assert(pem.read_X509(cert))) == 0)
        }
    }
--- request
GET /t
--- response_body
1
true
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: Certificate stack rejects non-table input
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local stack = require "resty.crypto.stack"
            ngx.say(stack.X509_new(nil) == nil)
            ngx.say(stack.X509_new("invalid") == nil)
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
