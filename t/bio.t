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

=== TEST 1: BIO accepts binary and empty input
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local bio = require "resty.crypto.bio"
            local data = "a" .. string.char(0) .. "b"
            ngx.say(bio.read(assert(bio.new(data))) == data)
            ngx.say(bio.read(assert(bio.new(""))) == "")
            local buffer = assert(bio.new())
            assert(bio.puts(buffer, data))
            ngx.say(bio.read(buffer) == data)
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
