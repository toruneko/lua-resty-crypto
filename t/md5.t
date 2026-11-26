# vi:ft=

use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    lua_package_cpath 'lib/?.so;;';
_EOC_

no_long_string();

run_tests();

__DATA__

=== TEST 1: hello MD5
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local resty_digest = require "resty.digest"
            local md5 = resty_digest.new("md5")
            ngx.say(md5:update("hello"))
            local digest = md5:final()
            ngx.say(digest == ngx.md5_bin("hello"))
            ngx.say("md5: ", md5.tohex(digest))
        ';
    }
--- request
GET /t
--- response_body
true
true
md5: 5d41402abc4b2a76b9719d911017c592
--- no_error_log
[error]



=== TEST 2: MD5 incremental
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local resty_digest = require "resty.digest"
            local md5 = resty_digest.new("md5")
            ngx.say(md5:update("hel"))
            ngx.say(md5:update("lo"))
            local digest = md5:final()
            ngx.say("md5: ", md5.tohex(digest))
        ';
    }
--- request
GET /t
--- response_body
true
true
md5: 5d41402abc4b2a76b9719d911017c592
--- no_error_log
[error]



=== TEST 3: MD5 empty string
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local resty_digest = require "resty.digest"
            local md5 = resty_digest.new("md5")
            ngx.say(md5:update(""))
            local digest = md5:final()
            ngx.say(digest == ngx.md5_bin(""))
            ngx.say("md5: ", md5.tohex(digest))
        ';
    }
--- request
GET /t
--- response_body
true
true
md5: d41d8cd98f00b204e9800998ecf8427e
--- no_error_log
[error]


=== TEST 4: MD5 reset discards unfinished input
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local digest = require "resty.digest"
            local md5 = assert(digest.new("md5"))
            assert(md5:update("discard"))
            assert(md5:reset())
            assert(md5:update("hello"))
            ngx.say(md5:final() == ngx.md5_bin("hello"))
        }
    }
--- request
GET /t
--- response_body
true
--- no_error_log
[error]


=== TEST 5: MD5 callable instance can be reused
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local md5 = assert(require("resty.digest").new("md5"))
            ngx.say(md5("hello") == ngx.md5("hello"))
            ngx.say(md5("world") == ngx.md5("world"))
            ngx.say(md5("") == ngx.md5(""))
        }
    }
--- request
GET /t
--- response_body
true
true
true
--- no_error_log
[error]
