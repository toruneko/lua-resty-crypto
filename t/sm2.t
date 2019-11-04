
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
            local pubkey, prvkey = resty_sm2.generate_key()
            local data = "ssssssssss"
            local digests = {"sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"}
            for _, digest in ipairs(digests) do
                local sm2_for_sign, err = resty_sm2.new({
                    private_key = prvkey,
                    algorithm = digest,
                })
                local signed, err = sm2_for_sign:sign(data)
                local sm2_for_verify, err = resty_sm2.new({
                    public_key = pubkey,
                    algorithm = digest,
                })
                local ok , err = sm2_for_verify:verify(data, signed)
                ngx.say(digest .. ":" .. tostring(ok))
            end
        }
    }
--- request
GET /t
--- response_body
sha1:true
sha224:true
sha256:true
sha384:true
sha512:true
sha3-224:true
sha3-256:true
sha3-384:true
sha3-512:true
--- error_code: 200
--- no_error_log
[error]

