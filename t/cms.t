use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(2);
plan tests => repeat_each() * (3 * blocks());

$ENV{TEST_NGINX_CWD} = cwd();
our $HttpConfig = <<'_EOC_';
    lua_package_path '$TEST_NGINX_CWD/lib/?.lua;;';
    init_by_lua_block {
        local function read(name)
            local f = assert(io.open("$TEST_NGINX_CWD/t/fixtures/" .. name))
            local data = f:read("*a")
            f:close()
            return data
        end
        CMS_CERT = read("cms-cert.pem")
        CMS_KEY = read("cms-key.pem")
    }
_EOC_

no_long_string();
run_tests();

__DATA__

=== TEST 4: CMS accepts cipher descriptors and native cipher pointers
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local cipher = assert(require("resty.aes").cipher("cbc", 256))
            for _, selected in ipairs({cipher, cipher.method}) do
                local cms = assert(require("resty.cms").new({
                    private_key = CMS_KEY, sign_cert = CMS_CERT,
                    cert = CMS_CERT, cipher = selected,
                }))
                ngx.say(cms:decrypt(assert(cms:encrypt("custom cipher"))) == "custom cipher")
            end
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

=== TEST 1: CMS signs and verifies with the configured private key
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local cms = assert(require("resty.cms").new({
                private_key = CMS_KEY, sign_cert = CMS_CERT,
                cert = CMS_CERT, root_cert = CMS_CERT,
            }))
            local plain = "cms original text"
            local signed = assert(cms:sign(plain))
            ngx.say(cms:verify(signed) == plain)
            local info = assert(cms:PEM_read_CMS(signed))
            local der = assert(cms:i2d_CMS_ContentInfo(info))
            local decoded = assert(cms:d2i_CMS_ContentInfo(der))
            ngx.say(cms:verify(assert(cms:PEM_write_CMS(decoded))) == plain)
            collectgarbage("collect")
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

=== TEST 2: CMS rejects modified signed content
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local cms = assert(require("resty.cms").new({
                private_key = CMS_KEY, sign_cert = CMS_CERT,
                cert = CMS_CERT, root_cert = CMS_CERT,
            }))
            local signed = assert(cms:sign("cms original text"))
            local encoded = assert(signed:match("BEGIN CMS%-%-%-%-%-%s*(.-)%s*%-%-%-%-%-END CMS"))
            local der = assert(ngx.decode_base64((encoded:gsub("%s", ""))))
            local tampered, count = der:gsub("cms original text", "cms modified text", 1)
            assert(count == 1)
            local pem = "-----BEGIN CMS-----\n" .. ngx.encode_base64(tampered) .. "\n-----END CMS-----\n"
            local result, err = cms:verify(pem)
            ngx.say(result == nil)
            ngx.say(err ~= nil and #err > 0)
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

=== TEST 3: CMS preserves binary data and empty plaintext
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local cms = assert(require("resty.cms").new({
                private_key = CMS_KEY, sign_cert = CMS_CERT,
                cert = CMS_CERT, root_cert = CMS_CERT,
            }))
            for _, plain in ipairs({"a" .. string.char(0) .. "b\nc\r\nd", ""}) do
                ngx.say(cms:decrypt(assert(cms:encrypt(plain))) == plain)
                ngx.say(cms:verify(assert(cms:sign(plain))) == plain)
            end
        }
    }
--- request
GET /t
--- response_body
true
true
true
true
--- error_code: 200
--- no_error_log
[error]
