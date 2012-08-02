# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket;
use Cwd qw(cwd);

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;;";
    lua_package_cpath "/usr/local/openresty-debug/lualib/?.so;/usr/local/openresty/lualib/?.so;;";
};

$ENV{TEST_NGINX_RESOLVER} = '8.8.8.8';

#no_long_string();

run_tests();

__DATA__

=== TEST 1: basic
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new()
            if not r then
                ngx.say("failed to instantiate resolver: ", err)
                return
            end

            local host = "$TEST_NGINX_RESOLVER"
            local ok, err = r:connect(host, 53)
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            local ans, err = r:query("www.google.com", r.TYPE_A)
            if not ans then
                ngx.say("failed to query: ", err)
                return
            end

            local cjson = require "cjson"
            ngx.say("records: ", cjson.encode(ans))

            local ok, err = r:close()
            if not ok then
                ngx.say("failed to close resolver: ", err)
                return
            end
        ';
    }
--- request
GET /t
--- response_body_like chop
^arecords: \[.*?"address":"(?:\d{1,3}\.){3}\d+".*?\]$
--- no_error_log
[error]

