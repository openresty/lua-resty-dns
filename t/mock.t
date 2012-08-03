# vim:set ft= ts=4 sw=4 et:

use lib 't';
use TestDNS;
use Cwd qw(cwd);

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;;";
    lua_package_cpath "/usr/local/openresty-debug/lualib/?.so;/usr/local/openresty/lualib/?.so;;";
};

$ENV{TEST_NGINX_RESOLVER} = '8.8.8.8';

no_long_string();

run_tests();

__DATA__

=== TEST 1: single answer reply
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local resolver = require "resty.dns.resolver"

            local r, err = resolver:new{
                nameservers = { {"127.0.0.1", 1953} }
            }
            if not r then
                ngx.say("failed to instantiate resolver: ", err)
                return
            end

            r._id = 125

            local ans, err = r:query("www.google.com", { qtype = r.TYPE_A })
            if not ans then
                ngx.say("failed to query: ", err)
                return
            end

            local cjson = require "cjson"
            ngx.say("records: ", cjson.encode(ans))
        ';
    }
--- udp_listen: 1953
--- udp_reply dns
{
    id => 125,
    opcode => 1,
    qname => 'www.google.com',
    answer => [{ name => "www.google.com", ipv4 => "127.0.0.1", ttl => 123456 }],
}
--- request
GET /t
--- response_body
records: [{"address":"127.0.0.1","class":1,"ttl":123456,"name":"www.google.com","typ":1}]
--- no_error_log eval
[error]



=== TEST 2: empty answer reply
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local resolver = require "resty.dns.resolver"

            local r, err = resolver:new{
                nameservers = { {"127.0.0.1", 1953} }
            }
            if not r then
                ngx.say("failed to instantiate resolver: ", err)
                return
            end

            r._id = 125

            local ans, err = r:query("www.google.com", { qtype = r.TYPE_A })
            if not ans then
                ngx.say("failed to query: ", err)
                return
            end

            local cjson = require "cjson"
            ngx.say("records: ", cjson.encode(ans))
        ';
    }
--- udp_listen: 1953
--- udp_reply dns
{
    id => 125,
    qname => 'www.google.com',
    opcode => 1,
}
--- request
GET /t
--- response_body
records: {}
--- no_error_log eval
[error]



=== TEST 3: one byte reply
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local resolver = require "resty.dns.resolver"

            local r, err = resolver:new{
                nameservers = { {"127.0.0.1", 1953} }
            }
            if not r then
                ngx.say("failed to instantiate resolver: ", err)
                return
            end

            local ans, err = r:query("www.google.com", { qtype = r.TYPE_A })
            if not ans then
                ngx.say("failed to query: ", err)
                return
            end

            local cjson = require "cjson"
            ngx.say("records: ", cjson.encode(ans))
        ';
    }
--- udp_listen: 1953
--- udp_reply: a
--- request
GET /t
--- response_body
failed to query: truncated
--- no_error_log
[error]



=== TEST 4: empty reply
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local resolver = require "resty.dns.resolver"

            local r, err = resolver:new{
                nameservers = { {"127.0.0.1", 1953} }
            }
            if not r then
                ngx.say("failed to instantiate resolver: ", err)
                return
            end

            r._id = 125

            local ans, err = r:query("www.google.com", { qtype = r.TYPE_A })
            if not ans then
                ngx.say("failed to query: ", err)
                return
            end

            local cjson = require "cjson"
            ngx.say("records: ", cjson.encode(ans))
        ';
    }
--- udp_listen: 1953
--- udp_reply:
--- request
GET /t
--- response_body
failed to query: truncated
--- no_error_log eval
[error]

