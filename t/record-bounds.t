# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(2);
plan tests => repeat_each() * blocks() * 3;

my $pwd = cwd();
our $HttpConfig = qq{lua_package_path "$pwd/lib/?.lua;;";};

no_long_string();
run_tests();

__DATA__

=== TEST 1: short A RDATA
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x21\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: truncated
--- no_error_log
[error]



=== TEST 2: short AAAA RDATA
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x21\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10\x7f\x00"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: truncated
--- no_error_log
[error]



=== TEST 3: short TXT RDATA
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x21\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x06\x05\x61"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: truncated
--- no_error_log
[error]



=== TEST 4: short SOA RDATA
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x21\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x16\x00\x00"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: truncated
--- no_error_log
[error]



=== TEST 5: short unknown RDATA
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x21\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\xff\x00\x00\x01\x00\x00\x00\x3c\x00\x0a\x61\x62"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: truncated
--- no_error_log
[error]



=== TEST 6: short RR header after long owner
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x2b\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\x14\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x00\x00\x01"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: truncated
--- no_error_log
[error]



=== TEST 7: short authority RDATA
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {authority_section = true})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x21\x00\x7d\x81\x80\x00\x01\x00\x00\x00\x01\x00\x00\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10\x61\x62"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: truncated
--- no_error_log
[error]



=== TEST 8: short additional RDATA
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {additional_section = true})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x21\x00\x7d\x81\x80\x00\x01\x00\x00\x00\x00\x00\x01\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x61\x62"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: truncated
--- no_error_log
[error]



=== TEST 9: skipped authority is checked
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {additional_section = true})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x31\x00\x7d\x81\x80\x00\x01\x00\x00\x00\x01\x00\x01\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x61\x62\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: truncated
--- no_error_log
[error]



=== TEST 10: empty TXT RDATA
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x1f\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x00"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: bad txt record value length: 0
--- no_error_log
[error]



=== TEST 11: TXT first string crosses record
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x21\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x02\x02\x61"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: bad txt record string length
--- no_error_log
[error]



=== TEST 12: TXT later string crosses record
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x22\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x03\x00\x02\x61"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: bad txt record string length
--- no_error_log
[error]



=== TEST 13: SOA integers cross record
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x34\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x3c\x00\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: bad SOA record value length: 21
--- no_error_log
[error]



=== TEST 14: CNAME encoding crosses record
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x24\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x01\x03\x61\x62\x63\x00"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: bad cname record length: 5 ~= 1
--- no_error_log
[error]



=== TEST 15: valid compressed CNAME
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x21\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x02\xc0\x0c"
--- request
GET /t
--- response_body
answer: x
--- no_error_log
[error]



=== TEST 16: valid A record
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x23\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
--- request
GET /t
--- response_body
answer: 127.0.0.1
--- no_error_log
[error]



=== TEST 17: truncated owner label
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x20\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\x20\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: truncated
--- no_error_log
[error]



=== TEST 18: owner compression pointer loop
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local resolver = require "resty.dns.resolver"
            local r, err = resolver:new{nameservers={{"127.0.0.1", 1953}}}
            if not r then
                ngx.say("new: ", err)
                return
            end

            r._id = 125
            local ans, err = r:tcp_query("x", {})
            if ans then
                ngx.say("answer: ", ans[1].address or ans[1].cname)

            else
                ngx.say("error: ", err)
            end

            r:destroy()
        }
    }
--- tcp_listen: 1953
--- tcp_reply eval
"\x00\x23\x00\x7d\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x01\x78\x00\x00\x01\x00\x01\xc0\x13\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
--- request
GET /t
--- response_body
error: failed to parse the reply from the TCP server 127.0.0.1:1953: too many compression pointers
--- no_error_log
[error]
