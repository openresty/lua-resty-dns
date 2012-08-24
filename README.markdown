Name
====

lua-resty-dns - Lua DNS resolver for the ngx_lua based on the cosocket API

Status
======

This library is already usable but is still considered experimental.

The API is still in flux and will change without notice.

Description
===========

This Lua library provies a DSN resolver for the ngx_lua nginx module:

http://wiki.nginx.org/HttpLuaModule

This Lua library takes advantage of ngx_lua's cosocket API, which ensures
100% nonblocking behavior.

Note that at least [ngx_lua 0.5.12](https://github.com/chaoslawful/lua-nginx-module/tags) or [ngx_openresty 1.2.1.11](http://openresty.org/#Download) is required.

Also, the [bit library](http://bitop.luajit.org/) is also required. If you're using LuaJIT 2.0 with ngx_lua, then the `bit` library is already available by default.

Synopsis
========

    lua_package_path "/path/to/lua-resty-dns/lib/?.lua;;";

    server {
        location = /dns {
            content_by_lua '
                local resolver = require "resty.dns.resolver"
                local r, err = resolver:new{
                    nameservers = {"8.8.8.8", {"8.8.4.4", 53} },
                    retrans = 5,  -- 5 retransmissions on receive timeout
                    timeout = 2000,  -- 2 sec
                }

                if not r then
                    ngx.say("failed to instantiate the resolver: ", err)
                    return
                end

                local answers, err = r:query("www.google.com")
                if not answers then
                    ngx.say("failed to query the DNS server: ", err)
                    return
                end

                for i = 1, #answers do
                    local ans = answers[i]
                    ngx.say(ans.name, " ", ans.address or ans.cname,
                            " type:", ans.type, " class:", ans.class,
                            " ttl:", ans.ttl)
                end
            ';
        }
    }

Methods
=======

new
---
`syntax: r, err = resty.dns.resolver:new(opts)`

Creates a dns.resolver object. Returns `nil` and an message string on error.

It accepts a `opts` table argument. The following options are supported:

* `nameservers`
	a list of nameservers to be used. Each nameserver entry can be either a single hostname string or a table holding both the hostname string and the port number. The nameserver is picked up by a simple round-robin algorithm for each `query` method call. This option is required.
* `retrans`
	the total number of times of retransmitting the DNS request when receiving a DNS response times out according to the `timeout` setting. Default to `5` times. When trying to retransmit the query, the next nameserver according to the round-robin algorithm will be picked up.
* `timeout`
	the time in milliseconds for waiting for the respond for a single attempt of request transmition. note that this is ''not'' the maximal total waiting time before giving up, the maximal total waiting time can be calculated by the expression `timeout x retrans`. The `timeout` setting can also be changed by calling the `set_timeout` method. The default `timeout` setting is 2000 milliseconds, or 2 seconds.
* `no_recurse`
	a boolean flag controls whether to disable the "recursion desired" (RD) flag in the UDP request. Default to `false`.

query
-----
`syntax: answers, err = r:query(name, options?)`

Performs a DNS standard query to the nameservers specified by the `new` method,
and returns all the answer records in an array-like Lua table. In case of errors, it will
return `nil` and a string describing the error instead.

Each entry in the `answers` returned table value is also a hash-like Lua table
which usually takes some of the following fields:

* `name`
	The resource record name.
* `type`
	The current resource record type, possible values are `1` (`TYPE_A`), `5` (`TYPE_CNAME`), `28` (`TYPE_AAAA`), and any other values allowed by RFC 1035.
* `address`
	The IPv4 or IPv6 address in their textual representations when the resource record type is either `1` (`TYPE_A`) or `28` (`TYPE_AAAA`), respectively. Secussesive 16-bit zero groups in IPv6 addresses will not be compressed by default, if you want that, you need to call the `compress_ipv6_addr` static method instead.
* `cname`
	The (decoded) record data value for `CNAME` resource records. Only present for `CNAME` records.
* `ttl`
	The time-to-live (TTL) value in seconds for the current resource record.
* `class`
	The current resource record class, possible values are `1` (`CLASS_IN`) or any other values allowed by RFC 1035.
* `preference`
	The preference integer number for `MX` resource records. Only present for `MX` type records.
* `exchange`
	The exchange domain name for `MX` resource records. Only present for `MX` type records.
* `nsdname`
	A domain-name which specifies a host which should be authoritative for the specified class and domain. Usually present for `NS` type records.
* `rdata`
	The raw resource data (RDATA) for resource records that are not recognized.
* `txt`
	The record value for `TXT` records.
* `ptrdname`
	The record value for `PTR` records.

This method also takes an optional `options` argument table, which takes the following fields:

* `qtype`
	The type of the question. Possible values are `1` (`TYPE_A`), `5` (`TYPE_CNAME`), `28` (`TYPE_AAAA`), or any other QTYPE value specified by RFC 1035 and RFC 3596. Default to `1` (`TYPE_A`).

When data truncation happens, the resolver will automatically retry using the TCP transport mode
to query the current nameserver. All TCP connections are short lived.

tcp_query
---------
`syntax: answers, err = r:tcp_query(name, options?)`

Just like the `query` method, but enforce the TCP transport mode instead of UDP.

All TCP connections are short lived.

Here is an example:

    local resolver = require "resty.dns.resolver"

    local r, err = resolver:new{
        nameservers = { "8.8.8.8" }
    }
    if not r then
        ngx.say("failed to instantiate resolver: ", err)
        return
    end

    local ans, err = r:tcp_query("www.google.com", { qtype = r.TYPE_A })
    if not ans then
        ngx.say("failed to query: ", err)
        return
    end

    local cjson = require "cjson"
    ngx.say("records: ", cjson.encode(ans))

set_timeout
-----------
`syntax: r:set_timeout(time)`

Overrides the current `timeout` setting by the `time` argument in milliseconds for all the nameserver peers.

compress_ipv6_addr
------------------
`syntax: compressed = resty.dns.resolver.compress_ipv6_addr(address)`

Compresses the successive 16-bit zero groups in the textual format of the IPv6 address.

For example,

    local resolver = require "resty.dns.resolver"
    local compress = resolver.compress_ipv6_addr
    local new_addr = compress("FF01:0:0:0:0:0:0:101")

will yield `FF01::101` in the `new_addr` return value.

Constants
=========

TYPE_A
------

The `A` resource record type, equal to the decimal number `1`.

TYPE_NS
-------

The `NS` resource record type, equal to the decimal number `2`.

TYPE_CNAME
----------

The `CNAME` resource record type, equal to the decimal number `5`.

TYPE_PTR
--------

The `PTR` resource record type, equal to the decimal number `12`.

TYPE_MX
-------

The `MX` resource record type, equal to the decimal number `15`.

TYPE_TXT
--------

The `TXT` resource record type, equal to the decimal number `16`.

TYPE_AAAA
---------
`syntax: typ = r.TYPE_AAAA`

The `AAAA` resource record type, equal to the decimal number `28`.

CLASS_IN
--------
`syntax: class = r.CLASS_IN`

The `Internet` resource record type, equal to the decimal number `1`.

Limitations
===========

* This library cannot be used in code contexts like set_by_lua*, log_by_lua*, and
header_filter_by_lua* where the ngx_lua cosocket API is not available.
* The `resty.dns.resolver` object instance cannot be stored in a Lua variable at the Lua module level,
because it will then be shared by all the concurrent requests handled by the same nginx
 worker process (see
http://wiki.nginx.org/HttpLuaModule#Data_Sharing_within_an_Nginx_Worker ) and
result in bad race conditions when concurrent requests are trying to use the same `resty.dns.resolver` instance.
You should always initiate `resty.dns.resolver` objects in function local
variables or in the `ngx.ctx` table. These places all have their own data copies for
each request.

TODO
====

* Concurrent (or parallel) query mode
* Better support for other resource record types like `SPF`.

Author
======

Yichun "agentzh" Zhang (章亦春) <agentzh@gmail.com>

Copyright and License
=====================

This module is licensed under the BSD license.

Copyright (C) 2012, by Yichun "agentzh" Zhang (章亦春) <agentzh@gmail.com>.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

See Also
========
* the ngx_lua module: http://wiki.nginx.org/HttpLuaModule
* the [lua-resty-memcached](https://github.com/agentzh/lua-resty-memcached) library.
* the [lua-resty-redis](https://github.com/agentzh/lua-resty-redis) library.
* the [lua-resty-mysql](https://github.com/agentzh/lua-resty-mysql) library.

