Name
====

lua-resty-dns - Lua DNS resolver for the ngx_lua based on the cosocket API

Status
======

This library is still under early development, and but usable yet.

The API is still in flux and will change without notice.

Description
===========

This Lua library provies a DSN resolver for the ngx_lua nginx module:

http://wiki.nginx.org/HttpLuaModule

This Lua library takes advantage of ngx_lua's cosocket API, which ensures
100% nonblocking behavior.

Note that at least [ngx_lua 0.5.11](https://github.com/chaoslawful/lua-nginx-module/tags) or [ngx_openresty 1.2.1.9](http://openresty.org/#Download) is required.

Synopsis
========

    lua_package_path "/path/to/lua-resty-dns/lib/?.lua;;";

    server {
        location /test {
            content_by_lua '
                local resolver = require "resty.dns.resolver"
                local r = resolver:new{
                    nameservers = {
                        {"8.8.8.8", 53},
                        "8.8.4.4",
                    }
                }

                r:set_timeout(1000) -- 1 sec

                -- other query types are r.TYPE_AAAA and r.TYPE_CNAME
                local answers, err = r:query("www.google.com",
                        { qtype = r.TYPE_A })

                if not answers then
                    ngx.say("failed to query: ", err)
                    return
                end

                for ans in answers do
                    local typ = ans.typ
                    local addr = ans.address
                    local class = ans.class
                    local cname = ans.cname
                    local ttl = ans.ttl
                    -- process these fields
                end
            ';
        }
    }

Methods
=======

new
---
`syntax: r, err = dns.resolver:new(opts)`

Creates a dns.resolver object. Returns `nil` and an message string on error.

It accepts a `opts` table argument. The following options are supported:

* `nameservers`
: a list of nameservers to be used. Each nameserver entry can be either a single hostname string or a table holding both the hostname string and the port number.

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

Author
======

Zhang "agentzh" Yichun (章亦春) <agentzh@gmail.com>

Copyright and License
=====================

This module is licensed under the BSD license.

Copyright (C) 2012, by Zhang "agentzh" Yichun (章亦春) <agentzh@gmail.com>.

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

