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
                local resolv = require "resty.dns.resolver"
                local resolv = resolv:new()

                resolv:set_timeout(1000) -- 1 sec

                -- or connect to a unix domain socket file listened
                -- by a dns.resolver server:
                --     local ok, err = resolv:connect("unix:/path/to/dns.sock")

                local ok, err = resolv:connect("8.8.8.8", 53)
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                -- other type argument can be "TYPE_AAAA" and "TYPE_CNAME"
                local answers, err = resolv:query("www.google.com", resolv.TYPE_A)
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

                local ok, err = resolv:close()
                if not ok then
                    ngx.say("failed to close: ", err)
                    return
                end
            ';
        }
    }

Methods
=======

new
---
`syntax: resolv, err = dns.resolver:new()`

Creates a dns.resolver object. Returns `nil` on error.

connect
-------
`syntax: ok, err = resolv:connect(host, port)`

`syntax: ok, err = resolv:connect("unix:/path/to/unix.sock")`

Attempts to "connect" to the remote host and port that the DNS nameserver is listening on or a local unix domain socket file listened by the DNS nameserver, using a UDP or unix datagram socket.

close
-----
`syntax: ok, err = resolv:close()`

Closes the current UDP/datagram socket and returns the status.

In case of success, returns `1`. In case of errors, returns `nil` with a string describing the error.

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

