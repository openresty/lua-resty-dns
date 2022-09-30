-- Copyright (C) Yichun Zhang (agentzh)


-- local socket = require "socket"

local ok, b64 = pcall(require,"ngx.base64")
if not ok then
    return false
end

local ok, bit = pcall(require, "bit")
if not ok then
    return false
end

local ok, wire = pcall(require, "resty.dns.wireformat")
if not ok then
    return false
end

local ok, new_tab = pcall(require, "table.new")
if not ok then
    new_tab = function (narr, nrec) return {} end
end

local udp = ngx.socket.udp
local tcp = ngx.socket.tcp
local rand = math.random
local char = string.char
local byte = string.byte
local find = string.find
local gsub = string.gsub
local sub = string.sub
local rep = string.rep
local format = string.format
local insert = table.insert
local concat = table.concat
local re_sub = ngx.re.sub
local re_match = ngx.re.match
local re_find = ngx.re.find
local log = ngx.log
local DEBUG = ngx.DEBUG
local unpack = unpack
local setmetatable = setmetatable
local type = type
local ipairs = ipairs
local agent = "ngx_lua/" .. ngx.config.ngx_lua_version
local str_lower = string.lower
local tolower = string.lower
local ngx_get = ngx.HTTP_GET
local ngx_post = ngx.HTT_POST
local band = bit.band
local wire_build = wire.build_request
local wire_parse = wire.parse_response
local bit = require "bit"
local band = bit.band
local rshift = bit.rshift
local lshift = bit.lshift

local arpa_tmpl = new_tab(72, 0)

local IP6_ARPA = "ip6.arpa"

for i = 1, #IP6_ARPA do
    arpa_tmpl[64 + i] = byte(IP6_ARPA, i)
end

for i = 2, 64, 2 do
    arpa_tmpl[i] = DOT_CHAR
end

local COLON_CHAR = byte(":")

local _M = {
    _VERSION    = '0.22',
    TYPE_A      = wire.TYPE.A,
    TYPE_NS     = wire.TYPE.NS,
    TYPE_CNAME  = wire.TYPE.CNAME,
    TYPE_SOA    = wire.TYPE.SOA,
    TYPE_PTR    = wire.TYPE.PTR,
    TYPE_MX     = wire.TYPE.MX,
    TYPE_TXT    = wire.TYPE.TXT,
    TYPE_AAAA   = wire.TYPE.AAAA,
    TYPE_SRV    = wire.TYPE.SRV,
    TYPE_SPF    = wire.TYPE.SPF,
    CLASS_IN    = wire.CLASS.IN,
    SECTION_AN  = wire.SECTION.AN,
    SECTION_NS  = wire.SECTION.NS,
    SECTION_AR  = wire.SECTION.AR,
    MODE        = {
        UDP     = 1,
        TCP     = 2,
        UDP_TCP = 3,
        DOT     = 4,
        DOH     = 8
    }
}

local MODE_UDP = _M.MODE.UDP
local MODE_TCP = _M.MODE.TCP
local MODE_DOT = _M.MODE.DOT
local MODE_DOH = _M.MODE.DOH
local MODE_UDP_TCP = _M.MODE.UDP_TCP

local DOH_METHOD = {
    GET  = ngx_get,
    POST = ngx_post
}

local function _is_ip(str)
    if type(str) ~= "string" then
        return false
    end
    
    local ret, err = re_match(str,"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
    
    if ret then
        return true
    end
    
    return false, err
end

local function _gen_id() -- (self)
    --local id = self._id   -- for regression testing
    --if id then
    --    return id
    --end
    return rand(0, 65535)   -- two bytes
end

----------------------[[ private implementation ]]----------------------------------------

local function _build_wire_request(self, qname, id, no_recurse, opts)    
    return wire_build(qname,id,no_recurse,opts)
end

local function _parse_wire_response(self, data, id, opts)
    return wire_parse(data, id, opts)
end

local function _build_post_wire_request(self, qname, id, no_recurse, opts)
    local opts = {
        method = ngx_post, 
        body = wire_build(qname, id, self.no_recurse, opts)
    }
    
    return id, opts
end

local function _build_post_json_request(self, qname, id, no_recurse, opts)
    local opts = {}
    
    return opts
end

local function _build_get_json_request(self, qname, id, no_recurse, opts)
    local opts = {
        method = ngx_get, 
        param = self.doh_encode and b64.encode_base64url(qname) or qname
    }
    
    return opts
end

local function _build_get_wire_request(self, qname, id, no_recurse, opts)
    local opts = {
        method = ngx_get, 
        param = self.doh_encode and b64.encode_base64url(qname) or qname
    }
    
    return opts
end

local function _parse_doh_wire_response(self, qname, id, no_recurse, opts)
    
    
end

local function _parse_doh_json_response(self, qname, id, no_recurse, opts)
    
end


--[[ sockets implementation ]]--

local function _sock_write(self, data)
    return self.fd:send(data)
end

local function _sock_read(self)
    return self.fd:receive()
end

local function _sock_close(self)
    return self.fd:close()
end

local function _sock_settimeout(self,timeout)
    return self:settimeout(timeout) 
end

--[[ udp stream implementation ]]--
local function _udp_open(self, host, port, opts, ip)
    local fd = udp()
    local addr = ip or self.ip or host or self.host
    local pnum = port or self.port
    local setts = opts or self.opts
    local timeout = setts and setts.timeout or 2000
        
    fd:settimeout(timeout)
        
    local ok, err = fd:setpeername(addr,pnum)
    if not ok then
        return false, err
    end
        
    self.fd = fd
    --self.id = _gen_id()
    
    return true
end


local _udp_stream_mt = {
    open        = _udp_open, --_udp_cached_open(),
    read        = _sock_read,
    write       = _sock_write,
    close       = _sock_close,
    settimeout  = _sock_settimeout
}

--[[ tcp stream implementation ]]--
local function _tcp_open(self, host, port, opts, ip)
    local fd = tcp()
    local addr = ip or self.ip or host or self.host
    local pnum = port or self.port
    local setts = opts or self.opts
    local timeout = setts and setts.timeout or 2000
    
    fd:settimeout(timeout)

    local ok, err = fd:connect(addr,pnum)
    if not ok then
        return false, err
    end
    
    self.fd = fd
    --self.id = _gen_id()
        
    return true
end

local function _tcp_sock_write(self, data)
    local query = concat(data,'')
    local len = #query
    local len_hi = char(rshift(len, 8))
    local len_lo = char(band(len, 0xff))
    
    return self.fd:send({len_hi, len_lo, query})
end

local function _tcp_sock_read(self)
    local buf, err = self.fd:receive(2)
    local len_hi = byte(buf, 1)
    local len_lo = byte(buf, 2)
    local len = lshift(len_hi, 8) + len_lo
    
    return self.fd:receive(len)
end

local _tcp_stream_mt = {
    open        = _tcp_open,
    read        = _tcp_sock_read,
    write       = _tcp_sock_write,
    close       = _sock_close,
    settimeout  = _sock_settimeout
}

-------------[[ encrypted ssl/tls tcp stream ]]------------

local function _enc_tcp_open(self, host, port, opts, ip)
    local addr = ip or host
    local ok, err = _tcp_open(self,addr,port,opts,ip)
    if not ok then
        return false, err
    end
    
    if self.fd:getreusedtimes() == 0 then
        local session, err = self.fd:sslhandshake(nil,host)
        if not session then
            return false, err
        end
    end
    
    return true
end

local _enc_tcp_stream_mt = {
    open        = _enc_tcp_open,
    read        = _sock_read,
    write       = _sock_write,
    close       = _sock_close,
    settimeout  = _sock_settimeout
}

-----------------[[ streams ]]---------------------------

local function _new_stream_int(class,mt)
    return setmetatable({
        host = class.host,
        port = class.port,
        ip   = class.ip
    },{ __index = mt})
end


local function _new_udp_stream(class)
   return _new_stream_int(class,_udp_stream_mt)
end


local function _new_tcp_stream(class)
    return _new_stream_int(class,_tcp_stream_mt)
end


local function _new_enc_stream(class)
    return _new_stream_int(class,_enc_tcp_stream_mt)
end


local _udp_pimpl = {
    build   = _build_wire_request, -- (qname, id, no_recurse, opts)
    parse   = _parse_wire_response, --(buf, id, opts),
    stream  = _new_udp_stream
}

local _tcp_pimpl = {
    build   = _build_wire_request,  -- (qname, id, no_recurse, opts)
    parse   = _parse_wire_response, --(buf, id, opts),
    stream  = _new_tcp_stream
}

local _udp_tcp_pimpl = {
    build   = _build_wire_request, -- (qname, id, no_recurse, opts)
    parse   = _parse_wire_response, --(buf, id, opts),
    stream  = _new_udp_stream
}

local _dot_pimpl = {
    build   = _build_wire_request, -- (qname, id, no_recurse, opts)
    parse   = _parse_wire_response, -- (buf, id, opts),
    stream  = _new_enc_stream
}

local _doh_wire_get_pimpl = {
    build   = _build_get_wire_request,
    parse   = _parse_wire_response,
    stream  = _new_enc_stream
}

local _doh_json_get_pimpl = {
    build   = _build_get_json_request,
    parse   = _parse_json_response,
    stream  = _new_enc_stream
}

local _doh_wire_post_pimpl = {
    build   = _build_post_wire_request,
    parse   = _parse_doh_wire_response,
    stream  = _new_enc_stream
}

local doh_json_post_pimpl = {
    build   = _build_post_json_request,
    parse   = _parse_doh_json_response,
    stream  = _new_enc_stream
}

---------------------------[[ server parsers ]]-------------------------------

local function _udp_tcp_server_parser_int(server, opts, pimpl, mode)
    local host, port
        
    if type(server) == 'table' then
        host = server[1]
        port = server[2] or 53
    else
        host = server
        port = 53
    end

    return setmetatable({ 
        host    = host, 
        port    = port,  
        mode    = mode
    }, { __index = pimpl })
end


local function _udp_server_parser(server, opts)
    return _udp_tcp_server_parser_int(server,opts,_udp_pimpl, MODE_UDP)
end


local function _tcp_server_parser(server, opts)
    return _udp_tcp_server_parser_int(server,opts,_tcp_pimpl, MODE_TCP)
end


local function _udp_tcp_server_parser(server, opts)
    return _udp_tcp_server_parser_int(server,opts,_udp_pimpl, MODE_UDP_TCP)
end


local function _dot_server_parser(server, opts)
    local res, err = _tcp_servers_parser(server,opts)
    if not res then
        return nil, err 
    end
    
    return setmetatable({ 
        host = host, 
        port = port,  
        mode = MODE_DOT
    }, { __index = _dot_pimpl })
end


local function _doh_server_parser(server, opts)
    local method = (type(server) == 'table') and server.method or 'GET'
    method = DOH_METHOD[method]
    if not method then
        return false, "invalid DoH mode specified"
    end 
            
    local res, err = _tcp_server_parser(server, opts)
    if not res then
       return false, err 
    end
    
    local url
    local method
    local ct
    local ac
        
    if type(server) == 'table' then
        url = server[1] or server.url
        method = server[2] or server.method or ngx_get
        ct = server[3] or server.ct or 'application/dns-message'
        ac = server[4] or server.ac or 'application/dns-message'   
    else
        url = server
        method = ngx_get
        ct = 'application/dns-message'
        ac = 'application/dns-message'
    end
    
    local captures, err = re_match(url,"^((https?)(://))?([A-Za-z0-9\\.-]+)(:[1-9][0-9]*)?(/.+)$")
    if not captures then
        return false, err
    end
        
    local host = captures[4]
    local ssl = (captures[1] == 'https://') and true or false
    local port
        
    if captures[5] then
        port = tonumber(sub(captures[5],2))
    elseif not ssl then
        port = 80
    else
        port = 443
    end
        
    if not port then
        return false, "invalid port specified"
    end
    
    local hoststr
    if (ssl and port ~= 443) or (not ssl and port ~= 80) then
        hoststr = host..":"..port
    else
        hoststr = host
    end
    
    local query = {
        'Host: '..hoststr..'\r\n',
        'User-Agent: '..agent..'\r\n',
        'Connection: keep-alive'..'\r\n',
        'Accept: '..ac..'\r\n'
    }

    insert(query,(method == ngx_post) and 'Content-Type: '..ct..'\r\n' or "\r\n")

    return setmetatable({
        host    = host,
        port    = port,
        url     = captures[6],
        ssl     = ssl,
        query   = query, 
        mode    = MODE_DOH
    }, { __index = _doh_pimpl })
end

local _server_parser_tbl = {
    { MODE_UDP,     _udp_server_parser      },
    { MODE_TCP,     _tcp_server_parser      },
    { MODE_UDP_TCP, _udp_tcp_server_parser  },
    { MODE_DOT,     _dot_server_parser      },
    { MODE_DOH,     _doh_server_parser      }
}

----------------------------[[ servers array ]]------------------------------------

local function _servers_at(self, at)
    return self.servers[at]
end


local function _servers_size(self) 
    return #self.servers 
end


local function _servers_array_new(opts)
    log(ngx.ERR,"NEW SERVER ARRAY")           
    
    local servers = opts.nameservers
    local pservers = {}
    local n = #servers
    local pn = #_server_parser_tbl
    
    for i = 1, n do
        local server = servers[i]
        local mode = (type(server) == 'table') and server.mode or MODE_UDP_TCP
        local pserver_tbl, err
        
        for k = 1, pn do
            local f_tbl = _server_parser_tbl[k]
            
            if f_tbl[1] == mode then
                local pserver_tbl, err = f_tbl[2](server, opts)
                 
                if not pserver_tbl then
                    return nil, "failed to create server at: "..k.."with error: "..err
                end
                
                insert(pservers,pserver_tbl)
                break
            end
        end
        
    end
    
    local servers_mt = {
        size        = _servers_size,
        at          = _servers_at
    }
    
    local servers_tbl = { 
        current = no_random and 1 or rand(1, #servers),
        servers = pservers
    }
    
    return setmetatable(servers_tbl, { __index = servers_mt })
end

--------------------------------------------------------------------------------

local function _generic_query()

end

local function answers__to_string(self)
        local ret =''
        for k,v in pairs(self) do
            local typ = type(v)
            if typ ~= 'function' then
                if typ == 'table' then
                    ret = ret..'[\r\n'
                    ret = ret..answers__to_string(v)
                    ret = ret..']\r\n'
                else
                    ret = ret..k..': '..v..'\r\n'
                end
            end
        end
        return ret
    end

local answers_mt = {
    __tostring = answers__to_string
}

--[[
Perform DNS TCP query over connected socket
]]
local function _tcp_query(self, server, qname, no_recurse, opts)
    if server == nil or qname == nil then
        return nil, 'invalid arguments', nil
    end
    
    local srv, err = _tcp_server_parser(server, opts)
    if srv == nil then
        return nil, err, nil
    end
    
    local id = _gen_id()
    local query, err = srv:build(qname,id,no_recurse, opts)
    if query == nil then
        return nil, err, nil
    end
    
    local stream, err = srv:stream()
    if stream == nil then
        return nil, err, nil
    end

    local ok, err = stream:open()
    if not ok then
        return nil, err, nil
    end
    
    local bytes, err = stream:write(query)
    if not bytes then
        return nil, "failed to send query to TCP server "
            .. stream.host .. ":" .. stream.port .. ": " .. err, nil
    end

    local buf, err = stream:read()
    if not buf then
        return nil, "failed to receive the reply length field from TCP server "
            .. stream.host, ":" .. stream.port.. ": " .. err, {}
    end

    local answers, err = srv:parse(buf,id)
    if not answers then
        return nil, err
    end
    
    return setmetatable(answers,answers_mt), nil, {}
end

local function _udp_query(self, server, qname, no_recurse, opts)
   if server == nil or qname == nil then
        return nil, 'invalid arguments', nil
    end
    
    local srv, err = _udp_server_parser(server, opts)
    if srv == nil then
        return nil, err, nil
    end
    
    local id = _gen_id()
    local query, err = srv:build(qname,id,no_recurse, opts)
    if query == nil then
        return nil, err, nil
    end
    
    local stream, err = srv:stream()
    if stream == nil then
        return nil, err, nil
    end

    local ok, err = stream:open()
    if not ok then
        return nil, err, nil
    end
    
    local bytes, err = stream:write(query)
    if not bytes then
        return nil, "failed to send query to UDP server "
            .. stream.host .. ":" .. stream.port .. ": " .. err, nil
    end

    local buf, err = stream:read()
    if not buf then
        return nil, "failed to receive the reply UDP server "
            .. stream.host, ":" .. stream.port.. ": " .. err, {}
    end

    local answers, err = srv:parse(buf,id)
    if not answers then
        return nil, err
    end

    return setmetatable(answers,answers_mt)
end


local function _dot_query(self, server, qname, no_recurse, opts)
    if server == nil or qname == nil then
        return nil, 'invalid arguments', nil
    end
    
    local srv, err = _dot_server_parser(server, opts)
    if srv == nil then
        return nil, err, nil
    end
    
    local id = _gen_id()
    local query, err = srv:build(qname,id,no_recurse, opts)
    if query == nil then
        return nil, err, nil
    end
    
    local stream, err = srv:stream()
    if stream == nil then
        return nil, err, nil
    end

    local ok, err = stream:open()
    if not ok then
        return nil, err, nil
    end
    
    local bytes, err = stream:write(query)
    if not bytes then
        return nil, "failed to send query to DoT server "
            .. stream.host .. ":" .. stream.port .. ": " .. err, nil
    end

    local buf, err = stream:read()
    if not buf then
        return nil, "failed to receive the reply DoT server "
            .. stream.host, ":" .. stream.port.. ": " .. err, {}
    end

    local answers, err = srv:parse(buf,id)
    if not answers then
        return nil, err
    end

    return setmetatable(answers,answers_mt)
end


--[[ local function _http_connect(sock,host)
    local ok, err = sock:connect(host[1], host[2])
    if not ok then
        return nil, "failed to connect to HTTP server "
        .. host[1] .. ":" .. host[2] .. ": " .. err
    end

    if host[4] and sock:getreusedtimes() == 0 then
        local session, err = sock:sslhandshake(nil,host[1])
        if not session then
            return nil, err
        end
    end

    return sock
end
]]--

local function _http_status_receive(sock)
    local line, err, partial = sock:receive("*l")
    if not line then
       return nil, nil, nil, "failed to read http header status line: "..err
    end

    local ret, err = re_match(line,"(HTTP/[0-3](\\.[0-1])?) ([1-5][0-9]{2}) ([A-Za-z ]+)")

    if not ret then
        return nil, nil, nil, "failed to parse http status with error: "..err
    end

    return ret[1], tonumber(ret[3]), ret[4]
end


local function _http_header_receive(sock)
    local ret = {}

    repeat
        local line, err = sock:receive("*l")
        if not line then
            return nil, err
        end

        local m, err = re_match(line, "([^:\\s]+):\\s*(.*)", "jo")
        if err then log(DEBUG, err) end

        if not m then
            break
        end

        local key = string.lower(m[1])
        local val = m[2]

        if ret[key] then
            if type(ret[key]) ~= "table" then
                ret[key] = { ret[key] }
            end
            insert(ret[key], tostring(val))
        else
            ret[key] = tostring(val)
        end
    until re_find(line, "^\\s*$", "jo")

    return ret
end


local function _http_header_send(sock, host, method, length, param)
    local hoststr

    -- HEADER

    local bytes, err = sock:send(query)

    if not bytes then
        return 0, err
    end

    return bytes
end


local function _http_body_receive(sock, header)
    local len = header["content-length"]

    if header["content-type"] ~= "application/dns-message" then
        return nil, "http query failed invalid Content-Type: "..header["content-type"]
    end

    local data, err = sock:receiveany(tonumber(len))

    if not data then
        return nil, "http query failed to receive body "..err
    end

    return data
end


local function _http_query(sock,host,opts)
    
    local sock, err = _http_connect(sock, host)
    if not sock then
        return nil, err
    end

    local bytes, err = _http_header_send(sock, host, opts.method, opts.body and #opts.body or 0, opts.param)
    if not bytes then
       return nil, err
    end

    if opts.body then
        local bytes, err = sock:send(opts.body)
        if not bytes or bytes < #opts.body then
            return nil, "http POST query failed body not sent"
        end
    end

    local version, status, reason, err = _http_status_receive(sock)

    if err then
        return nil, err
    end

    if status ~= 200 then
        return nil, "http query failed status code is: "..status.." reason: "..reason
    end

    local header, err = _http_header_receive(sock)
    if not header then
        return nil, err
    end

    local data, err = _http_body_receive(sock, header)
    if not data then
        return nil, err
    end

    sock:setkeepalive()

    return {
        status  = status,
        version = version,
        body = data
    }
end


local function _doh_query(qname, opts, tries, servers)
    --local sock = self.tcp_sock
    --if not sock then
    --    return nil, "not initialized"
    --end
    
    local servers = self.servers
    if not servers:size() then
        return nil, "no servers available"
    end

    local retrans = self.retrans
    if tries then
        tries[1] = nil
    end
    
    local method = self.doh_method
    local err

    --if method == ngx_post then
    --    id = _gen_id(self)
    --    opts = {
    --        method = ngx_post, 
    --        body = table.concat(_build_request(qname, id, self.no_recurse, opts))
    --    }
    --else
    --    opts = {
    --        method = ngx_get, 
    --        param = self.doh_encode and b64.encode_base64url(qname) or qname
    --    }
    --end
    
    for i = 1, retrans do
        local id, opts
        local server = servers:pick()
        
        local res, err = _http_query(sock, server, opts)
        if not res then
           return nil, err, tries
        end

        if res and res.status == 200 and res.body then
            local answers
            if method == ngx_get then
                local ident_hi = byte(res.body, 1)
                local ident_lo = byte(res.body, 2)
                id = lshift(ident_hi, 8) + ident_lo 
            end
            answers, err = _parse_response(res.body, id, opts)
            if answers then
                return answers, nil, tries
            end

            if err and err ~= "id mismatch" then
                break
            else
                log(DEBUG,"DoH query failed to parse response",err)
            end
        end

        if tries then
            tries[i] = err
            tries[i + 1] = nil -- ensure termination for user supplied table
        end
    end

    return nil, err, tries
end

local function _udp_tcp_query(qname, opts, tries, servers)
    if not servers then
        return nil, "not initialized"
    end

    --local id = _gen_id(self)

    local query, err = _build_request(qname, id, self.no_recurse, opts)
    if not query then
        return nil, err
    end

    -- local cjson = require "cjson"
    -- print("query: ", cjson.encode(concat(query, "")))

    local retrans = self.retrans
    if tries then
        tries[1] = nil
    end

    -- print("retrans: ", retrans)

    for i = 1, retrans do
        local sock = servers:pick_sock()
        
        local ok, err = sock:send(query)
        if not ok then
            local server = servers:current_server()
            err = "failed to send request to UDP server "
                .. concat(server, ":") .. ": " .. err

        else
            local buf

            for _ = 1, 128 do
                buf, err = sock:receive(4096)
                if err then
                    local server = servers:current_server()
                    err = "failed to receive reply from UDP server "
                        .. concat(server, ":") .. ": " .. err
                    break
                end

                if buf then
                    local answers
                    answers, err = _parse_response(buf, id, opts)
                    if err == "truncated" then
                        answers, err = _tcp_query(sock, query, id, opts, servers)
                    end

                    if err and err ~= "id mismatch" then
                        break
                    end

                    if answers then
                        return answers, nil, tries
                    end
                end
                -- only here in case of an "id mismatch"
            end
        end

        if tries then
            tries[i] = err
            tries[i + 1] = nil -- ensure termination for user supplied table
        end
    end

    return nil, err, tries
end


---------------------------[[ private functions ]]------------------------

local function _compress_ipv6_addr(addr)
    local addr = re_sub(addr, "^(0:)+|(:0)+$|:(0:)+", "::", "jo")
    if addr == "::0" then
        addr = "::"
    end
    
    return addr
end


local function _expand_ipv6_addr(addr)
    if find(addr, "::", 1, true) then
        local ncol, addrlen = 8, #addr
        
        for i = 1, addrlen do
            if byte(addr, i) == COLON_CHAR then
                ncol = ncol - 1
            end
        end
        
        if byte(addr, 1) == COLON_CHAR then
            addr = "0" .. addr
        end
        
        if byte(addr, -1) == COLON_CHAR then
            addr = addr .. "0"
        end
        
        addr = re_sub(addr, "::", ":" .. rep("0:", ncol), "jo")
    end
    
    return addr
end


local function _arpa_str(addr)
    if find(addr, ":", 1, true) then
        addr = _expand_ipv6_addr(addr)
        local idx, hidx, addrlen = 1, 1, #addr
        
        for i = addrlen, 0, -1 do
            local s = byte(addr, i)
            if s == COLON_CHAR or not s then
                for _ = hidx, 4 do
                    arpa_tmpl[idx] = ZERO_CHAR
                    idx = idx + 2
                end
                hidx = 1
            else
                arpa_tmpl[idx] = s
                idx = idx + 2
                hidx = hidx + 1
            end
        end
        
        addr = char(unpack(arpa_tmpl))
    else
        addr = re_sub(addr, [[(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})]],
                      "$4.$3.$2.$1.in-addr.arpa", "ajo")
    end
    
    return addr
end


------------------[[ public instance methods ]]---------------

local function _query(self, qname, opts, tries)
    log(ngx.ERR,"QUERY")
    
    local servers = self.servers
    if not servers then
        return nil, "not initialized"
    end
    
    local retrans = self.retrans
    -- print("retrans: ", retrans)
    if tries then
        tries[1] = nil
    end
    
    local id = _gen_id(self)
    local query, err = _build_wire_request(qname, id, self.no_recurse, opts)
    if not query then
        return nil, err
    end
    
    -- local cjson = require "cjson"
    -- print("query: ", cjson.encode(concat(query, "")))
    
    
    
    
    
    for i = 1, retrans do
        local sock = servers:pick()
        
        --[[ Abstract send ]]
        local ok, err = sock:send(query)
        if not ok then
            local server = servers:current_server()
            err = "failed to send request to UDP server "
            .. concat(server, ":") .. ": " .. err
            --[[ End Of Send ]]    
        else
            
            local buf
            for _ = 1, 128 do
                --[[ Receive ]]
                buf, err = sock:receive(4096)
                if err then
                    local server = servers:current_server()
                    err = "failed to receive reply from UDP server "
                    .. concat(server, ":") .. ": " .. err
                    break
                end
                --[[ End Of Receive]]
                
                --[[ Parse ]]
                if buf then
                    local answers
                    answers, err = _parse_response(buf, id, opts)
                    if err == "truncated" then
                        answers, err = _tcp_query(sock, query, id, opts, servers)
                    end
                    
                    if err and err ~= "id mismatch" then
                        break
                    end
                    
                    if answers then
                        return answers, nil, tries
                    end
                end
                --[[ End Of Parse ]]
                -- only here in case of an "id mismatch"
            end
            --[[ END ]]
        end
        
        if tries then
            tries[i] = err
            tries[i + 1] = nil -- ensure termination for user supplied table
        end
    end
    
    return nil, err, tries
end


local function _reverse_query(class, addr)
    log(ngx.ERR,"REVERSE QUERY")
    return query(class, arpa_str(addr),
                 {qtype = class.TYPE_PTR})
end


local resolver_mt = {
    udp_query       = _udp_query,
    udp_tcp_query   = _udp_tcp_query,
    tcp_query       = _tcp_query,
    dot_query       = _dot_query,
    doh_query       = _doh_query,
    query           = _query,
    reverse_query   = _reverse_query
}

-----------------------------------------------------------------------------

function _M.new(class, opts)
    if not opts then
        return nil, "no options table specified"
    end

    local nameservers = opts.nameservers
    if not nameservers or #nameservers == 0 then
        return nil, "no nameservers specified"
    end

    local servers, err = _servers_array_new(opts)
    if not servers then
        return nil, err 
    end
    
    return setmetatable({ 
            servers = servers,
            retrans = opts.retrans or 5,
            no_recurse = opts.no_recurse
        }, { __index = resolver_mt })
end

return _M
