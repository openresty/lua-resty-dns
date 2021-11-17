-- Copyright (C) Yichun Zhang (agentzh)


-- local socket = require "socket"
local bit = require "bit"
local udp = ngx.socket.udp
local rand = math.random
local char = string.char
local byte = string.byte
local find = string.find
local gsub = string.gsub
local sub = string.sub
local rep = string.rep
local format = string.format
local band = bit.band
local rshift = bit.rshift
local lshift = bit.lshift
local insert = table.insert
local concat = table.concat
local re_sub = ngx.re.sub
local re_match = ngx.re.match
local re_find = ngx.re.find
local tcp = ngx.socket.tcp
local log = ngx.log
local DEBUG = ngx.DEBUG
local unpack = unpack
local setmetatable = setmetatable
local type = type
local ipairs = ipairs
local b64 = require "ngx.base64"
local agent = "ngx_lua/" .. ngx.config.ngx_lua_version
local str_lower = string.lower
local ngx_ERR = ngx.ERR
local tbl_insert = table.insert
local tolower = string.lower

local ok, new_tab = pcall(require, "table.new")
if not ok then
    new_tab = function (narr, nrec) return {} end
end


local DOT_CHAR = byte(".")
local ZERO_CHAR = byte("0")
local COLON_CHAR = byte(":")

local IP6_ARPA = "ip6.arpa"

local TYPE_A      = 1
local TYPE_NS     = 2
local TYPE_CNAME  = 5
local TYPE_SOA    = 6
local TYPE_PTR    = 12
local TYPE_MX     = 15
local TYPE_TXT    = 16
local TYPE_AAAA   = 28
local TYPE_SRV    = 33
local TYPE_SPF    = 99

local CLASS_IN    = 1

local SECTION_AN  = 1
local SECTION_NS  = 2
local SECTION_AR  = 3


local _M = {
    _VERSION    = '0.22',
    TYPE_A      = TYPE_A,
    TYPE_NS     = TYPE_NS,
    TYPE_CNAME  = TYPE_CNAME,
    TYPE_SOA    = TYPE_SOA,
    TYPE_PTR    = TYPE_PTR,
    TYPE_MX     = TYPE_MX,
    TYPE_TXT    = TYPE_TXT,
    TYPE_AAAA   = TYPE_AAAA,
    TYPE_SRV    = TYPE_SRV,
    TYPE_SPF    = TYPE_SPF,
    CLASS_IN    = CLASS_IN,
    SECTION_AN  = SECTION_AN,
    SECTION_NS  = SECTION_NS,
    SECTION_AR  = SECTION_AR
}


local resolver_errstrs = {
    "format error",     -- 1
    "server failure",   -- 2
    "name error",       -- 3
    "not implemented",  -- 4
    "refused",          -- 5
}

local soa_int32_fields = { "serial", "refresh", "retry", "expire", "minimum" }

local mt = { __index = _M }


local arpa_tmpl = new_tab(72, 0)

for i = 1, #IP6_ARPA do
    arpa_tmpl[64 + i] = byte(IP6_ARPA, i)
end

for i = 2, 64, 2 do
    arpa_tmpl[i] = DOT_CHAR
end


local function pick_sock(self, socks)
    local cur = self.cur

    if cur == #socks then
        self.cur = 1
    else
        self.cur = cur + 1
    end

    return socks[cur]
end


local function _get_cur_server(self)
    local cur = self.cur

    local servers = self.servers

    if cur == 1 then
        return servers[#servers]
    end

    return servers[cur - 1]
end


function _M.set_timeout(self, timeout)
    local socks = self.socks
    if not socks then
        return nil, "not initialized"
    end

    for i = 1, #socks do
        local sock = socks[i]
        sock:settimeout(timeout)
    end

    local tcp_sock = self.tcp_sock
    if not tcp_sock then
        return nil, "not initialized"
    end

    tcp_sock:settimeout(timeout)
end


local function _encode_name(s)
    return char(#s) .. s
end


local function _decode_name(buf, pos)
    local labels = {}
    local nptrs = 0
    local p = pos
    while nptrs < 128 do
        local fst = byte(buf, p)

        if not fst then
            return nil, 'truncated';
        end

        -- print("fst at ", p, ": ", fst)

        if fst == 0 then
            if nptrs == 0 then
                pos = pos + 1
            end
            break
        end

        if band(fst, 0xc0) ~= 0 then
            -- being a pointer
            if nptrs == 0 then
                pos = pos + 2
            end

            nptrs = nptrs + 1

            local snd = byte(buf, p + 1)
            if not snd then
                return nil, 'truncated'
            end

            p = lshift(band(fst, 0x3f), 8) + snd + 1

            -- print("resolving ptr ", p, ": ", byte(buf, p))

        else
            -- being a label
            local label = sub(buf, p + 1, p + fst)
            insert(labels, label)

            -- print("resolved label ", label)

            p = p + fst + 1

            if nptrs == 0 then
                pos = p
            end
        end
    end

    return concat(labels, "."), pos
end


local function _build_request(qname, id, no_recurse, opts)
    local qtype

    if opts then
        qtype = opts.qtype
    end

    if not qtype then
        qtype = 1  -- A record
    end

    local ident_hi = char(rshift(id, 8))
    local ident_lo = char(band(id, 0xff))

    local flags
    if no_recurse then
        -- print("found no recurse")
        flags = "\0\0"
    else
        flags = "\1\0"
    end

    local nqs = "\0\1"
    local nan = "\0\0"
    local nns = "\0\0"
    local nar = "\0\0"
    local typ = char(rshift(qtype, 8), band(qtype, 0xff))
    local class = "\0\1"    -- the Internet class

    if byte(qname, 1) == DOT_CHAR then
        return nil, "bad name"
    end

    local name = gsub(qname, "([^.]+)%.?", _encode_name) .. '\0'

    return {
        ident_hi, ident_lo, flags, nqs, nan, nns, nar,
        name, typ, class
    }
end


local function parse_section(answers, section, buf, start_pos, size,
                             should_skip)
    local pos = start_pos

    for _ = 1, size do
        -- print(format("ans %d: qtype:%d qclass:%d", i, qtype, qclass))
        local ans = {}

        if not should_skip then
            insert(answers, ans)
        end

        ans.section = section

        local name
        name, pos = _decode_name(buf, pos)
        if not name then
            return nil, pos
        end

        ans.name = name

        -- print("name: ", name)

        local type_hi = byte(buf, pos)
        local type_lo = byte(buf, pos + 1)
        local typ = lshift(type_hi, 8) + type_lo

        ans.type = typ

        -- print("type: ", typ)

        local class_hi = byte(buf, pos + 2)
        local class_lo = byte(buf, pos + 3)
        local class = lshift(class_hi, 8) + class_lo

        ans.class = class

        -- print("class: ", class)

        local byte_1, byte_2, byte_3, byte_4 = byte(buf, pos + 4, pos + 7)

        local ttl = lshift(byte_1, 24) + lshift(byte_2, 16)
                    + lshift(byte_3, 8) + byte_4

        -- print("ttl: ", ttl)

        ans.ttl = ttl

        local len_hi = byte(buf, pos + 8)
        local len_lo = byte(buf, pos + 9)
        local len = lshift(len_hi, 8) + len_lo

        -- print("record len: ", len)

        pos = pos + 10

        if typ == TYPE_A then

            if len ~= 4 then
                return nil, "bad A record value length: " .. len
            end

            local addr_bytes = { byte(buf, pos, pos + 3) }
            local addr = concat(addr_bytes, ".")
            -- print("ipv4 address: ", addr)

            ans.address = addr

            pos = pos + 4

        elseif typ == TYPE_CNAME then

            local cname, p = _decode_name(buf, pos)
            if not cname then
                return nil, pos
            end

            if p - pos ~= len then
                return nil, format("bad cname record length: %d ~= %d",
                                   p - pos, len)
            end

            pos = p

            -- print("cname: ", cname)

            ans.cname = cname

        elseif typ == TYPE_AAAA then

            if len ~= 16 then
                return nil, "bad AAAA record value length: " .. len
            end

            local addr_bytes = { byte(buf, pos, pos + 15) }
            local flds = {}
            for i = 1, 16, 2 do
                local a = addr_bytes[i]
                local b = addr_bytes[i + 1]
                if a == 0 then
                    insert(flds, format("%x", b))

                else
                    insert(flds, format("%x%02x", a, b))
                end
            end

            -- we do not compress the IPv6 addresses by default
            --  due to performance considerations

            ans.address = concat(flds, ":")

            pos = pos + 16

        elseif typ == TYPE_MX then

            -- print("len = ", len)

            if len < 3 then
                return nil, "bad MX record value length: " .. len
            end

            local pref_hi = byte(buf, pos)
            local pref_lo = byte(buf, pos + 1)

            ans.preference = lshift(pref_hi, 8) + pref_lo

            local host, p = _decode_name(buf, pos + 2)
            if not host then
                return nil, pos
            end

            if p - pos ~= len then
                return nil, format("bad cname record length: %d ~= %d",
                                   p - pos, len)
            end

            ans.exchange = host

            pos = p

        elseif typ == TYPE_SRV then
            if len < 7 then
                return nil, "bad SRV record value length: " .. len
            end

            local prio_hi = byte(buf, pos)
            local prio_lo = byte(buf, pos + 1)
            ans.priority = lshift(prio_hi, 8) + prio_lo

            local weight_hi = byte(buf, pos + 2)
            local weight_lo = byte(buf, pos + 3)
            ans.weight = lshift(weight_hi, 8) + weight_lo

            local port_hi = byte(buf, pos + 4)
            local port_lo = byte(buf, pos + 5)
            ans.port = lshift(port_hi, 8) + port_lo

            local name, p = _decode_name(buf, pos + 6)
            if not name then
                return nil, pos
            end

            if p - pos ~= len then
                return nil, format("bad srv record length: %d ~= %d",
                                   p - pos, len)
            end

            ans.target = name

            pos = p

        elseif typ == TYPE_NS then

            local name, p = _decode_name(buf, pos)
            if not name then
                return nil, pos
            end

            if p - pos ~= len then
                return nil, format("bad cname record length: %d ~= %d",
                                   p - pos, len)
            end

            pos = p

            -- print("name: ", name)

            ans.nsdname = name

        elseif typ == TYPE_TXT or typ == TYPE_SPF then

            local key = (typ == TYPE_TXT) and "txt" or "spf"

            local slen = byte(buf, pos)
            if slen + 1 > len then
                -- truncate the over-run TXT record data
                slen = len
            end

            -- print("slen: ", len)

            local val = sub(buf, pos + 1, pos + slen)
            local last = pos + len
            pos = pos + slen + 1

            if pos < last then
                -- more strings to be processed
                -- this code path is usually cold, so we do not
                -- merge the following loop on this code path
                -- with the processing logic above.

                val = {val}
                local idx = 2
                repeat
                    local slen = byte(buf, pos)
                    if pos + slen + 1 > last then
                        -- truncate the over-run TXT record data
                        slen = last - pos - 1
                    end

                    val[idx] = sub(buf, pos + 1, pos + slen)
                    idx = idx + 1
                    pos = pos + slen + 1

                until pos >= last
            end

            ans[key] = val

        elseif typ == TYPE_PTR then

            local name, p = _decode_name(buf, pos)
            if not name then
                return nil, pos
            end

            if p - pos ~= len then
                return nil, format("bad cname record length: %d ~= %d",
                                   p - pos, len)
            end

            pos = p

            -- print("name: ", name)

            ans.ptrdname = name

        elseif typ == TYPE_SOA then
            local name, p = _decode_name(buf, pos)
            if not name then
                return nil, pos
            end
            ans.mname = name

            pos = p
            name, p = _decode_name(buf, pos)
            if not name then
                return nil, pos
            end
            ans.rname = name

            for _, field in ipairs(soa_int32_fields) do
                local byte_1, byte_2, byte_3, byte_4 = byte(buf, p, p + 3)
                ans[field] = lshift(byte_1, 24) + lshift(byte_2, 16)
                            + lshift(byte_3, 8) + byte_4
                p = p + 4
            end

            pos = p

        else
            -- for unknown types, just forward the raw value

            ans.rdata = sub(buf, pos, pos + len - 1)
            pos = pos + len
        end
    end

    return pos
end


local function parse_response(buf, id, opts)
    local n = #buf
    if n < 12 then
        return nil, 'truncated';
    end

    -- header layout: ident flags nqs nan nns nar

    local ident_hi = byte(buf, 1)
    local ident_lo = byte(buf, 2)
    local ans_id = lshift(ident_hi, 8) + ident_lo

    -- print("id: ", id, ", ans id: ", ans_id)

    if ans_id ~= id then
        -- identifier mismatch and throw it away
        log(DEBUG, "id mismatch in the DNS reply: ", ans_id, " ~= ", id)
        return nil, "id mismatch"
    end

    local flags_hi = byte(buf, 3)
    local flags_lo = byte(buf, 4)
    local flags = lshift(flags_hi, 8) + flags_lo

    -- print(format("flags: 0x%x", flags))

    if band(flags, 0x8000) == 0 then
        return nil, format("bad QR flag in the DNS response")
    end

    if band(flags, 0x200) ~= 0 then
        return nil, "truncated"
    end

    local code = band(flags, 0xf)

    -- print(format("code: %d", code))

    local nqs_hi = byte(buf, 5)
    local nqs_lo = byte(buf, 6)
    local nqs = lshift(nqs_hi, 8) + nqs_lo

    -- print("nqs: ", nqs)

    if nqs ~= 1 then
        return nil, format("bad number of questions in DNS response: %d", nqs)
    end

    local nan_hi = byte(buf, 7)
    local nan_lo = byte(buf, 8)
    local nan = lshift(nan_hi, 8) + nan_lo

    -- print("nan: ", nan)

    local nns_hi = byte(buf, 9)
    local nns_lo = byte(buf, 10)
    local nns = lshift(nns_hi, 8) + nns_lo

    local nar_hi = byte(buf, 11)
    local nar_lo = byte(buf, 12)
    local nar = lshift(nar_hi, 8) + nar_lo

    -- skip the question part

    local ans_qname, pos = _decode_name(buf, 13)
    if not ans_qname then
        return nil, pos
    end

    -- print("qname in reply: ", ans_qname)

    -- print("question: ", sub(buf, 13, pos))

    if pos + 3 + nan * 12 > n then
        -- print(format("%d > %d", pos + 3 + nan * 12, n))
        return nil, 'truncated';
    end

    -- question section layout: qname qtype(2) qclass(2)

    --[[
    local type_hi = byte(buf, pos)
    local type_lo = byte(buf, pos + 1)
    local ans_type = lshift(type_hi, 8) + type_lo
    ]]

    -- print("ans qtype: ", ans_type)

    local class_hi = byte(buf, pos + 2)
    local class_lo = byte(buf, pos + 3)
    local qclass = lshift(class_hi, 8) + class_lo

    -- print("ans qclass: ", qclass)

    if qclass ~= 1 then
        return nil, format("unknown query class %d in DNS response", qclass)
    end

    pos = pos + 4

    local answers = {}

    if code ~= 0 then
        answers.errcode = code
        answers.errstr = resolver_errstrs[code] or "unknown"
    end

    local authority_section, additional_section

    if opts then
        authority_section = opts.authority_section
        additional_section = opts.additional_section
        if opts.qtype == TYPE_SOA then
            authority_section = true
        end
    end

    local err

    pos, err = parse_section(answers, SECTION_AN, buf, pos, nan)

    if not pos then
        return nil, err
    end

    if not authority_section and not additional_section then
        return answers
    end

    pos, err = parse_section(answers, SECTION_NS, buf, pos, nns,
                             not authority_section)

    if not pos then
        return nil, err
    end

    if not additional_section then
        return answers
    end

    pos, err = parse_section(answers, SECTION_AR, buf, pos, nar)

    if not pos then
        return nil, err
    end

    return answers
end


local function _gen_id(self)
    local id = self._id   -- for regression testing
    if id then
        return id
    end
    return rand(0, 65535)   -- two bytes
end


local function _tcp_query(self, query, id, opts)
    local sock = self.tcp_sock
    if not sock then
        return nil, "not initialized"
    end

    log(DEBUG, "query the TCP server due to reply truncation")

    local server = _get_cur_server(self)

    local ok, err = sock:connect(server[1], server[2])
    if not ok then
        return nil, "failed to connect to TCP server "
            .. concat(server, ":") .. ": " .. err
    end

    query = concat(query, "")
    local len = #query

    local len_hi = char(rshift(len, 8))
    local len_lo = char(band(len, 0xff))

    local bytes, err = sock:send({len_hi, len_lo, query})
    if not bytes then
        return nil, "failed to send query to TCP server "
            .. concat(server, ":") .. ": " .. err
    end

    local buf, err = sock:receive(2)
    if not buf then
        return nil, "failed to receive the reply length field from TCP server "
            .. concat(server, ":") .. ": " .. err
    end

    len_hi = byte(buf, 1)
    len_lo = byte(buf, 2)
    len = lshift(len_hi, 8) + len_lo

    -- print("tcp message len: ", len)

    buf, err = sock:receive(len)
    if not buf then
        return nil, "failed to receive the reply message body from TCP server "
            .. concat(server, ":") .. ": " .. err
    end

    local answers, err = parse_response(buf, id, opts)
    if not answers then
        return nil, "failed to parse the reply from the TCP server "
            .. concat(server, ":") .. ": " .. err
    end

    sock:close()

    return answers
end


function _M.tcp_query(self, qname, opts)
    local socks = self.socks
    if not socks then
        return nil, "not initialized"
    end

    pick_sock(self, socks)

    local id = _gen_id(self)

    local query, err = _build_request(qname, id, self.no_recurse, opts)
    if not query then
        return nil, err
    end

    return _tcp_query(self, query, id, opts)
end


local function _http_connect(self,host)
    local sock = self.tcp_sock
    if not sock then
        return nil, "not initialized"
    end

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
            tbl_insert(ret[key], tostring(val))
        else
            ret[key] = tostring(val)
        end
    until re_find(line, "^\\s*$", "jo")

    return ret
end


local function _http_header_send(sock, host, method, length, param)
    local hoststr

    if (host[4] and host[2] ~= 443) or (not host[4] and host[2] ~= 80) then
        hoststr = host[1]..":"..host[2]
    else
        hoststr = host[1]
    end

    local query = {
        true,
        'Host: '..hoststr,
        'User-Agent: '..agent,
        'Accept: application/dns-message',
        'Connection: keep-alive'
    }

    if method == nil or method == ngx.HTTP_GET then
        query[1] = 'GET '.. host[3]..param.. ' HTTP/1.1'
        query = concat(query,"\r\n").."\r\n\r\n"
    elseif method == ngx.HTTP_POST then
        query[1] = 'POST '.. host[3] .. ' HTTP/1.1'
        insert(query,'Content-Length: '..length)
        insert(query,'Content-Type: application/dns-message')
        query = concat(query, "\r\n").."\r\n\r\n"
    else
        return nil, "unsupported method"
    end

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


local function _http_query(self,host,opts)
    local sock, err = _http_connect(self, host)

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

local function _doh_query(self, qname, opts, tries)
    local retrans = self.retrans
    if tries then
        tries[1] = nil
    end

    local servers = self.servers

    if #servers == 0 then
        return nil, "no servers available"
    end

    local err

    for i = 1, retrans do
        local idx = i

        if idx > #servers then
            idx = 1
        end

        local res
        local id 

        if self.doh_method == ngx.HTTP_GET then
            res = _http_query(self,servers[idx], { method = ngx.HTTP_GET, param = b64.encode_base64url(qname) })
        else
            id = _gen_id(self)
            local bdata = table.concat(_build_request(qname, id, self.no_recurse, opts))
            res, err = _http_query(self,servers[idx],{ method = ngx.HTTP_POST, body = bdata }) 
        end

        if not res then
           return nil, err, tries
        end

        if res.status == 200 and res.body then
            local answers
            if self.doh_method == ngx.HTTP_GET then
                local ident_hi = byte(res.body, 1)
                local ident_lo = byte(res.body, 2)
                id = lshift(ident_hi, 8) + ident_lo 
            end
            answers, err = parse_response(res.body, id, opts)
            if answers then
                return answers, nil, tries
            end

            if err and err ~= "id mismatch" then
                break
            else
                log(DEBUG,"doh query failed to parse response",err)
            end
        end

        if tries then
            tries[i] = err
            tries[i + 1] = nil -- ensure termination for user supplied table
        end
    end

    return nil, err, tries
end


local function _udp_tcp_query(self, qname, opts, tries)
    local socks = self.socks
    if not socks then
        return nil, "not initialized"
    end

    local id = _gen_id(self)

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
        local sock = pick_sock(self, socks)

        local ok
        ok, err = sock:send(query)
        if not ok then
            local server = _get_cur_server(self)
            err = "failed to send request to UDP server "
                .. concat(server, ":") .. ": " .. err

        else
            local buf

            for _ = 1, 128 do
                buf, err = sock:receive(4096)
                if err then
                    local server = _get_cur_server(self)
                    err = "failed to receive reply from UDP server "
                        .. concat(server, ":") .. ": " .. err
                    break
                end

                if buf then
                    local answers
                    answers, err = parse_response(buf, id, opts)
                    if err == "truncated" then
                        answers, err = _tcp_query(self, query, id, opts)
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


function _M.compress_ipv6_addr(addr)
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


_M.expand_ipv6_addr = _expand_ipv6_addr


function _M.arpa_str(addr)
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


function _M.reverse_query(self, addr)
    return self.query(self, self.arpa_str(addr),
                      {qtype = self.TYPE_PTR})
end


local function _new_doh(class,opts)
    local method
    if opts.doh_method == 'POST' then
        method = ngx.HTTP_POST
    elseif opts.doh_method == 'GET' then
        method = ngx.HTTP_GET
    else
        return nil, nil, "invalid DoH mode specified"
    end

    local servers = opts.nameservers
    local n = #servers

    for i = 1, n do
        local captures, err = re_match(servers[i],"^((https?)(://))?([A-Za-z0-9\\.-]+)(:[1-9][0-9]*)?(/.+)$")

        if not captures then
            return nil, nil, err
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
            return nil, nil, "invalid port specified"
        end

        servers[i] = { host, port, captures[6], ssl}
    end

    _M.query = _doh_query

    return servers, method
end

local function _new_tcp_udp(class,opts,timeout)
    local servers = opts.nameservers
    local n = #servers
    local socks = {}

    for i = 1, n do
        local server = servers[i]
        local host, port, ssl

        if type(server) == 'table' then
            host = server[1]
            port = server[2] or 53
        else
            host = server
            port = 53
            servers[i] = {host, port}
        end

        local sock, err = udp()
        if not sock then
            return nil, "failed to create udp socket: " .. err
        end

        local ok, err = sock:setpeername(host, port)
        if not ok then
            return nil, "failed to set peer name: " .. err
        end

        sock:settimeout(timeout)

        insert(socks, sock)
    end

    _M.query = _udp_tcp_query

    return servers,socks
end


function _M.new(class, opts)
    if not opts then
        return nil, "no options table specified"
    end

    local servers = opts.nameservers
    if not servers or #servers == 0 then
        return nil, "no nameservers specified"
    end

    local timeout = opts.timeout or 2000 -- default 2 sec
    local servers, socks, err
    local method

    if opts.doh then
        servers, method, err = _new_doh(class,opts)
    else
        servers, socks, err = _new_tcp_udp(class,opts,timeout)
    end

    if not servers then
       return nil, err
    end

    local tcp_sock, err = tcp()
    if not tcp_sock then
        return nil, "failed to create tcp socket: " .. err
    end

    tcp_sock:settimeout(timeout)
    
    return setmetatable(
        { cur = opts.no_random and 1 or rand(1, #servers),
          socks = socks,
          tcp_sock = tcp_sock,
          servers = servers,
          retrans = opts.retrans or 5,
          no_recurse = opts.no_recurse,
          doh = opts.doh,
          doh_method = method
    }, mt)
end


return _M
