local bit = require "bit"
local band = bit.band
local rshift = bit.rshift
local lshift = bit.lshift
local insert = table.insert
local concat = table.concat
local byte = string.byte
local char= string.char
local byte = string.byte
local sub = string.sub
local gsub = string.gsub

local log = ngx.log
local DEBUG = ngx.DEBUG

local DOT_CHAR = byte(".")
local ZERO_CHAR = byte("0")

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

local soa_int32_fields = { "serial", "refresh", "retry", "expire", "minimum" }

local resolver_errstrs = {
    "format error",     -- 1
    "server failure",   -- 2
    "name error",       -- 3
    "not implemented",  -- 4
    "refused",          -- 5
}

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


local function _parse_wire_section(answers, section, buf, start_pos, size,
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


local function _parse_wire_response(buf, id, opts)
    local n = #buf
    if n < 12 then
        return nil, 'truncated'
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
        return nil, 'truncated'
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
    
    pos, err = _parse_wire_section(answers, SECTION_AN, buf, pos, nan)
    
    if not pos then
        return nil, err
    end
    
    if not authority_section and not additional_section then
        return answers
    end
    
    pos, err = _parse_wire_section(answers, SECTION_NS, buf, pos, nns,
                                   not authority_section)
    
    if not pos then
        return nil, err
    end
    
    if not additional_section then
        return answers
    end
    
    pos, err = _parse_wire_section(answers, SECTION_AR, buf, pos, nar)
    
    if not pos then
        return nil, err
    end
    
    return answers
end

local function _build_wire_request(qname, id, no_recurse, opts)
    local qtype = opts and opts.qtype or 1
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


return {
    TYPE = {
        A      = TYPE_A,
        NS     = TYPE_NS,
        CNAME  = TYPE_CNAME,
        SOA    = TYPE_SOA,
        PTR    = TYPE_PTR,
        MX     = TYPE_MX,
        TXT    = TYPE_TXT,
        AAAA   = TYPE_AAAA,
        SRV    = TYPE_SRV,
        SPF    = TYPE_SPF
    },
    CLASS = {
        IN    = CLASS_IN
    },
    SECTION = {
        AN  = SECTION_AN,
        NS  = SECTION_NS,
        AR  = SECTION_AR
    },
    build_request = _build_wire_request,
    parse_response = _parse_wire_response
}
