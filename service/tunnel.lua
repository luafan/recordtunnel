require "compat53"

status = "n/a"

local fan = require "fan"
local connector = require "fan.connector"
local utils = require "fan.utils"
local tcpd = require "fan.tcpd"
local mariadb = require "fan.mariadb"
local stream = require "fan.stream"
local config = require "config"

local RECORD = config.record
local BLOCK_MODE = config.block_mode

local tunnelhook = require "tunnelhook"

local ssl = require "ssl"

local json = require "cjson.safe"

local lfs = require "lfs"
local lpeg = require "lpeg"

lfs.mkdir("certs")

local ctxpool = require "ctxpool"

local openssl = require 'openssl'
local crl, csr, x509 = openssl.x509.crl, openssl.x509.req, openssl.x509

local function gettime()
    return utils.gettime() * 1000
end

local f = io.open(config.cert_crt, "r")
local cert_crt = f:read("*all")
f:close()

local f = io.open(config.cert_key, "r")
local cert_key = f:read("*all")
f:close()

local cakey = assert(openssl.pkey.read(cert_key, true))
local cacert = assert(openssl.x509.read(cert_crt))

local function build_cert_by_subject(hostname, subject, certpath)
    local req = assert(csr.new(subject, cakey))
    local cert = openssl.x509.new(3, req)
    cert:validat(os.time() - 3600 * 24, os.time() + 3600 * 24 * 365)
    cert:extensions{
    openssl.x509.extension.new_extension{
        object='subjectAltName',
        value='DNS:' .. hostname
    }
    }
    assert(cert:sign(cakey, cacert, "SHA256"))
    
    local f = io.open(certpath, "w")
    f:write(cert:export("pem", false), "\n")
    f:write(cert_crt)
    f:close()
end

local function split(str, pat)
    local t = {}
    if str then
        local fpat = "(.-)" .. pat
        local last_end = 1
        local s, e, cap = str:find(fpat, 1)
        while s do
            if s ~= 1 or cap ~= "" then
                table.insert(t, cap)
            end
            last_end = e + 1
            s, e, cap = str:find(fpat, last_end)
        end
        if last_end <= #str then
            cap = str:sub(last_end)
            table.insert(t, cap)
        end
    end
    return t
end

if os.getenv("SSL_PORTS") then
    local list = split(os.getenv("SSL_PORTS"), ",")
    for i, v in ipairs(list) do
        config.ssl_ports[v] = true
    end
end

if os.getenv("SSL_WHITELIST") then
    local list = split(os.getenv("SSL_WHITELIST"), ",")
    for i, v in ipairs(list) do
        config.ssl_whitelist[v] = true
    end
end
--[[
http://yourip:8888/ get the list of tunnels

Proxy yourip:8888 support CONNECT only.
]]
local tunnels = {}
local tunnel_index = 1

local tunnel_mt = {}
tunnel_mt.__index = tunnel_mt

function tunnel_mt:__tostring()
    return string.format("[T%03d][%s]", self.index, self.original_host)
end

function tunnel_mt:append(buf)
    self.cache = self.cache and (self.cache .. buf) or buf
end

function tunnel_mt:readall()
    local cache = self.cache
    self.cache = nil
    return cache
end

function tunnel_mt:readline()
    if self.cache then
        local st, ed = string.find(self.cache, "\r\n", 1, true)
        if not st or not ed then
            st, ed = string.find(self.cache, "\n", 1, true)
        end
        if st and ed then
            local data = string.sub(self.cache, 1, st - 1)
            if #(self.cache) > ed then
                self.cache = string.sub(self.cache, ed + 1)
            else
                self.cache = nil
            end
            return data
        end
    end
end

function tunnel_mt:readheader()
    while not self.header_complete do
        local line = self:readline()
        if not line then
            break
        else
            if #(line) == 0 then
                self.header_complete = true
            else
                if self.first_line then
                    local k, v = string.match(line, "([^:]+):[ ]*(.*)")
                    k = string.lower(k)
                    local old = self.headers[k]
                    if old then
                        if type(old) == "table" then
                            table.insert(old, v)
                        else
                            self.headers[k] = {old, v}
                        end
                    else
                        self.headers[k] = v
                    end
                else
                    self.method, self.path, self.version = string.match(line, "([A-Z]+) ([^ ]+) HTTP/([0-9.]+)")
                    self.original_host, self.original_port = string.match(self.path, "([^:]+):(%d+)")
                    
                    self.first_line = true
                end
            end
        end
    end
end

function tunnel_mt:record_send(buf)
    if self.record then
        ctxpool:safe(
            function(ctx)
                ctx.recordpart(
                    "new",
                    {["record"] = self.record.id, ["type"] = "request", ["data"] = function(stmt, idx)
                            assert(stmt:send_long_data(idx, buf))
                        end, ["length"] = #(buf), ["created"] = gettime()}
                )
            end
        )
    end
end

function tunnel_mt:record_receive(buf)
    if self.record then
        ctxpool:safe(
            function(ctx)
                ctx.recordpart(
                    "new",
                    {["record"] = self.record.id, ["type"] = "response", ["data"] = function(stmt, idx)
                            assert(stmt:send_long_data(idx, buf))
                        end, ["length"] = #(buf), ["created"] = gettime()}
                )
            end
        )
    end
end

function tunnel_mt:remote_send(buf)
    if not buf then
        return 
    end
    
    if not self.sslport then
        if tunnelhook.dosend then
            buf = tunnelhook.dosend(self, buf)
        end
    end
    
    self.conn:send(buf)
    if BLOCK_MODE then
        self.apt:pause_read()
    end
    
    if config.debug then
        print(self, "remote sending", #(buf), self.sslport and "<ssldata>" or buf)
    end
    
    if not self.sslport then
        self:record_send(buf)
    end
end

function tunnel_mt:cleanup()
    if self.sslconn then
        self.sslconn:close()
        self.sslconn = nil
    end
    
    if self.conn then
        self.conn:close()
        self.conn = nil
    end
    
    if self.sslserv then
        self.sslserv:close()
        self.sslserv = nil
    end
    
    if self.apt then
        tunnels[self.apt] = nil
        self.apt:close()
        self.apt = nil
    end
    
    if config.debug then
        print(self, "cleanup")
    end
end

local ip_hostname_cache = {}

function tunnel_mt:ssl_proxy(buf, host, port)
    if not self.sslport then
        local hostname, contentType, var = ssl.get_hostname_from_clienthello(buf)
        
        if not hostname then
            hostname = ip_hostname_cache[self.original_host]
        end
        
        if not hostname then
            if contentType ~= 22 or (var and var ~= 3.0 and var ~= 2.0) then
                -- print("unknown ssl protocol! ignore ssl_proxy.")
                return host, port
            end
            -- print("connecting", self.original_host, self.original_port)
            local cli = connector.connect(string.format("tcp://%s:%s", self.original_host, self.original_port))
            cli:send(buf)
            local input = cli:receive()
            local body = input:GetBytes()
            cli:close()
            local subject, expect = ssl.get_subject_from_server_hello(body)
            if subject then
                hostname = subject:get_text("CN")
                ip_hostname_cache[self.original_host] = hostname
                print(self.original_host, "get_hostname", hostname)
            end
        end
        if not hostname or config.ssl_whitelist[hostname] then
            -- print("hostname not found! ignore ssl_proxy.")
            return host, port
        end
        
        self.original_host = hostname
        if RECORD then
            ctxpool:safe(
                function(ctx)
                    self.record = ctx.recordproxy("one", "where id=?", self.record.id)
                    self.record.hostname = hostname
                    self.record:update()
                end
            )
        end
        local cert_path
        
        local parts = split(hostname, "[.]")
        if #(parts) > 2 then
            cert_path = string.format("certs/_.%s.pem", table.concat(parts, ".", 2))
            hostname = string.format("*.%s", table.concat(parts, ".", 2))
        else
            cert_path = string.format("certs/%s.pem", hostname)
        end
        
        if not lfs.attributes(cert_path) then
            local subject = openssl.x509.name.new({{commonName = hostname}, {C = 'CN'}})
            build_cert_by_subject(hostname, subject, cert_path)
        else
            if config.debug then
                print("using certs cache", cert_path)
            end
        end
        
        self.sslserv, self.sslport = tcpd.bind {ssl = true, cert = cert_path, key = config.cert_key, onaccept = function(sslapt)
                if config.debug then
                    print(self, "[sslapt] onaccept")
                end
                self.sslapt = sslapt
                
                local cache = nil
                
                local ssl_remote_send = function(buf)
                    if tunnelhook.dosend then
                        buf = tunnelhook.dosend(self, buf)
                    end
                    
                    self.sslconn:send(buf)
                    if BLOCK_MODE then
                        sslapt:pause_read()
                    end
                    if config.debug then
                        print(self, "[sslapt] remote sending", #(buf), buf)
                    end
                    self:record_send(buf)
                end
                
                sslapt:bind {onread = function(buf)
                        if self.sslconn then
                            if self.sslconn_connected then
                                ssl_remote_send(buf)
                            else
                                cache = cache and (cache .. buf) or buf
                            end
                            return 
                        end
                        
                        cache = cache and (cache .. buf) or buf
                        
                        local a, b = string.find(cache:lower(), "host: ([^\r\n:]*)")
                        if a and b then
                            self.original_host = string.sub(cache, a + 6, b)
                        end
                        
                        if config.debug then
                            print(self, "[sslapt] connecting", self.original_host, self.original_port)
                        end
                        
                        self.sslconn = tcpd.connect {host = self.original_host, port = self.original_port, ssl = true, ssl_verifyhost = 0, ssl_verifypeer = 0, cainfo = "cert.pem", onconnected = function()
                                if config.debug then
                                    print(self, "[sslapt] remote onconnected")
                                end
                                self.sslconn_connected = true
                                if cache then
                                    ssl_remote_send(cache)
                                    cache = nil
                                end
                            end, onsendready = function()
                                if config.debug then
                                    print(self, "[sslapt] remote sent.")
                                end
                                if BLOCK_MODE then
                                    sslapt:resume_read()
                                end
                            end, onread = function(buf)
                                if config.debug then
                                    print(self, "[sslapt] remote receive/forward", #(buf), buf)
                                end
                                if tunnelhook.doreceive then
                                    buf = tunnelhook.doreceive(self, buf)
                                end
                                sslapt:send(buf)
                                self:record_receive(buf)
                            end, ondisconnected = function(msg)
                                if config.debug then
                                    print(self, "[sslapt] remote disconnected", msg)
                                end
                                sslapt:close()
                                self:cleanup()
                            end}
                    end, ondisconnected = function(msg)
                        if config.debug then
                            print(self, "[sslapt] disconnected", msg)
                        end
                        self:cleanup()
                    end}
            end}
    end
    
    return "127.0.0.1", self.sslport
end

function tunnel_mt:lifecycle(buf)
    if self.conn then
        if conn_connected then
            self:remote_send(buf)
        else
            self:append(buf)
        end
    else -- create connection on the first time receive tunnel data.
        self:append(buf)
        
        local host = self.original_host
        local port = self.original_port
        
        self.ssl_verified = ssl.verify_clienthello(buf)
        
        if self.ssl_verified or config.ssl_ports[port] then
            host, port = self:ssl_proxy(buf, host, port)
        else
            local a, b = string.find(buf:lower(), "host: ([^\r\n:]*)")
            if a and b then
                self.original_host = string.sub(buf, a + 6, b)
            end
        end
        
        self.conn = tcpd.connect {host = host, port = tonumber(port), onconnected = function()
                if config.debug then
                    print(self, self.path, "onconnected")
                end
                conn_connected = true
                self:remote_send(self:readall())
            end, onsendready = function()
                if config.debug then
                    print(self, "remote sent.")
                end
                if BLOCK_MODE then
                    self.apt:resume_read()
                end
            end, onread = function(buf)
                if config.debug then
                    print(self, "remote receive/feedbackclient", #(buf), self.sslport and "<ssldata>" or buf)
                end
                
                if not self.sslport then
                    if tunnelhook.doreceive then
                        buf = tunnelhook.doreceive(self, buf)
                    end
                end
                
                self.apt:send(buf)
                if not self.sslport then
                    self:record_receive(buf)
                end
            end, ondisconnected = function(msg)
                if config.debug then
                    print(self, self.path, msg)
                end
                self:cleanup()
            end}
    end
end

function tunnel_mt.new(apt, path)
    local tunnel = {apt = apt, index = tunnel_index, headers = {}}
    
    setmetatable(tunnel, tunnel_mt)
    
    tunnel_index = tunnel_index + 1
    
    tunnels[apt] = tunnel
    
    return tunnel
end

local function onaccept(apt)
    local accepted = false
    
    local tunnel = tunnel_mt.new(apt)
    local self = tunnel
    
    apt:bind {
        onread = function(buf)
            if accepted then
                self:lifecycle(buf)
            else
                self:append(buf)
                
                if not self.header_complete then
                    self:readheader()
                end
                
                if self.header_complete then
                    if self.method == "CONNECT" and not self.conn then
                        if not accepted then
                            accepted = true
                            
                            self.hostname = self.headers["Host"] or self.headers["host"]
                            -- print("link", self.original_host, self.original_port)
                            
                            if RECORD then
                                self.record = ctxpool:safe(
                                    function(ctx)
                                        return ctx.recordproxy("new", {path = self.path, host = self.original_host, port = self.original_port, hostname = self.hostname, created = gettime()})
                                    end
                                )
                            end
                            apt:send("HTTP/1.1 200 Connection Established\r\n\r\n")
                        end
                    elseif self.method == "GET" then
                        apt:send("HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                    end
                end
            end
        end,
        ondisconnected = function(msg)
            -- print("client disconnected", msg)
            tunnel:cleanup()
        end
    }
end

function onStart()
    if serv then
        return 
    end
    
    serv = tcpd.bind {host = config.service_host, port = config.tunnel_port, onaccept = onaccept}
    print("serv", serv)
    
    if serv then
        status = "running"
    else
        status = "error"
    end
end

function onStop()
    if serv then
        serv:close()
        serv = nil
    end
    
    status = "stopped"
end

function getStatus()
    return string.format("%s", status)
end

function getTunnels()
    return tunnels
end
