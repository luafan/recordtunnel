local RECORD = true
local BLOCK_MODE = false

require "compat53"

status = "n/a"

local fan = require "fan"
local utils = require "fan.utils"
local tcpd = require "fan.tcpd"
local mariadb = require "fan.mariadb"
local stream = require "fan.stream"
local config = require "config"

local json = require "cjson.safe"

local lfs = require "lfs"
local lpeg = require "lpeg"

lfs.mkdir("certs")

local ctxpool = require "ctxpool"

local openssl = require'openssl'
local crl,csr,x509 = openssl.x509.crl,openssl.x509.req,openssl.x509

local function gettime()
  return utils.gettime() * 1000
end

local function get_hostname_from_clienthello(data)
  local d = stream.new(data)

  local contentType = d:GetU8()
  local major = d:GetU8()
  local minor = d:GetU8()
  local var = tonumber(string.format("%d.%d", major, minor))
  assert(var >= 3.1, string.format("support tls only, %d.%d", major, minor))

  local length = string.unpack(">I2", d:GetBytes(2))

  local handshakeType = d:GetU8()
  local length = string.unpack(">I3", d:GetBytes(3))
  local major = d:GetU8()
  local minor = d:GetU8()

  d:GetBytes(4 + 28) -- skip random
  local sessionIdLength = d:GetU8()
  d:GetBytes(sessionIdLength) -- skip sessionId

  local cipherSuitesLength = string.unpack(">I2", d:GetBytes(2))
  d:GetBytes(cipherSuitesLength) -- skip cipherSuites

  local compressMethodLength = d:GetU8()
  d:GetBytes(compressMethodLength) -- skip compressMethod

  local extensionLength = string.unpack(">I2", d:GetBytes(2))

  while d:available() > 4 do
    local itemType = string.unpack(">I2", d:GetBytes(2))
    local itemLength = string.unpack(">I2", d:GetBytes(2))
    local itemData = d:GetBytes(itemLength)
    if itemType == 0x0000 then
      local sd = stream.new(itemData)
      local serverNameListLength = string.unpack(">I2", sd:GetBytes(2))
      while sd:available() > 0 do
        local serverNameType = sd:GetU8()
        local serverNameLength = string.unpack(">I2", sd:GetBytes(2))
        local servrNameValue = sd:GetBytes(serverNameLength)
        if serverNameType == 0 then
          return servrNameValue
        end
      end
    end
  end
end

local f = io.open(config.cert_crt, "r")
local cert_crt = f:read("*all")
f:close()

local f = io.open(config.cert_key, "r")
local cert_key = f:read("*all")
f:close()

local cakey = assert(openssl.pkey.read(cert_key, true))
local cacert = assert(openssl.x509.read(cert_crt))

local function build_cert_by_hostname(hostname, certpath)
  local dn = openssl.x509.name.new({{commonName = hostname}, {C='CN'}})
  local req = assert(csr.new(dn, cakey))
  local cert = openssl.x509.new(3, req)
  cert:validat(os.time() - 3600 * 24, os.time() + 3600*24*365)
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
        table.insert(t,cap)
      end
      last_end = e+1
      s, e, cap = str:find(fpat, last_end)
    end
    if last_end <= #str then
      cap = str:sub(last_end)
      table.insert(t, cap)
    end
  end
  return t
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
  return string.format("[T%03d]", self.index)
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
    local st,ed = string.find(self.cache, "\r\n", 1, true)
    if not st or not ed then
      st,ed = string.find(self.cache, "\n", 1, true)
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
          local k,v = string.match(line, "([^:]+):[ ]*(.*)")
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
          self.method,self.path,self.version = string.match(line, "([A-Z]+) ([^ ]+) HTTP/([0-9.]+)")
          self.original_host,self.original_port = string.match(self.path, "([^:]+):(%d+)")

          self.first_line = true
        end
      end
    end
  end
end

function tunnel_mt:record_send(buf)
  if self.record then
    ctxpool:safe(function(ctx)
        ctx.recordpart("new", {
            ["record"] = self.record.id,
            ["type"] = "request",
            ["data"] = function(stmt, idx)
              assert(stmt:send_long_data(idx, buf))
            end,
            ["length"] = #(buf),
            ["created"] = gettime(),
          })
      end)
  end
end

function tunnel_mt:record_receive(buf)
  if self.record then
    ctxpool:safe(function(ctx)
        ctx.recordpart("new", {
            ["record"] = self.record.id,
            ["type"] = "response",
            ["data"] = function(stmt, idx)
              assert(stmt:send_long_data(idx, buf))
            end,
            ["length"] = #(buf),
            ["created"] = gettime(),
          })
      end)
  end
end

function tunnel_mt:remote_send(buf)
  if not buf then
    return
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

function tunnel_mt:ssl_proxy(buf)
  if not self.sslport then
    local hostname = get_hostname_from_clienthello(buf)
    assert(hostname, "host name not found!")
    self.original_host = hostname
    if RECORD then
      ctxpool:safe(function(ctx)
          self.record = ctx.recordproxy("one", "where id=?", self.record.id)
          self.record.hostname = hostname
          self.record:update()
        end)
    end
    local cert_path

    local parts = split(hostname, "[.]")
    if #(parts) > 2 then
      cert_path = string.format("certs/_.%s.pem", table.concat(parts, ".", 2))
      hostname = string.format("*.%s", table.concat(parts, ".", 2))
    else
      cert_path = string.format("certs/%s.pem", hostname)
    end
    if hostname then
      if not lfs.attributes(cert_path) then
        build_cert_by_hostname(hostname, cert_path)
      else
        if config.debug then
          print("using certs cache", cert_path)
        end
      end
    end

    self.sslserv,self.sslport = tcpd.bind{
      ssl = true,
      cert = cert_path,
      key = config.cert_key,
      onaccept = function(sslapt)
        if config.debug then
          print(self, "[sslapt] onaccept")
        end
        self.sslapt = sslapt

        local cache = nil

        local ssl_remote_send = function(buf)
          self.sslconn:send(buf)
          if BLOCK_MODE then
            sslapt:pause_read()
          end
          if config.debug then
            print(self, "[sslapt] remote sending", #(buf), buf)
          end
          self:record_send(buf)
        end

        sslapt:bind{
          onread = function(buf)
            if self.sslconn then
              if self.sslconn_connected then
                ssl_remote_send(buf)
              else
                cache = cache and (cache .. buf) or buf
              end
              return
            end

            cache = cache and (cache .. buf) or buf

            if config.debug then
              print(self, "[sslapt] connecting", self.original_host, self.original_port)
            end

            self.sslconn = tcpd.connect{
              host = self.original_host,
              port = self.original_port,
              ssl = true,
              ssl_verifyhost = 0,
              ssl_verifypeer = 0,
              cainfo = "cert.pem",
              onconnected = function()
                if config.debug then
                  print(self, "[sslapt] remote onconnected")
                end
                self.sslconn_connected = true
                if cache then
                  ssl_remote_send(cache)
                  cache = nil
                end
              end,
              onsendready = function()
                if config.debug then
                  print(self, "[sslapt] remote sent.")
                end
                if BLOCK_MODE then
                  sslapt:resume_read()
                end
              end,
              onread = function(buf)
                if config.debug then
                  print(self, "[sslapt] remote receive/forward", #(buf), buf)
                end
                sslapt:send(buf)
                self:record_receive(buf)
              end,
              ondisconnected = function(msg)
                if config.debug then
                  print(self, "[sslapt] remote disconnected", msg)
                end
                sslapt:close()
                self:cleanup()
              end
            }
          end,
          ondisconnected = function(msg)
            if config.debug then
              print(self, "[sslapt] disconnected", msg)
            end
            self:cleanup()
          end
        }
      end
    }
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

    if port == "443" then
      host,port = self:ssl_proxy(buf)
    end

    self.conn = tcpd.connect{
      host = host,
      port = tonumber(port),
      onconnected = function()
        if config.debug then
          print(self, self.path, "onconnected")
        end
        conn_connected = true
        self:remote_send(self:readall())
      end,
      onsendready = function()
        if config.debug then
          print(self, "remote sent.")
        end
        if BLOCK_MODE then
          self.apt:resume_read()
        end
      end,
      onread = function(buf)
        if config.debug then
          print(self, "remote receive/feedbackclient", #(buf), self.sslport and "<ssldata>" or buf)
        end
        self.apt:send(buf)
        if not self.sslport then
          self:record_receive(buf)
        end
      end,
      ondisconnected = function(msg)
        if config.debug then
          print(self, self.path, msg)
        end
        self:cleanup()
      end
    }
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

  local info = apt:remoteinfo()

  local tunnel = tunnel_mt.new(apt)
  local self = tunnel

  apt:bind{
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

              if RECORD then
                self.record = ctxpool:safe(function(ctx)
                    return ctx.recordproxy("new", {
                        path = self.path,
                        host = self.original_host,
                        port = self.original_port,
                        hostname = self.hostname,
                        created = gettime()
                      })
                  end)
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
      tunnel:cleanup()
    end
  }
end

function onStart()
  if serv then
    return
  end

  serv = tcpd.bind{
    host = config.service_host,
    port = config.tunnel_port,
    onaccept = onaccept,
  }
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
