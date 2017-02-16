require "compat53"

status = "n/a"

local fan = require "fan"
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

--[[
http://yourip:8888/ get the list of tunnels

Proxy yourip:8888 support CONNECT only.
]]

local tunnels = {}
local tunnel_index = 1
local RECORD = true

local function gettime()
  local sec,usec = fan.gettime()
  return sec * 1000 + math.floor(usec / 1000)
end

local function apt_tostring(tunnel_context)
  local index = tunnel_context.index
  return string.format("[T%03d]", index)
end

local function get_hostname_from_clienthello(data)
  local d = stream.new(data)

  local contentType = d:GetU8()
  local major = d:GetU8()
  local minor = d:GetU8()
  assert(major == 3, "support tls only.")
  assert(minor == 1, "support tls only.")

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

function split(s, sep)
  sep = lpeg.P(sep)
  local elem = lpeg.C((1 - sep)^0)
  local p = lpeg.Ct(elem * (sep * elem)^0) -- make a table capture
  return lpeg.match(p, s)
end

local function onaccept(apt)
  local cache = nil

  local method
  local path
  local version
  local headers = {}

  local first_line = false
  local header_complete = false
  local accepted = false
  local disconnected = false
  local tunnel_context

  local record

  local original_host
  local original_port

  local sslconn
  local sslconn_connected = false

  local conn
  local conn_connected = false

  local readline = function()
    if cache then
      local st,ed = string.find(cache, "\r\n", 1, true)
      if not st or not ed then
        st,ed = string.find(cache, "\n", 1, true)
      end
      if st and ed then
        data = string.sub(cache, 1, st - 1)
        if #(cache) > ed then
          cache = string.sub(cache, ed + 1)
        else
          cache = nil
        end
        return data
      end
    end
  end

  local readheader = function()
    while not header_complete do
      local line = readline()
      if not line then
        break
      else
        if #(line) == 0 then
          header_complete = true
        else
          if first_line then
            local k,v = string.match(line, "([^:]+):[ ]*(.*)")
            k = string.lower(k)
            local old = headers[k]
            if old then
              if type(old) == "table" then
                table.insert(old, v)
              else
                headers[k] = {old, v}
              end
            else
              headers[k] = v
            end
          else
            method,path,version = string.match(line, "([A-Z]+) ([^ ]+) HTTP/([0-9.]+)")
            first_line = true
          end
        end
      end
    end
  end

  local info = apt:remoteinfo()

  local record_send = function(buf)
    if RECORD then
      pcall(function()
        ctxpool:safe(function(ctx)
            ctx.recordpart("new", {
                ["record"] = record.id,
                ["type"] = "request",
                ["data"] = function(stmt, idx)
                  assert(stmt:send_long_data(idx, buf))
                end,
                ["length"] = #(buf),
                ["created"] = gettime(),
              })
          end)
      end)
    end
  end

  local record_receive = function(buf)
    if RECORD then
      pcall(function()
      ctxpool:safe(function(ctx)
          ctx.recordpart("new", {
              ["record"] = record.id,
              ["type"] = "response",
              ["data"] = function(stmt, idx)
                assert(stmt:send_long_data(idx, buf))
              end,
              ["length"] = #(buf),
              ["created"] = gettime(),
            })
        end)
      end)
    end
  end

  local remote_send = function(buf)
    conn:send(buf)
    apt:pause_read()
    if config.debug then
      print(apt_tostring(tunnel_context), "remote sending", #(buf), tunnel_context.sslport and "<ssldata>" or buf)
    end
    if not tunnel_context.sslport then
      record_send(buf)
    end
  end

  local cleanup = function()
    if sslconn then
      sslconn:close()
      sslconn = nil
    end

    if conn then
      conn:close()
      conn = nil
    end

    if tunnel_context and tunnel_context.sslserv then
      tunnel_context.sslserv:close()
      tunnel_context.sslserv = nil
    end

    if apt then
      tunnels[apt] = nil
      apt:close()
      apt = nil
    end

    if tunnel_context and config.debug then
      print(apt_tostring(tunnel_context), "cleanup")
    end
  end

  apt:bind{
    onread = function(buf)
      if accepted then
        if conn then
          if conn_connected then
            remote_send(buf)
          else
            cache = cache and (cache .. buf) or buf
          end
        else -- create connection on the first time receive tunnel data.
          cache = cache and (cache .. buf) or buf

          local host = original_host
          local port = original_port

          if original_port == "443" then
            if not tunnels[apt].sslport then
              local hostname = get_hostname_from_clienthello(buf)
              assert(hostname, "host name not found!")
              original_host = hostname
              if RECORD then
                pcall(function()
                ctxpool:safe(function(ctx)
                    record = ctx.recordproxy("one", "where id=?", record.id)
                    record.hostname = hostname
                    record:update()
                  end)
                end)
              end
              local cert_path

              local parts = split(hostname, ".")
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

              tunnels[apt].sslserv,tunnels[apt].sslport = tcpd.bind{
                ssl = true,
                cert = cert_path,
                key = config.cert_key,
                onaccept = function(sslapt)
                  if config.debug then
                    print(apt_tostring(tunnel_context), "[sslapt] onaccept")
                  end
                  tunnels[apt].sslapt = sslapt

                  local cache = nil

                  local ssl_remote_send = function(buf)
                    sslconn:send(buf)
                    sslapt:pause_read()
                    if config.debug then
                      print(apt_tostring(tunnel_context), "[sslapt] remote sending", #(buf), buf)
                    end
                    record_send(buf)
                  end
                  sslapt:bind{
                    onread = function(buf)
                      if sslconn then
                        if sslconn_connected then
                          ssl_remote_send(buf)
                        else
                          cache = cache and (cache .. buf) or buf
                        end
                        return
                      end

                      cache = cache and (cache .. buf) or buf

                      if config.debug then
                        print(apt_tostring(tunnel_context), "[sslapt] connecting", original_host, original_port)
                      end
                      sslconn = tcpd.connect{
                        host = original_host,
                        port = original_port,
                        ssl = true,
                        ssl_verifyhost = 0,
                        ssl_verifypeer = 0,
                        cainfo = "cert.pem",
                        onconnected = function()
                          if config.debug then
                            print(apt_tostring(tunnel_context), "[sslapt] remote onconnected")
                          end
                          sslconn_connected = true
                          if cache then
                            ssl_remote_send(cache)
                            cache = nil
                          end
                        end,
                        onsendready = function()
                          if config.debug then
                            print(apt_tostring(tunnel_context), "[sslapt] remote sent.")
                          end
                          sslapt:resume_read()
                        end,
                        onread = function(buf)
                          if config.debug then
                            print(apt_tostring(tunnel_context), "[sslapt] remote receive/forward", #(buf), buf)
                          end
                          sslapt:send(buf)
                          record_receive(buf)
                        end,
                        ondisconnected = function(msg)
                          if config.debug then
                            print(apt_tostring(tunnel_context), "[sslapt] remote disconnected", msg)
                          end
                          tunnels[apt] = nil
                          sslapt:close()

                          cleanup()
                        end
                      }
                    end,
                    ondisconnected = function(msg)
                      if config.debug then
                        print(apt_tostring(tunnel_context), "[sslapt] disconnected", msg)
                      end
                      cleanup()
                    end
                  }
                end
              }
            end

            host = "127.0.0.1"
            port = tunnels[apt].sslport
          end

          conn = tcpd.connect{
            host = host,
            port = tonumber(port),
            onconnected = function()
              if config.debug then
                print(apt_tostring(tunnel_context), path, "onconnected")
              end
              conn_connected = true
              if cache then
                remote_send(cache)
                cache = nil
              end
            end,
            onsendready = function()
              if config.debug then
                print(apt_tostring(tunnel_context), "remote sent.")
              end
              apt:resume_read()
            end,
            onread = function(buf)
              if config.debug then
                print(apt_tostring(tunnel_context), "remote receive/feedbackclient", #(buf), tunnel_context.sslport and "<ssldata>" or buf)
              end
              apt:send(buf)
              if not tunnel_context.sslport then
                record_receive(buf)
              end
            end,
            ondisconnected = function(msg)
              if config.debug then
                print(apt_tostring(tunnel_context), path, msg)
              end
              cleanup()
            end
          }
        end

        return
      end

      cache = cache and (cache .. buf) or buf
      if not header_complete then
        readheader()
      end

      if header_complete then
        if method == "CONNECT" and not conn then
          if not accepted then
            accepted = true
            tunnel_context = {path = path, index = tunnel_index}
            tunnel_index = tunnel_index + 1

            tunnels[apt] = tunnel_context
            if RECORD then
              pcall(function()
              record = ctxpool:safe(function(ctx)
                  return ctx.recordproxy("new", {
                      host = path,
                      hostname = headers["Host"] or headers["host"],
                      created = gettime()
                    })
                end)
              end)
            end
            apt:send("HTTP/1.1 200 Connection Established\r\n\r\n")
          end

          local host,port = string.match(path, "([^:]+):(%d+)")
          original_host = host
          original_port = port
        elseif method == "GET" then
          local list = {}
          for k,v in pairs(tunnels) do
            table.insert(list, v.path)
          end
          local body = table.concat(list, "\n")
          apt:send(string.format("HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", #(body), body))
        end
      end
    end,
    ondisconnected = function(msg)
      cleanup()
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
