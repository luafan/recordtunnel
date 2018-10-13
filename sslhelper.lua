local stream = require "fan.stream"
local openssl = require 'openssl'
local crl, csr, x509 = openssl.x509.crl, openssl.x509.req, openssl.x509

local minium_client_hello_size = 1 + 2 + 2 + 1 + 3 + 2

local function verify_clienthello(data)
    if #(data) < minium_client_hello_size then
        return false
    end
    
    local d = stream.new(data)
    
    local contentType = d:GetU8()
    local major = d:GetU8()
    local minor = d:GetU8()
    local var = tonumber(string.format("%d.%d", major, minor))
    if var < 3.1 and var ~= 2.0 and var ~= 3.0 then
        return false
    end
    
    local length = string.unpack(">I2", d:GetBytes(2))
    
    if length > d:available() then
        return false
    end
    
    local handshakeType = d:GetU8()
    local length = string.unpack(">I3", d:GetBytes(3))
    if length > d:available() then
        return false
    end
    
    local major = d:GetU8()
    local minor = d:GetU8()
    
    if d:available() < 4 + 28 + 1 then
        return false
    end
    
    d:GetBytes(4 + 28) -- skip random
    
    local sessionIdLength = d:GetU8()
    if d:available() < sessionIdLength + 2 then
        return false
    end
    d:GetBytes(sessionIdLength) -- skip sessionId
    
    local cipherSuitesLength = string.unpack(">I2", d:GetBytes(2))
    if d:available() < cipherSuitesLength + 1 then
        return false
    end
    d:GetBytes(cipherSuitesLength) -- skip cipherSuites
    
    local compressMethodLength = d:GetU8()
    if d:available() < compressMethodLength + 2 then
        return false
    end
    d:GetBytes(compressMethodLength) -- skip compressMethod
    
    local extensionLength = string.unpack(">I2", d:GetBytes(2))
    
    if d:available() < extensionLength then
        return false
    end
    
    return true
end

local function get_hostname_from_clienthello(data)
    local d = stream.new(data)
    
    local contentType = d:GetU8()
    local major = d:GetU8()
    local minor = d:GetU8()
    local var = tonumber(string.format("%d.%d", major, minor))
    if var < 3.1 then
        -- print(string.format("contentType=%d, support tls only, %d.%d", contentType, major, minor))
        return nil, contentType, var
    end
    
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
        local itemData
        if itemLength > 0 then
            itemData = d:GetBytes(itemLength)
        else
            itemData = ""
        end
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

local function get_subject_from_server_hello(data)
    local input = stream.new(data)
    
    while input:available() > 0 do
        local contentType = input:GetU8()
        local major = input:GetU8()
        local minor = input:GetU8()
        local var = tonumber(string.format("%d.%d", major, minor))
        -- print(string.format("server version: %d.%d", major, minor))
        
        local len = string.unpack(">I2", input:GetBytes(2))
        
        local body = input:GetBytes(len)
        
        local d = stream.new(body)
        local handshakeType = d:GetU8()
        if handshakeType == 11 then
            local len = string.unpack(">I3", d:GetBytes(3))
            
            local certslen = string.unpack(">I3", d:GetBytes(3))
            -- print("handshakeType == 11", certslen, d:available())
            -- if certslen > d:available() then
            -- return nil, certslen
            -- end
            while d:available() > 0 do
                local certlen = string.unpack(">I3", d:GetBytes(3))
                local cert = d:GetBytes(certlen)
                return x509.read(cert):subject()
            end
        end
    end
end

return {get_hostname_from_clienthello = get_hostname_from_clienthello, get_subject_from_server_hello = get_subject_from_server_hello, verify_clienthello = verify_clienthello}
