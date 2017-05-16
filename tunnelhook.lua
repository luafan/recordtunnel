local function dosend(tunnel, buf)
    if config.debug then
        print(tunnel, tunnel.original_port, buf)
    end
    return buf
end

local function doreceive(tunnel, buf)
    if config.debug then
        print(tunnel, tunnel.original_port, buf)
    end
    return buf
end

return {dosend = dosend, doreceive = doreceive}
