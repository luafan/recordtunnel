local service = require "service"

local function onGet(req, resp)
  local svs = service.get("tunnel")

  local list = {}
  for k,v in pairs(svs.getTunnels()) do
    table.insert(list, string.format("%s:%d", v.original_host, v.original_port or 0))
  end

  local body = table.concat(list, "\n")

  resp:addheader("Content-Type", "text/plain")
  resp:reply(200, "OK", body)
end

return {
  onGet = onGet
}
