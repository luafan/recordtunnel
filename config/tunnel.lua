tunnel_port = tonumber(os.getenv("TUNNEL_PORT") or 8888)
cert_key = os.getenv("CERT_KEY") or "cacert.key"
cert_crt = os.getenv("CERT_CRT") or "cacert.crt"

ssl_ports = {
  ["443"] = true
}

ssl_whitelist = {}

record = os.getenv("RECORD") and os.getenv("RECORD") == "true"
block_mode = os.getenv("BLOCK_MODE") and os.getenv("BLOCK_MODE") == "true"
