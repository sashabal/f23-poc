import http.server, socket, subprocess, os, json

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        r = {}
        try:
            r["disable_ipv6"] = int(open("/proc/sys/net/ipv6/conf/all/disable_ipv6").read().strip())
        except Exception as e:
            r["disable_ipv6"] = f"N/A: {e}"
        try:
            p = subprocess.run(["ip", "-6", "addr", "show"], capture_output=True, text=True, timeout=5)
            r["ipv6_addrs"] = p.stdout.strip() or "none"
        except Exception as e:
            r["ipv6_addrs"] = f"N/A: {e}"
        try:
            k = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            k.bind(("::1", 0))
            k.sendto(b"probe", ("::1", 9))
            k.close()
            r["udpv6"] = "WORKING"
        except OSError as e:
            r["udpv6"] = f"BLOCKED: {e}"
        r["kernel"] = os.uname().release
        try:
            k = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
            k.close()
            r["net_raw"] = "AVAILABLE"
        except Exception:
            r["net_raw"] = "DROPPED"
        try:
            caps = {}
            for line in open("/proc/self/status"):
                if line.startswith("Cap"):
                    parts = line.strip().split(":\t")
                    if len(parts) == 2:
                        caps[parts[0]] = parts[1]
            r["capabilities"] = caps
        except Exception:
            pass
        body = json.dumps(r, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

print("IPv6 check server on :3478")
http.server.HTTPServer(("0.0.0.0", 3478), H).serve_forever()

