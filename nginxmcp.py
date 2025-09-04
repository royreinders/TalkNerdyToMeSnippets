import base64
import json
import os
import re
import subprocess
from datetime import datetime

from fastmcp import FastMCP


mcp = FastMCP("NGINX MCP", stateless_http=True)

class ShellResult:
    def __init__(self, ok, code, out, err):
        self.ok = ok
        self.code = code
        self.out = out
        self.err = err


def _run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return ShellResult(p.returncode == 0, p.returncode, p.stdout.strip(), p.stderr.strip())
    except Exception as e:
        return ShellResult(False, 999, "", f"{type(e).__name__}: {e}")


def _nginx_test_and_reload():
    test = _run(["nginx", "-t"])
    if not test.ok:
        return False, f"nginx -t failed: {test.err or test.out}"
    svc = _run(["systemctl", "reload", "nginx"])
    if svc.ok:
        return True, "reloaded via systemctl"
    alt = _run(["nginx", "-s", "reload"])
    if alt.ok:
        return True, "reloaded via nginx -s reload"
    return False, f"reload failed: {svc.err or svc.out} / {alt.err or alt.out}"


def _parse_nginx_dump():
    dump = _run(["nginx", "-T"])
    text = "\n".join([dump.out, dump.err])
    roots = {}
    server_blocks = re.split(r"\n\s*server\s*\{", text)
    for block in server_blocks:
        names = re.findall(r"\n\s*server_name\s+([^;]+);", block)
        roots_in_block = re.findall(r"\n\s*root\s+([^;]+);", block)
        if not names or not roots_in_block:
            continue
        root_path = roots_in_block[-1].strip()
        for name in re.split(r"\s+", names[-1].strip()):
            roots[name] = root_path
    return roots


@mcp.tool()
def discover_payload_root():
    """Locate the directory used to host payloads by inspecting NGINX config; fall back to /var/www/payloads."""
    roots = _parse_nginx_dump()
    for name, root in roots.items():
        if "payload" in name or "/payload" in root:
            return {"server": name, "root": root}
    try:
        os.makedirs("/var/www/payloads", exist_ok=True)
    except Exception as e:
        return {"error": f"failed to ensure payload root: {e}"}
    return {"server": None, "root": "/var/www/payloads"}


@mcp.tool()
def read_access_log(limit: int = 100, status: int | None = None, method: str | None = None, contains: str | None = None):
    """
    Read and parse the NGINX access log.
    """
    if not os.path.exists("/var/log/nginx/access.log"):
        raise Exception(f"Access log not found: /var/log/nginx/access.log")

    results = []
    try:
        with open("/var/log/nginx/access.log", "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[-limit * 5:]  # grab more in case filters remove many
    except Exception as e:
        raise Exception(f"Failed to read access log: {e}")

    log_re = re.compile(
        r'(?P<remote_addr>\S+) - \S+ \[(?P<time>[^\]]+)\] '
        r'"(?P<method>[A-Z]+) (?P<url>\S+) \S+" '
        r'(?P<status>\d{3}) (?P<bytes_sent>\d+) '
        r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )

    for line in reversed(lines):
        m = log_re.match(line)
        if not m:
            continue
        entry = {
            "remote_addr": m.group("remote_addr"),
            "timestamp": m.group("time"),
            "method": m.group("method"),
            "url": m.group("url"),
            "status": int(m.group("status")),
            "bytes_sent": int(m.group("bytes_sent")),
            "referer": m.group("referer"),
            "user_agent": m.group("user_agent"),
        }
        if status and entry["status"] != status:
            continue
        if method and entry["method"].upper() != method.upper():
            continue
        if contains and contains not in entry["url"]:
            continue
        results.append(entry)
        if len(results) >= limit:
            break

    return results


@mcp.tool()
def list_vhosts():
    """List configured virtual hosts and their document roots (best-effort)."""
    mapping = _parse_nginx_dump()
    return [{"server_name": k, "root": v} for k, v in mapping.items()]


@mcp.tool()
def add_vhost(server_name, root=None, enable_ssl=False):
    """Create and enable an NGINX server block for `server_name`; optionally prepare for SSL."""
    try:
        vhost_file = os.path.join("/etc/nginx/sites-available", server_name)
        if os.path.exists(vhost_file):
            return {"error": f"vhost {server_name} already exists at {vhost_file}"}
        webroot = root if root else os.path.join("/var/www", server_name, "html")
        os.makedirs(webroot, exist_ok=True)
        index_file = os.path.join(webroot, "index.html")
        if not os.path.exists(index_file):
            with open(index_file, "w") as f:
                f.write(f"<h1>{server_name}</h1>\n<p>OK: {datetime.utcnow().isoformat()}Z</p>\n")
        server_block = f"""
server {{
    listen 80;
    listen [::]:80;
    server_name {server_name};
    root {webroot};
    index index.html index.htm;

    location / {{
        try_files $uri $uri/ =404;
    }}
}}
"""
        with open(vhost_file, "w") as f:
            f.write(server_block)
        link = os.path.join("/etc/nginx/sites-enabled", server_name)
        if os.path.islink(link) or os.path.exists(link):
            os.unlink(link)
        os.symlink(vhost_file, link)
        ok, msg = _nginx_test_and_reload()
        if not ok:
            return {"error": msg}
        result = {"status": "vhost_created", "server_name": server_name, "root": webroot}
        if enable_ssl:
            result["next"] = "call request_certificate to get a Let’s Encrypt cert"
        return result
    except Exception as e:
        return {"error": f"failed to create vhost: {e}"}


@mcp.tool()
def request_certificate(server_name, email, staging=False):
    """Obtain/renew a Let’s Encrypt certificate for `server_name` using certbot (nginx plugin)."""
    args = ["certbot", "--nginx", "-n", "--agree-tos", "-d", server_name, "-m", email]
    if staging:
        args.append("--staging")
    res = _run(args)
    if not res.ok:
        return {"error": f"certbot failed: {res.err or res.out}", "code": res.code}
    _nginx_test_and_reload()
    return {"status": "certificate_obtained", "details": res.out}


_STR_RE = re.compile(rb"[\x20-\x7e]{4,}")
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN_RE = re.compile(r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
_URL_RE = re.compile(r"https?://[\w.-]+(?:/[^\s'"]*)?", re.I)
_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|/)(?:[^\s]+)")

_MARKERS = [
    r"powershell -enc", r"IEX\(", r"Invoke-Expression", r"Invoke-WebRequest", r"DownloadString",
    r"Add-MpPreference", r"Set-MpPreference", r"DisableRealtimeMonitoring", r"AMSI", r"AmsiScanBuffer",
    r"rundll32", r"regsvr32", r"wmic", r"bitsadmin", r"certutil", r"mshta", r"wscript", r"cscript",
    r"sliver", r"cobalt", r"beacon", r"meterpreter", r"empire", r"havoc", r"mythic", r"pupy",
]
_MARKER_RE = re.compile("|".join(_MARKERS), re.I)


def _extract_strings(blob):
    return [s.decode("ascii", errors="ignore") for s in _STR_RE.findall(blob)]


@mcp.tool()
def analyze_payload(filename, content_b64=None, path=None):
    """Heuristically analyze a payload for OPSEC risks (strings, URLs, markers, paths, IPs)."""
    try:
        if path:
            with open(path, "rb") as f:
                blob = f.read()
        elif content_b64:
            blob = base64.b64decode(content_b64)
        else:
            return {"error": "provide either content_b64 or path"}
    except Exception as e:
        return {"error": f"failed to read payload: {e}"}

    lower = filename.lower()
    is_text = any(lower.endswith(ext) for ext in (".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".hta", ".sh", ".py", ".txt"))
    if not is_text:
        strings = _extract_strings(blob)
    else:
        strings = blob.decode("utf-8", errors="ignore").splitlines()

    text = "\n".join(strings)
    issues = []

    urls = sorted(set(_URL_RE.findall(text)))
    domains = sorted(set(d for d in _DOMAIN_RE.findall(text) if d not in {"localhost"}))
    ips = sorted(set(_IP_RE.findall(text)))
    paths = sorted(set(_PATH_RE.findall(text)))

    if urls:
        issues.append({"issue": "Hardcoded URLs", "severity": "medium", "details": urls[:50]})
    if domains:
        issues.append({"issue": "Hardcoded domains", "severity": "medium", "details": domains[:50]})
    if ips:
        issues.append({"issue": "Hardcoded IP addresses", "severity": "high", "details": ips[:50]})
    if paths:
        issues.append({"issue": "Absolute filesystem paths", "severity": "low", "details": paths[:50]})

    if _MARKER_RE.search(text):
        hits = sorted(set(m for m in _MARKERS if re.search(m, text, re.I)))
        issues.append({"issue": "Suspicious markers", "severity": "medium", "details": hits[:50]})

    if re.search(r"DEBUG|TODO|FIXME|test-key|sample|poc", text, re.I):
        issues.append({"issue": "Debug/PoC artifacts", "severity": "low"})

    if re.search(r"\\Users\\|/home/|/Users/", text):
        issues.append({"issue": "User home paths present", "severity": "low"})

    if re.search(r"ConvertTo-SecureString|FromBase64String\(", text, re.I):
        issues.append({"issue": "Sensitive encoding patterns", "severity": "low"})

    import math
    def shannon_entropy(b):
        if not b:
            return 0.0
        counts = [0] * 256
        for by in b:
            counts[by] += 1
        probs = [c / len(b) for c in counts if c]
        return -sum(p * math.log2(p) for p in probs)

    ent = shannon_entropy(blob[:1024 * 128])
    if ent > 7.5:
        issues.append({"issue": "High-entropy content (possible packed/encoded)", "severity": "info", "details": f"entropy≈{ent:.2f}"})

    return {
        "filename": filename,
        "size": len(blob),
        "issues": issues,
        "summary": {
            "url_count": len(urls),
            "domain_count": len(domains),
            "ip_count": len(ips),
            "path_count": len(paths),
            "entropy": round(ent, 2),
        },
        "advice": [
            "Avoid hardcoding IPs/domains; consider DNS indirection or short-lived infra.",
            "Strip AMSI/Defender bypasses unless explicitly required for testing.",
            "Remove absolute paths, usernames, or debug strings before delivery.",
            "Prefer HTTPS and consistent User-Agent if making outbound requests.",
            "Stage payloads with unique names and per-engagement secrets.",
        ],
    }


@mcp.tool()
def remove_vhost(server_name):
    """Disable and remove the NGINX server block for `server_name` without deleting webroot."""
    try:
        vhost_file = os.path.join("/etc/nginx/sites-available", server_name)
        link = os.path.join("/etc/nginx/sites-enabled", server_name)
        if os.path.islink(link) or os.path.exists(link):
            os.unlink(link)
        ok, msg = _nginx_test_and_reload()
        if not ok:
            return {"error": msg}
        if os.path.exists(vhost_file):
            os.unlink(vhost_file)
        return {"status": "vhost_removed", "server_name": server_name}
    except Exception as e:
        return {"error": f"failed to remove vhost: {e}"}


if __name__ == "__main__":
    mcp.run(transport="http", path="/nginx", host="127.0.0.1", port=8889)
