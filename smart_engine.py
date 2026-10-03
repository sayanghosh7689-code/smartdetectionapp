"""

smart_engine.py - offline log intelligence. No backend, no API key, no ML install.

Pipeline: parse -> per-IP behaviour profiles -> detections -> statistical anomaly
check -> attack-chain correlation -> plain-English summary.
Returns the same JSON shape the Streamlit UI already understands.
"""

import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import unquote

# ---------------------------------------------------------------- parsing
LINE_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
)
LOOSE_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?\b(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+'
    r'(?P<path>\S+).*?\b(?P<status>[1-5]\d{2})\b', re.I)
ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
TS_FORMATS = ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S")


def parse_ts(text):
    text = (text or "").strip()
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=None)
        except ValueError:
            pass
    return None


def parse_line(line):
    m = LINE_RE.match(line)
    ts = None
    if m:
        d = m.groupdict()
        ts = parse_ts(d["ts"])
        size = int(d["size"]) if d["size"].isdigit() else 0
    else:
        m = LOOSE_RE.search(line)
        if not m:
            return None
        d = m.groupdict()
        iso = ISO_RE.search(line)
        ts = parse_ts(iso.group(0)) if iso else None
        size = 0
    quoted = re.findall(r'"([^"]*)"', line)
    return {"ip": d["ip"], "method": d["method"].upper(), "path": d["path"],
            "status": int(d["status"]), "size": size, "ts": ts,
            "ua": quoted[-1] if quoted else "", "raw": line}


# ---------------------------------------------------------------- signatures
LOGIN_PATH = re.compile(r"login|signin|sign-in|auth|token|session|password|admin", re.I)
EXPORT_PATH = re.compile(r"export|download|dump|backup|all-|report", re.I)
SENSITIVE = re.compile(r"/\.env|/\.git|wp-config|wp-login|phpmyadmin|/admin|/etc/(?:passwd|shadow)|"
                       r"server-status|actuator|backup|\.sql|\.bak|id_rsa", re.I)
SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|ffuf|wpscan|"
                        r"acunetix|nessus|openvas|burp|hydra", re.I)
SIGS = {
    "sqli": re.compile(r"union\s+(?:all\s+)?select|\bor\s+'?1'?\s*=\s*'?1|sleep\s*\(|benchmark\s*\(|"
                       r"information_schema|drop\s+table|xp_cmdshell|waitfor\s+delay|'\s*--", re.I),
    "xss": re.compile(r"<script|javascript:|onerror\s*=|onload\s*=|<iframe|document\.cookie", re.I),
    "traversal": re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow", re.I),
    "cmdi": re.compile(r";\s*(?:cat|id|whoami|uname|wget|curl|bash|sh)\b|\|\s*(?:bash|sh|nc)\b|"
                       r"\$\((?:id|whoami|curl|wget)|cmd\.exe|powershell", re.I),
}
SIG_INFO = {
    "sqli": ("high", "Possible SQL injection", "SQL-style payloads were sent in requests"),
    "xss": ("high", "Possible cross-site scripting (XSS)", "script-injection payloads were sent"),
    "traversal": ("high", "Possible path traversal", "requests tried to read files outside the web root"),
    "cmdi": ("critical", "Possible command injection", "shell commands were embedded in requests"),
}
WEIGHT = {"low": 1, "medium": 3, "high": 6, "critical": 10}
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
BIG_BYTES = 1_000_000


def _evidence(lines):
    return [x[:220] for x in lines[:5]]


def _robust_outliers(counts, min_value):
    """IPs whose request count is a statistical outlier (median/MAD z-score)."""
    if len(counts) < 4:
        return {ip for ip, c in counts.items() if c >= max(min_value, 100)}
    vals = list(counts.values())
    med = statistics.median(vals)
    mad = statistics.median(abs(v - med) for v in vals) or 1
    return {ip for ip, c in counts.items() if c >= min_value and 0.6745 * (c - med) / mad > 3.5}


# ---------------------------------------------------------------- main
def analyze(text, max_lines=20000):
    raw = [ln.strip() for ln in text.splitlines() if ln.strip()]
    lines = raw[:max_lines]
    records = [r for r in (parse_line(ln) for ln in lines) if r]
    if records and all(r["ts"] for r in records):
        records.sort(key=lambda r: r["ts"])

    P = defaultdict(lambda: {"n": 0, "fail": 0, "login_fail": 0, "takeover": None, "paths": set(),
                             "n404": 0, "sens": [], "scan": [], "export": [], "big": 0,
                             "sigs": defaultdict(list), "min": Counter(), "ts": []})
    total_fail = 0
    for r in records:
        p = P[r["ip"]]
        dec = unquote(unquote(r["path"] + " " + r["ua"]))
        login = bool(LOGIN_PATH.search(r["path"]))
        p["n"] += 1
        p["paths"].add(r["path"].split("?")[0])
        if r["ts"]:
            p["ts"].append(r["ts"])
            p["min"][r["ts"].strftime("%Y%m%d%H%M")] += 1
        if r["status"] == 404:
            p["n404"] += 1
        if r["status"] in (401, 403):
            total_fail += 1
            p["fail"] += 1
            if login:
                p["login_fail"] += 1
        if login and r["method"] in ("POST", "PUT") and 200 <= r["status"] < 400 \
                and p["login_fail"] >= 5 and not p["takeover"]:
            p["takeover"] = r["raw"]
        for name, rx in SIGS.items():
            if rx.search(dec):
                p["sigs"][name].append(r["raw"])
        if SENSITIVE.search(unquote(r["path"])):
            p["sens"].append(r["raw"])
        if SCANNER_UA.search(r["ua"]):
            p["scan"].append(r["raw"])
        if EXPORT_PATH.search(r["path"]) and 200 <= r["status"] < 300:
            p["export"].append(r["raw"])
            if r["size"] >= BIG_BYTES:
                p["big"] += 1

    findings = []   # (severity, title, detail, evidence, ip, stage)

    def add(sev, title, detail, ev, ip, stage):
        findings.append((sev, title, detail, _evidence(ev), ip, stage))

    outliers = _robust_outliers({ip: p["n"] for ip, p in P.items()}, 20)

    for ip, p in P.items():
        if p["login_fail"] >= 5:
            add("high" if p["login_fail"] >= 20 else "medium", "Brute-force login attempts",
                f"{ip} failed {p['login_fail']} logins" + _span(p), [], ip, "credential attack")
        if p["takeover"]:
            add("critical", "Possible account takeover",
                f"{ip} logged in successfully right after {p['login_fail']} failed attempts - "
                "the password may have been guessed.", [p["takeover"]], ip, "successful access")
        if p["n404"] >= 5 or len(p["sens"]) >= 2:
            examples = ", ".join(sorted({x.split('"')[1].split()[1] if x.count('"') >= 2 else ''
                                         for x in p["sens"]} - {''})[:4])
            add("high" if len(p["sens"]) >= 3 else "medium", "Reconnaissance / path probing",
                f"{ip} caused {p['n404']} not-found responses and {len(p['sens'])} sensitive-path probes"
                + (f" ({examples})" if examples else "") + ".", p["sens"], ip, "reconnaissance")
        for name, hits in p["sigs"].items():
            sev, title, what = SIG_INFO[name]
            add(sev, title, f"{ip}: {what} ({len(hits)} request(s)).", hits, ip, "attack payloads")
        if p["scan"]:
            add("medium", "Security scanner detected",
                f"{ip} used a known scanning tool ({len(p['scan'])} request(s)).", p["scan"], ip, "reconnaissance")
        if p["export"] and p["big"]:
            risky = p["takeover"] or p["login_fail"] >= 5 or p["sens"]
            add("high" if risky else "medium", "Large data download",
                f"{ip} downloaded {p['big']} large response(s) from export-style endpoints"
                + (" after suspicious activity." if risky else "."), p["export"], ip, "data download")
        if ip in outliers:
            add("medium", "Abnormal request volume",
                f"{ip} sent {p['n']} requests, far above the typical IP in this log.", [], ip, "volume")
        if p["min"] and max(p["min"].values()) >= 60:
            add("medium", "Request burst", f"{ip} peaked at {max(p['min'].values())} requests/minute.", [], ip, "volume")

    findings.sort(key=lambda f: (ORDER[f[0]], f[4]))
    out_findings = [{"severity": s, "title": t, "detail": d, "evidence": ev, "source": "smart-engine"}
                    for s, t, d, ev, _, _ in findings]
    if not out_findings:
        out_findings = [{"severity": "low", "title": "No suspicious pattern detected",
                         "detail": "Behaviour, signatures and volume all looked normal.",
                         "evidence": [], "source": "smart-engine"}]

    # per-IP scores + attack-chain correlation
    score, reasons, stages = Counter(), defaultdict(list), defaultdict(list)
    for s, t, _, _, ip, st in findings:
        score[ip] += WEIGHT[s]
        reasons[ip].append(t)
        if st not in stages[ip]:
            stages[ip].append(st)
    stage_rank = ["reconnaissance", "attack payloads", "credential attack", "successful access", "data download"]
    insights = []
    for ip, st in stages.items():
        chain = [x for x in stage_rank if x in st]
        if len(chain) >= 2:
            insights.append(f"{ip} shows a multi-stage attack: {' -> '.join(chain)}. "
                            "Treat anything this IP touched as potentially compromised.")
    top_ips = [{"ip": ip, "score": min(100, sc * 7), "reasons": sorted(set(reasons[ip]))}
               for ip, sc in score.most_common(5)]

    kinds = {t for _, t, _, _, _, _ in findings}
    risk = next((lv for lv in ("critical", "high", "medium") if any(f[0] == lv for f in findings)), "low")
    bad_ips = [t["ip"] for t in top_ips]

    recs = []
    if "Possible account takeover" in kinds:
        recs.append("Reset passwords and revoke active sessions for any account the flagged IP logged into.")
    if "Brute-force login attempts" in kinds:
        recs.append("Add rate limiting and lockout/CAPTCHA on login endpoints; enable multi-factor authentication.")
    if kinds & {"Possible SQL injection"}:
        recs.append("Use parameterized queries and server-side input validation.")
    if kinds & {"Possible cross-site scripting (XSS)"}:
        recs.append("Encode output and add a Content-Security-Policy header.")
    if kinds & {"Possible path traversal", "Reconnaissance / path probing"}:
        recs.append("Block public access to .env, .git, admin and backup paths; validate file paths.")
    if "Possible command injection" in kinds:
        recs.append("Never pass user input to a shell; use strict allow-lists.")
    if "Large data download" in kinds:
        recs.append("Audit what was exported and add authorization checks and size limits on export endpoints.")
    if bad_ips and risk != "low":
        recs.insert(0, "Block or rate-limit: " + ", ".join(bad_ips[:3]) + ".")
    if not recs:
        recs.append("No action needed. Keep monitoring logs and keep software patched.")

    total_requests = sum(p["n"] for p in P.values())
    if risk == "low":
        summary = (f"LOW risk: {total_requests} requests from {len(P)} IP address(es) "
                   "were analysed and nothing suspicious was found.")
    else:
        worst = findings[0]
        summary = (f"{risk.upper()} risk: {total_requests} requests from {len(P)} IP address(es) "
                   f"were analysed. Most serious: {worst[1].lower()} - {worst[2]}")
        if insights:
            summary += " " + insights[0]

    sig_count = lambda n: sum(len(p["sigs"].get(n, [])) for p in P.values())
    return {
        "risk_level": risk,
        "summary": summary,
        "stats": {"requests": total_requests, "failed_logins": total_fail,
                  "suspicious_ips": len(stages),
                  "sql_injection_attempts": sig_count("sqli"), "xss_attempts": sig_count("xss"),
                  "path_traversal_attempts": sig_count("traversal"),
                  "command_injection_attempts": sig_count("cmdi"),
                  "sensitive_path_attempts": sum(len(p["sens"]) for p in P.values()),
                  "scanner_requests": sum(len(p["scan"]) for p in P.values())},
        "findings": out_findings,
        "recommendations": recs,
        "ai_insights": insights,
        "top_ips": top_ips,
        "metadata": {"engine": "smart-engine (offline)", "lines_received": len(raw),
                     "lines_analyzed": len(lines), "lines_unparsed": len(lines) - len(records),
                     "truncated": len(raw) > max_lines},
    }


def _span(p):
    if len(p["ts"]) >= 2:
        mins = max(1, round((max(p["ts"]) - min(p["ts"])).total_seconds() / 60))
        return f" over about {mins} minute(s)."
    return "."
