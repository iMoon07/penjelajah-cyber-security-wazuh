#!/var/ossec/framework/python/bin/python3
"""
Wazuh -> Discord integration (Penjelajah CyberSecurity v2) with GeoIP (ip-api.com)
Usage:
  /var/ossec/framework/python/bin/python3 wazuh_discord_dewa_v2_geo.py <alert_file> <server_url> <discord_webhook_url>
Notes:
 - Uses ip-api.com for GeoIP (no API key). Be mindful of rate limits (45 req/min from same IP).
 - If you prefer another provider or a local MaxMind DB, adapt get_geo() accordingly.
"""
from __future__ import annotations
import sys
import json
import time
import re
import requests
from typing import Any, Dict, Optional

# === CONFIG ===
LOG_PATH = "/var/ossec/logs/integrations.log"
DESC_LOG_MAX = 1400   # max characters kept in the Log field
FALLBACK_EXCERPT = 400

# Set role id to mention (string), or None to disable mentions
MENTION_ROLE_ID: Optional[str] = None  # e.g. "123456789012345678"

# Colors
COLOR_INFO = 0x57B1FF
COLOR_LOW = 0x57F287
COLOR_WARN = 0xFEE75C
COLOR_HIGH = 0xED6C63
COLOR_CRIT = 0xED4245

# === Helpers ===
def now_str(fmt: str = "%Y/%m/%d %H:%M:%S %Z") -> str:
    return time.strftime(fmt, time.localtime())

def logger(msg: str) -> None:
    try:
        with open(LOG_PATH, "a") as f:
            f.write(f"{now_str()} [Discord] {msg}\n")
    except Exception:
        pass

def safe_load_json(path: str) -> Dict:
    with open(path, "r") as f:
        return json.load(f)

def truncate(text: Any, limit: int) -> str:
    t = str(text) if text is not None else ""
    return t if len(t) <= limit else t[:limit] + "\n...[truncated]..."

def list_to_str(v: Any) -> str:
    if isinstance(v, list):
        return ", ".join(map(str, v)) if v else "–"
    if v is None:
        return "–"
    return str(v)

def severity_map(level: Any):
    try:
        lvl = int(level)
    except Exception:
        lvl = 0
    if lvl <= 2:
        return {"emoji":"ℹ️", "label":"INFO", "color": COLOR_INFO}
    if lvl <= 4:
        return {"emoji":"✅", "label":"LOW", "color": COLOR_LOW}
    if lvl <= 7:
        return {"emoji":"⚠️", "label":"WARNING", "color": COLOR_WARN}
    if lvl <= 9:
        return {"emoji":"🔥", "label":"HIGH", "color": COLOR_HIGH}
    return {"emoji":"🚨", "label":"CRITICAL", "color": COLOR_CRIT}

# Optional small icon mapping for groups/compliance (tweak as you like)
GROUP_ICON = {
    "web": "🌐",
    "accesslog": "📘",
    "attack": "⚔️",
}

PCI_ICON = "💳"
GDPR_ICON = "🔒"
MITRE_ICON = "⚔️"

# === Log parsing ===
COMBINED_LOG_RE = re.compile(
    r'(?P<ip>\S+) '                # remote IP
    r'\S+ \S+ '                    # ident, authuser (ignored)
    r'\[(?P<time>[^\]]+)\] '       # time
    r'"(?P<method>\S+)\s(?P<path>\S+)(?:\s(?P<proto>[^"]+))?" '  # request
    r'(?P<status>\d{3}) '          # status
    r'(?P<size>\S+) '              # size
    r'"(?P<referrer>[^"]*)" '      # referrer
    r'"(?P<agent>[^"]*)"'          # user agent
)

def parse_access_log_line(line: str) -> Optional[Dict[str, str]]:
    if not line:
        return None
    m = COMBINED_LOG_RE.search(line)
    if not m:
        return None
    return m.groupdict()

def http_status_flag(status: Optional[str]) -> str:
    try:
        s = int(status)
    except Exception:
        return "•"
    if 100 <= s < 300:
        return "✔️"
    if 300 <= s < 400:
        return "➡️"
    if 400 <= s < 500:
        return "⚠️"
    if 500 <= s < 600:
        return "🔥"
    return "•"

# === GeoIP ===
def get_geo(ip: str, timeout: float = 3.0) -> Dict[str, Optional[str]]:
    """
    Query ip-api.com for simple GeoIP fields.
    Returns dict with keys: city, region, country, isp, org, query, status
    On failure returns status != 'success'.
    """
    if not ip:
        return {"status": "fail"}
    url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,query,message"
    try:
        r = requests.get(url, timeout=timeout)
        data = r.json() if r.ok else {}
        # normalize keys we care about
        return {
            "status": data.get("status"),
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "query": data.get("query"),
            "message": data.get("message"),
        }
    except Exception as e:
        logger(f"GeoIP request failed for {ip}: {e}")
        return {"status": "fail"}

def geo_pretty(geo: Dict[str, Optional[str]]) -> str:
    if not geo or geo.get("status") != "success":
        return "–"
    parts = []
    city = geo.get("city")
    region = geo.get("region")
    country = geo.get("country")
    isp = geo.get("isp") or geo.get("org")
    # Build readable location
    loc_parts = [p for p in (city, region, country) if p]
    loc = ", ".join(loc_parts) if loc_parts else "–"
    parts.append(f"{loc}")
    if isp:
        parts.append(f"ISP: {isp}")
    return " • ".join(parts)

# === Payload builder (DEWA v2) ===
def build_payload(alert: Dict, server_url: Optional[str] = None) -> Dict:
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}

    level = rule.get("level", 0)
    sev = severity_map(level)
    emoji = sev["emoji"]; sev_label = sev["label"]; color = sev["color"]

    title = rule.get("description") or "Wazuh Alert"
    pretty_title = f"{emoji} {sev_label} • {title}"

    full_log = alert.get("full_log", "") or ""
    # Use first non-empty line for parsing (many alerts include single-line access log)
    first_line = ""
    for ln in str(full_log).splitlines():
        if ln.strip():
            first_line = ln.strip()
            break

    parsed = parse_access_log_line(first_line)
    parsed_summary = None
    geo_field_value = "–"

    if parsed:
        # basic parsed fields
        ip = parsed.get("ip", "-")
        t = parsed.get("time", "-")
        method = parsed.get("method", "-")
        path = parsed.get("path", "-")
        proto = parsed.get("proto", "-")
        status = parsed.get("status", "-")
        size = parsed.get("size", "-")
        ref = parsed.get("referrer", "-")
        ua = parsed.get("agent", "-")

        status_flag = http_status_flag(status)

        # Build pretty list-style block (uses newlines, bold labels)
        parsed_lines = [
            f"**{status_flag} {status}**  • `{method} {path} {proto}`",
            f"**IP**: `{ip}`",
            f"**Time**: `{t}`",
            f"**Size**: `{size}`",
            f"**Referrer**: {ref if ref != '-' else '–'}",
            f"**UA**: {ua if ua != '-' else '–'}",
        ]
        parsed_summary = "  \n".join(parsed_lines)

        # GeoIP lookup (best-effort)
        geo = get_geo(ip)
        geo_field_value = geo_pretty(geo)

    # Truncate raw log for the log field
    log_trunc = truncate(full_log, DESC_LOG_MAX)
    log_field_value = f"```text\n{log_trunc}\n```" if log_trunc else "–"

    agent_name = agent.get("name", "Unknown")
    agent_id = agent.get("id", "N/A")
    rule_id = rule.get("id", "N/A")
    groups = rule.get("groups", []) or []
    mitre = rule.get("mitre", {}) or {}
    pci = rule.get("pci_dss", []) or []
    gdpr = rule.get("gdpr", []) or []
    location = alert.get("location", "N/A")
    timestamp = alert.get("timestamp")

    # Build composed group string with small icons if known
    groups_pretty = " ".join(GROUP_ICON.get(g, "") for g in groups).strip()
    groups_pretty = f"{groups_pretty} {list_to_str(groups)}" if groups_pretty else list_to_str(groups)

    # Fields: Quick summary, Parsed (if any), Geo, Details, Compliance, Log
    quick_value = (
        f"**Agent**: `{agent_name}`  \n"
        f"**Rule**: `{rule_id}`  \n"
        f"**Location**: `{location}`"
    )

    details_value = (
        f"**Level**: `{level}` ({sev_label})  \n"
        f"**Groups**: {groups_pretty}  \n"
        f"**MITRE**: {list_to_str(mitre.get('tactic')) if isinstance(mitre, dict) else list_to_str(mitre)}"
    )

    compliance_value = f"{PCI_ICON} {list_to_str(pci)}  \n{GDPR_ICON} {list_to_str(gdpr)}"

    footer_text = f"🛡️ Cyber Alert Wazuh By M00NL16Ht • {time.strftime('%d/%m/%Y %H:%M', time.localtime())}"

    fields = [
        {"name": "🧭 Quick", "value": quick_value, "inline": False},
    ]
    if parsed_summary:
        # parsed_summary now is a multi-line, labeled list for readability
        fields.append({"name": "🔎 Parsed Access Log", "value": parsed_summary, "inline": False})
        # Geo field separate for clearer UI (as in screenshot)
        fields.append({"name": "🌍 GeoIP", "value": geo_field_value, "inline": False})

    fields.extend([
        {"name": "📊 Details", "value": details_value, "inline": True},
        {"name": "🧾 Compliance", "value": compliance_value, "inline": True},
        {"name": "📜 Log (truncated)", "value": log_field_value, "inline": False},
    ])

    embed: Dict[str, Any] = {
        "title": pretty_title,
        "color": color,
        "author": {"name": f"{agent_name} (ID: {agent_id})"},
        "fields": fields,
        "footer": {"text": footer_text},
    }

    if server_url:
        embed["url"] = f"{server_url.rstrip('/')}/app/discover"
    if timestamp:
        embed["timestamp"] = timestamp

    # Fallback content: mention for CRITICAL only
    content = ""
    try:
        lvl = int(level)
    except Exception:
        lvl = 0

    if lvl >= 10:
        if MENTION_ROLE_ID:
            content = f"<@&{MENTION_ROLE_ID}> 🚨 **CRITICAL** • {title}\nAgent: {agent_name} • Rule: {rule_id}"
        else:
            content = f"@here 🚨 **CRITICAL** • {title}\nAgent: {agent_name} • Rule: {rule_id}"
    else:
        content = f"{emoji} **{sev_label}** • {title}"

    payload = {"content": content, "embeds": [embed]}
    return payload

def post_to_discord(payload: Dict, webhook: str) -> None:
    headers = {"Content-Type": "application/json", "Accept-Charset": "UTF-8"}
    try:
        r = requests.post(webhook, json=payload, headers=headers, timeout=10)
        logger(f"POST {r.status_code} - {(r.text or '')[:400]}")
        r.raise_for_status()
    except requests.RequestException as e:
        logger(f"Request error: {e}")

def main(argv: list[str]) -> int:
    if len(argv) < 4:
        msg = "Usage: script <alert_file> <server_url> <discord_webhook_url>"
        logger(msg); print(msg, file=sys.stderr)
        return 2

    alert_file, server_url, webhook = argv[1], argv[2] or None, argv[3]
    try:
        alert = safe_load_json(alert_file)
    except Exception as e:
        logger(f"Failed to load alert JSON: {e}")
        return 1

    try:
        payload = build_payload(alert, server_url)
        post_to_discord(payload, webhook)
        return 0
    except Exception as e:
        logger(f"Unhandled: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main(sys.argv))
