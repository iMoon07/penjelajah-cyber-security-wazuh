#!/var/ossec/framework/python/bin/python3
"""
Wazuh -> Discord integration (Penjelajah CyberSecurity v3) with GeoIP (ip-api.com) + optional AbuseIPDB + simple file cache
Usage:
  /var/ossec/framework/python/bin/python3 wazuh_discord_dewa_v2_geo_abuse.py <alert_file> <server_url> <discord_webhook_url>
Config:
 - ABUSEIPDB_KEY: set to your key or leave None to disable AbuseIPDB checks
 - CACHE_FILE: simple JSON cache for geo/abuse results (reduces external calls)
 - CACHE_TTL: seconds to keep cached entries
"""
from __future__ import annotations
import sys
import json
import time
import re
import requests
import os
from typing import Any, Dict, Optional, Tuple

# === CONFIG ===
LOG_PATH = "/var/ossec/logs/integrations.log"
CACHE_FILE = "/var/ossec/logs/geoip_cache.json"
CACHE_TTL = 60 * 60 * 24  # 24 hours
DESC_LOG_MAX = 1400   # max characters kept in the Log field
FALLBACK_EXCERPT = 400

# AbuseIPDB: set your key here (or keep None to disable)
ABUSEIPDB_KEY: Optional[str] = None  # e.g. "your_abuseipdb_api_key_here"

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

def safe_write_json(path: str, obj: Any) -> None:
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(obj, f)
        os.replace(tmp, path)
    except Exception as e:
        logger(f"Failed writing cache: {e}")

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

# === Simple file cache ===
def load_cache() -> Dict[str, Any]:
    try:
        if os.path.exists(CACHE_FILE):
            data = safe_load_json(CACHE_FILE)
            if isinstance(data, dict):
                return data
    except Exception as e:
        logger(f"Failed loading cache: {e}")
    return {}

def save_cache(cache: Dict[str, Any]) -> None:
    try:
        safe_write_json(CACHE_FILE, cache)
    except Exception as e:
        logger(f"Failed saving cache: {e}")

def cache_get(cache: Dict[str, Any], key: str) -> Optional[Dict[str, Any]]:
    ent = cache.get(key)
    if not ent:
        return None
    # ent expected: {"ts": epoch, "data": {...}}
    try:
        if time.time() - ent.get("ts", 0) > CACHE_TTL:
            return None
        return ent.get("data")
    except Exception:
        return None

def cache_set(cache: Dict[str, Any], key: str, data: Dict[str, Any]) -> None:
    cache[key] = {"ts": time.time(), "data": data}
    save_cache(cache)

# === GeoIP via ip-api.com (with lat/lon) ===
def get_geo_raw(ip: str, timeout: float = 3.0) -> Dict[str, Any]:
    if not ip:
        return {"status": "fail", "message": "no ip"}
    url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,query,lat,lon,message"
    try:
        r = requests.get(url, timeout=timeout)
        data = r.json() if r.ok else {}
        return {
            "status": data.get("status"),
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "query": data.get("query"),
            "message": data.get("message"),
        }
    except Exception as e:
        logger(f"GeoIP request failed for {ip}: {e}")
        return {"status": "fail", "message": str(e)}

def geo_pretty_and_links(geo: Dict[str, Any]) -> Tuple[str, str]:
    """
    Return (pretty_text, map_links)
    map_links is markdown-like text with Google Maps and OSM links (if lat/lon available).
    """
    if not geo or geo.get("status") != "success":
        return "–", "–"
    city = geo.get("city")
    region = geo.get("region")
    country = geo.get("country")
    isp = geo.get("isp") or geo.get("org")
    lat = geo.get("lat")
    lon = geo.get("lon")
    loc_parts = [p for p in (city, region, country) if p]
    loc = ", ".join(loc_parts) if loc_parts else "–"
    pretty = f"{loc} • ISP: {isp}" if isp else f"{loc}"
    links = "–"
    if lat is not None and lon is not None:
        gmap = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
        osm = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=10/{lat}/{lon}"
        # Provide both links (Discord will auto-link)
        links = f"[Google Maps]({gmap}) • [OpenStreetMap]({osm})"
    return pretty, links

# === AbuseIPDB lookup (optional) ===
def get_abuseipdb(ip: str, timeout: float = 4.0) -> Dict[str, Any]:
    """
    If ABUSEIPDB_KEY is set, query AbuseIPDB /check endpoint.
    Returns dict with keys: success(bool), abuseConfidenceScore(int), totalReports(int), url(str)
    If disabled or failed, returns {'success': False, 'reason': '...'}
    """
    if not ABUSEIPDB_KEY:
        return {"success": False, "reason": "Not configured"}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    try:
        r = requests.get(url, params=params, headers=headers, timeout=timeout)
        if r.status_code != 200:
            logger(f"AbuseIPDB returned {r.status_code} for {ip}: {r.text[:200]}")
            return {"success": False, "reason": f"HTTP {r.status_code}"}
        data = r.json().get("data", {})
        score = data.get("abuseConfidenceScore")
        reports = data.get("totalReports")
        # link to abuseipdb details page
        page = f"https://www.abuseipdb.com/check/{ip}"
        return {"success": True, "abuseConfidenceScore": score, "totalReports": reports, "url": page}
    except Exception as e:
        logger(f"AbuseIPDB request failed for {ip}: {e}")
        return {"success": False, "reason": str(e)}

# === Payload builder (DEWA v2) ===
def build_payload(alert: Dict, server_url: Optional[str] = None) -> Dict:
    cache = load_cache()
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
    geo_links_value = "–"
    abuse_field_value = "–"

    if parsed:
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

        parsed_lines = [
            f"**{status_flag} {status}**  • `{method} {path} {proto}`",
            f"**IP**: `{ip}`",
            f"**Time**: `{t}`",
            f"**Size**: `{size}`",
            f"**Referrer**: {ref if ref != '-' else '–'}",
            f"**UA**: {ua if ua != '-' else '–'}",
        ]
        parsed_summary = "  \n".join(parsed_lines)

        # caching key
        cache_key = f"geoabuse:{ip}"
        cached = cache_get(cache, cache_key)
        if cached:
            geo = cached.get("geo")
            abuse = cached.get("abuse")
        else:
            geo = get_geo_raw(ip)
            abuse = get_abuseipdb(ip) if ABUSEIPDB_KEY else {"success": False, "reason": "Not configured"}
            # store compact result
            cache_set(cache, cache_key, {"geo": geo, "abuse": abuse})

        # pretty geo + links
        geo_pretty_text, geo_links_value = geo_pretty_and_links(geo)
        geo_field_value = geo_pretty_text

        # abuse field
        if abuse.get("success"):
            score = abuse.get("abuseConfidenceScore")
            reports = abuse.get("totalReports")
            url = abuse.get("url")
            abuse_field_value = f"Score: `{score}` • Reports: `{reports}` • {url}"
        else:
            abuse_field_value = f"Not checked ({abuse.get('reason','no key')})"

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
        fields.append({"name": "🔎 Parsed Access Log", "value": parsed_summary, "inline": False})
        fields.append({"name": "🌍 GeoIP", "value": geo_field_value, "inline": False})
        # include map links if available in a separate small field for compactness
        fields.append({"name": "🗺️ Map Links", "value": geo_links_value, "inline": False})
        fields.append({"name": "🚫 AbuseIPDB", "value": abuse_field_value, "inline": False})

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
