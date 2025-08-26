#!/usr/bin/env python3

import sys
import json
import requests

# Destination Groups Telegram you can put "-0000000"
CHAT_ID = "<chat id groups>"

if len(sys.argv) < 3:
    print("Usage: python3 script.py <alert-file> <unused> <webhook-url>")
    sys.exit(1)

alert_file_path = sys.argv[1]
hook_url = sys.argv[3]

try:
    with open(alert_file_path) as f:
        alert_json = json.load(f)
except Exception as e:
    print(f"[!] Failed to load alert file: {e}")
    sys.exit(1)

# Extract data with get() to avoid KeyError
rule = alert_json.get('rule', {})
agent = alert_json.get('agent', {})
data = alert_json.get('data', {})

rule_id = rule.get('id', "N/A")
alert_level = rule.get('level', "N/A")
description = rule.get('description', "N/A")
agent_name = agent.get('name', "N/A")
timestamp = alert_json.get('timestamp', "N/A")
srcip = data.get('srcip', "N/A")
dstuser = data.get('dstuser', "N/A")
full_log = alert_json.get('full_log', "N/A")
rule_groups = ", ".join(rule.get('groups', [])) or "N/A"

def get_severity(level):
    try: level = int(level)
    except: return "Unknown"
    if level >= 15: return "Critical severity"
    elif 12 <= level <= 14: return "High severity"
    elif 7 <= level <= 11: return "Medium severity"
    elif 0 <= level <= 6: return "Low severity"
    return "Unknown"

severity = get_severity(alert_level)

message = (
    f"🚨 Beruang Cyber Alert 🚨\n"
    f"🆔 Rule ID: `{rule_id}`\n"
    f"⚠️ Alert Level: `{alert_level}`\n"
    f"🔴 Severity: {severity}\n"
    f"🖥 Agent: `{agent_name}`\n"
    f"📝 Description: {description}\n"
    f"🕒 Time: {timestamp}\n"
    f"🌐 Source IP: {srcip}\n"
    f"📜 Full Log: `{full_log}`\n"
    f"🎯 Destination User: `{dstuser}`\n"
    f"📦 Rule Groups: `{rule_groups}`\n"
    f"\n  🐻 Beruang Cyber Monitoring 🌐"
)

msg_data = {
    'chat_id': CHAT_ID,
    'text': message,
    'parse_mode': 'Markdown'
}

headers = {'content-type': 'application/json'}

try:
    r = requests.post(hook_url, headers=headers, data=json.dumps(msg_data))
    r.raise_for_status()
except requests.exceptions.RequestException as e:
    print(f"[!] Error sending Telegram alert: {e}")