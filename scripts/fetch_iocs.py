#!/usr/bin/env python3
"""Recolhe domínios IOC do hunt feed ScanMalware (Fake 'PDF Viewer' / remote-access agent)
e mantém uma lista acumulada em data/domains.txt + histórico em data/history.csv.
"""

import csv
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import requests

FEED_URL = "https://scanmalware.com/api/v1/hunts/f58cdf91-d99c-43a5-854b-e337666756d2/feed.atom"
DATA_DIR = "data"
DOMAINS_FILE = os.path.join(DATA_DIR, "domains.txt")
HISTORY_FILE = os.path.join(DATA_DIR, "history.csv")

NS = {"atom": "http://www.w3.org/2005/Atom"}
SCAN_RE = re.compile(r"matched a scan of ([^\s(]+) \(by hunting rule\)")

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
    ),
    "Accept": "application/atom+xml, application/xml, text/xml, */*",
}


def fetch_feed() -> str:
    resp = requests.get(FEED_URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    return resp.text


def parse_entries(xml_text: str):
    root = ET.fromstring(xml_text)
    entries = []
    for entry in root.findall("atom:entry", NS):
        entry_id = entry.findtext("atom:id", default="", namespaces=NS)
        title = entry.findtext("atom:title", default="", namespaces=NS)
        updated = entry.findtext("atom:updated", default="", namespaces=NS)
        link_el = entry.find("atom:link", NS)
        link = link_el.get("href") if link_el is not None else ""
        match = SCAN_RE.search(title)
        domain = match.group(1).rstrip(".") if match else None
        entries.append({"id": entry_id, "title": title, "domain": domain, "updated": updated, "link": link})
    return entries


def load_known_domains() -> set:
    if not os.path.exists(DOMAINS_FILE):
        return set()
    with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    xml_text = fetch_feed()
    entries = parse_entries(xml_text)

    print(f"DEBUG raw response length: {len(xml_text)} chars")
    print(f"DEBUG entries found in feed: {len(entries)}")
    if entries:
        print(f"DEBUG sample title: {entries[0]['title']!r}")
        print(f"DEBUG sample domain match: {entries[0]['domain']!r}")
    else:
        print(f"DEBUG raw response (first 500 chars): {xml_text[:500]!r}")

    known = load_known_domains()
    new_domains = []
    history_exists = os.path.exists(HISTORY_FILE)

    with open(HISTORY_FILE, "a", newline="", encoding="utf-8") as hf:
        writer = csv.writer(hf)
        if not history_exists:
            writer.writerow(["collected_at", "domain", "entry_id", "updated", "link", "title"])
        now = datetime.now(timezone.utc).isoformat()
        for e in entries:
            if not e["domain"] or e["domain"] in known:
                continue
            known.add(e["domain"])
            new_domains.append(e["domain"])
            writer.writerow([now, e["domain"], e["id"], e["updated"], e["link"], e["title"]])

    with open(DOMAINS_FILE, "w", encoding="utf-8") as f:
        for d in sorted(known):
            f.write(d + "\n")

    print(f"NEW_DOMAINS={','.join(sorted(new_domains))}")
    print(f"Total domains: {len(known)}; novos nesta run: {len(new_domains)}")


if __name__ == "__main__":
    main()
