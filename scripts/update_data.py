#!/usr/bin/env python3
"""Fetch latest CVEs from NVD and write data.json. Run by GitHub Action every 15 min."""
import json, os, time
import urllib.request
from datetime import datetime, timedelta, timezone

OUT = os.path.join(os.path.dirname(__file__), "..", "data.json")
API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch(days=30, results=2000):
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    url = (f"{API}?resultsPerPage={results}"
           f"&pubStartDate={start:%Y-%m-%dT%H:%M:%S.000}"
           f"&pubEndDate={now:%Y-%m-%dT%H:%M:%S.000}")
    req = urllib.request.Request(url, headers={"User-Agent": "subzero-radar/1.0"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=40) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            print("retry", attempt, e); time.sleep(6)
    return None

def sev_of(s):
    if s is None: return "unknown"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"

def main():
    d = fetch()
    if not d:
        print("NVD unreachable, keeping existing data.json"); return
    items = []
    for v in d.get("vulnerabilities", []):
        c = v["cve"]
        m = (c.get("metrics", {}).get("cvssMetricV31")
             or c.get("metrics", {}).get("cvssMetricV30")
             or c.get("metrics", {}).get("cvssMetricV2") or [{}])[0]
        score = m.get("cvssData", {}).get("baseScore")
        desc = next((x["value"] for x in c.get("descriptions", []) if x["lang"] == "en"), "No description.")
        vendors = set()
        for cfg in c.get("configurations", []):
            for nd in cfg.get("nodes", []):
                for cm in nd.get("cpeMatch", []):
                    p = (cm.get("criteria", "")).split(":")
                    if len(p) > 3 and p[3]: vendors.add(p[3])
        items.append({"id": c["id"], "title": desc.split(". ")[0][:110], "desc": desc,
                      "score": score, "sev": sev_of(score), "published": c.get("published"),
                      "vendors": sorted(vendors)[:6],
                      "refs": [r.get("url") for r in c.get("references", []) if r.get("url")][:5],
                      "sources": ["NVD", "CVE.org"]})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    items.sort(key=lambda x: order.get(x["sev"], 9))
    data = {"updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "count": len(items), "cves": items}
    with open(OUT, "w") as f:
        json.dump(data, f, separators=(",", ":"))
    print("wrote", len(items), "cves")

if __name__ == "__main__":
    main()
