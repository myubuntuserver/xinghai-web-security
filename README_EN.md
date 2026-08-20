# 🌊 StarSea Web Security

A browser security extension powered by Security.X threat intelligence, supporting Chrome / Edge / other Chromium-based browsers.

## Core Features

- **Real-time Threat Blocking**: 4,000+ local IOC rules (domains, IPs, URLs) with millisecond-level O(1) matching
- **Phishing Detection**: Built-in signatures for fake software download sites (Tuba Toolbox, Fan Control, Bilibili, etc.)
- **C2 Communication Blocking**: Blocks connections to known botnet C2 servers (SilverFox/ValleyRAT, etc.)
- **Malicious Download Blocking**: Prevents file downloads from known malicious sources
- **ML Heuristic Engine v5.3**: DGA domain detection, Punycode homograph attacks, typosquatting edit distance, cloud storage abuse, n-gram anomaly analysis, suspicious TLD detection
- **Allowlist System**: Built-in trusted domains + user-defined + wildcard support + per-session bypass, checked before all other detection
- **Custom Rules**: Manually add domain/IP/URL blacklist entries
- **Block Statistics**: Logs all blocked events, categorized by threat family and severity
- **Cloud Threat Intelligence**: Optional Security.X cloud Worker API integration with VirusTotal support

## Installation

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" (top-right toggle)
3. Click "Load unpacked"
4. Select the `starsea-web-security` folder
5. The extension icon appears in your toolbar — installation complete

> For Edge, visit `edge://extensions/` and follow the same steps.

## File Structure

```
starsea-web-security/
├── manifest.json          # MV3 extension manifest
├── background.js          # Service Worker (core interception logic)
├── lib/
│   ├── matcher.js         # IOC high-performance matching engine (Map-based O(1))
│   ├── ml-engine.js       # ML inference engine v5.3 (feature extraction + weighted scoring + multi-signal gating)
│   ├── allowlist.js       # Allowlist manager (built-in + user + wildcard + session)
│   └── cloud-client.js    # Cloud lookup client (Worker API communication)
├── popup/
│   ├── popup.html         # Popup panel UI
│   └── popup.js           # Popup panel logic
├── options/
│   ├── options.html       # Settings page
│   └── options.js         # Settings page logic
├── blockpage/
│   └── blockpage.html     # Threat block page (with confirmation + add to allowlist)
├── rules/
│   └── blocklist.json     # Built-in IOC rule database (4,138 entries)
└── icons/
    ├── icon16.png
    ├── icon32.png
    ├── icon48.png
    └── icon128.png
```

## Detection Pipeline

```
URL Request
  → Allowlist Check (built-in → user-defined → wildcard → session bypass)
  → Exact Domain Match (O(1) Map lookup)
  → Subdomain Traversal (parent domain match)
  → IP Address Match
  → URL Prefix/Contains Match
  → ML Engine Inference (feature extraction → weighted scoring → multi-signal gating)
  → Cloud Lookup (optional, Security.X Worker API)
  → Block / Allow
```

### ML Engine Decision Logic

| Signal Type | Examples | Threshold |
|-------------|----------|-----------|
| Strong | C2 port, Punycode attack, zinst/nsis naming | Single signal triggers block |
| Combined | Brand impersonation + suspicious TLD, phishing path + non-HTTPS | Requires 2+ factors |
| Weak | Suspicious keywords, unusual ports, long URLs | Requires ≥3 cumulative |

## Threat Intelligence Sources

- Security.X Cloud Threat Intelligence (Cloudflare D1, 35,000+ IOCs)
- VirusTotal file correlation analysis
- Kaspersky OpenTIP
- ThreatBook (Weibu)
- DBAPP Security TI
- Sangfor NDR alert correlation
- Manual reverse engineering (SilverFox/ValleyRAT, Noah Relay, etc.)

## Privacy

- All IOC matching is performed locally in the browser — no browsing data is uploaded
- No user data collection, no browsing history tracking
- Remote rule updates only download rule files — no request data is sent

## Changelog

### v1.2.0 (2026-08-20)
- Added allowlist system (built-in trusted domains + user-defined + temporary bypass)
- ML engine upgraded to v5.3 (multi-signal gating, false positive/negative suppression)
- Block page now includes "Add to Allowlist" button
- Allowlist takes priority over all detection logic

### v1.0.0 (2026-08-19)
- Initial release
- 4,138 IOC rules (4,084 domains + 29 IPs + 15 URLs + 10 file hashes)
- Four interception categories: phishing / malware / C2 / downloads
- Heuristic detection engine
- Custom rule management
- Block statistics and logging

## Tech Stack

- Manifest V3 (Service Worker + ES Module)
- chrome.declarativeNetRequest
- chrome.downloads API
- Pure vanilla JavaScript, zero third-party dependencies