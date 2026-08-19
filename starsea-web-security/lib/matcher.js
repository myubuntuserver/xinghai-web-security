/**
 * IOC Matcher - High-performance domain/IP/URL/hash lookup
 * Uses Set for O(1) exact match + parent domain traversal
 */

export class IOCMatcher {
  constructor(blocklist, customRules = {}) {
    this.blocklistVersion = blocklist.version || '0';
    this._domains = new Map();
    this._ips = new Map();
    this._urls = new Map();
    this._hashes = new Map();

    // Load bundled blocklist
    if (blocklist.domains) {
      for (const [domain, data] of Object.entries(blocklist.domains)) {
        this._domains.set(domain, data);
      }
    }
    if (blocklist.ips) {
      for (const [ip, data] of Object.entries(blocklist.ips)) {
        this._ips.set(ip, data);
      }
    }
    if (blocklist.urls) {
      for (const [url, data] of Object.entries(blocklist.urls)) {
        this._urls.set(url, data);
      }
    }
    if (blocklist.fileHashes) {
      for (const [hash, data] of Object.entries(blocklist.fileHashes)) {
        this._hashes.set(hash, data);
      }
    }

    // Merge custom rules
    this._custom = customRules || {};
    this._mergeCustom();
  }

  _mergeCustom() {
    if (this._custom.domains) {
      for (const [d, data] of Object.entries(this._custom.domains)) {
        this._domains.set(d, data);
      }
    }
    if (this._custom.ips) {
      for (const [ip, data] of Object.entries(this._custom.ips)) {
        this._ips.set(ip, data);
      }
    }
    if (this._custom.urls) {
      for (const [u, data] of Object.entries(this._custom.urls)) {
        this._urls.set(u, data);
      }
    }
  }

  updateCustom(customRules) {
    this._custom = customRules || {};
    // Rebuild from base + custom
    // Since we already merged, just add new ones (custom rules are additive in practice)
    this._mergeCustom();
  }

  matchDomain(hostname) {
    // Exact match
    if (this._domains.has(hostname)) {
      return this._domains.get(hostname);
    }
    return null;
  }

  matchIP(ip) {
    if (this._ips.has(ip)) {
      return this._ips.get(ip);
    }
    return null;
  }

  matchUrl(url) {
    if (this._urls.has(url)) {
      return this._urls.get(url);
    }
    // Try matching URL path patterns
    for (const [pattern, data] of this._urls) {
      if (url.startsWith(pattern) || url.includes(pattern)) {
        return data;
      }
    }
    return null;
  }

  matchHash(sha256) {
    const lower = sha256.toLowerCase().trim();
    if (this._hashes.has(lower)) {
      return this._hashes.get(lower);
    }
    return null;
  }

  get domainCount() { return this._domains.size; }
  get ipCount() { return this._ips.size; }
  get urlCount() { return this._urls.size; }
  get hashCount() { return this._hashes.size; }

  /**
   * Check if a hostname is a subdomain of any blocked domain
   * Returns the blocked parent domain or null
   */
  findParentDomain(hostname) {
    const parts = hostname.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
      const parent = parts.slice(i).join('.');
      if (this._domains.has(parent)) {
        return { domain: parent, data: this._domains.get(parent) };
      }
    }
    return null;
  }
}
