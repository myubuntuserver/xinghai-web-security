/**
 * StarSea Security - Allowlist Manager
 *
 * 功能：
 * - 内置可信域名白名单（官网、CDN、安全厂商等）
 * - 用户自定义白名单（域名/IP/URL 三级匹配）
 * - 通配符支持 (*.example.com)
 * - 临时放行（会话级，重启失效）
 * - 白名单优先于所有检测逻辑
 */

// 内置白名单（与 ml-engine.js OFFICIAL_DOMAINS 保持同步）
const BUILTIN_ALLOWLIST = [
  // 科技巨头
  'microsoft.com', 'windows.com', 'live.com', 'office.com', 'azure.com',
  'google.com', 'gstatic.com', 'googleapis.com', 'googlevideo.com',
  'googleusercontent.com', 'googlemail.com', 'gmail.com', 'youtube.com',
  'ytimg.com', 'ggpht.com', 'firebaseio.com', 'appspot.com',
  'apple.com', 'icloud.com', 'mzstatic.com', 'cdn-apple.com',
  'amazon.com', 'amazonaws.com', 'amazon.cn', 'amazon.co.jp',
  'cloudfront.net', 'media-amazon.com', 'ssl-images-amazon.com',
  'adobe.com', 'adobe.io', 'typekit.net',
  'meta.com', 'facebook.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com',
  'twitter.com', 'x.com', 'twimg.com',
  'linkedin.com', 'licdn.com',
  'github.com', 'githubusercontent.com', 'githubassets.com', 'github.io',
  'gitlab.com', 'bitbucket.org', 'npmjs.com', 'yarnpkg.com',
  'stackoverflow.com', 'stackexchange.com',
  'wikipedia.org', 'wikimedia.org',
  'mozilla.org', 'mozilla.net', 'firefox.com',
  // 中国互联网
  'baidu.com', 'bdstatic.com', 'bdimg.com', 'bcebos.com', 'baidubcs.com',
  'qq.com', 'tencent.com', 'weixin.qq.com', 'gtimg.cn', 'gtimg.com',
  'myqcloud.com', 'qpic.cn', 'qlogo.cn',
  'alicdn.com', 'aliyun.com', 'alibaba.com', 'taobao.com', 'tmall.com',
  'alipay.com', 'alipayobjects.com', 'tbcdn.cn',
  'jd.com', 'jcloudcs.com', '360buyimg.com',
  'bilibili.com', 'bilibili.cn', 'hdslb.com', 'bilivideo.com',
  'zhihu.com', 'zhimg.com',
  'weibo.com', 'weibocdn.com', 'sinaimg.cn', 'sina.com.cn',
  'douyin.com', 'bytedance.com', 'bytecdn.cn', 'byteimg.com',
  'xiaomi.com', 'mi.com',
  'huawei.com', 'hicloud.com',
  'oppo.com', 'vivo.com.cn', 'meizu.com',
  'netease.com', '126.com', '163.com',
  'meituan.com', 'dianping.com',
  'pinduoduo.com', 'yangkeduo.com',
  // 安全厂商
  'virustotal.com', 'kaspersky.com', 'mcafee.com', 'symantec.com',
  'norton.com', 'avast.com', 'bitdefender.com', 'eset.com',
  'malwarebytes.com', 'windowsupdate.com',
  '360.cn', '360totalsecurity.com', 'huorong.cn',
  'threatbook.cn', 'qianxin.com', 'dbappsecurity.com.cn',
  'hybrid-analysis.com', 'filescan.io', 'malshare.com',
  'abuse.ch', 'urlhaus.abuse.ch', 'threatfox.abuse.ch',
  // 开发/工具
  'python.org', 'pypi.org', 'golang.org', 'go.dev', 'gopkg.in',
  'nodejs.org', 'nodejs.cn', 'deno.land',
  'rust-lang.org', 'crates.io', 'rustup.rs',
  'docker.com', 'hub.docker.com',
  'jetbrains.com', 'visualstudio.com', 'code.visualstudio.com',
  'nuget.org',
  'sourceforge.net', 'getfancontrol.com',
  'tbtool.cn', 'tbtool.com',
  '7-zip.org', 'rarlab.com', 'notepad-plus-plus.org', 'libreoffice.org',
  // CDN
  'cloudflare.com', 'cloudflareinsights.com', 'cdnjs.cloudflare.com',
  'jsdelivr.net', 'unpkg.com', 'bootstrapcdn.com',
  'akamai.net', 'akamaihd.net', 'akamaized.net', 'fastly.net',
  'jquery.com', 'jqueryui.com',
  // 常见服务
  'paypal.com', 'stripe.com',
  'dropbox.com', 'dropboxusercontent.com',
  'slack.com', 'zoom.us',
  'discord.com', 'discord.gg', 'discordapp.com',
  'telegram.org', 't.me',
  'notion.so', 'notion.site',
  'figma.com', 'canva.com',
  'spotify.com', 'netflix.com',
  'steamcommunity.com', 'steampowered.com', 'steamstatic.com',
  'epicgames.com', 'unity.com',
  'w3.org', 'ietf.org'
];

export class Allowlist {
  constructor() {
    this._builtin = new Set(BUILTIN_ALLOWLIST);
    this._userDomains = new Map();
    this._userIPs = new Map();
    this._userUrls = new Map();
    this._sessionAllow = new Set(); // 临时放行
    this._wildcardPatterns = [];
  }

  /**
   * 从存储加载用户白名单
   */
  loadFromStorage(customAllowlist) {
    if (!customAllowlist) return;
    this._userDomains = new Map(Object.entries(customAllowlist.domains || {}));
    this._userIPs = new Map(Object.entries(customAllowlist.ips || {}));
    this._userUrls = new Map(Object.entries(customAllowlist.urls || {}));
    this._compileWildcards();
  }

  /**
   * 编译通配符规则
   */
  _compileWildcards() {
    this._wildcardPatterns = [];
    for (const [pattern, data] of this._userDomains) {
      if (pattern.includes('*')) {
        // Convert *.example.com → regex
        const regexStr = '^' + pattern.replace(/\./g, '\\.').replace(/\*/g, '[^.]+') + '$';
        try {
          this._wildcardPatterns.push({
            regex: new RegExp(regexStr, 'i'),
            data,
            pattern
          });
        } catch {}
      }
    }
  }

  /**
   * 提取主机名
   */
  _extractHostname(url) {
    try {
      return new URL(url).hostname.toLowerCase().replace(/^www\./, '');
    } catch {
      return url.toLowerCase().replace(/^www\./, '');
    }
  }

  /**
   * 提取IP
   */
  _extractIP(url) {
    const m = url.match(/https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    return m ? m[1] : null;
  }

  /**
   * 检查 URL 是否在白名单中
   * @returns {object|null} 白名单条目或 null
   */
  check(url) {
    if (!url) return null;
    const lower = url.toLowerCase();

    // 1. 临时放行（session）
    if (this._sessionAllow.has(lower)) {
      return { allowed: true, source: 'session', reason: '本次会话临时放行' };
    }

    const hostname = this._extractHostname(url);

    // 2. 内置白名单（域名及父域匹配）
    if (this._isBuiltinAllowed(hostname)) {
      return { allowed: true, source: 'builtin', reason: '内置可信域名' };
    }

    // 3. 用户白名单 - 精确域名
    if (this._userDomains.has(hostname)) {
      return { allowed: true, source: 'user', ...this._userDomains.get(hostname) };
    }

    // 4. 用户白名单 - 父域匹配（允许子域）
    const parts = hostname.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
      const parent = parts.slice(i).join('.');
      if (this._userDomains.has(parent)) {
        const entry = this._userDomains.get(parent);
        if (entry && entry.includeSubdomains !== false) {
          return { allowed: true, source: 'user', ...entry, matchedParent: parent };
        }
      }
    }

    // 5. 通配符匹配
    for (const wp of this._wildcardPatterns) {
      if (wp.regex.test(hostname)) {
        return { allowed: true, source: 'user', ...wp.data, matchedPattern: wp.pattern };
      }
    }

    // 6. IP 白名单
    const ip = this._extractIP(url);
    if (ip && this._userIPs.has(ip)) {
      return { allowed: true, source: 'user', ...this._userIPs.get(ip) };
    }

    // 7. URL 精确/前缀匹配
    for (const [pattern, data] of this._userUrls) {
      if (lower === pattern || lower.startsWith(pattern)) {
        return { allowed: true, source: 'user', ...data };
      }
    }

    return null;
  }

  /**
   * 检查内置白名单（含父域匹配）
   */
  _isBuiltinAllowed(hostname) {
    if (this._builtin.has(hostname)) return true;
    const parts = hostname.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
      if (this._builtin.has(parts.slice(i).join('.'))) return true;
    }
    return false;
  }

  /**
   * 添加用户白名单条目
   */
  add(type, value, note = '', includeSubdomains = true) {
    const entry = {
      note,
      includeSubdomains,
      addedAt: new Date().toISOString()
    };
    const v = value.toLowerCase().trim();
    switch (type) {
      case 'domain':
        this._userDomains.set(v, entry);
        if (v.includes('*')) this._compileWildcards();
        break;
      case 'ip':
        this._userIPs.set(v, entry);
        break;
      case 'url':
        this._userUrls.set(v, entry);
        break;
    }
    return this.toStorageFormat();
  }

  /**
   * 移除白名单条目
   */
  remove(value) {
    const v = value.toLowerCase().trim();
    this._userDomains.delete(v);
    this._userIPs.delete(v);
    this._userUrls.delete(v);
    this._sessionAllow.delete(v);
    this._compileWildcards();
    return this.toStorageFormat();
  }

  /**
   * 临时放行（会话级）
   */
  allowSession(url) {
    this._sessionAllow.add(url.toLowerCase());
  }

  /**
   * 清除会话白名单
   */
  clearSession() {
    this._sessionAllow.clear();
  }

  /**
   * 转换为存储格式
   */
  toStorageFormat() {
    return {
      domains: Object.fromEntries(this._userDomains),
      ips: Object.fromEntries(this._userIPs),
      urls: Object.fromEntries(this._userUrls)
    };
  }

  get stats() {
    return {
      builtin: this._builtin.size,
      userDomains: this._userDomains.size,
      userIPs: this._userIPs.size,
      userUrls: this._userUrls.size,
      session: this._sessionAllow.size,
      wildcards: this._wildcardPatterns.length
    };
  }

  /**
   * 获取所有用户白名单条目（用于 UI 展示）
   */
  getAllEntries() {
    const entries = [];
    for (const [value, data] of this._userDomains) {
      entries.push({ type: 'domain', value, ...data });
    }
    for (const [value, data] of this._userIPs) {
      entries.push({ type: 'ip', value, ...data });
    }
    for (const [value, data] of this._userUrls) {
      entries.push({ type: 'url', value, ...data });
    }
    return entries;
  }
}
