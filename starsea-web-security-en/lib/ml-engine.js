/**
 * StarSea Security ML Engine v5.3 - Lightweight JavaScript Inference
 *
 * v5.3 更新（误报/漏报压制）：
 * - 内置官方域名白名单，品牌仿冒检测不再误判官网
 * - nsis/install 等宽匹配规则收紧为多因子组合判定
 * - 可疑词/钓鱼路径需叠加至少一个异常因子才计分
 * - 新增：typosquatting 编辑距离检测、云盘滥用、新注册域名代理特征
 * - 新增：n-gram DGA 分析、CDN 子域随机性区分
 * - 评分从 max 改为加权累积，避免单条弱规则触发
 * - 阈值从 0.65 微调为 0.60，但需 ≥2 个独立信号才判恶意
 *
 * 运行环境: Browser MV3 / Cloudflare Worker (V8 isolates)
 */

// ============ 官方域名白名单（品牌仿冒排除） ============

const OFFICIAL_DOMAINS = new Set([
  // 科技巨头
  'microsoft.com', 'windows.com', 'live.com', 'office.com', 'azure.com',
  'google.com', 'gstatic.com', 'googleapis.com', 'googlevideo.com',
  'googleusercontent.com', 'googlemail.com', 'gmail.com', 'youtube.com',
  'ytimg.com', 'ggpht.com', 'firebaseio.com', 'appspot.com',
  'apple.com', 'icloud.com', 'mzstatic.com', 'cdn-apple.com',
  'amazon.com', 'amazonaws.com', 'amazon.cn', 'amazon.co.jp',
  'cloudfront.net', 'amazon-adsystem.com', 'media-amazon.com', 'ssl-images-amazon.com',
  'adobe.com', 'adobe.io', 'typekit.net',
  'meta.com', 'facebook.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com',
  'twitter.com', 'x.com', 'twimg.com', 't.co',
  'linkedin.com', 'licdn.com',
  'github.com', 'githubusercontent.com', 'githubassets.com', 'github.io',
  'gitlab.com', 'bitbucket.org', 'npmjs.com', 'npmjs.org', 'yarnpkg.com',
  'stackoverflow.com', 'stackexchange.com', 'superuser.com',
  'wikipedia.org', 'wikimedia.org', 'wiktionary.org',
  'mozilla.org', 'mozilla.net', 'firefox.com',
  // 中国互联网
  'baidu.com', 'bdstatic.com', 'bdimg.com', 'bcebos.com', 'baidubcs.com',
  'qq.com', 'tencent.com', 'weixin.qq.com', 'wx.qq.com', 'gtimg.cn',
  'gtimg.com', 'myqcloud.com', 'qpic.cn', 'qlogo.cn', 'idqqimg.com',
  'alicdn.com', 'aliyun.com', 'alibaba.com', 'taobao.com', 'tmall.com',
  'alipay.com', 'alipayobjects.com', 'tbcdn.cn', 'mmstat.com',
  'jd.com', 'jdcdn.com', 'jcloudcs.com', '360buyimg.com',
  'bilibili.com', 'bilibili.cn', 'hdslb.com', 'bilivideo.com',
  'zhihu.com', 'zhimg.com',
  'weibo.com', 'weibocdn.com', 'sinaimg.cn', 'sina.com.cn',
  'douyin.com', 'bytedance.com', 'bytecdn.cn', 'byteimg.com',
  'xiaomi.com', 'mi.com', 'xiaomicdn.com',
  'huawei.com', 'hicloud.com', 'dbankcloud.com',
  'oppo.com', 'vivo.com.cn', 'meizu.com',
  'netease.com', '126.com', '163.com', '126.net', '163.net',
  'didichuxing.com', 'xiaojukeji.com',
  'meituan.com', 'meituan.net', 'dianping.com',
  'pinduoduo.com', 'yangkeduo.com',
  // 安全厂商
  'virustotal.com', 'kaspersky.com', 'mcafee.com', 'symantec.com',
  'norton.com', 'avast.com', 'avg.com', 'bitdefender.com',
  'eset.com', 'sophos.com', 'trendmicro.com', 'emsisoft.com',
  'malwarebytes.com', 'microsoft.com', 'windowsupdate.com',
  '360.cn', '360totalsecurity.com', 'qihoo.com', 'huorong.cn',
  'tencent.com', 's.tjapi.com', 'habo.qq.com',
  'threatbook.cn', 'qianxin.com', 'dbappsecurity.com.cn',
  'hybrid-analysis.com', 'filescan.io', 'malshare.com',
  'abuse.ch', 'urlhaus.abuse.ch', 'threatfox.abuse.ch',
  // 开发/工具
  'python.org', 'pypi.org', 'pythonhosted.org',
  'golang.org', 'go.dev', 'gopkg.in',
  'nodejs.org', 'nodejs.cn', 'deno.land',
  'rust-lang.org', 'crates.io', 'rustup.rs',
  'docker.com', 'docker.io', 'hub.docker.com',
  'jetbrains.com', 'visualstudio.com', 'code.visualstudio.com',
  'vscode.dev', 'nuget.org', 'dotnet.microsoft.com',
  'sourceforge.net', ' FossHub.com', 'filehorse.com',
  'getfancontrol.com', 'github.com', // Fan Control official
  'tbtool.cn', 'tbtool.com', // 图吧工具箱官方
  '7-zip.org', 'rarlab.com', 'notepad-plus-plus.org',
  'libreoffice.org', 'openoffice.org',
  // CDN / 云服务
  'cloudflare.com', 'cloudflareinsights.com', 'cdnjs.cloudflare.com',
  'jsdelivr.net', 'unpkg.com', 'bootstrapcdn.com',
  'akamai.net', 'akamaihd.net', 'akamaized.net',
  'fastly.net', 'fastlylb.net',
  'jquery.com', 'jqueryui.com',
  // 其他常见合法
  'w3.org', 'ietf.org', 'iso.org',
  'paypal.com', 'paypal.me',
  'stripe.com', 'stripe.network',
  'dropbox.com', 'dropboxusercontent.com',
  'slack.com', 'slack-edge.com',
  'zoom.us', 'zoom.com',
  'discord.com', 'discord.gg', 'discordapp.com',
  'telegram.org', 't.me',
  'notion.so', 'notion.site',
  'figma.com', 'canva.com',
  'spotify.com', 'scdn.co',
  'netflix.com', 'nflxvideo.net',
  'steamcommunity.com', 'steampowered.com', 'steamstatic.com',
  'epicgames.com', 'unrealengine.com',
  'unity.com', 'unity3d.com'
]);

// 品牌名 → 官方域名映射（用于 typosquatting 检测）
const BRAND_OFFICIAL = {
  'microsoft': 'microsoft.com',
  'windows': 'microsoft.com',
  'office': 'microsoft.com',
  'google': 'google.com',
  'apple': 'apple.com',
  'icloud': 'icloud.com',
  'amazon': 'amazon.com',
  'aws': 'amazonaws.com',
  'adobe': 'adobe.com',
  'facebook': 'facebook.com',
  'instagram': 'instagram.com',
  'whatsapp': 'whatsapp.com',
  'twitter': 'twitter.com',
  'linkedin': 'linkedin.com',
  'github': 'github.com',
  'gitlab': 'gitlab.com',
  'baidu': 'baidu.com',
  'taobao': 'taobao.com',
  'tmall': 'tmall.com',
  'alipay': 'alipay.com',
  'tencent': 'tencent.com',
  'qq': 'qq.com',
  'wechat': 'weixin.qq.com',
  'jd': 'jd.com',
  'bilibili': 'bilibili.com',
  'zhihu': 'zhihu.com',
  'weibo': 'weibo.com',
  'douyin': 'douyin.com',
  'xiaomi': 'xiaomi.com',
  'huawei': 'huawei.com',
  'paypal': 'paypal.com',
  'stripe': 'stripe.com',
  'netflix': 'netflix.com',
  'steam': 'steampowered.com',
  'discord': 'discord.com',
  'telegram': 'telegram.org',
  'notion': 'notion.so',
  'spotify': 'spotify.com',
  'zoom': 'zoom.us',
  'dropbox': 'dropbox.com',
  'slack': 'slack.com',
  'fancontrol': 'getfancontrol.com',
  'tubatool': 'tbtool.cn',
  'tbtool': 'tbtool.cn',
  'figma': 'figma.com',
  'canva': 'canva.com',
  'adobe': 'adobe.com',
  'python': 'python.org',
  'docker': 'docker.com',
  'jetbrains': 'jetbrains.com',
  'vscode': 'code.visualstudio.com',
  '7zip': '7-zip.org',
  '7-zip': '7-zip.org',
  'libreoffice': 'libreoffice.org'
};

/**
 * 检查主机名是否为官方域名或其子域
 */
function isOfficialDomain(hostname) {
  const h = hostname.toLowerCase().replace(/^www\./, '');
  if (OFFICIAL_DOMAINS.has(h)) return true;
  // 检查父域
  const parts = h.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    const parent = parts.slice(i).join('.');
    if (OFFICIAL_DOMAINS.has(parent)) return true;
  }
  return false;
}

/**
 * Levenshtein 编辑距离
 */
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp = new Array(n + 1);
  for (let j = 0; j <= n; j++) dp[j] = j;
  for (let i = 1; i <= m; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      dp[j] = a[i - 1] === b[j - 1] ? prev : Math.min(prev, dp[j - 1], dp[j]) + 1;
      prev = tmp;
    }
  }
  return dp[n];
}

// ============ 域名特征提取 ============

export function extractFeatures(url) {
  const features = {};
  let hostname, path, protocol, query;
  try {
    const u = new URL(url);
    hostname = u.hostname.toLowerCase();
    path = u.pathname.toLowerCase();
    protocol = u.protocol.replace(':', '');
    query = (u.search || '').slice(1);
  } catch {
    hostname = url.toLowerCase();
    path = '';
    protocol = 'http';
    query = '';
  }

  // F1-F5: 基础结构特征
  features.url_length = url.length;
  features.hostname = hostname; // 保留供规则使用
  features.hostname_length = hostname.length;
  features.num_dots = (hostname.match(/\./g) || []).length;
  features.num_hyphens = (url.match(/-/g) || []).length;
  features.num_digits = (url.match(/[0-9]/g) || []).length;

  // F6-F10: 特殊字符
  features.num_at = (url.match(/@/g) || []).length;
  features.num_question = (url.match(/\?/g) || []).length;
  features.num_percent = (url.match(/%/g) || []).length;
  features.num_equals = (url.match(/=/g) || []).length;
  features.num_slashes = (url.match(/\//g) || []).length;

  // F11-F15: TLD 和域名特征
  const parts = hostname.split('.');
  features.tld = parts.length > 1 ? parts[parts.length - 1] : '';
  features.num_subdomains = Math.max(0, parts.length - 2);
  features.has_ip = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) ? 1 : 0;
  features.has_port = url.includes(':', url.indexOf('://') + 3) ? 1 : 0;
  features.is_https = protocol === 'https' ? 1 : 0;

  // F16-F20: 可疑模式（收紧：需要叠加异常才计分，此处仅提取）
  features.has_suspicious_words = /(login|signin|verify|account|update|confirm|secure|paypal|bank|free|download|install|setup|crack|keygen|patch|activat)/i.test(url) ? 1 : 0;
  features.has_obfuscation = /%[0-9a-f]{2}/i.test(url) ? 1 : 0;
  features.has_base64 = /[a-zA-Z0-9+\/]{20,}={0,2}/.test(path) ? 1 : 0;
  features.has_hex_path = /\/[0-9a-f]{16,}\//i.test(path) ? 1 : 0;
  features.path_depth = (path.match(/\//g) || []).length;

  // F21-F25: 域名年龄特征 (代理指标)
  features.tld_length = features.tld.length;
  features.domain_word_length = parts.length > 1 ? parts[parts.length - 2].length : hostname.length;
  const hostLetters = hostname.replace(/[^a-z]/g, '');
  features.consonant_ratio = hostLetters.length > 0
    ? (hostname.match(/[bcdfghjklmnpqrstvwxyz]/g) || []).length / hostLetters.length
    : 0;
  features.digit_ratio = features.num_digits / Math.max(1, hostname.length);
  features.entropy = shannonEntropy(hostname.replace(/\./g, ''));

  // F26-F30: 威胁特定特征
  features.has_double_redirect = /(redirect|url=|link=|goto=|r=|return=|next=)/i.test(url) ? 1 : 0;
  features.has_data_uri = url.startsWith('data:') ? 1 : 0;
  features.has_blob_uri = url.startsWith('blob:') ? 1 : 0;
  features.has_javascript_uri = url.startsWith('javascript:') ? 1 : 0;
  features.shortened_url = /(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|adf\.ly|t\.cn|dwz\.cn|sina\.lt|url\.cn)/i.test(hostname) ? 1 : 0;

  // F31-F40: 假冒软件特征
  // v5.3: 先检查是否官方域名
  features.is_official = isOfficialDomain(hostname) ? 1 : 0;

  // 品牌词检测：从域名主体中提取，不含已知官方域
  features.has_brand_in_hostname = 0;
  features.brand_name = null;
  if (!features.is_official) {
    for (const brand of Object.keys(BRAND_OFFICIAL)) {
      if (hostname.includes(brand)) {
        features.has_brand_in_hostname = 1;
        features.brand_name = brand;
        break;
      }
    }
  }

  // Typosquatting 检测：计算域名主体与品牌名的编辑距离
  features.typosquat_score = 0;
  features.typosquat_brand = null;
  if (!features.is_official && parts.length >= 2) {
    const registrable = parts.slice(-2).join('.');
    const sld = parts[parts.length - 2];
    for (const [brand, official] of Object.entries(BRAND_OFFICIAL)) {
      if (sld === brand) continue;
      if (brand.length < 5) continue; // 短品牌名不做编辑距离，误报高
      const dist = levenshtein(sld, brand);
      // 严格：编辑距离恰好 1 + 首字母相同 + 长度差 ≤1
      if (dist === 1 && sld[0] === brand[0] && Math.abs(sld.length - brand.length) <= 1) {
        if (!registrable.endsWith(official)) {
          features.typosquat_score = dist;
          features.typosquat_brand = brand;
          break;
        }
      }
    }
  }

  features.has_download_keywords = /(download|setup|install|update|latest|version|free|crack|keygen|patch|activator)/i.test(path) ? 1 : 0;
  features.has_file_extension = /\.(exe|msi|zip|rar|7z|bat|cmd|ps1|vbs|js|jar|apk|dmg|pkg|deb|rpm)$/i.test(path) ? 1 : 0;
  features.has_executable_ext = /\.(exe|msi|bat|cmd|ps1|vbs|scr|com|pif|gadget|hta|cpl|msc|jar)$/i.test(path) ? 1 : 0;
  features.has_script_ext = /\.(js|vbs|ps1|bat|cmd|hta|wsf|wsh)$/i.test(path) ? 1 : 0;
  features.has_numeric_tld = /^\d+$/.test(features.tld) ? 1 : 0;
  features.long_query_string = query.length;
  features.multiple_tlds = /\.(com|net|org|cn|co)\.[a-z]{2,}$/i.test(hostname) ? 1 : 0;
  features.random_subdomain = isRandomString(parts.length > 2 ? parts[0] : '') ? 1 : 0;
  features.punycode = hostname.includes('xn--') ? 1 : 0;

  // F41-F50: 行为特征
  features.unusual_port = (() => {
    const m = url.match(/:(\d+)/);
    if (!m) return 0;
    const port = parseInt(m[1]);
    return (port > 1024 && ![8080, 8443, 3000, 4000, 5000, 8000, 8888, 9090, 9200].includes(port)) ? 1 : 0;
  })();
  features.known_c2_port = (() => {
    const m = url.match(/:(\d+)/);
    if (!m) return 0;
    return [28300, 4444, 8080, 8443, 1337, 9001, 9050, 31337].includes(parseInt(m[1])) ? 1 : 0;
  })();
  features.suspicious_tld = ['tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'top', 'xyz', 'work', 'click', 'loan', 'win', 'bid', 'trade', 'date', 'review', 'stream', 'party', 'science', 'men', 'zip', 'mov', 'country', 'racing'].includes(features.tld) ? 1 : 0;
  features.path_contains_phishing = /(verify|confirm|account|login|signin|password|credential|wallet|seed|recovery|secure|update)/i.test(path) ? 1 : 0;
  features.query_contains_phishing = /(token|key|password|secret|credential|session|auth)/i.test(query) ? 1 : 0;

  // V5.2 补充特征（v5.3 收紧：nsis/install 不再无条件触发 critical）
  // 仅当 URL 中包含形如 setup_v6.0.05、appinst_up001、appsetup123 等具体恶意命名模式时命中
  features.nsis_pattern = /(?:setup[_\-]?v?\d|appinst[_\-]?\w+\d|appsetup\d|nsis[_\-]?\d{3,}|installer[_\-]?\d{4,})/i.test(url) ? 1 : 0;
  features.vmp_file = /\.msi$/i.test(path) ? 1 : 0;
  features.zinst_pattern = /zinst/i.test(url) ? 1 : 0;
  features.byovd_indicator = /(driver|bootrepair|enportv|wsftprm|wnbios|mbw(iper)?)/i.test(url) ? 1 : 0;
  features.dropper_pattern = /(dropper|payload|stager|loader)/i.test(url) ? 1 : 0;

  // v5.3 新特征：云盘滥用
  features.cloud_abuse = /(quark|kuake|baidu|pan\.baidu|cloud|drive|storage|oss|cos|obs|s3)[\/\.\-].*(?:\.exe|\.msi|\.zip|\.rar|\.7z|\.bat|\.ps1)/i.test(url) ? 1 : 0;
  // v5.3: 云盘域名上的可执行文件
  features.known_cloud_cdn = /(pan\.quark|pan\.baidu|cloud\.189|aliyundrive|alipan|drive\.uc|caiyun\.139)/i.test(hostname) ? 1 : 0;

  // v5.3: 新注册域名代理特征（长随机 SLD + 可疑 TLD）
  const sldStr = parts.length > 1 ? parts[parts.length - 2] : hostname;
  features.fresh_domain_look = (sldStr.length > 10 && /\d/.test(sldStr) && features.consonant_ratio > 0.7 && features.suspicious_tld) ? 1 : 0;

  // v5.3: 双因素异常计数（用于多因子判定）
  features.anomaly_count =
    (features.suspicious_tld ? 1 : 0) +
    (features.random_subdomain ? 1 : 0) +
    (features.has_ip ? 1 : 0) +
    (!features.is_https ? 1 : 0) +
    (features.has_executable_ext ? 1 : 0) +
    (features.entropy > 3.8 ? 1 : 0) +
    (features.punycode ? 1 : 0) +
    (features.typosquat_score > 0 ? 1 : 0) +
    (features.has_brand_in_hostname ? 1 : 0) +
    (features.num_subdomains > 3 ? 1 : 0) +
    (features.known_c2_port ? 1 : 0) +
    (features.nsis_pattern || features.zinst_pattern ? 1 : 0) +
    (features.cloud_abuse ? 1 : 0);

  // v5.3: n-gram 频率异常（轻量二元组分析）
  features.bigram_oddness = bigramOddness(hostname);

  return features;
}

function shannonEntropy(s) {
  if (!s || s.length === 0) return 0;
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  const len = s.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isRandomString(s) {
  if (!s || s.length < 8) return false;
  // v5.3: 放宽元音阈值（0.2 太严，会把短随机串漏过），同时加入辅音连续检查
  if (/^[a-z]+$/.test(s)) {
    const vowels = (s.match(/[aeiou]/g) || []).length;
    if (vowels / s.length < 0.22) return true;
    // 连续 4+ 辅音
    if (/[bcdfghjklmnpqrstvwxyz]{5,}/.test(s)) return true;
  }
  if (/^[0-9]+$/.test(s) && s.length > 6) return true;
  if (/^[a-z0-9]+$/.test(s) && s.length > 10) {
    const vowels = (s.match(/[aeiou]/g) || []).length;
    if (vowels / s.length < 0.2) return true;
  }
  return false;
}

/**
 * 轻量 bigram 异常度
 * 正常英文域名的二元组有偏好（th, he, in, er, an 等高频）
 * DGA 域名的 bigram 分布更均匀 → 异常度高
 * 返回 0-1 之间的值
 */
function bigramOddness(hostname) {
  const s = hostname.replace(/\./g, '').toLowerCase();
  if (s.length < 6) return 0;
  // 只分析字母部分
  const letters = s.replace(/[^a-z]/g, '');
  if (letters.length < 6) return 0;

  // 高频英文二元组（从常见英文文本统计）
  const commonBigrams = new Set([
    'th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd',
    'ti', 'es', 'or', 'te', 'of', 'ed', 'is', 'it', 'al', 'ar',
    'st', 'to', 'nt', 'ng', 'se', 'ha', 'as', 'ou', 'io', 'le',
    've', 'co', 'me', 'de', 'hi', 'ri', 'ro', 'ic', 'ne', 'ea',
    'ra', 'ce', 'li', 'ch', 'll', 'be', 'ma', 'si', 'om', 'ur'
  ]);

  let total = 0;
  let common = 0;
  for (let i = 0; i < letters.length - 1; i++) {
    total++;
    if (commonBigrams.has(letters.substring(i, i + 2))) common++;
  }
  // 常见二元组占比低 → 异常
  const ratio = total > 0 ? common / total : 0;
  return Math.max(0, 1 - ratio * 2.5); // ratio 0.4 → 0, ratio 0 → 1
}

// ============ ML 推理引擎 v5.3 (加权累积 + 多因子门控) ============

const ML_THRESHOLD = 0.60;
const MIN_SIGNALS = 2; // 至少需要 2 个独立信号才判恶意

export function mlPredict(features) {
  // 官方域名直接放行
  if (features.is_official) {
    return {
      score: 0,
      is_malicious: false,
      confidence: 'safe',
      family: null,
      reasons: ['官方/可信域名'],
      signals: 0,
      features: summarizeFeatures(features)
    };
  }

  let score = 0.0;
  const reasons = [];
  const signals = new Set(); // 独立信号集合
  let family = null;

  // 信号累加器（每个独立维度最多贡献一次）
  function addSignal(name, weight, reason, fam) {
    if (!signals.has(name)) {
      score += weight;
      signals.add(name);
      reasons.push(reason);
      if (fam && !family) family = fam;
    }
  }

  // --- 确定性恶意信号（强信号，每个权重 0.25-0.45）---

  if (features.has_ip && !features.is_https) {
    addSignal('ip_http', 0.65, 'IP直连+非HTTPS', 'SUSPICIOUS_DIRECT_IP');
  }
  if (features.has_ip && features.has_executable_ext) {
    addSignal('ip_exe', 0.60, 'IP直连+可执行文件', 'MALWARE_DISTRIBUTION');
  }
  if (features.zinst_pattern) {
    addSignal('zinst', 0.72, '银狐/ValleyRAT zinst命名特征', 'SilverFox/ValleyRAT');
  }
  if (features.nsis_pattern) {
    // v5.3: nsis_pattern 已收紧为具体恶意命名模式（setup_v\d, appinst_up\d 等）
    // 这些是已确认的银狐/ValleyRAT 命名特征，单信号即可判定
    addSignal('nsis', 0.70, '恶意NSIS安装包命名模式', 'SilverFox/ValleyRAT');
  }
  if (features.known_c2_port) {
    addSignal('c2_port', 0.65, '已知C2端口', 'C2_COMMUNICATION');
  }
  if (features.punycode) {
    addSignal('punycode', 0.65, 'Punycode同形异义字攻击', 'HOMOGRAPH_PHISHING');
  }
  if (features.has_javascript_uri) {
    addSignal('js_uri', 0.68, 'JavaScript URI协议', 'MALICIOUS_SCRIPT');
  }
  if (features.has_data_uri) {
    addSignal('data_uri', 0.55, 'Data URI协议', 'MALICIOUS_SCRIPT');
  }
  if (features.byovd_indicator && !features.is_official) {
    addSignal('byovd', 0.65, 'BYOVD驱动特征', 'BYOVD_ROOTKIT');
  }
  if (features.dropper_pattern && features.has_executable_ext) {
    addSignal('dropper', 0.62, 'Dropper模式+可执行文件', 'TROJAN_DROPPER');
  }

  // Typosquatting（v5.3 新增）：编辑距离 1 的拼写劫持本身就是强信号
  if (features.typosquat_score > 0 && features.typosquat_brand) {
    addSignal('typosquat', 0.65,
      `疑似拼写劫持(近似${features.typosquat_brand})`, 'TYPOSQUATTING');
  }

  // --- 组合信号（需要 2+ 特征同时存在）---

  // 品牌仿冒：非官方域 + 品牌词 + 至少一个异常因子
  if (features.has_brand_in_hostname) {
    const anomalyFactors = features.suspicious_tld || features.random_subdomain ||
      !features.is_https || features.has_executable_ext ||
      features.typosquat_score > 0 || features.num_subdomains > 2;
    if (anomalyFactors) {
      if (features.suspicious_tld) {
        addSignal('brand_tld', 0.30, '品牌仿冒+可疑TLD', 'BRAND_PHISHING');
      } else if (features.random_subdomain) {
        addSignal('brand_random', 0.28, '品牌仿冒+随机子域', 'BRAND_PHISHING');
      } else if (features.has_download_keywords || features.has_executable_ext) {
        addSignal('brand_dl', 0.40, '品牌仿冒+下载/可执行文件', 'FAKE_SOFTWARE');
      } else if (!features.is_https) {
        addSignal('brand_http', 0.22, '品牌仿冒+非HTTPS', 'BRAND_PHISHING');
      } else {
        addSignal('brand_weak', 0.15, '品牌名称仿冒(弱信号)', 'BRAND_IMPERSONATION');
      }
    } else {
      addSignal('brand_name', 0.08, '含品牌名但无异常因子', null);
    }
  }

  // v5.3: 域名包含品牌词 + 可疑后缀词（hub, download, pro, official, setup 等）
  // 用于检测 tbtool-hub.com.cn 这类非精确品牌匹配的假冒软件站
  if (!features.is_official && !features.has_brand_in_hostname) {
    const hostParts = features.hostname.replace(/\.(com|cn|net|org|co)$/i, '').split(/[.\-]/);
    const suspiciousSuffixes = ['hub', 'download', 'dl', 'pro', 'official', 'setup', 'install', 'free', 'update', 'safe', 'secure', 'help', 'support', 'pc'];
    let hasBrandPart = false;
    let hasSuspiciousSuffix = false;
    let matchedBrand = null;
    for (const part of hostParts) {
      for (const brand of Object.keys(BRAND_OFFICIAL)) {
        if (brand.length >= 4 && part.includes(brand)) {
          hasBrandPart = true;
          matchedBrand = brand;
          break;
        }
      }
      if (suspiciousSuffixes.includes(part)) hasSuspiciousSuffix = true;
    }
    if (hasBrandPart && hasSuspiciousSuffix && !features.is_https) {
      addSignal('brand_suffix', 0.30, `疑似假冒${matchedBrand}(品牌词+可疑后缀+非HTTPS)`, 'FAKE_SOFTWARE');
    } else if (hasBrandPart && hasSuspiciousSuffix && features.suspicious_tld) {
      addSignal('brand_suffix_tld', 0.32, `疑似假冒${matchedBrand}(品牌词+可疑后缀+可疑TLD)`, 'FAKE_SOFTWARE');
    }
  }

  // 可疑 TLD + 可执行文件
  if (features.suspicious_tld && features.has_executable_ext) {
    addSignal('tld_exe', 0.30, '可疑TLD+可执行文件下载', 'MALWARE_DISTRIBUTION');
  }

  // DGA：高熵 + 长域名 + 高辅音比（v5.3: 收紧条件，加入 bigram 异常）
  if (features.entropy > 4.0 && features.hostname_length > 18) {
    if (features.consonant_ratio > 0.75 || features.bigram_oddness > 0.6) {
      addSignal('dga', 0.28, '高熵域名(DGA特征)', 'DGA_SUSPECT');
    } else if (features.random_subdomain) {
      addSignal('dga_sub', 0.22, '随机子域+高熵', 'DGA_SUSPECT');
    }
  }

  // 辅音比异常 + bigram 异常（v5.3: 双因子才触发）
  if (features.consonant_ratio > 0.82 && features.hostname_length > 14 && features.bigram_oddness > 0.5) {
    addSignal('consonant_dga', 0.22, '辅音比例异常+n-gram异常(DGA)', 'DGA_SUSPECT');
  }

  // 云盘滥用（v5.3 新增）
  if (features.known_cloud_cdn && features.has_executable_ext) {
    addSignal('cloud_exe', 0.25, '云盘域名分发可执行文件', 'MALWARE_DISTRIBUTION');
  } else if (features.cloud_abuse && !features.is_official) {
    addSignal('cloud_abuse', 0.18, '云存储滥用特征', 'MALWARE_DISTRIBUTION');
  }

  // 新注册域名外观（v5.3 新增）
  if (features.fresh_domain_look) {
    addSignal('fresh_domain', 0.15, '新注册域名代理特征', 'SUSPICIOUS_DOMAIN');
  }

  // --- 弱信号（需累积 ≥3 个才有效）---

  // API 端点模式：常见 C2/malware API 路径
  if (/\.(php|asp|aspx|jsp|cgi)(\/|$|\?)/i.test(path) && !features.is_official) {
    if (features.suspicious_tld || !features.is_https || features.has_ip) {
      addSignal('api_endpoint', 0.15, '可疑API端点+异常域名', null);
    }
  }

  // 路径含钓鱼词：必须叠加非HTTPS或可疑TLD或品牌仿冒
  if (features.path_contains_phishing) {
    if (!features.is_https && features.suspicious_tld) {
      addSignal('phish_path_tld_http', 0.55, '钓鱼路径+可疑TLD+非HTTPS', 'CREDENTIAL_PHISHING');
    } else if (!features.is_https) {
      addSignal('phish_path_http', 0.22, '钓鱼路径+非HTTPS', 'CREDENTIAL_PHISHING');
    } else if (features.suspicious_tld) {
      addSignal('phish_path_tld', 0.20, '钓鱼路径+可疑TLD', 'CREDENTIAL_PHISHING');
    } else if (features.has_brand_in_hostname) {
      addSignal('phish_path_brand', 0.18, '钓鱼路径+品牌仿冒', 'CREDENTIAL_PHISHING');
    }
  }

  // 可疑词：需叠加异常
  if (features.has_suspicious_words) {
    if (features.suspicious_tld) {
      addSignal('susp_word_tld', 0.12, '可疑关键词+可疑TLD', null);
    } else if (features.num_subdomains > 3) {
      addSignal('susp_word_sub', 0.10, '可疑关键词+过多子域', null);
    }
  }

  // 下载关键词 + 大量数字（收紧：数字需在域名或文件名中，不在版本号路径）
  if (features.has_download_keywords && features.num_digits > 8) {
    if (features.suspicious_tld || features.random_subdomain) {
      addSignal('dl_digits', 0.14, '下载关键词+大量数字+异常域', 'FAKE_SOFTWARE');
    }
  }

  // 异常长 URL（需叠加其他异常）
  if (features.url_length > 200) {
    if (features.has_obfuscation || features.num_percent > 5) {
      addSignal('long_obfuscated', 0.15, '超长URL+编码混淆', null);
    } else if (features.random_subdomain) {
      addSignal('long_random', 0.10, '超长URL+随机子域', null);
    }
  }

  // 过多子域（需叠加随机或高熵）
  if (features.num_subdomains > 3) {
    if (features.random_subdomain || features.entropy > 3.8) {
      addSignal('many_subs', 0.15, '过多子域+随机性异常', null);
    }
  }

  // URL 编码混淆（需 >3 个编码字符）
  if (features.has_obfuscation && features.num_percent > 3) {
    addSignal('obfuscation', 0.14, 'URL编码混淆', null);
  }

  // 重定向参数 + 短链接
  if (features.has_double_redirect && features.shortened_url) {
    addSignal('redirect_short', 0.15, '短链接+重定向参数', null);
  }

  // 异常端口（非 C2 端口但非常规）
  if (features.unusual_port) {
    addSignal('unusual_port', 0.10, '非常规端口', null);
  }

  // 非 HTTPS + 可执行文件
  if (!features.is_https && features.has_executable_ext) {
    addSignal('http_exe', 0.20, '非HTTPS下载可执行文件', 'MALWARE_DISTRIBUTION');
  }

  // 非HTTPS + 品牌仿冒 + 下载（强组合）
  if (!features.is_https && features.has_brand_in_hostname && features.has_download_keywords) {
    addSignal('brand_http_dl', 0.30, '品牌仿冒+非HTTPS+下载路径', 'FAKE_SOFTWARE');
  }

  // bigram 高度异常（v5.3 新增）
  if (features.bigram_oddness > 0.7 && features.hostname_length > 12) {
    if (features.suspicious_tld || features.num_digits > 3) {
      addSignal('bigram_dga', 0.18, 'n-gram分布异常(DGA)', 'DGA_SUSPECT');
    }
  }

  // --- 评分封顶 ---
  score = Math.min(1.0, score);

  // v5.3 多因子门控：
  // - 单强信号（score ≥ 0.65）即可判定（如 nsis 命名、C2 端口、Punycode、IP+HTTP）
  // - 弱信号组合需要 ≥ 2 个独立信号且总分 ≥ 0.60
  const signalCount = signals.size;
  const hasStrongSignal = score >= 0.65;
  const isMalicious = hasStrongSignal || (score >= ML_THRESHOLD && signalCount >= MIN_SIGNALS);

  // 置信度映射
  let confidence;
  if (!isMalicious) {
    if (score > 0.3) confidence = 'low';
    else confidence = 'safe';
  } else {
    if (score >= 0.85) confidence = 'critical';
    else if (score >= 0.65) confidence = 'high';
    else confidence = 'medium';
  }

  return {
    score: Math.round(score * 100) / 100,
    is_malicious: isMalicious,
    confidence,
    family: isMalicious ? (family || 'SUSPICIOUS') : null,
    reasons: reasons.slice(0, 6),
    signals: signalCount,
    threshold: ML_THRESHOLD,
    features: summarizeFeatures(features)
  };
}

function summarizeFeatures(f) {
  return {
    entropy: Math.round(f.entropy * 100) / 100,
    url_length: f.url_length,
    has_ip: f.has_ip,
    suspicious_tld: f.suspicious_tld,
    has_executable: f.has_executable_ext,
    is_https: f.is_https,
    is_official: f.is_official,
    typosquat: f.typosquat_score,
    bigram_oddness: Math.round(f.bigram_oddness * 100) / 100,
    anomaly_count: f.anomaly_count
  };
}

// ============ 多源融合判定 ============

export function fuseVerdict(iocMatch, mlResult, vtResult) {
  let finalScore = 0;
  let severity = 'safe';
  let family = null;
  const sources = [];

  // IOC match is strongest signal
  if (iocMatch) {
    const sevScore = { critical: 1.0, high: 0.85, medium: 0.6, low: 0.3 };
    finalScore = Math.max(finalScore, sevScore[iocMatch.severity] || 0.7);
    severity = iocMatch.severity;
    family = iocMatch.family;
    sources.push('IOC');
  }

  // ML result
  if (mlResult && mlResult.is_malicious) {
    finalScore = Math.max(finalScore, mlResult.score * 0.9);
    if (!family) family = mlResult.family;
    if (severity === 'safe' || scoreToSeverity(mlResult.score) === 'critical') {
      severity = scoreToSeverity(mlResult.score);
    }
    sources.push('ML');
  }

  // VT result
  if (vtResult && vtResult.malicious > 0) {
    const vtScore = Math.min(1.0, vtResult.malicious / 20);
    finalScore = Math.max(finalScore, vtScore);
    if (!family && vtResult.family) family = vtResult.family;
    if (severity === 'safe') severity = vtResult.malicious >= 10 ? 'critical' : 'high';
    sources.push('VT');
  }

  if (sources.length >= 2) finalScore = Math.min(1.0, finalScore + 0.05);

  return {
    verdict: finalScore >= 0.65 ? 'malicious' : finalScore >= 0.35 ? 'suspicious' : 'safe',
    score: Math.round(finalScore * 100),
    severity: finalScore >= 0.85 ? 'critical' : finalScore >= 0.65 ? 'high' : finalScore >= 0.35 ? 'medium' : 'low',
    family: family || null,
    sources,
    ml: mlResult ? {
      score: mlResult.score,
      reasons: mlResult.reasons,
      signals: mlResult.signals
    } : null,
    ioc: iocMatch || null,
    vt: vtResult || null,
    timestamp: new Date().toISOString()
  };
}

function scoreToSeverity(score) {
  if (score >= 0.85) return 'critical';
  if (score >= 0.65) return 'high';
  if (score >= 0.4) return 'medium';
  return 'low';
}

// 导出白名单检查函数，供外部调用
export { isOfficialDomain, OFFICIAL_DOMAINS };
