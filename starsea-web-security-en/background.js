/**
 * StarSea Web Security - Background Service Worker (MV3) v1.2.0
 *
 * v1.2.0:
 * - Added allowlist system (built-in trusted domains + user-defined + temporary bypass)
 * - ML engine upgraded to v5.3 (multi-signal gating, false positive/negative suppression)
 * - Block page supports "Add to Allowlist" button
 * - Allowlist takes priority over all detection
 */

import { IOCMatcher } from './lib/matcher.js';
import { initCloudClient, cloudScan, isCloudEnabled, getCloudConfig, fullScan } from './lib/cloud-client.js';
import { extractFeatures, mlPredict, isOfficialDomain } from './lib/ml-engine.js';
import { Allowlist } from './lib/allowlist.js';

const STORAGE_KEYS = {
  BLOCKLIST: 'starsea_blocklist',
  STATS: 'starsea_stats',
  SETTINGS: 'starsea_settings',
  CUSTOM_RULES: 'starsea_custom_rules',
  ALLOWLIST: 'starsea_allowlist',
  CLOUD: 'starsea_cloud'
};

const DEFAULT_SETTINGS = {
  enabled: true,
  blockPhishing: true,
  blockMalware: true,
  blockC2: true,
  blockDownloads: true,
  showNotifications: true,
  heuristicCheck: true,
  blocklistUrl: '',
  updateInterval: 360,
  // v1.2.0: 白名单默认启用
  allowlistEnabled: true,
  // v1.2.0: ML 严格度（standard/strict）
  mlMode: 'standard'
};

let matcher = null;
let allowlist = null;
let settings = { ...DEFAULT_SETTINGS };

// ============ Initialization ============

async function init() {
  await loadSettings();
  await loadBlocklist();
  await loadAllowlist();
  await initCloudClient();
  setupListeners();
  setupAlarms();
  console.log('[StarSea Security] v1.2.0 initialized', {
    domains: matcher?.domainCount || 0,
    ips: matcher?.ipCount || 0,
    urls: matcher?.urlCount || 0,
    hashes: matcher?.hashCount || 0,
    allowlist: allowlist?.stats
  });
}

async function loadSettings() {
  const stored = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
  settings = { ...DEFAULT_SETTINGS, ...stored[STORAGE_KEYS.SETTINGS] };
}

async function loadBlocklist() {
  try {
    const cached = await chrome.storage.local.get(STORAGE_KEYS.BLOCKLIST);
    let blocklist = cached[STORAGE_KEYS.BLOCKLIST];

    const bundled = await fetch(chrome.runtime.getURL('rules/blocklist.json'));
    const bundledData = await bundled.json();

    if (!blocklist || blocklist.version !== bundledData.version) {
      blocklist = bundledData;
      await chrome.storage.local.set({ [STORAGE_KEYS.BLOCKLIST]: blocklist });
    }

    const custom = await chrome.storage.local.get(STORAGE_KEYS.CUSTOM_RULES);
    const customRules = custom[STORAGE_KEYS.CUSTOM_RULES] || { domains: {}, ips: {}, urls: {} };

    matcher = new IOCMatcher(blocklist, customRules);
  } catch (e) {
    console.error('[StarSea Security] Failed to load blocklist:', e);
    try {
      const bundled = await fetch(chrome.runtime.getURL('rules/blocklist.json'));
      const data = await bundled.json();
      matcher = new IOCMatcher(data, {});
    } catch (e2) {
      console.error('[StarSea Security] Fatal: could not load any blocklist', e2);
    }
  }
}

async function loadAllowlist() {
  allowlist = new Allowlist();
  if (!settings.allowlistEnabled) return;

  const stored = await chrome.storage.local.get(STORAGE_KEYS.ALLOWLIST);
  const userAllowlist = stored[STORAGE_KEYS.ALLOWLIST];
  if (userAllowlist) {
    allowlist.loadFromStorage(userAllowlist);
  }
}

// ============ URL/Domain Checking ============

function extractHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return '';
  }
}

function extractIP(url) {
  const match = url.match(/https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return match ? match[1] : null;
}

/**
 * v1.2.0: 白名单检查优先
 */
function isAllowlisted(url) {
  if (!settings.allowlistEnabled || !allowlist) return null;
  return allowlist.check(url);
}

function checkUrl(url) {
  if (!matcher || !settings.enabled) return null;

  const hostname = extractHostname(url);
  if (!hostname) return null;

  // 1. 白名单优先（内置 + 用户 + 临时）
  const allowEntry = isAllowlisted(url);
  if (allowEntry) {
    return {
      allowed: true,
      allowSource: allowEntry.source,
      allowReason: allowEntry.reason || allowEntry.note || '',
      url,
      matched: hostname,
      type: 'allowlist'
    };
  }

  // 2. 精确域名匹配
  let match = matcher.matchDomain(hostname);
  if (match) return { ...match, url, matched: hostname, type: 'domain' };

  // 3. 子域匹配
  const parts = hostname.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    const parent = parts.slice(i).join('.');
    match = matcher.matchDomain(parent);
    if (match) return { ...match, url, matched: parent, type: 'subdomain' };
  }

  // 4. IP 匹配
  const ip = extractIP(url);
  if (ip) {
    match = matcher.matchIP(ip);
    if (match) return { ...match, url, matched: ip, type: 'ip' };
  }

  // 5. 完整 URL 匹配
  match = matcher.matchUrl(url.toLowerCase());
  if (match) return { ...match, url, matched: url, type: 'url' };

  // 6. ML 引擎推理（v5.3）
  if (settings.heuristicCheck) {
    try {
      const features = extractFeatures(url);
      // 官方域名跳过 ML（双重保险）
      if (!features.is_official) {
        const mlResult = mlPredict(features);
        if (mlResult.is_malicious) {
          return {
            severity: mlResult.confidence,
            family: mlResult.family || 'ML_SUSPECT',
            context: `ML引擎(${mlResult.signals}信号): ${mlResult.reasons.join('; ')}`,
            matched: hostname,
            type: 'ml',
            ml: mlResult
          };
        }
      }
    } catch (e) {
      // ML failed, fall through
    }

    // 7. 轻量启发式（保留，但收紧）
    const heurResult = heuristicCheck(url, hostname);
    if (heurResult) return { ...heurResult, url, type: 'heuristic' };
  }

  return null;
}

function heuristicCheck(url, hostname) {
  // v1.2.0: 启发式也先过白名单
  if (isOfficialDomain(hostname)) return null;

  const lower = url.toLowerCase();

  // 已知假冒软件模式
  const fakeSoftwarePatterns = [
    { pattern: /tubatool|tbtool|tuba-tool/i, family: 'ValleyRAT/SilverFox', name: '假冒图吧工具箱', official: ['tbtool.cn', 'tbtool.com'] },
    { pattern: /fancontrol/i, family: 'FakeSoftware_FanControl', name: '假冒Fan Control', official: ['getfancontrol.com', 'github.com'] },
    { pattern: /bilibili.*直播|bilibili.*live.*(?:download|setup|install)/i, family: 'BILIBILI_PHISHING', name: '假冒哔哩哔哩', official: ['bilibili.com', 'bilibili.cn'] },
    { pattern: /dazi.*jinshan|打字.*金山/i, family: 'FAKE_DAZI_JINSHAN', name: '假冒打字金山', official: ['jd.com', 'kingsoft.com'] }
  ];

  for (const fp of fakeSoftwarePatterns) {
    if (fp.pattern.test(lower) || fp.pattern.test(hostname)) {
      const isOfficial = (fp.official || []).some(d =>
        hostname === d || hostname.endsWith('.' + d));
      if (!isOfficial) {
        // v1.2.0: 额外要求非 HTTPS 或可疑 TLD 或可执行文件
        const extra = !url.startsWith('https') ||
          /\.(exe|msi|zip|rar|bat|cmd|ps1)/i.test(lower) ||
          /\.(tk|ml|ga|cf|gq|buzz|top|xyz|work|click)$/i.test(hostname);
        if (extra) {
          return {
            severity: 'high',
            family: fp.family,
            context: `启发式检测：${fp.name} - 非官方域名+异常特征`,
            heuristic: true
          };
        }
      }
    }
  }

  // Punycode
  if (hostname.includes('xn--')) {
    return {
      severity: 'medium',
      family: 'PUNYCODE_SUSPECT',
      context: 'Punycode 编码域名，可能是同形异义字钓鱼',
      heuristic: true
    };
  }

  // DGA 子域（v1.2.0: 收紧阈值）
  if (hostname.split('.').length > 5) {
    const subPart = hostname.split('.').slice(0, -2).join('');
    if (subPart.length > 25 && /[0-9]/.test(subPart) && /[a-z]/.test(subPart)) {
      const vowels = (subPart.match(/[aeiou]/g) || []).length;
      if (vowels / subPart.length < 0.18) {
        return {
          severity: 'medium',
          family: 'DGA_SUSPECT',
          context: '疑似 DGA 域名 - 子域名随机性异常',
          heuristic: true
        };
      }
    }
  }

  return null;
}

// ============ Navigation Blocking ============

function setupListeners() {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading' && tab.url) {
      checkAndBlock(tabId, tab.url);
    }
  });

  chrome.downloads.onCreated.addListener(async (downloadItem) => {
    if (!settings.enabled || !settings.blockDownloads) return;
    await checkDownload(downloadItem);
  });

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    handleMessage(msg, sender, sendResponse);
    return true;
  });
}

async function checkAndBlock(tabId, url) {
  if (!url || url.startsWith('chrome://') || url.startsWith('edge://') ||
      url.startsWith('about:') || url.startsWith('chrome-extension://')) {
    return;
  }

  let result = checkUrl(url);

  // 白名单放行
  if (result && result.allowed) {
    // 清除 badge
    chrome.action.setBadgeText({ text: '', tabId });
    return;
  }

  // 如果本地无威胁，尝试云端
  if (!result && isCloudEnabled()) {
    const cloudResult = await cloudScan(url, { useVT: false });
    if (cloudResult && !cloudResult.error &&
        (cloudResult.verdict === 'malicious' || cloudResult.verdict === 'suspicious')) {
      result = {
        severity: cloudResult.severity || 'high',
        family: cloudResult.family || 'CLOUD_THREAT',
        context: cloudResult.ml?.reasons?.join('; ') || cloudResult.sources?.join('+') || '云端威胁情报命中',
        matched: cloudResult.indicator || url,
        type: 'cloud',
        cloud: true
      };
    }
  }

  if (!result) return;

  // 云端结果也检查白名单（兜底）
  if (isAllowlisted(url)) return;

  if (!shouldBlockBasedOnSettings(result)) return;

  updateBadge(tabId, result.severity);

  if (settings.showNotifications) {
    showBlockNotification(result);
  }

  await recordBlock(result);

  const blockUrl = chrome.runtime.getURL(
    `blockpage/blockpage.html?url=${encodeURIComponent(url)}` +
    `&severity=${result.severity}` +
    `&family=${encodeURIComponent(result.family || 'unknown')}` +
    `&context=${encodeURIComponent(result.context || '')}` +
    `&matched=${encodeURIComponent(result.matched || '')}` +
    `&type=${result.type || 'domain'}`
  );

  chrome.tabs.update(tabId, { url: blockUrl });
}

function shouldBlockBasedOnSettings(result) {
  if (result.allowed) return false;
  if (result.severity === 'critical') return true;
  if (result.heuristic && !settings.heuristicCheck) return false;

  const family = (result.family || '').toLowerCase();
  if (family.includes('phishing') || family.includes('fake') || family.includes('钓鱼') || family.includes('typosquat')) {
    return settings.blockPhishing;
  }
  if (family.includes('c2') || family.includes('botnet') || family.includes('僵尸')) {
    return settings.blockC2;
  }
  return settings.blockMalware;
}

function updateBadge(tabId, severity) {
  const colors = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#2563eb'
  };
  chrome.action.setBadgeBackgroundColor({ color: colors[severity] || colors.high, tabId });
  chrome.action.setBadgeText({ text: '🛡', tabId });
}

function showBlockNotification(result) {
  const icons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: `${icons[result.severity] || '⚠️'} StarSea Security Blocked`,
    message: `Threat: ${result.family || 'Unknown threat'}\n${result.context?.substring(0, 100) || ''}`,
    priority: 2
  });
}

async function checkDownload(downloadItem) {
  const url = downloadItem.finalUrl || downloadItem.url;

  // 白名单放行
  if (isAllowlisted(url)) return;

  const result = checkUrl(url);
  if (result && !result.allowed) {
    try {
      await chrome.downloads.cancel(downloadItem.id);
    } catch {}

    await recordBlock({ ...result, context: 'Malicious download: ' + (result.context || '') });

    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: '🚫 Malicious Download Blocked',
      message: `File from known malicious source: ${result.family || 'Unknown'}\nURL: ${url.substring(0, 80)}`,
      priority: 2
    });
  }
}

// ============ Stats ============

async function recordBlock(result) {
  const stored = await chrome.storage.local.get(STORAGE_KEYS.STATS);
  const stats = stored[STORAGE_KEYS.STATS] || {
    totalBlocks: 0,
    blocksByFamily: {},
    blocksBySeverity: {},
    recentBlocks: [],
    lastBlock: null
  };

  stats.totalBlocks++;
  const family = result.family || 'unknown';
  stats.blocksByFamily[family] = (stats.blocksByFamily[family] || 0) + 1;
  stats.blocksBySeverity[result.severity] = (stats.blocksBySeverity[result.severity] || 0) + 1;
  stats.lastBlock = new Date().toISOString();

  stats.recentBlocks.unshift({
    url: result.url?.substring(0, 200),
    family,
    severity: result.severity,
    context: result.context?.substring(0, 150),
    time: stats.lastBlock
  });
  stats.recentBlocks = stats.recentBlocks.slice(0, 50);

  await chrome.storage.local.set({ [STORAGE_KEYS.STATS]: stats });
}

// ============ Message Handler ============

function handleMessage(msg, sender, sendResponse) {
  switch (msg.action) {
    case 'checkUrl':
      sendResponse(checkUrl(msg.url));
      break;
    case 'getStats':
      chrome.storage.local.get(STORAGE_KEYS.STATS).then(r => {
        sendResponse(r[STORAGE_KEYS.STATS] || { totalBlocks: 0 });
      });
      break;
    case 'getSettings':
      sendResponse(settings);
      break;
    case 'updateSettings':
      settings = { ...settings, ...msg.settings };
      chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: settings });
      sendResponse({ ok: true });
      break;
    case 'getBlocklistInfo':
      sendResponse({
        version: matcher?.blocklistVersion || 'unknown',
        domains: matcher?.domainCount || 0,
        ips: matcher?.ipCount || 0,
        urls: matcher?.urlCount || 0,
        hashes: matcher?.hashCount || 0
      });
      break;
    // 自定义黑名单
    case 'addCustomRule':
      addCustomRule(msg.rule).then(() => sendResponse({ ok: true }));
      break;
    case 'removeCustomRule':
      removeCustomRule(msg.value).then(() => sendResponse({ ok: true }));
      break;
    case 'getCustomRules':
      chrome.storage.local.get(STORAGE_KEYS.CUSTOM_RULES).then(r => {
        sendResponse(r[STORAGE_KEYS.CUSTOM_RULES] || { domains: {}, ips: {}, urls: {} });
      });
      break;
    // v1.2.0: 白名单管理
    case 'getAllowlist':
      sendResponse({
        entries: allowlist?.getAllEntries() || [],
        stats: allowlist?.stats || {},
        enabled: settings.allowlistEnabled
      });
      break;
    case 'addToAllowlist':
      addToAllowlist(msg.entry).then(() => sendResponse({ ok: true }));
      break;
    case 'removeFromAllowlist':
      removeFromAllowlist(msg.value).then(() => sendResponse({ ok: true }));
      break;
    case 'allowSession':
      if (allowlist && msg.url) {
        allowlist.allowSession(msg.url);
        sendResponse({ ok: true });
      } else {
        sendResponse({ ok: false });
      }
      break;
    case 'checkAllowlist':
      sendResponse(isAllowlisted(msg.url));
      break;
    case 'reloadBlocklist':
      loadBlocklist().then(() => sendResponse({ ok: true }));
      break;
    case 'cloudConfig':
      sendResponse(getCloudConfig());
      break;
    case 'cloudUpdate':
      initCloudClient().then(() => {
        const cc = getCloudConfig();
        sendResponse({ ok: true, config: cc });
      });
      break;
    case 'cloudScan':
      cloudScan(msg.url, { useVT: msg.useVT }).then(r => sendResponse(r));
      break;
    default:
      sendResponse({ error: 'Unknown action' });
  }
}

// ============ Custom Rules (黑名单) ============

async function addCustomRule(rule) {
  const stored = await chrome.storage.local.get(STORAGE_KEYS.CUSTOM_RULES);
  const custom = stored[STORAGE_KEYS.CUSTOM_RULES] || { domains: {}, ips: {}, urls: {} };
  const entry = {
    severity: rule.severity || 'high',
    family: 'custom',
    context: rule.note || '用户自定义规则',
    custom: true
  };

  if (rule.type === 'domain') custom.domains[rule.value.toLowerCase()] = entry;
  else if (rule.type === 'ip') custom.ips[rule.value] = entry;
  else if (rule.type === 'url') custom.urls[rule.value.toLowerCase()] = entry;

  await chrome.storage.local.set({ [STORAGE_KEYS.CUSTOM_RULES]: custom });
  if (matcher) {
    matcher.updateCustom(custom);
  }
}

async function removeCustomRule(value) {
  const stored = await chrome.storage.local.get(STORAGE_KEYS.CUSTOM_RULES);
  const custom = stored[STORAGE_KEYS.CUSTOM_RULES] || { domains: {}, ips: {}, urls: {} };
  delete custom.domains[value.toLowerCase()];
  delete custom.ips[value];
  delete custom.urls[value.toLowerCase()];
  await chrome.storage.local.set({ [STORAGE_KEYS.CUSTOM_RULES]: custom });
  if (matcher) matcher.updateCustom(custom);
}

// ============ Allowlist (白名单) ============

async function addToAllowlist(entry) {
  if (!allowlist || !entry || !entry.type || !entry.value) return;
  const storage = allowlist.add(entry.type, entry.value, entry.note || '', entry.includeSubdomains !== false);
  await chrome.storage.local.set({ [STORAGE_KEYS.ALLOWLIST]: storage });
}

async function removeFromAllowlist(value) {
  if (!allowlist) return;
  const storage = allowlist.remove(value);
  await chrome.storage.local.set({ [STORAGE_KEYS.ALLOWLIST]: storage });
}

// ============ Periodic Updates ============

function setupAlarms() {
  chrome.alarms.create('starsea-update', {
    periodInMinutes: settings.updateInterval
  });

  chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === 'starsea-update') {
      await tryRemoteUpdate();
    }
  });
}

async function tryRemoteUpdate() {
  if (!settings.blocklistUrl) return;
  try {
    const resp = await fetch(settings.blocklistUrl, { cache: 'no-cache' });
    if (resp.ok) {
      const data = await resp.json();
      if (data && data.domains) {
        await chrome.storage.local.set({ [STORAGE_KEYS.BLOCKLIST]: data });
        const custom = (await chrome.storage.local.get(STORAGE_KEYS.CUSTOM_RULES))[STORAGE_KEYS.CUSTOM_RULES] || {};
        matcher = new IOCMatcher(data, custom);
        console.log('[StarSea Security] Blocklist updated remotely', data.version);
      }
    }
  } catch (e) {
    console.log('[StarSea Security] Remote update failed:', e.message);
  }
}

// Start
init();
