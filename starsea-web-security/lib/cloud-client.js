/**
 * 星海安全 - 云端查杀客户端
 * 
 * 与 Cloud Worker API 通信：
 * - URL/域名/IP/文件哈希 云查
 * - 批量 IOC 查询
 * - 威胁库统计
 * 
 * 配置通过 chrome.storage.local 管理：
 *   cloudEndpoint - Worker URL (不含末尾斜杠)
 *   cloudApiKey   - API Key
 *   cloudEnabled  - 是否启用云查 (默认 true)
 *   cloudVt       - 是否请求 VT 数据 (默认 false，延迟较高)
 */

const STORAGE_KEY = 'starsea_cloud';

const DEFAULT_CONFIG = {
  endpoint: '',
  apiKey: '',
  enabled: false,
  useVT: false,
  timeout: 5000,
  cacheTtl: 300 // 5 minutes
};

let config = { ...DEFAULT_CONFIG };
const cache = new Map();

export async function initCloudClient() {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  config = { ...DEFAULT_CONFIG, ...stored[STORAGE_KEY] };
  return config;
}

export async function updateCloudConfig(newConfig) {
  config = { ...config, ...newConfig };
  await chrome.storage.local.set({ [STORAGE_KEY]: config });
  return config;
}

export function getCloudConfig() {
  return { ...config };
}

export function isCloudEnabled() {
  return config.enabled && config.endpoint && config.apiKey;
}

/**
 * 云端查杀单个指标
 * @param {string} indicator - URL/域名/IP/SHA256
 * @param {object} options - { useVT, skipCache }
 * @returns {object|null} 云查结果 or null if cloud disabled/error
 */
export async function cloudScan(indicator, options = {}) {
  if (!isCloudEnabled()) return null;

  const useVT = options.useVT ?? config.useVT;
  const skipCache = options.skipCache ?? false;

  // Cache check
  const cacheKey = `${indicator}:${useVT}`;
  if (!skipCache) {
    const cached = cache.get(cacheKey);
    if (cached && Date.now() - cached.ts < config.cacheTtl * 1000) {
      return { ...cached.data, cached: true };
    }
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.timeout);

    const resp = await fetch(`${config.endpoint}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': config.apiKey
      },
      body: JSON.stringify({
        indicator,
        vt: useVT
      }),
      signal: controller.signal
    });

    clearTimeout(timer);

    if (!resp.ok) {
      if (resp.status === 429) return { error: 'rate_limited', indicator };
      if (resp.status === 401) return { error: 'unauthorized', indicator };
      return null;
    }

    const data = await resp.json();

    // Cache result
    cache.set(cacheKey, { data, ts: Date.now() });

    // Clean old cache entries
    if (cache.size > 500) {
      const cutoff = Date.now() - config.cacheTtl * 1000;
      for (const [k, v] of cache) {
        if (v.ts < cutoff) cache.delete(k);
      }
    }

    return data;
  } catch (e) {
    if (e.name === 'AbortError') {
      return { error: 'timeout', indicator };
    }
    return null;
  }
}

/**
 * 批量云端 IOC 查询
 * @param {string[]} indicators
 * @returns {object|null}
 */
export async function cloudBatchLookup(indicators) {
  if (!isCloudEnabled() || !indicators.length) return null;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.timeout * 2);

    const resp = await fetch(`${config.endpoint}/ioc/batch`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': config.apiKey
      },
      body: JSON.stringify({ indicators: indicators.slice(0, 100) }),
      signal: controller.signal
    });

    clearTimeout(timer);
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}

/**
 * 获取云端威胁库统计
 */
export async function getCloudStats() {
  if (!isCloudEnabled()) return null;
  try {
    const resp = await fetch(`${config.endpoint}/stats`, {
      headers: { 'X-API-Key': config.apiKey }
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}

/**
 * 融合本地 IOC + 本地 ML + 云查 结果
 * 优先级：本地 IOC > 云查 > 本地 ML
 */
export async function fullScan(localIocMatch, localMlResult, indicator) {
  // If local IOC match found, it's definitive — still do cloud lookup for enrichment
  let cloudResult = null;
  if (isCloudEnabled()) {
    cloudResult = await cloudScan(indicator);
  }

  // Local IOC is highest confidence
  if (localIocMatch) {
    return {
      ...localIocMatch,
      verdict: 'malicious',
      source: localIocMatch.source || 'local_ioc',
      cloud: cloudResult
    };
  }

  // Cloud result
  if (cloudResult && !cloudResult.error) {
    if (cloudResult.verdict === 'malicious' || cloudResult.verdict === 'suspicious') {
      return {
        ...cloudResult,
        localMl: localMlResult
      };
    }
  }

  // Local ML fallback
  if (localMlResult && localMlResult.is_malicious) {
    return {
      verdict: 'suspicious',
      score: localMlResult.score * 100,
      severity: localMlResult.confidence,
      family: localMlResult.family,
      reasons: localMlResult.reasons,
      source: 'local_ml',
      cloud: cloudResult
    };
  }

  return {
    verdict: 'safe',
    score: 0,
    severity: 'safe',
    source: cloudResult ? 'cloud' : 'local',
    cloud: cloudResult
  };
}
