/**
 * 星海 Web 安全 - Options Page Script
 */
const $ = (id) => document.getElementById(id);

let settings = {};

async function init() {
  // Load settings
  await new Promise(r => chrome.runtime.sendMessage({ action: 'getSettings' }, (s) => { settings = s; r(); }));
  
  // Set toggles
  $('tEnabled').classList.toggle('on', settings.enabled);
  $('tPhishing').classList.toggle('on', settings.blockPhishing);
  $('tMalware').classList.toggle('on', settings.blockMalware);
  $('tC2').classList.toggle('on', settings.blockC2);
  $('tDownloads').classList.toggle('on', settings.blockDownloads);
  $('tHeuristic').classList.toggle('on', settings.heuristicCheck);
  $('tNotifications').classList.toggle('on', settings.showNotifications);
  $('remoteUrl').value = settings.blocklistUrl || '';

  // v1.2.0: 白名单开关
  if ($('tAllowlist')) {
    $('tAllowlist').classList.toggle('on', settings.allowlistEnabled !== false);
    $('tAllowlist').addEventListener('click', () => {
      const on = !$('tAllowlist').classList.contains('on');
      $('tAllowlist').classList.toggle('on', on);
      chrome.runtime.sendMessage({ action: 'updateSettings', settings: { allowlistEnabled: on } });
    });
  }

  // Toggle handlers
  const toggles = [
    ['tEnabled', 'enabled'],
    ['tPhishing', 'blockPhishing'],
    ['tMalware', 'blockMalware'],
    ['tC2', 'blockC2'],
    ['tDownloads', 'blockDownloads'],
    ['tHeuristic', 'heuristicCheck'],
    ['tNotifications', 'showNotifications']
  ];
  toggles.forEach(([id, key]) => {
    $(id).addEventListener('click', () => {
      settings[key] = !settings[key];
      $(id).classList.toggle('on', settings[key]);
      chrome.runtime.sendMessage({ action: 'updateSettings', settings: { [key]: settings[key] } });
    });
  });

  // Load stats
  chrome.runtime.sendMessage({ action: 'getStats' }, (stats) => {
    if (stats) {
      $('sBlocks').textContent = stats.totalBlocks || 0;
      renderBlockLog(stats.recentBlocks || []);
    }
  });

  // Load blocklist info
  chrome.runtime.sendMessage({ action: 'getBlocklistInfo' }, (info) => {
    if (info) {
      $('sDomains').textContent = info.domains || 0;
      $('sIPs').textContent = info.ips || 0;
      $('sVersion').textContent = (info.version || '').replace('2026.', '');
    }
  });

  // Load custom rules
  loadCustomRules();

  // v1.2.0: Load allowlist
  loadAllowlist();

  // Buttons
  $('saveUrl').addEventListener('click', () => {
    const url = $('remoteUrl').value.trim();
    chrome.runtime.sendMessage({ action: 'updateSettings', settings: { blocklistUrl: url } }, () => {
      alert('已保存，将在下个更新周期同步');
    });
  });

  $('reloadRules').addEventListener('click', () => {
    $('reloadRules').textContent = '加载中...';
    chrome.runtime.sendMessage({ action: 'reloadBlocklist' }, () => {
      $('reloadRules').textContent = '重新加载内置规则';
      init();
    });
  });

  $('addRule').addEventListener('click', () => {
    const type = $('ruleType').value;
    const value = $('ruleValue').value.trim();
    const note = $('ruleNote').value.trim();
    if (!value) return;
    chrome.runtime.sendMessage({ action: 'addCustomRule', rule: { type, value, note } }, () => {
      $('ruleValue').value = '';
      $('ruleNote').value = '';
      loadCustomRules();
    });
  });

  // v1.2.0: Allowlist add button
  if ($('addAllow')) {
    $('addAllow').addEventListener('click', () => {
      const type = $('allowType').value;
      const value = $('allowValue').value.trim();
      const note = $('allowNote').value.trim();
      if (!value) return;
      chrome.runtime.sendMessage({
        action: 'addToAllowlist',
        entry: { type, value, note, includeSubdomains: true }
      }, () => {
        $('allowValue').value = '';
        $('allowNote').value = '';
        loadAllowlist();
      });
    });
  }

  $('clearStats').addEventListener('click', () => {
    if (confirm('确定清空所有拦截记录？')) {
      chrome.storage.local.set({ starsea_stats: { totalBlocks: 0, blocksByFamily: {}, blocksBySeverity: {}, recentBlocks: [], lastBlock: null } }, init);
    }
  });

  // Cloud config
  chrome.storage.local.get('starsea_cloud', (data) => {
    const cc = data.starsea_cloud || {};
    $('tCloud').classList.toggle('on', cc.enabled !== false);
    $('tCloudVT').classList.toggle('on', !!cc.useVT);
    $('cloudEndpoint').value = cc.endpoint || '';
    $('cloudApiKey').value = cc.apiKey || '';
  });

  $('tCloud').addEventListener('click', () => {
    const on = !$('tCloud').classList.contains('on');
    $('tCloud').classList.toggle('on', on);
    const cur = JSON.parse(localStorage.getItem('_cloud') || '{}');
    cur.enabled = on;
    localStorage.setItem('_cloud', JSON.stringify(cur));
  });
  $('tCloudVT').addEventListener('click', () => {
    $('tCloudVT').classList.toggle('on');
  });

  $('saveCloud').addEventListener('click', () => {
    const cloudConfig = {
      enabled: $('tCloud').classList.contains('on'),
      endpoint: $('cloudEndpoint').value.trim().replace(/\/$/, ''),
      apiKey: $('cloudApiKey').value.trim(),
      useVT: $('tCloudVT').classList.contains('on'),
      timeout: 5000,
      cacheTtl: 300
    };
    chrome.storage.local.set({ starsea_cloud: cloudConfig }, () => {
      chrome.runtime.sendMessage({ action: 'cloudUpdate' }, () => {
        $('cloudStatus').textContent = '✓ 云查配置已保存';
        $('cloudStatus').style.color = '#4ade80';
        setTimeout(() => { $('cloudStatus').textContent = ''; }, 3000);
      });
    });
  });

  $('testCloud').addEventListener('click', async () => {
    const endpoint = $('cloudEndpoint').value.trim().replace(/\/$/, '');
    const apiKey = $('cloudApiKey').value.trim();
    if (!endpoint || !apiKey) {
      $('cloudStatus').textContent = '请先填写 API 地址和 Key';
      $('cloudStatus').style.color = '#f87171';
      return;
    }
    $('cloudStatus').textContent = '测试中...';
    $('cloudStatus').style.color = '#94a3b8';
    try {
      const resp = await fetch(`${endpoint}/health`);
      if (resp.ok) {
        const data = await resp.json();
        $('cloudStatus').textContent = `✓ 连接成功 - ${data.service} v${data.version}`;
        $('cloudStatus').style.color = '#4ade80';
      } else {
        $('cloudStatus').textContent = `✗ HTTP ${resp.status}`;
        $('cloudStatus').style.color = '#f87171';
      }
    } catch (e) {
      $('cloudStatus').textContent = `✗ 连接失败: ${e.message}`;
      $('cloudStatus').style.color = '#f87171';
    }
  });
}

function loadCustomRules() {
  chrome.runtime.sendMessage({ action: 'getCustomRules' }, (rules) => {
    const container = $('ruleList');
    const all = [];
    if (rules) {
      for (const [d, v] of Object.entries(rules.domains || {})) all.push({ type: 'domain', value: d, ...v });
      for (const [ip, v] of Object.entries(rules.ips || {})) all.push({ type: 'ip', value: ip, ...v });
      for (const [u, v] of Object.entries(rules.urls || {})) all.push({ type: 'url', value: u, ...v });
    }
    if (all.length === 0) {
      container.innerHTML = '<div style="color:#475569; font-size:12px; text-align:center; padding:12px;">暂无自定义规则</div>';
      return;
    }
    container.innerHTML = all.map(r => `
      <div class="rule-item">
        <span><strong style="color:#60a5fa">[${r.type}]</strong> ${r.value} <span style="color:#64748b">${r.context || ''}</span></span>
        <span class="del" data-value="${r.value}">✕ 删除</span>
      </div>
    `).join('');
    container.querySelectorAll('.del').forEach(el => {
      el.addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: 'removeCustomRule', value: el.dataset.value }, loadCustomRules);
      });
    });
  });
}

function renderBlockLog(blocks) {
  const container = $('blockList');
  if (!blocks || blocks.length === 0) {
    container.innerHTML = '<div style="color:#475569; font-size:13px; text-align:center; padding:20px;">🛡️ 暂无拦截记录，安全护航中</div>';
    return;
  }
  container.innerHTML = blocks.map(b => {
    const time = new Date(b.time).toLocaleString('zh-CN');
    const color = b.severity === 'critical' ? '#f87171' : (b.severity === 'high' ? '#fb923c' : '#fde047');
    return `
      <div style="padding:10px; background:#0f172a; border-radius:6px; margin-bottom:6px; border-left:3px solid ${color};">
        <div style="display:flex; justify-content:space-between;">
          <strong style="color:${color}">${b.family || '未知威胁'}</strong>
          <span style="color:#475569; font-size:11px;">${time}</span>
        </div>
        <div style="font-size:12px; color:#94a3b8; margin-top:4px; word-break:break-all;">${b.url || ''}</div>
        <div style="font-size:11px; color:#64748b; margin-top:2px;">${b.context || ''}</div>
      </div>
    `;
  }).join('');
}

// v1.2.0: 白名单加载和渲染
function loadAllowlist() {
  chrome.runtime.sendMessage({ action: 'getAllowlist' }, (data) => {
    if (!data) return;
    const container = $('allowList');
    if (!container) return;

    if ($('builtinCount')) {
      $('builtinCount').textContent = data.stats?.builtin || 0;
    }

    const entries = data.entries || [];
    if (entries.length === 0) {
      container.innerHTML = '<div style="color:#475569; font-size:12px; text-align:center; padding:12px;">暂无自定义白名单</div>';
      return;
    }

    const typeColors = { domain: '#6ee7b7', ip: '#93c5fd', url: '#c4b5fd' };
    container.innerHTML = entries.map(e => `
      <div class="rule-item" style="border-left:3px solid ${typeColors[e.type] || '#6ee7b7'};">
        <span>
          <strong style="color:${typeColors[e.type] || '#6ee7b7'}">[${e.type}]</strong>
          ${e.value}
          ${e.note ? `<span style="color:#64748b; margin-left:8px;">${e.note}</span>` : ''}
        </span>
        <span class="del-allow" data-value="${e.value}" style="color:#f87171;cursor:pointer;">✕ 移除</span>
      </div>
    `).join('');

    container.querySelectorAll('.del-allow').forEach(el => {
      el.addEventListener('click', () => {
        chrome.runtime.sendMessage({
          action: 'removeFromAllowlist',
          value: el.dataset.value
        }, loadAllowlist);
      });
    });
  });
}

init();
