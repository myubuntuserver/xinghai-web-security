/**
 * 星海 Web 安全 - Popup Script
 */

const $ = (id) => document.getElementById(id);

async function init() {
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url || '';
  
  // Check URL safety
  if (url && !url.startsWith('chrome://') && !url.startsWith('edge://') && !url.startsWith('chrome-extension://')) {
    $('currentUrl').textContent = new URL(url).hostname;
    chrome.runtime.sendMessage({ action: 'checkUrl', url }, (resp) => {
      if (resp) {
        const verdict = $('siteVerdict');
        verdict.className = 'site-verdict';
        if (resp.severity === 'critical' || resp.severity === 'high') {
          verdict.classList.add('verdict-danger');
          verdict.textContent = `🚫 ${resp.family || '恶意网站'}`;
        } else if (resp.severity === 'medium' || resp.severity === 'low') {
          verdict.classList.add('verdict-warn');
          verdict.textContent = `⚠️ ${resp.family || '可疑网站'}`;
        } else {
          verdict.classList.add('verdict-safe');
          verdict.textContent = '✓ 安全';
        }
      } else {
        $('siteVerdict').className = 'site-verdict verdict-safe';
        $('siteVerdict').textContent = '✓ 安全';
      }
    });
  } else {
    $('currentUrl').textContent = url || '内部页面';
    $('siteVerdict').className = 'site-verdict verdict-safe';
    $('siteVerdict').textContent = '系统页面';
  }

  // Load stats
  chrome.runtime.sendMessage({ action: 'getStats' }, (stats) => {
    if (stats) {
      $('totalBlocks').textContent = stats.totalBlocks || 0;
      renderRecentBlocks(stats.recentBlocks || []);
    }
  });

  // Load blocklist info
  chrome.runtime.sendMessage({ action: 'getBlocklistInfo' }, (info) => {
    if (info) {
      $('domainCount').textContent = info.domains || 0;
      $('ipCount').textContent = info.ips || 0;
      $('urlCount').textContent = info.urls || 0;
      $('hashCount').textContent = info.hashes || 0;
      $('blocklistVersion').textContent = info.version || '-';
    }
  });

  // Load settings for toggle
  chrome.runtime.sendMessage({ action: 'getSettings' }, (settings) => {
    if (settings) {
      const toggle = $('toggleBtn');
      toggle.classList.toggle('on', settings.enabled);
      $('statusDot').classList.toggle('off', !settings.enabled);
      $('statusText').textContent = settings.enabled ? '防护已启用' : '防护已暂停';
      $('heuristicStatus').textContent = settings.heuristicCheck ? '已启用' : '已关闭';
    }
  });

  // Toggle
  $('toggleBtn').addEventListener('click', async () => {
    chrome.runtime.sendMessage({ action: 'getSettings' }, (settings) => {
      const newEnabled = !settings.enabled;
      chrome.runtime.sendMessage({ action: 'updateSettings', settings: { enabled: newEnabled } }, () => {
        $('toggleBtn').classList.toggle('on', newEnabled);
        $('statusDot').classList.toggle('off', !newEnabled);
        $('statusText').textContent = newEnabled ? '防护已启用' : '防护已暂停';
      });
    });
  });

  // Buttons
  $('optionsBtn').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  $('refreshBtn').addEventListener('click', () => {
    $('refreshBtn').textContent = '更新中...';
    chrome.runtime.sendMessage({ action: 'reloadBlocklist' }, () => {
      $('refreshBtn').textContent = '🔄 更新规则';
      init();
    });
  });
}

function renderRecentBlocks(blocks) {
  const container = $('threatList');
  if (!blocks || blocks.length === 0) {
    container.innerHTML = '<div style="color:#475569; font-size:12px; text-align:center; padding:12px;">暂无拦截记录</div>';
    return;
  }

  container.innerHTML = blocks.slice(0, 10).map(b => {
    const time = new Date(b.time).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
    const cls = b.severity === 'critical' ? '' : (b.severity === 'high' ? 'high' : 'medium');
    return `
      <div class="threat-item ${cls}">
        <div class="threat-family">${b.family || '未知威胁'}</div>
        <div class="threat-url">${(b.url || '').substring(0, 60)}</div>
        <div class="threat-time">${time}</div>
      </div>
    `;
  }).join('');
}

init();
