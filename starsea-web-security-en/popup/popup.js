/**
 * StarSea Web Security - Popup Script
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
          verdict.textContent = `🚫 ${resp.family || 'Malicious'}`;
        } else if (resp.severity === 'medium' || resp.severity === 'low') {
          verdict.classList.add('verdict-warn');
          verdict.textContent = `⚠️ ${resp.family || 'Suspicious'}`;
        } else {
          verdict.classList.add('verdict-safe');
          verdict.textContent = '✓ Safe';
        }
      } else {
        $('siteVerdict').className = 'site-verdict verdict-safe';
        $('siteVerdict').textContent = '✓ Safe';
      }
    });
  } else {
    $('currentUrl').textContent = url || 'Internal Page';
    $('siteVerdict').className = 'site-verdict verdict-safe';
    $('siteVerdict').textContent = 'System Page';
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
      $('statusText').textContent = settings.enabled ? 'Protection Active' : 'Protection Paused';
      $('heuristicStatus').textContent = settings.heuristicCheck ? 'Enabled' : 'Disabled';
    }
  });

  // Toggle
  $('toggleBtn').addEventListener('click', async () => {
    chrome.runtime.sendMessage({ action: 'getSettings' }, (settings) => {
      const newEnabled = !settings.enabled;
      chrome.runtime.sendMessage({ action: 'updateSettings', settings: { enabled: newEnabled } }, () => {
        $('toggleBtn').classList.toggle('on', newEnabled);
        $('statusDot').classList.toggle('off', !newEnabled);
        $('statusText').textContent = newEnabled ? 'Protection Active' : 'Protection Paused';
      });
    });
  });

  // Buttons
  $('optionsBtn').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  $('refreshBtn').addEventListener('click', () => {
    $('refreshBtn').textContent = 'Updating...';
    chrome.runtime.sendMessage({ action: 'reloadBlocklist' }, () => {
      $('refreshBtn').textContent = '🔄 Update Rules';
      init();
    });
  });
}

function renderRecentBlocks(blocks) {
  const container = $('threatList');
  if (!blocks || blocks.length === 0) {
    container.innerHTML = '<div style="color:#475569; font-size:12px; text-align:center; padding:12px;">No blocked threats yet</div>';
    return;
  }

  container.innerHTML = blocks.slice(0, 10).map(b => {
    const time = new Date(b.time).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    const cls = b.severity === 'critical' ? '' : (b.severity === 'high' ? 'high' : 'medium');
    return `
      <div class="threat-item ${cls}">
        <div class="threat-family">${b.family || 'Unknown Threat'}</div>
        <div class="threat-url">${(b.url || '').substring(0, 60)}</div>
        <div class="threat-time">${time}</div>
      </div>
    `;
  }).join('');
}

init();