// SafeBrowse - Background Service Worker (Manifest V3)
// Handles real-time URL scanning when user navigates to a new page.

const VERCEL_API_URL = 'http://localhost:3000/api/check-url'; // IMPORTANT: UPDATE TO VERCEL DOMAIN WHEN DEPLOYED

// Helper to get anonymous endpoint ID
async function getEndpointId(): Promise<string> {
  const result = await chrome.storage.local.get('endpoint_id');
  if (result.endpoint_id) return result.endpoint_id;
  const newId = 'EP-' + Math.random().toString(36).substring(2, 10);
  await chrome.storage.local.set({ endpoint_id: newId });
  return newId;
}

// In-memory cache to avoid repeated API calls for the same URL
const scanCache = new Map<string, ScanResult>();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface ScanResult {
  url: string;
  status: 'safe' | 'warning' | 'danger' | 'scanning' | 'error';
  label: string;
  confidence: number;
  phishingProbability: number;
  legitimateProbability: number;
  inferenceTimeMs: number;
  modelUsed: string;
  ssl: { status: 'safe' | 'warning' | 'danger'; text: string };
  forms: { status: 'safe' | 'warning' | 'danger'; text: string };
  timestamp: number;
}

// URLs that should never be scanned (browser internals, etc.)
function shouldSkipUrl(url: string): boolean {
  if (!url) return true;
  const skip = [
    'chrome://', 'chrome-extension://', 'about:', 'data:',
    'file://', 'moz-extension://', 'edge://', 'devtools://',
    'localhost:'
  ];
  return skip.some(prefix => url.startsWith(prefix));
}

// Extract protocol info for SSL check
function checkSSL(url: string): ScanResult['ssl'] {
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'https:') {
      return { status: 'safe', text: 'HTTPS – Connection Encrypted' };
    } else {
      return { status: 'danger', text: 'HTTP – No Encryption (Plain Text)' };
    }
  } catch {
    return { status: 'warning', text: 'Unable to parse URL protocol' };
  }
}

// Map label + confidence to our status (Fallback if Vercel doesn't map it)
function mapToStatus(label: string, confidence: number, phishingProb: number): ScanResult['status'] {
  if (label === 'phishing') {
    if (phishingProb > 0.85) return 'danger';
    return 'warning';
  }
  if (label === 'legitimate') {
    if (confidence < 0.70) return 'warning';
    return 'safe';
  }
  return 'warning';
}

// Set badge color on the extension icon
async function updateBadge(tabId: number, status: ScanResult['status']): Promise<void> {
  const colors: Record<string, string> = {
    safe: '#10b981',      // emerald
    warning: '#f59e0b',   // amber
    danger: '#ef4444',    // red
    scanning: '#6366f1',  // indigo
    error: '#6b7280',     // gray
  };
  const texts: Record<string, string> = {
    safe: '✓',
    warning: '!',
    danger: '✗',
    scanning: '…',
    error: '?',
  };
  try {
    await chrome.action.setBadgeBackgroundColor({ color: colors[status] || '#6b7280', tabId });
    await chrome.action.setBadgeText({ text: texts[status] || '?', tabId });
  } catch {
    // Tab may have been closed
  }
}

// Core scanning function – calls Vercel API
async function scanUrl(url: string, tabId: number): Promise<ScanResult> {
  const cacheKey = url;
  const cached = scanCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return cached;
  }

  const ssl = checkSSL(url);
  
  // Set scanning state in storage immediately
  const scanningResult: ScanResult = {
    url,
    status: 'scanning',
    label: 'Scanning…',
    confidence: 0,
    phishingProbability: 0,
    legitimateProbability: 0,
    inferenceTimeMs: 0,
    modelUsed: 'ModernBERT',
    ssl,
    forms: { status: 'safe', text: 'Checking forms…' },
    timestamp: Date.now(),
  };
  await chrome.storage.local.set({ [`scan_${tabId}`]: scanningResult });

  try {
    const endpoint_id = await getEndpointId();
    
    // Call Vercel Unified API Instead of Raw hugging Face
    const response = await fetch(VERCEL_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, endpoint_id }),
      signal: AbortSignal.timeout(15000), // 15s timeout
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();

    const status = data.status || mapToStatus(data.label, data.confidence, data.phishingProbability);
    
    // Form protection: if HTTP and contains login, flag it
    let forms: ScanResult['forms'] = { status: 'safe', text: 'No sensitive forms detected' };
    if (ssl.status === 'danger') {
      forms = { status: 'danger', text: 'Unencrypted connection – don\'t enter passwords!' };
    }

    const result: ScanResult = {
      url,
      status,
      label: data.label === 'phishing' ? 'Phishing Detected' : 'Legitimate',
      confidence: data.confidence,
      phishingProbability: data.phishingProbability,
      legitimateProbability: data.legitimateProbability,
      inferenceTimeMs: data.inferenceTimeMs,
      modelUsed: data.modelUsed || 'ModernBERT',
      ssl: data.ssl || ssl,
      forms,
      timestamp: Date.now(),
    };

    scanCache.set(cacheKey, result);
    
    // Limit cache size
    if (scanCache.size > 200) {
      const firstKey = scanCache.keys().next().value;
      if (firstKey) scanCache.delete(firstKey);
    }

    return result;
  } catch (error) {
    console.error('[SafeBrowse] Scan failed:', error);
    const errorResult: ScanResult = {
      url,
      status: 'error',
      label: 'Scan Failed',
      confidence: 0,
      phishingProbability: 0,
      legitimateProbability: 0,
      inferenceTimeMs: 0,
      modelUsed: 'ModernBERT',
      ssl,
      forms: { status: 'safe', text: 'Unable to check' },
      timestamp: Date.now(),
    };
    return errorResult;
  }
}

// Show Chrome notification for high-confidence phishing
async function showDangerNotification(url: string): Promise<void> {
  const domain = new URL(url).hostname;
  chrome.notifications.create({
    type: 'basic',
    iconUrl: '../icons/icon128.png',
    title: '⚠️ SafeBrowse: Phishing Detected!',
    message: `The site "${domain}" has been identified as a phishing threat. Stay safe!`,
    priority: 2,
  });
}

// Main event listener: fires when a tab finishes loading
chrome.webNavigation.onCompleted.addListener(async (details) => {
  const { tabId, url, frameId } = details;
  
  // Only scan main frame navigation (frameId 0), skip iframes
  if (frameId !== 0) return;
  if (shouldSkipUrl(url)) return;

  await updateBadge(tabId, 'scanning');

  const result = await scanUrl(url, tabId);
  
  // Store result
  await chrome.storage.local.set({ [`scan_${tabId}`]: result });
  
  // Update badge
  await updateBadge(tabId, result.status);
  
  // Fire notification and on-page popup for confirmed phishing
  if (result.status === 'danger') {
    await showDangerNotification(url);
    // Instruct content script to show the full-page danger overlay pop-up
    try {
      await chrome.tabs.sendMessage(tabId, {
        type: 'SHOW_DANGER_OVERLAY',
        url: url,
        confidence: result.confidence
      });
    } catch (e) {
      console.log('Could not send message to content script', e);
    }
  }
});

// Clear old scan data when a tab is removed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`scan_${tabId}`);
});

// Handle messages from popup requesting a manual rescan
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'RESCAN') {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const tab = tabs[0];
      if (!tab?.id || !tab?.url) return;
      
      // Remove from cache to force fresh scan
      scanCache.delete(tab.url);
      
      await updateBadge(tab.id, 'scanning');
      const result = await scanUrl(tab.url, tab.id);
      await chrome.storage.local.set({ [`scan_${tab.id}`]: result });
      await updateBadge(tab.id, result.status);
      sendResponse({ success: true, result });
    });
    return true; // Keep channel open for async sendResponse
  }
  
  if (message.type === 'GET_SCAN') {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const tab = tabs[0];
      if (!tab?.id) { sendResponse({ result: null }); return; }
      const stored = await chrome.storage.local.get(`scan_${tab.id}`);
      sendResponse({ result: stored[`scan_${tab.id}`] || null, tabUrl: tab.url });
    });
    return true;
  }
});

console.log('[SafeBrowse] Background service worker started.');
