// SafeBrowse – Content Script
// Runs in every page context. Detects insecure forms and warns users.

(function () {
  'use strict';

  // Don't run in iframes
  if (window.self !== window.top) return;

  let warningBannerShown = false;

  // Check if the page is on HTTP (not HTTPS)
  const isInsecure = window.location.protocol === 'http:';

  // Find password input fields in the document
  function findPasswordInputs(): HTMLInputElement[] {
    return Array.from(document.querySelectorAll('input[type="password"]'));
  }

  // Inject a warning banner above insecure password forms
  function injectInsecureBanner(form: HTMLElement): void {
    if (warningBannerShown) return;
    warningBannerShown = true;

    const banner = document.createElement('div');
    banner.id = 'safebrowse-warning-banner';
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 2147483647;
      background: linear-gradient(135deg, #7f1d1d, #991b1b);
      color: white;
      padding: 12px 20px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 14px;
      font-weight: 500;
      display: flex;
      align-items: center;
      gap: 12px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.4);
      border-bottom: 2px solid rgba(255,255,255,0.15);
    `;

    banner.innerHTML = `
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <span><strong>SafeBrowse Warning:</strong> This page uses HTTP (not HTTPS). Any password you enter will be sent in <strong>plain text</strong> and can be intercepted.</span>
      <button id="safebrowse-dismiss" style="margin-left:auto;background:rgba(255,255,255,0.15);border:1px solid rgba(255,255,255,0.3);color:white;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:13px;flex-shrink:0;">
        Dismiss
      </button>
    `;

    document.body.insertBefore(banner, document.body.firstChild);

    document.getElementById('safebrowse-dismiss')?.addEventListener('click', () => {
      banner.remove();
    });
  }

  // Observe form changes (some SPAs inject forms dynamically)
  function observeForms(): void {
    const checkForms = () => {
      const passwords = findPasswordInputs();
      if (passwords.length > 0 && isInsecure) {
        const form = passwords[0].closest('form') || passwords[0].parentElement;
        if (form) injectInsecureBanner(form as HTMLElement);
      }
    };

    // Initial check
    checkForms();

    // Watch for dynamically injected forms
    const observer = new MutationObserver(checkForms);
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // Listen for messages from background worker (e.g. overlay danger message)
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'SHOW_DANGER_OVERLAY') {
      showDangerOverlay(message.url, message.confidence);
    }
  });

  function showDangerOverlay(url: string, confidence: number): void {
    // Don't show if already present
    if (document.getElementById('safebrowse-danger-overlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'safebrowse-danger-overlay';
    overlay.style.cssText = `
      position: fixed;
      inset: 0;
      z-index: 2147483647;
      background: rgba(0, 0, 0, 0.85);
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      backdrop-filter: blur(8px);
    `;

    overlay.innerHTML = `
      <div style="background: #0f172a; border: 1px solid rgba(239,68,68,0.4); border-radius: 16px; padding: 40px; max-width: 440px; text-align: center; box-shadow: 0 0 60px rgba(239,68,68,0.3);">
        <div style="width:64px;height:64px;border-radius:50%;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);display:flex;align-items:center;justify-content:center;margin:0 auto 20px">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
        </div>
        <h2 style="color:#ef4444;font-size:22px;font-weight:700;margin:0 0 8px">Phishing Site Detected!</h2>
        <p style="color:rgba(255,255,255,0.7);font-size:14px;line-height:1.6;margin:0 0 8px">Our AI model identified this site as a <strong>phishing threat</strong> with <strong style="color:#ef4444">${(confidence * 100).toFixed(1)}% confidence</strong>.</p>
        <p style="color:rgba(255,255,255,0.4);font-size:12px;font-family:monospace;margin:0 0 28px;word-break:break-all;">${url}</p>
        <div style="display:flex;gap:10px;justify-content:center;">
          <button id="safebrowse-go-back" style="flex:1;background:#ef4444;border:0;color:white;padding:12px 20px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;">
            ← Go Back to Safety
          </button>
          <button id="safebrowse-proceed" style="flex:1;background:transparent;border:1px solid rgba(255,255,255,0.15);color:rgba(255,255,255,0.5);padding:12px 20px;border-radius:8px;font-size:14px;cursor:pointer;">
            Proceed Anyway
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);
    document.body.style.overflow = 'hidden';

    document.getElementById('safebrowse-go-back')?.addEventListener('click', () => {
      history.back();
    });

    document.getElementById('safebrowse-proceed')?.addEventListener('click', () => {
      overlay.remove();
      document.body.style.overflow = '';
    });
  }

  // Initialize
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', observeForms);
  } else {
    observeForms();
  }
})();
