// Vercel Serverless Function: /api/check-url
// Unified endpoint: calls HF ModernBERT API and returns phishing verdict.
import type { VercelRequest, VercelResponse } from '@vercel/node';
import { createClient } from '@supabase/supabase-js';
import tls from 'tls';

type ScanStatus = 'safe' | 'warning' | 'danger';

interface QuickVerdict {
  status: ScanStatus | 'unknown';
  label: string;
  confidence: number;
  phishingProbability: number;
  legitimateProbability: number;
  modelUsed: string;
  reason: string;
}

interface ScanLogPayload {
  endpointId?: string;
  userId?: string;
  url: string;
  status: ScanStatus;
  confidence: number;
  modelUsed: string;
}

function checkStrongSSL(hostname: string): Promise<{ valid: boolean, issuer: string, isFreeCA: boolean, ageDays: number }> {
  return new Promise((resolve) => {
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
       return resolve({ valid: true, issuer: 'Localhost', isFreeCA: false, ageDays: 1000 });
    }
    try {
      const socket = tls.connect(443, hostname, { servername: hostname, rejectUnauthorized: false }, () => {
        const cert = socket.getPeerCertificate(true);
        if (!cert || Object.keys(cert).length === 0) {
          socket.destroy();
          return resolve({ valid: false, issuer: 'Unknown', isFreeCA: true, ageDays: 0 });
        }
        const valid = socket.authorized;
        const rawIssuerO = cert.issuer?.O;
        const rawIssuerCN = cert.issuer?.CN;
        const issuer =
          typeof rawIssuerO === 'string'
            ? rawIssuerO
            : Array.isArray(rawIssuerO)
              ? rawIssuerO[0]
              : typeof rawIssuerCN === 'string'
                ? rawIssuerCN
                : Array.isArray(rawIssuerCN)
                  ? rawIssuerCN[0]
                  : 'Unknown';
        const freeCAs = ["Let's Encrypt", "Cloudflare", "ZeroSSL", "cPanel", "GoGetSSL", "Sectigo", "Google Trust Services", "Hostinger"];
        const isFreeCA = freeCAs.some(ca => issuer && issuer.includes(ca));
        const validFrom = cert.valid_from ? new Date(cert.valid_from).getTime() : Date.now();
        const ageDays = (Date.now() - validFrom) / (1000 * 60 * 60 * 24);
        socket.destroy();
        resolve({ valid, issuer: issuer || 'Unknown', isFreeCA, ageDays });
      });
      socket.on('error', () => resolve({ valid: false, issuer: 'None', isFreeCA: true, ageDays: 0 }));
      socket.setTimeout(2500, () => {
        socket.destroy();
        resolve({ valid: false, issuer: 'Timeout', isFreeCA: true, ageDays: 0 });
      });
    } catch {
      resolve({ valid: false, issuer: 'Error', isFreeCA: true, ageDays: 0 });
    }
  });
}

const HF_API_URL = 'https://alimusarizvi-phishing.hf.space/predict';

const HIGH_TRUST_SUFFIXES = [
  'google.com',
  'googleusercontent.com',
  'gstatic.com',
  'youtube.com',
  'github.com',
  'microsoft.com',
  'apple.com',
  'amazon.com',
  'wikipedia.org',
  'cloudflare.com',
  'supabase.co',
  'vercel.app',
];

const HIGH_TRUST_REGEXES = [
  /^([a-z0-9-]+\.)*google\.[a-z.]+$/i,
  /^([a-z0-9-]+\.)*github\.[a-z.]+$/i,
];

const SUSPICIOUS_TOKENS = [
  'login',
  'signin',
  'verify',
  'secure',
  'update',
  'password',
  'account',
  'bank',
  'wallet',
  'auth',
  'confirm',
];

function isHighTrustHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (HIGH_TRUST_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`))) {
    return true;
  }
  return HIGH_TRUST_REGEXES.some((pattern) => pattern.test(host));
}

function getQuickVerdict(parsedUrl: URL): QuickVerdict {
  const href = parsedUrl.href.toLowerCase();
  const host = parsedUrl.hostname.toLowerCase();
  const hostSegments = host.split('.');
  const hasAtSymbol = parsedUrl.href.includes('@');
  const hasPunycode = host.includes('xn--');
  const hasSuspiciousToken = SUSPICIOUS_TOKENS.some((token) => href.includes(token));
  const hasExcessiveSubdomains = hostSegments.length > 5;
  const isRawIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);

  if (parsedUrl.protocol === 'https:' && isHighTrustHost(host) && !hasAtSymbol && !hasPunycode) {
    return {
      status: 'safe',
      label: 'legitimate',
      confidence: 0.995,
      phishingProbability: 0.005,
      legitimateProbability: 0.995,
      modelUsed: 'RuleEngine::TrustedDomain',
      reason: 'trusted_https_domain',
    };
  }

  if (
    hasAtSymbol ||
    hasPunycode ||
    hasExcessiveSubdomains ||
    (isRawIPv4 && hasSuspiciousToken) ||
    (parsedUrl.protocol !== 'https:' && hasSuspiciousToken)
  ) {
    return {
      status: 'danger',
      label: 'phishing',
      confidence: 0.93,
      phishingProbability: 0.93,
      legitimateProbability: 0.07,
      modelUsed: 'RuleEngine::RiskHeuristics',
      reason: 'high_risk_url_pattern',
    };
  }

  return {
    status: 'unknown',
    label: 'unknown',
    confidence: 0,
    phishingProbability: 0,
    legitimateProbability: 0,
    modelUsed: 'RuleEngine::Unknown',
    reason: 'requires_ml_analysis',
  };
}

async function logScanToSupabase(payload: ScanLogPayload): Promise<void> {
  if (!payload.endpointId && !payload.userId) return;

  const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL;
  const supabaseApiKey =
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    process.env.VITE_SUPABASE_ANON_KEY;
  if (!supabaseUrl || !supabaseApiKey) return;

  const supabase = createClient(supabaseUrl, supabaseApiKey);
  const actionTaken =
    payload.status === 'danger' ? 'Blocked' : payload.status === 'warning' ? 'Warned' : 'Passed';

  const baseInsert = {
    endpoint_id: payload.endpointId,
    url: payload.url,
    status: payload.status,
    confidence: payload.confidence,
    model_used: payload.modelUsed,
    action_taken: actionTaken,
  };

  if (payload.userId) {
    const withUser = { ...baseInsert, user_id: payload.userId };
    const withUserRes = await supabase.from('scan_logs').insert(withUser);
    if (!withUserRes.error) return;
    console.error('[check-url] Failed to insert user-linked scan log:', withUserRes.error.message);
  }

  const fallbackRes = await supabase.from('scan_logs').insert(baseInsert);
  if (fallbackRes.error) {
    console.error('[check-url] Failed to insert scan log:', fallbackRes.error.message);
  }
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // CORS headers – allow extension and portal to call this
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { url } = req.body || {};
  
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid "url" field' });
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url.startsWith('http') ? url : `https://${url}`);
  } catch {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  const startTime = Date.now();
  const endpointId = typeof req.body?.endpoint_id === 'string' ? req.body.endpoint_id : undefined;
  const userId = typeof req.body?.user_id === 'string' ? req.body.user_id : undefined;

  const quickVerdict = getQuickVerdict(parsedUrl);
  if (quickVerdict.status !== 'unknown') {
    const sslStatus = parsedUrl.protocol === 'https:' ? 'safe' : 'danger';
    const quickStatus = quickVerdict.status as ScanStatus;
    await logScanToSupabase({
      endpointId,
      userId,
      url: parsedUrl.href,
      status: quickStatus,
      confidence: quickVerdict.confidence,
      modelUsed: quickVerdict.modelUsed,
    });

    return res.status(200).json({
      url: parsedUrl.href,
      status: quickStatus,
      label: quickVerdict.label,
      confidence: quickVerdict.confidence,
      phishingProbability: quickVerdict.phishingProbability,
      legitimateProbability: quickVerdict.legitimateProbability,
      inferenceTimeMs: 0,
      totalTimeMs: Date.now() - startTime,
      modelUsed: quickVerdict.modelUsed,
      ssl: {
        status: sslStatus,
        text: parsedUrl.protocol === 'https:' ? 'HTTPS – Trusted domain check passed' : 'HTTP – Unencrypted',
      },
      timestamp: new Date().toISOString(),
      reason: quickVerdict.reason,
    });
  }

  try {
    const hfResponse = await fetch(HF_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: parsedUrl.href }),
      signal: AbortSignal.timeout(20000),
    });

    if (!hfResponse.ok) {
      throw new Error(`HF API responded with ${hfResponse.status}`);
    }

    const hfData = await hfResponse.json();
    const totalTime = Date.now() - startTime;

    // --- Strong SSL/TLS Validation ---
    const sslDetails = parsedUrl.protocol === 'https:' ? await checkStrongSSL(parsedUrl.hostname) : { valid: false, issuer: 'None', isFreeCA: true, ageDays: 0 };
    
    let sslRiskScore = 0;
    if (parsedUrl.protocol !== 'https:') {
      sslRiskScore += 0.4;
    } else {
      if (!sslDetails.valid) sslRiskScore += 0.45;
      if (sslDetails.ageDays < 7) sslRiskScore += 0.2;
    }

    // Override Model strictness based on TLS characteristics
    let finalPhishingProb = Math.min(1, Math.max(0, (hfData.phishing_probability ?? 0) + sslRiskScore));
    
    let status: 'safe' | 'warning' | 'danger';
    if (finalPhishingProb > 0.85) {
      status = 'danger';
    } else if (finalPhishingProb > 0.50) {
      status = 'warning';
    } else {
      status = 'safe';
    }
    // --- External Integrations: VirusTotal & Google Safe Browsing ---
    // Objective 4 Integration: These run if environment API keys are available in Vercel.
    let externalRiskFlags = 0;
    
    // 1. Google Safe Browsing
    if (process.env.GOOGLE_SAFE_BROWSING_API_KEY) {
      try {
        const gsbUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_API_KEY}`;
        const gsbRes = await fetch(gsbUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client: { clientId: "safebrowse-extension", clientVersion: "1.0.0" },
            threatInfo: {
              threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{ url: parsedUrl.href }]
            }
          })
        });
        const gsbData = await gsbRes.json();
        if (gsbData.matches && gsbData.matches.length > 0) externalRiskFlags++;
      } catch (e) {
        console.error("GSB check failed", e);
      }
    }

    // 2. VirusTotal (Requires base64 encoding of URL for v3 API)
    if (process.env.VIRUSTOTAL_API_KEY) {
      try {
        const vtUrlId = Buffer.from(parsedUrl.href).toString('base64').replace(/=/g, '');
        const vtRes = await fetch(`https://www.virustotal.com/api/v3/urls/${vtUrlId}`, {
          headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
        });
        if (vtRes.ok) {
          const vtData = await vtRes.json();
          const maliciousVotes = vtData.data?.attributes?.last_analysis_stats?.malicious || 0;
          if (maliciousVotes > 0) externalRiskFlags++;
        }
      } catch (e) {
        console.error("VT check failed", e);
      }
    }

    // Adjust status if external APIs flag the URL
    if (externalRiskFlags > 0 && status !== 'danger') {
      status = 'danger'; // Override Model output if GSB/VT flags it
    }
    // ---------------------------------------------------------------

    await logScanToSupabase({
      endpointId,
      userId,
      url: parsedUrl.href,
      status,
      confidence: hfData.confidence,
      modelUsed: hfData.model_used || 'ModernBERT Ensemble',
    });

    return res.status(200).json({
      url: parsedUrl.href,
      status,
      label: hfData.label,
      confidence: hfData.confidence,
      phishingProbability: finalPhishingProb,
      legitimateProbability: hfData.legitimate_probability,
      inferenceTimeMs: hfData.inference_time_ms,
      totalTimeMs: totalTime,
      modelUsed: hfData.model_used || 'ModernBERT',
      ssl: {
        status: parsedUrl.protocol !== 'https:' ? 'danger' : sslRiskScore >= 0.5 ? 'danger' : sslRiskScore > 0 ? 'warning' : 'safe',
        text: parsedUrl.protocol === 'https:' ? `HTTPS (Issuer: ${sslDetails.issuer}, Age: ${Math.round(sslDetails.ageDays)}d)` : 'HTTP – Unencrypted'
      },
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    console.error('[check-url] Error:', error);
    const message = error instanceof Error ? error.message : 'Unknown error';
    return res.status(502).json({
      error: 'Failed to reach AI model',
      detail: message,
      url: parsedUrl.href,
    });
  }
}
