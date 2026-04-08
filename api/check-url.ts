// Vercel Serverless Function: /api/check-url
// Unified endpoint: calls HF ModernBERT API and returns phishing verdict.
import type { VercelRequest, VercelResponse } from '@vercel/node';
import { createClient } from '@supabase/supabase-js';
import tls from 'tls';

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
      if (!sslDetails.valid) sslRiskScore += 0.5;
      if (sslDetails.isFreeCA) sslRiskScore += 0.25;
      if (sslDetails.ageDays < 30) sslRiskScore += 0.35; // Young certs are highly suspicious for phishing
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

    // --- SUPABASE DATABASE LOGGING ---
    // Objective 8: Log anonymous endpoint scans to the global Threat Intelligence Database
    const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL;
    const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY;
    if (supabaseUrl && supabaseAnonKey && endpointId) {
      try {
        const supabase = createClient(supabaseUrl, supabaseAnonKey);
        
        await supabase.from('scan_logs').insert({
          endpoint_id: endpointId,
          url: parsedUrl.href,
          status: status,
          confidence: hfData.confidence,
          model_used: hfData.model_used || 'ModernBERT Ensemble',
          action_taken: status === 'danger' ? 'Blocked' : status === 'warning' ? 'Warned' : 'Passed'
        });
      } catch (e) {
        console.error('Failed to log to Supabase:', e);
      }
    }
    // ---------------------------------

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
