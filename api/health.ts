// Vercel Serverless Function: /api/health
// Returns health status of the HF ModernBERT API.
// Used by Admin Dashboard "ML Models" tab.

import type { VercelRequest, VercelResponse } from '@vercel/node';

const HF_HEALTH_URL = 'https://alimusarizvi-phishing.hf.space/health';
const HF_API_URL = 'https://alimusarizvi-phishing.hf.space/predict';

export default async function handler(_req: VercelRequest, res: VercelResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (_req.method === 'OPTIONS') return res.status(200).end();

  const start = Date.now();

  // Ping HF health endpoint
  let hfOnline = false;
  let hfLatencyMs = -1;
  try {
    const hfRes = await fetch(HF_HEALTH_URL, { signal: AbortSignal.timeout(8000) });
    hfLatencyMs = Date.now() - start;
    hfOnline = hfRes.ok;
  } catch {
    hfLatencyMs = Date.now() - start;
  }

  // Quick test prediction for latency benchmark
  let sampleInferenceMs = -1;
  if (hfOnline) {
    const t = Date.now();
    try {
      const testRes = await fetch(HF_API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://google.com' }),
        signal: AbortSignal.timeout(10000),
      });
      const testData = await testRes.json();
      sampleInferenceMs = testData.inference_time_ms || (Date.now() - t);
    } catch {
      sampleInferenceMs = Date.now() - t;
    }
  }

  return res.status(200).json({
    modernbert: {
      online: hfOnline,
      latencyMs: hfLatencyMs,
      sampleInferenceMs,
      endpoint: 'https://alimusarizvi-phishing.hf.space',
      model: 'ModernBERT (Fine-tuned on PhishTank + DMOZ)',
    },
    timestamp: new Date().toISOString(),
  });
}
