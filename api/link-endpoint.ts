import type { VercelRequest, VercelResponse } from '@vercel/node';
import { createClient } from '@supabase/supabase-js';

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const endpointId = typeof req.body?.endpointId === 'string' ? req.body.endpointId.trim() : '';
  const userId = typeof req.body?.userId === 'string' ? req.body.userId.trim() : '';

  if (!endpointId || !userId) {
    return res.status(400).json({ error: 'endpointId and userId are required' });
  }

  const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL;
  const supabaseKey =
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    process.env.VITE_SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseKey) {
    return res.status(500).json({ error: 'Supabase environment is not configured correctly' });
  }

  const supabase = createClient(supabaseUrl, supabaseKey);

  let ownerLinked = false;
  let ownerWarning = '';

  const ownerResult = await supabase.from('endpoint_owners').upsert(
    {
      endpoint_id: endpointId,
      user_id: userId,
      device_name: 'Linked via user portal',
    },
    { onConflict: 'endpoint_id' }
  );

  if (ownerResult.error) {
    ownerWarning = ownerResult.error.message;
  } else {
    ownerLinked = true;
  }

  const updateResult = await supabase
    .from('scan_logs')
    .update({ user_id: userId })
    .eq('endpoint_id', endpointId)
    .or(`user_id.is.null,user_id.eq.${userId}`)
    .select('id');

  if (updateResult.error) {
    return res.status(500).json({
      error: 'Failed to link scan logs to this user',
      detail: updateResult.error.message,
      ownerWarning,
    });
  }

  return res.status(200).json({
    success: true,
    endpointId,
    ownerLinked,
    ownerWarning,
    linkedScanCount: updateResult.data?.length || 0,
  });
}
