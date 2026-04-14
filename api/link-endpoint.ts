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
  const authHeader = typeof req.headers.authorization === 'string' ? req.headers.authorization : '';
  const accessToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

  if (!endpointId || !userId) {
    return res.status(400).json({ error: 'endpointId and userId are required' });
  }

  const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const anonKey = process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY;

  if (!supabaseUrl || (!serviceRoleKey && !anonKey)) {
    return res.status(500).json({ error: 'Supabase environment is not configured correctly' });
  }

  let supabase;
  if (serviceRoleKey) {
    supabase = createClient(supabaseUrl, serviceRoleKey);
  } else {
    if (!anonKey || !accessToken) {
      return res.status(401).json({ error: 'Authentication token is required to link endpoint' });
    }
    supabase = createClient(supabaseUrl, anonKey, {
      global: {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
    });

    const userResult = await supabase.auth.getUser();
    const callerUserId = userResult.data.user?.id;
    if (userResult.error || !callerUserId || callerUserId !== userId) {
      return res.status(403).json({ error: 'Invalid user token for requested userId' });
    }
  }

  let ownerLinked = false;

  const ownerResult = await supabase.from('browser_endpoint_owners').upsert(
    {
      endpoint_id: endpointId,
      user_id: userId,
      device_name: 'Linked via user portal',
    },
    { onConflict: 'endpoint_id' }
  );

  if (ownerResult.error) {
    return res.status(500).json({
      error: 'Failed to link endpoint ownership',
      detail: ownerResult.error.message,
    });
  }
  ownerLinked = true;

  const updateResult = await supabase
    .from('browser_scan_logs')
    .update({ user_id: userId })
    .eq('endpoint_id', endpointId)
    .or(`user_id.is.null,user_id.eq.${userId}`)
    .select('id');

  if (updateResult.error) {
    return res.status(500).json({
      error: 'Failed to link scan logs to this user',
      detail: updateResult.error.message,
    });
  }

  return res.status(200).json({
    success: true,
    endpointId,
    ownerLinked,
    linkedScanCount: updateResult.data?.length || 0,
  });
}
