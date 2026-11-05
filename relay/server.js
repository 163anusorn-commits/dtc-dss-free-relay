import http from 'node:http';
import { createHmac, createPublicKey, timingSafeEqual, verify } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { resolveCloudVehicle } from '../src/cloud-dss.js';

export function createRelayServer(env = process.env, lookup = resolveCloudVehicle) {
  const usedNonces = new Map();
  let running = 0;
  return http.createServer(async (req, res) => {
    const reply = (status, value) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(value)); };
    if (req.method === 'GET' && req.url === '/health') return reply(200, { success: true, service: 'dtc-dss-free-relay', release: '1.0.1' });
    if (req.method !== 'POST' || req.url !== '/lookup') return reply(404, { code: 'NOT_FOUND' });
    const secret = String(env.DSS_RELAY_SHARED_SECRET || '');
    const publicJwk = String(env.DSS_RELAY_PUBLIC_JWK || '');
    if (!publicJwk && secret.length < 32) return reply(503, { code: 'RELAY_NOT_CONFIGURED' });
    let raw = '';
    try {
      const chunks = []; let size = 0;
      for await (const chunk of req) { chunks.push(chunk); size += chunk.length; if (size > 4096) return reply(413, { code: 'REQUEST_TOO_LARGE' }); }
      raw = Buffer.concat(chunks).toString('utf8');
      const provided = String(req.headers['x-service-signature'] || '');
      let authenticated = false;
      if (publicJwk) {
        const publicKey = createPublicKey({ key: JSON.parse(publicJwk), format: 'jwk' });
        authenticated = verify('sha256', Buffer.from(raw), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(provided, 'base64url'));
      } else {
        const expected = createHmac('sha256', secret).update(raw).digest('base64url');
        authenticated = provided.length === expected.length && timingSafeEqual(Buffer.from(expected), Buffer.from(provided));
      }
      if (!authenticated) return reply(401, { code: 'UNAUTHORIZED' });
      const data = JSON.parse(raw);
      if (!Number.isFinite(data.timestamp) || Math.abs(Date.now() / 1000 - data.timestamp) > 300 || !/^[a-f0-9-]{20,80}$/i.test(String(data.nonce || ''))) return reply(401, { code: 'REQUEST_EXPIRED' });
      const now = Date.now();
      for (const [nonce, expiry] of usedNonces) if (expiry < now) usedNonces.delete(nonce);
      if (usedNonces.has(data.nonce)) return reply(409, { code: 'REPLAY_DETECTED' });
      if (running >= 2) return reply(429, { code: 'RELAY_BUSY' });
      usedNonces.set(data.nonce, now + 600000);
      running++;
      try { return reply(200, { success: true, vehicle: await lookup(env, data.request || {}) }); }
      catch (error) { return reply(502, { success: false, code: String(error.code || 'DSS_LOOKUP_FAILED'), stage: error.stage || '', transportCode: error.transportCode || '',
        ...(error.code==='DSS_PLATE_CONFIRMATION_REQUIRED'?{identityConflict:error.identityConflict}:{}) }); }
      finally { running--; }
    } catch { return reply(400, { code: 'INVALID_REQUEST' }); }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = createRelayServer();
  server.requestTimeout = 180000;
  server.listen(Number(process.env.PORT || 10000), '0.0.0.0', () => console.log('DSS relay ready'));
}
