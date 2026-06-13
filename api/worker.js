/**
 * DS-160 美签项目 - Cloudflare Worker API
 * 
 * 处理一次性链接的创建、验证、消耗
 * 部署: npx wrangler deploy
 */

// ═════════════ 配置 ═════════════
const SECRET = 'ds160-secret-key-2026';
const ADMIN_PASSWORD = 'ds160admin';

// ═════════════ HMAC 签名 ═════════════
async function hmacSign(message, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function hmacVerify(message, signature, secret) {
  const expected = await hmacSign(message, secret);
  return expected === signature;
}

function generateToken() {
  const id = crypto.randomUUID().slice(0, 8);
  const ts = Date.now();
  return { id, ts };
}

// ═════════════ CORS ═════════════
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
  });
}

// ═════════════ API ═════════════
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS 预检
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    // ── POST /api/create ──
    if (path === '/api/create' && request.method === 'POST') {
      try {
        const body = await request.json();
        // 验证管理员密码
        if (body.password !== ADMIN_PASSWORD) {
          return json({ error: '密码错误' }, 403);
        }
        
        const count = body.count || 1;
        const label = body.label || '';
        const tokens = [];

        for (let i = 0; i < count; i++) {
          const { id, ts } = generateToken();
          const payload = `${id}.${ts}`;
          const sig = await hmacSign(payload, SECRET);
          const token = `${id}.${ts}.${sig}`;
          
          // 存入 KV
          await env.TOKENS.put(id, JSON.stringify({
            token,
            ts,
            label,
            used: false,
            usedAt: null,
            createdAt: new Date().toISOString(),
          }));

          tokens.push({ token, id, label });
        }

        return json({ success: true, tokens });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── GET /api/check?token=xxx ──
    if (path === '/api/check' && request.method === 'GET') {
      const token = url.searchParams.get('token');
      if (!token) return json({ valid: false, reason: 'no token' }, 400);

      const parts = token.split('.');
      if (parts.length !== 3) return json({ valid: false, reason: 'invalid format' });

      const [id, ts, sig] = parts;
      
      // 验证签名
      const payload = `${id}.${ts}`;
      const valid = await hmacVerify(payload, sig, SECRET);
      if (!valid) return json({ valid: false, reason: 'signature mismatch' });

      // 检查是否已使用
      const record = await env.TOKENS.get(id, 'json');
      if (!record) return json({ valid: false, reason: 'not found' });
      if (record.used) return json({ valid: false, reason: 'already used' });

      return json({ valid: true, id, label: record.label });
    }

    // ── POST /api/consume ──
    if (path === '/api/consume' && request.method === 'POST') {
      try {
        const body = await request.json();
        const token = body.token;
        if (!token) return json({ error: 'no token' }, 400);

        const parts = token.split('.');
        if (parts.length !== 3) return json({ error: 'invalid token' }, 400);
        
        const id = parts[0];
        const record = await env.TOKENS.get(id, 'json');
        if (!record) return json({ error: 'not found' }, 404);
        
        // 标记为已使用
        record.used = true;
        record.usedAt = new Date().toISOString();
        await env.TOKENS.put(id, JSON.stringify(record));

        return json({ success: true });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── GET /api/tokens ── (查看所有 token，管理用)
    if (path === '/api/tokens' && request.method === 'GET') {
      const pwd = url.searchParams.get('password');
      if (pwd !== ADMIN_PASSWORD) return json({ error: 'unauthorized' }, 403);
      
      const list = await env.TOKENS.list();
      const tokens = [];
      for (const key of list.keys) {
        const record = await env.TOKENS.get(key.name, 'json');
        tokens.push(record);
      }
      return json({ tokens });
    }

    return json({ error: 'not found' }, 404);
  },
};
