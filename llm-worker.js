/**
 * ДОЗВОН · прокси к нейросети (Cloudflare Worker)
 * ---------------------------------------------------------------------------
 * Зачем он нужен. Ключ нельзя класть в код страницы: страницу видит весь
 * интернет, и любой сможет тратить вашу квоту. Поэтому ключ лежит в
 * зашифрованных секретах этого воркера, а браузер стучится не напрямую
 * в Google, а сюда — и передаёт кодовое слово.
 *
 * Три кармана квоты, чтобы тренажёр не останавливался:
 *   1. Gemini (основной) — нужен ключ GEMINI_API_KEY;
 *   2. Workers AI (резерв) — модель Cloudflare, ключ не нужен,
 *      бесплатно 10 000 нейронов в сутки, хватает примерно на 150–400 реплик;
 *   3. Кэш (если подключили KV) — одна и та же ситуация больше не тратит квоту.
 * Если не ответил никто — тренажёр берёт реплику из сценария. Это не ошибка.
 *
 * Секреты (Settings → Variables and Secrets):
 *   GEMINI_API_KEY  (Encrypt) ключ Gemini
 *   GEMINI_MODEL    (Text)    модель, например gemini-3.5-flash-lite
 *   DOZVON_TOKEN    (Encrypt) кодовое слово из сборки
 *   ALLOWED_ORIGIN  (Text)    например https://elena.github.io
 *   CF_AI_MODEL     (Text)    резерв: @cf/meta/llama-3.1-8b-instruct
 *   GEMINI_THINKING (Text)    не задаём: «размышление» только тратит квоту
 *
 * Биндинги (Settings → Bindings):
 *   AI    → Workers AI       (для резерва, имя обязательно AI)
 *   CACHE → KV namespace     (для кэша, имя обязательно CACHE)
 */

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';

    /* ---- CORS: пускаем только свой сайт -------------------------------- */
    const allowed = [env.ALLOWED_ORIGIN, 'http://localhost:8000', 'null'].filter(Boolean);
    const corsHeaders = {
      'Access-Control-Allow-Origin': allowed.includes(origin) ? origin : (allowed[0] || '*'),
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Dozvon-Token',
      'Access-Control-Max-Age': '86400'
    };
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });

    const path = new URL(request.url).pathname.replace(/\/+$/, '');

    /* ---- Проверка «жив ли»: открыли адрес в браузере -------------------- */
    if (request.method === 'GET') {
      if (path === '' || path === '/llm/turn') {
        return json({
          ok: true, service: 'dozvon-llm',
          hint: 'Воркер на связи. Сюда нужно отправлять POST /llm/turn с заголовком X-Dozvon-Token.',
          expect: { method: 'POST', path: '/llm/turn', headers: ['Content-Type', 'X-Dozvon-Token'] },
          tokenSet: !!env.DOZVON_TOKEN,
          keySet: !!env.GEMINI_API_KEY,
          model: env.GEMINI_MODEL || 'gemini-3.5-flash-lite',
          reserve: env.CF_AI_MODEL || '(не задан)',
          cache: env.CACHE ? 'подключён' : 'не подключён',
          allowedOrigin: env.ALLOWED_ORIGIN || '(не задан)'
        }, 200, corsHeaders);
      }
      return json({ error: 'not found', hint: 'Правильный путь — /llm/turn', got: path }, 404, corsHeaders);
    }

    if (request.method !== 'POST' || path !== '/llm/turn') {
      return json({ error: 'not found', hint: 'Нужен POST на /llm/turn', got: request.method + ' ' + path }, 404, corsHeaders);
    }
    /* Пустой Origin — это curl или сервер, не браузер: пускаем */
    if (origin && !allowed.includes(origin)) {
      return json({ error: 'origin not allowed', got: origin, allowed }, 403, corsHeaders);
    }

    /* ---- кодовое слово --------------------------------------------------- */
    const token = request.headers.get('X-Dozvon-Token') || '';
    if (!env.DOZVON_TOKEN || token !== env.DOZVON_TOKEN) {
      return json({
        error: 'forbidden',
        hint: env.DOZVON_TOKEN ? 'Неверное кодовое слово в заголовке X-Dozvon-Token'
          : 'Секрет DOZVON_TOKEN не задан: Settings → Variables and Secrets'
      }, 403, corsHeaders);
    }

    /* ---- лимит на один адрес -------------------------------------------- */
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (hitLimit(ip)) return json({ error: 'too many requests', hint: 'Больше 30 запросов в минуту с одного адреса' }, 429, corsHeaders);

    let payload;
    try { payload = await request.json(); } catch (e) { return json({ error: 'bad json', hint: 'Тело запроса должно быть JSON' }, 400, corsHeaders); }

    const system = payload.system || '';
    const text = payload.prompt || payload.text ||
      (Array.isArray(payload.messages) ? payload.messages.map(m => m.text || m.content || '').join('\n') : '');
    if (!text) return json({ error: 'empty prompt', hint: 'Нужно поле prompt или messages' }, 400, corsHeaders);

    /* ---- кэш: та же ситуация — не тратим квоту второй раз ---------------- */
    const key = env.CACHE ? ('r:' + await sha256(system + '|' + text)) : '';
    if (key) {
      try {
        const hit = await env.CACHE.get(key, 'json');
        if (hit && hit.text) return json({ ok: true, text: hit.text, model: hit.model, usage: hit.usage, cached: true }, 200, corsHeaders);
      } catch (e) { /* кэш — удобство, не необходимость */ }
    }

    /* ---- основной провайдер, потом резерв ------------------------------- */
    let out = null, why = [];

    if (env.GEMINI_API_KEY) {
      out = await askGemini(env, system, text, why);
    } else {
      why.push('не задан GEMINI_API_KEY');
    }

    if (!out && env.AI && env.CF_AI_MODEL) {
      out = await askWorkersAI(env, system, text, why);
    }

    if (!out) {
      return json({
        error: 'no provider',
        hint: 'Ни один провайдер не ответил. Тренажёр возьмёт реплику из сценария — это штатная ситуация.',
        detail: why
      }, 502, corsHeaders);
    }

    if (key) {
      try { await env.CACHE.put(key, JSON.stringify(out), { expirationTtl: 60 * 60 * 24 * 30 }); } catch (e) {}
    }
    return json({ ok: true, text: out.text, model: out.model, usage: out.usage, cached: false }, 200, corsHeaders);
  }
};

/* ================= ГЕМИНИ =============================================== */
async function askGemini(env, system, text, why) {
  const model = env.GEMINI_MODEL || 'gemini-3.5-flash-lite';
  const call = () => fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${env.GEMINI_API_KEY}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        system_instruction: system ? { parts: [{ text: system }] } : undefined,
        contents: [{ role: 'user', parts: [{ text }] }],
        generationConfig: {
          temperature: 0.7,
          /* 500 было мало: модель с «размышлением» не дописывала реплику */
          maxOutputTokens: 1500,
          ...(env.GEMINI_THINKING ? { thinkingConfig: { thinkingLevel: env.GEMINI_THINKING } } : {})
        }
      })
    });

  try {
    let r = await call();
    /* 429 — кончилась дневная квота; 5xx — модель перегружена.
       Один повтор через паузу часто выручает, но лимит он не отменяет. */
    if (!r.ok && (r.status === 429 || r.status >= 500)) {
      await new Promise(res => setTimeout(res, 2500));
      r = await call();
    }
    const data = await r.json();
    if (!r.ok) {
      why.push('gemini http ' + r.status + (data && data.error ? ': ' + data.error.message : ''));
      return null;
    }
    const reply = data?.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('') || '';
    const u = data.usageMetadata || {};
    return {
      text: reply, model,
      usage: {
        input: u.promptTokenCount || 0,
        output: u.candidatesTokenCount || 0,
        total: u.totalTokenCount || (u.promptTokenCount || 0) + (u.candidatesTokenCount || 0)
      }
    };
  } catch (e) {
    why.push('gemini: ' + String(e));
    return null;
  }
}

/* ================= РЕЗЕРВ: WORKERS AI (ключ не нужен) ==================== */
async function askWorkersAI(env, system, text, why) {
  try {
    const res = await env.AI.run(env.CF_AI_MODEL, {
      messages: [
        ...(system ? [{ role: 'system', content: system }] : []),
        { role: 'user', content: text }
      ],
      max_tokens: 300,
      temperature: 0.7
    });
    const reply = (res && (res.response || (res.result && res.result.response))) || '';
    if (!reply) { why.push('workers ai: пустой ответ'); return null; }
    const u = res.usage || {};
    return {
      text: reply, model: env.CF_AI_MODEL,
      usage: {
        input: u.prompt_tokens || 0,
        output: u.completion_tokens || 0,
        total: u.total_tokens || 0
      }
    };
  } catch (e) {
    why.push('workers ai: ' + String(e));
    return null;
  }
}

/* ================= МЕЛОЧИ =============================================== */
function json(obj, status, headers) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...(headers || {}) }
  });
}

async function sha256(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

/* Счётчик: до 30 запросов в минуту с одного адреса */
const HITS = new Map();
function hitLimit(ip) {
  const now = Date.now(), key = ip + ':' + Math.floor(now / 60000);
  const n = (HITS.get(key) || 0) + 1;
  HITS.set(key, n);
  if (HITS.size > 5000) HITS.clear();
  return n > 30;
}

/* ---------------------------------------------------------------------------
   ПРОВЕРКА

   Шаг 1. Открыть в браузере: https://dozvon-llm.<поддомен>.workers.dev/llm/turn
     Ждём ok, service, tokenSet, keySet, model, reserve, cache.

   Шаг 2. Настоящий запрос (Linux, macOS, PowerShell 7):
     curl -X POST https://dozvon-llm.<поддомен>.workers.dev/llm/turn \
          -H "Content-Type: application/json" \
          -H "X-Dozvon-Token: ВАШЕ_КОДОВОЕ_СЛОВО" \
          -d '{"prompt":"Скажи коротко: тренажёр работает"}'
     Ждём {"ok":true,"text":"...","model":"...","usage":{"total":123},"cached":false}

   Windows, командная строка (одинарные кавычки не работают):
     curl -X POST https://dozvon-llm.<поддомен>.workers.dev/llm/turn -H "Content-Type: application/json" -H "X-Dozvon-Token: ВАШЕ_КОДОВОЕ_СЛОВО" -d "{\"prompt\":\"Скажи коротко: тренажёр работает\"}"

   Что значит какой ответ:
     {"ok":true,...}            — работает
     {"error":"not found"}      — не тот путь или не POST
     {"error":"forbidden"}      — неверное кодовое слово или не задан DOZVON_TOKEN
     {"error":"origin not allowed"} — запрос с чужого сайта
     {"error":"no provider"}    — кончилась квота у всех провайдеров: тренажёр
                                  берёт реплику из сценария, это штатно
--------------------------------------------------------------------------- */

