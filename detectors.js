/* Hide My PII: detection engine. Pure functions, runs fully on-device. */
(() => {
  'use strict';

  const CATEGORIES = {
    secrets:   { label: 'Secrets and keys',        hint: 'API keys, tokens, passwords, private keys, seed phrases' },
    pii:       { label: 'Personal data',           hint: 'Emails, phone numbers, tax IDs, birth dates, IPs' },
    financial: { label: 'Financial details',       hint: 'Card numbers, IBANs, SSNs' },
    injection: { label: 'Suspicious instructions', hint: 'Prompt-injection phrases and hidden characters' }
  };

  const DEFAULTS = {
    enabled: true,
    highlight: true,
    categories: { secrets: true, pii: true, financial: true, injection: true }
  };

  const mergeSettings = (s = {}) => ({
    ...DEFAULTS,
    ...s,
    categories: { ...DEFAULTS.categories, ...(s.categories || {}) }
  });

  /* ---------- validators ---------- */
  const digits = (s) => s.replace(/\D/g, '');

  const luhn = (s) => {
    const d = digits(s);
    if (d.length < 13 || d.length > 19 || /^(\d)\1+$/.test(d)) return false;
    let sum = 0, alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let n = +d[i];
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  };

  const iban = (s) => {
    const v = s.replace(/\s+/g, '').toUpperCase();
    if (v.length < 15 || v.length > 34) return false;
    const r = v.slice(4) + v.slice(0, 4);
    let rem = 0;
    for (const ch of r) {
      const c = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
      for (const d of c) rem = (rem * 10 + +d) % 97;
    }
    return rem === 1;
  };

  // Portuguese NIF checksum
  const nif = (s) => {
    const d = digits(s);
    if (d.length !== 9 || !/^[1235689]/.test(d)) return false;
    let sum = 0;
    for (let i = 0; i < 8; i++) sum += +d[i] * (9 - i);
    let chk = 11 - (sum % 11);
    if (chk >= 10) chk = 0;
    return chk === +d[8];
  };

  const phone = (s) => {
    const d = digits(s);
    if (d.length < 9 || d.length > 15) return false;
    if (!s.startsWith('+') && !/[\s.\-()]/.test(s)) return false;
    return true;
  };

  const notPlaceholder = (v) =>
    !/^(?:x+|\*+|\.+|<.*>|\{.*\}|your[_-]|example|changeme|null|none|true|false|undefined|process\.env)/i.test(v);

  /* ---------- rules (earlier = higher priority when matches overlap) ---------- */
  const rule = (cat, label, tag, sev, re, extra = {}) => ({ cat, label, tag, sev, re, ...extra });

  const RULES = [
    // secrets
    rule('secrets', 'Private key', 'PRIVATE_KEY', 'high', /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/gd),
    rule('secrets', 'Wallet seed phrase', 'SEED_PHRASE', 'high',
      /\b(?:seed\s*phrase|mnemonic|recovery\s*phrase|secret\s*recovery\s*phrase)\b\s*(?:is|:|=|-)?\s*((?:(?:[a-z]{3,8}[ \t]+){23}|(?:[a-z]{3,8}[ \t]+){11})[a-z]{3,8})\b/gdi, { group: 1 }),
    rule('secrets', 'AI API key', 'API_KEY', 'high', /\bsk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/gd),
    rule('secrets', 'AWS access key', 'AWS_KEY', 'high', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/gd),
    rule('secrets', 'GitHub token', 'GITHUB_TOKEN', 'high', /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b/gd),
    rule('secrets', 'Google API key', 'API_KEY', 'high', /\bAIza[0-9A-Za-z_-]{35}\b/gd),
    rule('secrets', 'Slack token', 'SLACK_TOKEN', 'high', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/gd),
    rule('secrets', 'Stripe key', 'API_KEY', 'high', /\b[sr]k_(?:live|test)_[0-9a-zA-Z]{16,}\b/gd),
    rule('secrets', 'JSON web token', 'JWT', 'high', /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gd),
    rule('secrets', 'Bearer token', 'TOKEN', 'high', /\bBearer\s+([A-Za-z0-9._~+/-]{20,}={0,2})/gd, { group: 1 }),
    rule('secrets', 'Password in URL', 'PASSWORD', 'high', /\b[a-z][a-z0-9+.-]{1,15}:\/\/[^\s:@/]+:([^\s@/]+)@[^\s]+/gdi, { group: 1 }),
    rule('secrets', 'Wallet private key', 'PRIVATE_KEY', 'high', /\b0x[a-fA-F0-9]{64}\b/gd),
    rule('secrets', 'Password or secret', 'PASSWORD', 'high',
      /\b(?:pass(?:word|wd|code|phrase)?|pwd|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|private[_-]?key)\b["']?\s*[:=]\s*["']?([^\s"'`,;]{6,})/gdi,
      { group: 1, validate: notPlaceholder }),
    rule('secrets', 'Password or secret', 'PASSWORD', 'high',
      /\b(?:password|passcode|passphrase|pin)\s+(?:is|was|=|:)\s+["']?([^\s"',;]{4,})/gdi,
      { group: 1, validate: notPlaceholder }),

    // financial
    rule('financial', 'Credit card number', 'CARD', 'high', /(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])/gd, { validate: luhn }),
    rule('financial', 'US Social Security number', 'SSN', 'high', /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/gd),
    rule('financial', 'IBAN', 'IBAN', 'high', /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/gd, { validate: iban }),

    // personal data
    rule('pii', 'Email address', 'EMAIL', 'med', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/gd),
    rule('pii', 'Tax ID (NIF)', 'TAX_ID', 'med', /\b(?:nif|nipc|tax\s*id|vat)\s*(?:number|no\.?|#)?\s*[:\-]?\s*(\d{9})\b/gdi, { group: 1, validate: nif }),
    rule('pii', 'Date of birth', 'DOB', 'med', /\b(?:dob|date\s+of\s+birth|born\s+on)\b\s*[:\-]?\s*(\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4})/gdi, { group: 1 }),
    rule('pii', 'IP address', 'IP', 'low', /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/gd),
    rule('pii', 'Wallet address', 'WALLET', 'low', /\b0x[a-fA-F0-9]{40}\b/gd),
    rule('pii', 'Phone number', 'PHONE', 'med', /(?<![\w@.])\+?\(?\d[\d\s().-]{7,18}\d(?![\w@])/gd, { validate: phone }),

    // suspicious instructions (warn only, never rewritten)
    rule('injection', 'Hidden characters', '', 'low', /(?:[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]|[\u{E0000}-\u{E007F}])+/gdu),
    rule('injection', 'Suspicious instruction', 'INSTRUCTION', 'low',
      /\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions?|prompts?|rules|messages?)/gdi, { redact: false }),
    rule('injection', 'Suspicious instruction', 'INSTRUCTION', 'low',
      /\byou\s+are\s+now\s+(?:in\s+)?(?:DAN|developer\s+mode|jailbroken|unrestricted)\b/gdi, { redact: false }),
    rule('injection', 'Suspicious instruction', 'INSTRUCTION', 'low',
      /\b(?:reveal|print|show|repeat|leak)\s+(?:me\s+)?(?:your\s+|the\s+)?(?:system\s+prompt|hidden\s+instructions|initial\s+instructions)/gdi, { redact: false }),
    rule('injection', 'Suspicious instruction', 'INSTRUCTION', 'low',
      /<\/?\s*(?:system|instructions?)\s*>|\[\/?INST\]|<\|im_start\|>/gdi, { redact: false })
  ].map((r, i) => ({ ...r, pri: i }));

  /* ---------- scan ---------- */
  function scan(text, enabled) {
    const raw = [];
    for (const r of RULES) {
      if (enabled && enabled[r.cat] === false) continue;
      r.re.lastIndex = 0;
      let m;
      while ((m = r.re.exec(text))) {
        if (m[0] === '') { r.re.lastIndex++; continue; }
        let start = m.index, end = m.index + m[0].length;
        if (r.group) {
          const ix = m.indices && m.indices[r.group];
          if (!ix) continue;
          [start, end] = ix;
        }
        const value = text.slice(start, end);
        if (r.validate && !r.validate(value, m)) continue;
        raw.push({ start, end, value, cat: r.cat, label: r.label, tag: r.tag, sev: r.sev, redact: r.redact, pri: r.pri });
      }
    }
    raw.sort((a, b) => a.pri - b.pri || (b.end - b.start) - (a.end - a.start));
    const kept = [];
    for (const f of raw) if (!kept.some((k) => f.start < k.end && f.end > k.start)) kept.push(f);
    kept.sort((a, b) => a.start - b.start);
    kept.forEach((f, i) => (f.id = i));
    return kept;
  }

  /* ---------- redact ---------- */
  // Returns { text, parts: [{ t, redacted }] }. `selected` is a Set of finding ids (null = all redactable).
  function redact(text, findings, selected = null) {
    const counters = {}, seen = {};
    const parts = [];
    let last = 0;
    const push = (t, redacted) => { if (t) parts.push({ t, redacted }); };
    for (const f of findings) {
      if (f.redact === false || (selected && !selected.has(f.id))) continue;
      push(text.slice(last, f.start), false);
      if (f.tag) {
        const key = f.tag + '|' + f.value;
        if (!seen[key]) { counters[f.tag] = (counters[f.tag] || 0) + 1; seen[key] = counters[f.tag]; }
        push(`[${f.tag}_${seen[key]}]`, true);
      }
      last = f.end;
    }
    push(text.slice(last), false);
    return { text: parts.map((p) => p.t).join(''), parts };
  }

  const mask = (v) => {
    const one = v.split('\n')[0];
    if (one.length <= 4) return '•'.repeat(one.length);
    const keep = one.length > 12 ? 3 : 2;
    return one.slice(0, keep) + '•'.repeat(Math.min(8, one.length - keep - 1)) + one.slice(-1);
  };

  /* ---------- the "no" emoji (original artwork, finger-wag) ---------- */
  function emojiSVG(uid = 'x') {
    return `
<svg viewBox="0 0 232 212" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" focusable="false">
  <defs>
    <radialGradient id="f-${uid}" cx="35%" cy="25%" r="85%">
      <stop offset="0" stop-color="#FFF6B0"/><stop offset=".42" stop-color="#FFD93B"/><stop offset="1" stop-color="#EFA22C"/>
    </radialGradient>
    <linearGradient id="h-${uid}" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#FFE57A"/><stop offset="1" stop-color="#F2A93A"/>
    </linearGradient>
  </defs>
  <ellipse cx="108" cy="202" rx="64" ry="7" fill="#1B1630" opacity=".12"/>
  <g class="face">
    <circle cx="100" cy="106" r="84" fill="url(#f-${uid})" stroke="#E39A26" stroke-width="2.5"/>
    <ellipse cx="66" cy="50" rx="34" ry="14" fill="#fff" opacity=".34" transform="rotate(-24 66 50)"/>
    <g stroke="#D9901F" stroke-width="2.5">
      <ellipse cx="68" cy="102" rx="23" ry="19" fill="#fff"/>
      <ellipse cx="132" cy="102" rx="23" ry="19" fill="#fff"/>
    </g>
    <g>
      <circle cx="77" cy="108" r="10" fill="#4FA3E8"/><circle cx="78" cy="109" r="4.2" fill="#14213D"/><circle cx="80" cy="106" r="1.7" fill="#fff"/>
      <circle cx="141" cy="108" r="10" fill="#4FA3E8"/><circle cx="142" cy="109" r="4.2" fill="#14213D"/><circle cx="144" cy="106" r="1.7" fill="#fff"/>
    </g>
    <g fill="#F7C23C" stroke="#D9901F" stroke-width="2.5" stroke-linejoin="round">
      <path d="M45 104 A23 19 0 0 1 91 104 Z"/>
      <path d="M109 104 A23 19 0 0 1 155 104 Z"/>
    </g>
    <g fill="none" stroke="#C47F1A" stroke-width="2" stroke-linecap="round" opacity=".6">
      <path d="M48 121 Q68 131 90 121"/><path d="M112 121 Q132 131 152 121"/>
    </g>
    <g fill="none" stroke="#B56A12" stroke-width="4" stroke-linecap="round">
      <path d="M44 66 Q62 56 84 62"/><path d="M116 50 Q136 42 156 58"/>
    </g>
    <path d="M66 148 Q82 135 100 146" fill="none" stroke="#B56A12" stroke-width="3.5" stroke-linecap="round"/>
  </g>
  <g class="finger">
    <rect x="166" y="46" width="30" height="104" rx="15" fill="url(#h-${uid})" stroke="#D9901F" stroke-width="2.5"/>
    <ellipse cx="173" cy="62" rx="4" ry="9" fill="#fff" opacity=".45"/>
    <ellipse cx="178" cy="152" rx="37" ry="32" fill="url(#h-${uid})" stroke="#D9901F" stroke-width="2.5"/>
    <g fill="none" stroke="#D9901F" stroke-width="2.5" stroke-linecap="round">
      <path d="M154 150 Q166 138 178 152"/><path d="M172 162 Q186 150 200 164"/><path d="M160 170 Q170 164 180 172"/>
    </g>
  </g>
</svg>`;
  }

  window.HMP = { CATEGORIES, DEFAULTS, mergeSettings, scan, redact, mask, emojiSVG };
})();
