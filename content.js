/* Hide My PII: content script. Intercepts sends on ChatGPT / Gemini, scans the prompt, shows the review modal. */
(() => {
  'use strict';
  const HMP = window.HMP;
  if (!HMP) return;
  const { scan, redact, mask, emojiSVG, mergeSettings } = HMP;

  const ADAPTERS = [
    {
      name: 'ChatGPT',
      match: /(^|\.)(chatgpt\.com|chat\.openai\.com)$/,
      editor: ['#prompt-textarea', 'div.ProseMirror[contenteditable="true"]', 'textarea[name="prompt-textarea"]'],
      send: ['button[data-testid="send-button"]', 'button[aria-label="Send prompt"]', 'button[aria-label="Send message"]']
    },
    {
      name: 'Gemini',
      match: /(^|\.)gemini\.google\.com$/,
      editor: ['rich-textarea .ql-editor', 'div.ql-editor[contenteditable="true"]', 'div[contenteditable="true"][role="textbox"]'],
      send: ['button.send-button', 'button[aria-label="Send message"]', 'button[aria-label="Send"]']
    },
    {
      name: 'Claude',
      match: /(^|\.)claude\.ai$/,
      editor: ['div[data-testid="chat-input"]', 'div.ProseMirror[contenteditable="true"]', 'div[contenteditable="true"][role="textbox"]'],
      send: ['button[aria-label="Send message" i]', 'button[aria-label="Send Message" i]', 'button[data-testid="send-button"]']
    }
  ];
  const adapter = ADAPTERS.find((a) => a.match.test(location.hostname));
  if (!adapter) return;

  let settings = mergeSettings();
  let bypassUntil = 0;
  let modal = null;
  let lastText = null;
  let lastFindings = [];

  /* ---------- helpers ---------- */
  const h = (tag, props = {}, ...kids) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (v === true) el.setAttribute(k, '');
      else if (v !== false && v != null) el.setAttribute(k, v);
    }
    for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid); // append(string) = text node, never HTML
    return el;
  };

  const alive = () => { try { return !!chrome.runtime?.id; } catch { return false; } };
  const bump = (key) => {
    if (!alive()) return;
    chrome.storage.local.get({ stats: { scanned: 0, blocked: 0, cleaned: 0, bypassed: 0 } }, ({ stats }) => {
      stats[key] = (stats[key] || 0) + 1;
      chrome.storage.local.set({ stats });
    });
  };

  const getEditor = () => {
    for (const sel of adapter.editor) {
      const el = document.querySelector(sel);
      if (el) return el;
    }
    return null;
  };
  const getSendButton = () => {
    for (const sel of adapter.send) {
      const el = document.querySelector(sel);
      if (el) return el;
    }
    return null;
  };
  const isSendButton = (btn) => adapter.send.some((sel) => btn.matches(sel));
  const isTextControl = (ed) => ed instanceof HTMLTextAreaElement || ed instanceof HTMLInputElement;

  const BLOCKS = 'p,div,li,pre,h1,h2,h3,h4,h5,h6,blockquote,tr';
  function collectText(ed) {
    if (isTextControl(ed)) return { text: ed.value, segs: null };
    const walker = document.createTreeWalker(ed, NodeFilter.SHOW_TEXT);
    const segs = [];
    let text = '', prevBlock = null, n;
    while ((n = walker.nextNode())) {
      const v = n.nodeValue;
      if (!v) continue;
      const block = n.parentElement ? n.parentElement.closest(BLOCKS) : null;
      if (segs.length && (block !== prevBlock || n.previousSibling?.nodeName === 'BR')) text += '\n';
      segs.push({ node: n, start: text.length, end: text.length + v.length });
      text += v;
      prevBlock = block;
    }
    return { text, segs };
  }

  function setEditorText(ed, text) {
    ed.focus();
    if (isTextControl(ed)) {
      const proto = ed instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, 'value').set.call(ed, text);
      ed.dispatchEvent(new Event('input', { bubbles: true }));
      return;
    }
    const selectAll = () => {
      const sel = getSelection();
      const range = document.createRange();
      range.selectNodeContents(ed);
      sel.removeAllRanges();
      sel.addRange(range);
    };
    selectAll();
    // Rich editors (ProseMirror, Quill) handle paste properly, so replacement stays in their own state.
    const dt = new DataTransfer();
    dt.setData('text/plain', text);
    const ev = new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true });
    ed.dispatchEvent(ev);
    if (!ev.defaultPrevented) {
      selectAll();
      document.execCommand('insertText', false, text);
    }
  }

  /* ---------- UI root (shadow DOM so page CSS can't touch us) ---------- */
  const CSS_TEXT = `
  :host{all:initial}
  *{box-sizing:border-box}
  .layer{position:fixed;inset:0;pointer-events:none;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#1B1630;font-size:14px;line-height:1.45}
  button{font:inherit;cursor:pointer}
  .badge{position:fixed;pointer-events:auto;display:flex;align-items:center;gap:8px;padding:6px 12px 6px 8px;border-radius:999px;border:1px solid #E9E5F7;background:#fff;color:#1B1630;box-shadow:0 6px 20px rgba(27,22,48,.14);font-weight:550;font-size:13px}
  .badge[hidden]{display:none}
  .badge:hover{border-color:#6D4AFF}
  .badge:focus-visible,.card button:focus-visible{outline:2px solid #6D4AFF;outline-offset:2px}
  .badge .mini{width:22px;height:22px;display:grid;place-items:center;border-radius:50%;background:#FFE9E9;color:#E5484D;font-weight:700;font-size:12px}
  .badge .act{color:#6D4AFF}
  .scrim{position:fixed;inset:0;pointer-events:auto;display:grid;place-items:center;padding:16px;background:rgba(27,22,48,.46);backdrop-filter:blur(3px);animation:fade .18s ease-out both}
  .card{position:relative;width:min(468px,100%);max-height:min(90vh,760px);overflow:auto;background:#fff;border-radius:22px;padding:8px 22px 18px;box-shadow:0 24px 70px rgba(27,22,48,.35);animation:card .38s cubic-bezier(.2,1.3,.4,1) both}
  .x{position:absolute;top:12px;right:12px;width:32px;height:32px;border:0;border-radius:50%;background:#F4F1FF;color:#6B6785;font-size:18px;line-height:1}
  .x:hover{background:#E9E5F7}
  .hero{display:grid;place-items:center;margin:6px auto 0;width:132px;height:112px}
  .emoji{width:128px;animation:pop .55s cubic-bezier(.2,1.6,.4,1) both}
  .emoji svg{display:block;width:100%;height:auto;overflow:visible}
  .finger{transform-origin:178px 164px;animation:wag 1.7s ease-in-out .5s infinite}
  .face{transform-origin:100px 106px;animation:tilt 1.7s ease-in-out .5s infinite}
  h2{margin:4px 0 2px;text-align:center;font-size:20px;font-weight:700;letter-spacing:-.01em}
  .sub{margin:0 0 14px;text-align:center;color:#6B6785;font-size:13.5px}
  .rows{max-height:150px;overflow:auto;border:1px solid #E9E5F7;border-radius:14px;margin-bottom:12px}
  .row{display:grid;grid-template-columns:20px 10px 1fr auto auto;align-items:center;gap:8px;padding:8px 12px;border-top:1px solid #F0EDFA;cursor:pointer}
  .row:first-child{border-top:0}
  .row input{margin:0;accent-color:#6D4AFF;width:16px;height:16px}
  .row.warn{cursor:default}
  .dot{width:9px;height:9px;border-radius:50%}
  .dot.high{background:#E5484D}.dot.med{background:#FF8A1F}.dot.low{background:#E8A100}
  .name{font-weight:550;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .val{color:#6B6785;font-size:12.5px;font-variant-ligatures:none;letter-spacing:.02em}
  .pill{font-size:11.5px;color:#8A5A00;background:#FFF3D1;border-radius:99px;padding:1px 8px}
  .seg{display:inline-flex;padding:3px;border-radius:12px;background:#F4F1FF;margin-bottom:8px}
  .seg button{border:0;background:transparent;padding:5px 12px;border-radius:9px;color:#6B6785;font-weight:550;font-size:13px}
  .seg button[aria-pressed=true]{background:#fff;color:#1B1630;box-shadow:0 1px 3px rgba(27,22,48,.15)}
  .preview{white-space:pre-wrap;word-break:break-word;max-height:150px;overflow:auto;padding:12px 14px;border-radius:14px;background:#FAF9FE;border:1px solid #E9E5F7;font-size:13.5px}
  .t{background:#E7E0FF;color:#4B2EC9;border-radius:6px;padding:0 4px;font-weight:600}
  .hi{border-radius:4px;padding:0 2px;font-weight:550}
  .hi.high{background:#FFDCDD;color:#B3262B}.hi.med{background:#FFE6CC;color:#A24A00}.hi.low{background:#FFF0BF;color:#7A5200}
  .actions{display:flex;gap:10px;margin-top:14px}
  .primary{flex:1;border:0;border-radius:12px;padding:11px 16px;background:#6D4AFF;color:#fff;font-weight:650}
  .primary:hover{background:#5836E6}
  .ghost{border:1px solid #E9E5F7;border-radius:12px;padding:11px 14px;background:#fff;color:#B3262B;font-weight:550}
  .ghost:hover{background:#FFF5F5;border-color:#F5C2C4}
  .foot{margin:12px 0 0;text-align:center;color:#8C88A3;font-size:12px}
  .toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%);pointer-events:none;background:#1B1630;color:#fff;padding:10px 16px;border-radius:12px;font-weight:550;box-shadow:0 10px 30px rgba(27,22,48,.3);animation:toast .25s ease-out both}
  .toast[hidden]{display:none}
  @keyframes fade{from{opacity:0}to{opacity:1}}
  @keyframes card{from{opacity:0;transform:translateY(14px) scale(.96)}to{opacity:1;transform:none}}
  @keyframes pop{0%{opacity:0;transform:scale(.3) translateY(24px)}100%{opacity:1;transform:none}}
  @keyframes wag{0%,72%,100%{transform:rotate(0)}8%{transform:rotate(-17deg)}22%{transform:rotate(17deg)}36%{transform:rotate(-15deg)}50%{transform:rotate(13deg)}62%{transform:rotate(-6deg)}}
  @keyframes tilt{0%,72%,100%{transform:rotate(0)}22%{transform:rotate(-3deg)}50%{transform:rotate(2deg)}}
  @keyframes toast{from{opacity:0;transform:translate(-50%,10px)}to{opacity:1;transform:translate(-50%,0)}}
  @media (prefers-reduced-motion:reduce){.finger,.face,.emoji,.card,.scrim,.toast{animation:none}}
  `;

  const rootHost = document.createElement('div');
  rootHost.id = 'hide-my-pii-root';
  rootHost.style.cssText = 'all:initial;position:fixed;inset:0;pointer-events:none;z-index:2147483647;';
  const shadow = rootHost.attachShadow({ mode: 'open' });
  const style = document.createElement('style');
  style.textContent = CSS_TEXT;
  const layer = h('div', { class: 'layer' });
  const badge = h('button', { class: 'badge', hidden: true, type: 'button', onclick: () => openFromBadge() });
  const toastEl = h('div', { class: 'toast', hidden: true, role: 'status' });
  layer.append(badge, toastEl);
  shadow.append(style, layer);
  document.documentElement.appendChild(rootHost);

  let toastTimer;
  function toast(msg) {
    toastEl.textContent = msg;
    toastEl.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (toastEl.hidden = true), 2800);
  }

  /* ---------- live highlights + badge ---------- */
  function paint(findings, segs) {
    if (!window.CSS || !CSS.highlights) return;
    const buckets = { high: [], med: [], low: [] };
    if (settings.enabled && settings.highlight && segs) {
      for (const f of findings) {
        const first = segs.findIndex((s) => f.start < s.end && f.end > s.start);
        if (first < 0) continue;
        let last = first;
        for (let i = first; i < segs.length && segs[i].start < f.end; i++) last = i;
        const a = segs[first], b = segs[last];
        const r = new Range();
        r.setStart(a.node, Math.max(f.start, a.start) - a.start);
        r.setEnd(b.node, Math.min(f.end, b.end) - b.start);
        buckets[f.sev].push(r);
      }
    }
    for (const k of Object.keys(buckets)) {
      if (buckets[k].length) CSS.highlights.set('hmp-' + k, new Highlight(...buckets[k]));
      else CSS.highlights.delete('hmp-' + k);
    }
  }

  function updateBadge(ed, findings) {
    if (!settings.enabled || !findings.length || modal) { badge.hidden = true; return; }
    const n = findings.length;
    badge.replaceChildren(
      h('span', { class: 'mini' }, String(n)),
      h('span', {}, n === 1 ? 'risky item in your prompt' : 'risky items in your prompt'),
      h('span', { class: 'act' }, 'Review')
    );
    badge.hidden = false;
    position(ed);
  }

  function position(ed) {
    if (badge.hidden) return;
    const box = ed.closest('form') || ed.parentElement || ed;
    const r = box.getBoundingClientRect();
    if (!r.width) { badge.hidden = true; return; }
    badge.style.top = Math.max(8, r.top - 42) + 'px';
    badge.style.right = Math.max(8, window.innerWidth - r.right + 8) + 'px';
  }

  function refresh(force = false) {
    const ed = getEditor();
    if (!ed || !settings.enabled) { paint([], null); badge.hidden = true; lastText = null; return; }
    const info = collectText(ed);
    if (!force && info.text === lastText) return position(ed);
    lastText = info.text;
    lastFindings = scan(info.text, settings.categories);
    paint(lastFindings, info.segs);
    updateBadge(ed, lastFindings);
  }

  /* ---------- review modal ---------- */
  function closeModal(silent = false) {
    if (!modal) return;
    modal.el.remove();
    const ed = modal.ed;
    modal = null;
    if (!silent) ed.focus();
    refresh(true);
  }

  function openFromBadge() {
    const ed = getEditor();
    if (!ed) return;
    const info = collectText(ed);
    const findings = scan(info.text, settings.categories);
    if (findings.length) openModal({ ed, info, findings, mode: 'review' });
  }

  function openModal({ ed, info, findings, mode }) {
    closeModal(true);
    badge.hidden = true;
    const text = info.text;
    const redactable = findings.filter((f) => f.redact !== false);
    const selected = new Set(redactable.map((f) => f.id));
    let tab = redactable.length ? 'safe' : 'orig';
    const warnOnly = !redactable.length;

    const title = warnOnly ? 'Heads up: suspicious instructions' : 'Nope! Sensitive info spotted';
    const sub = mode === 'block'
      ? `Your prompt wasn't sent. Review the clean version before it goes to ${adapter.name}.`
      : `Here's what's in your prompt before it goes to ${adapter.name}.`;

    const emoji = h('div', { class: 'emoji' });
    emoji.innerHTML = emojiSVG('m' + Date.now()); // static, trusted markup only

    const preview = h('div', { class: 'preview', 'aria-live': 'polite' });
    const primary = h('button', { class: 'primary', type: 'button' });
    const segSafe = h('button', { type: 'button', onclick: () => setTab('safe') }, 'Safe version');
    const segOrig = h('button', { type: 'button', onclick: () => setTab('orig') }, 'Original');

    function renderPreview() {
      preview.replaceChildren();
      segSafe.setAttribute('aria-pressed', String(tab === 'safe'));
      segOrig.setAttribute('aria-pressed', String(tab === 'orig'));
      if (tab === 'safe') {
        for (const p of redact(text, findings, selected).parts) {
          preview.append(p.redacted ? h('span', { class: 't' }, p.t) : document.createTextNode(p.t));
        }
      } else {
        let last = 0;
        for (const f of findings) {
          preview.append(document.createTextNode(text.slice(last, f.start)));
          preview.append(h('span', { class: 'hi ' + f.sev }, text.slice(f.start, f.end)));
          last = f.end;
        }
        preview.append(document.createTextNode(text.slice(last)));
      }
      primary.textContent = selected.size ? 'Use safe version' : 'Back to prompt';
    }
    function setTab(t) { tab = t; renderPreview(); }

    const rows = h('div', { class: 'rows' }, findings.map((f) => {
      const canToggle = f.redact !== false;
      return h('label', { class: 'row' + (canToggle ? '' : ' warn') },
        canToggle
          ? h('input', {
              type: 'checkbox', checked: true, 'aria-label': 'Redact ' + f.label,
              onchange: (e) => { e.target.checked ? selected.add(f.id) : selected.delete(f.id); renderPreview(); }
            })
          : h('span'),
        h('span', { class: 'dot ' + f.sev }),
        h('span', { class: 'name' }, f.label),
        h('span', { class: 'val' }, mask(f.value)),
        canToggle ? null : h('span', { class: 'pill' }, 'Warning')
      );
    }));

    primary.addEventListener('click', () => {
      if (selected.size) {
        const clean = redact(text, findings, selected).text;
        closeModal(true);
        setEditorText(ed, clean);
        bump('cleaned');
        toast('Prompt cleaned. Give it a last look, then send.');
        setTimeout(() => refresh(true), 150);
      } else {
        closeModal();
      }
    });

    const card = h('div', { class: 'card', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
      h('button', { class: 'x', type: 'button', 'aria-label': 'Close', onclick: () => closeModal() }, '×'),
      h('div', { class: 'hero' }, emoji),
      h('h2', {}, title),
      h('p', { class: 'sub' }, sub),
      rows,
      h('div', { class: 'seg', role: 'group', 'aria-label': 'Preview' }, segSafe, segOrig),
      preview,
      h('div', { class: 'actions' },
        primary,
        h('button', { class: 'ghost', type: 'button', onclick: () => sendAnyway(ed) }, 'Send anyway')
      ),
      h('p', { class: 'foot' }, 'Checked on your device. Nothing leaves your browser.')
    );
    const scrim = h('div', { class: 'scrim', onclick: (e) => { if (e.target === scrim) closeModal(); } }, card);
    layer.append(scrim);
    modal = { el: scrim, ed };
    renderPreview();
    primary.focus();
  }

  function sendAnyway(ed) {
    bump('bypassed');
    closeModal(true);
    bypassUntil = Date.now() + 2000;
    setTimeout(() => {
      const btn = getSendButton();
      if (btn) btn.click();
      else ed.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true }));
    }, 60);
  }

  /* ---------- interception ---------- */
  const halt = (e) => { e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation(); };

  function guard(e, ed) {
    if (!settings.enabled || Date.now() < bypassUntil) return;
    if (modal) return halt(e);
    const info = collectText(ed);
    if (!info.text.trim()) return;
    const findings = scan(info.text, settings.categories);
    bump('scanned');
    if (!findings.length) return;
    halt(e);
    bump('blocked');
    openModal({ ed, info, findings, mode: 'block' });
  }

  document.addEventListener('keydown', (e) => {
    if (modal && e.key === 'Escape') { closeModal(); return halt(e); }
    if (e.key !== 'Enter' || e.shiftKey || e.isComposing) return;
    const ed = getEditor();
    if (!ed) return;
    const t = e.target;
    if (t === ed || (t instanceof Node && ed.contains(t))) guard(e, ed);
  }, true);

  document.addEventListener('click', (e) => {
    const t = e.target instanceof Element ? e.target : null;
    const btn = t && t.closest('button, [role="button"]');
    if (!btn || !isSendButton(btn)) return;
    const ed = getEditor();
    if (ed) guard(e, ed);
  }, true);

  /* ---------- lifecycle ---------- */
  let timer;
  document.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => refresh(), 120); }, true);
  window.addEventListener('resize', () => { const ed = getEditor(); if (ed) position(ed); }, { passive: true });
  window.addEventListener('scroll', () => { const ed = getEditor(); if (ed) position(ed); }, { passive: true, capture: true });
  setInterval(() => { if (alive() && !modal) refresh(); }, 600); // catches programmatic changes (e.g. after send)

  const loadSettings = () => {
    if (!alive()) return;
    chrome.storage.sync.get(null, (s) => { settings = mergeSettings(s); refresh(true); });
  };
  loadSettings();
  if (alive()) chrome.storage.onChanged.addListener((_, area) => { if (area === 'sync') loadSettings(); });
})();
