(() => {
  const { CATEGORIES, mergeSettings, emojiSVG } = window.HMP;
  const $ = (id) => document.getElementById(id);
  $('logo').innerHTML = emojiSVG('p'); // static, trusted markup

  let settings = mergeSettings();

  const row = (key, label, hint, checked) => {
    const wrap = document.createElement('div');
    wrap.className = 'rule';
    const text = document.createElement('div');
    const b = document.createElement('b'); b.textContent = label;
    const s = document.createElement('small'); s.textContent = hint;
    text.append(b, s);
    const sw = document.createElement('label'); sw.className = 'sw';
    const input = document.createElement('input'); input.type = 'checkbox'; input.checked = checked; input.setAttribute('aria-label', label);
    input.addEventListener('change', () => {
      if (key === 'highlight') settings.highlight = input.checked;
      else settings.categories[key] = input.checked;
      save();
    });
    sw.append(input, document.createElement('i'));
    wrap.append(text, sw);
    return wrap;
  };

  function render() {
    document.body.classList.toggle('off', !settings.enabled);
    $('enabled').checked = settings.enabled;
    $('status').textContent = settings.enabled ? 'Protection is on' : 'Protection is off';
    const box = $('rules');
    box.replaceChildren(
      ...Object.entries(CATEGORIES).map(([k, c]) => row(k, c.label, c.hint, settings.categories[k])),
      row('highlight', 'Highlight while typing', 'Underline risky text in the prompt box', settings.highlight)
    );
  }

  const save = () => chrome.storage.sync.set({ enabled: settings.enabled, highlight: settings.highlight, categories: settings.categories });

  $('enabled').addEventListener('change', (e) => {
    settings.enabled = e.target.checked;
    document.body.classList.toggle('off', !settings.enabled);
    $('status').textContent = settings.enabled ? 'Protection is on' : 'Protection is off';
    save();
  });

  const renderStats = (stats = {}) => {
    $('s-scanned').textContent = stats.scanned || 0;
    $('s-blocked').textContent = stats.blocked || 0;
    $('s-cleaned').textContent = stats.cleaned || 0;
  };

  chrome.storage.sync.get(null, (s) => { settings = mergeSettings(s); render(); });
  chrome.storage.local.get({ stats: {} }, ({ stats }) => renderStats(stats));
  chrome.storage.onChanged.addListener((ch, area) => {
    if (area === 'local' && ch.stats) renderStats(ch.stats.newValue);
  });
})();
