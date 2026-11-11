'use strict';
// GoServerPanel — SPA без внешних зависимостей. Весь вывод строится через DOM-API (без innerHTML) — защита от XSS.

const $app = document.getElementById('app');
let ME = null;
let cleanups = [];

// ---------- утилиты ----------
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'class') e.className = v;
    else if (k === 'value') e.value = v ?? '';
    else if (['checked', 'disabled', 'selected', 'readOnly'].includes(k)) e[k] = !!v;
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const c of kids.flat(Infinity)) {
    if (c == null || c === false) continue;
    e.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return e;
}
const fmtBytes = n => { if (!n) return '0 Б'; const u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + ' ' + u[i]; };
const fmtDate = s => s ? new Date(s).toLocaleString('ru-RU') : '';
const fmtUptime = s => { const d = Math.floor(s / 86400), hh = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return (d ? d + ' д ' : '') + hh + ' ч ' + m + ' мин'; };

async function api(method, path, body) {
  const opt = { method, headers: { 'X-Requested-With': 'gsp' }, credentials: 'same-origin' };
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch('/api' + path, opt);
  let data = null;
  try { data = await r.json(); } catch (e) { /* не JSON */ }
  if (r.status === 401 && path !== '/login') { ME = null; renderLogin(); throw new Error('требуется вход'); }
  if (!r.ok) { const err = new Error((data && data.error) || ('HTTP ' + r.status)); err.data = data; throw err; }
  return data;
}

function toast(msg, isErr) {
  const t = h('div', { class: 'toast', style: isErr ? 'border-color:var(--err);color:var(--err)' : '' }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), isErr ? 6000 : 2500);
}
const guard = fn => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message, true); } };

function modal(title, body, buttons, wide) {
  const err = h('div', { class: 'err-box', style: 'display:none' });
  const close = () => ov.remove();
  const foot = h('div', { class: 'foot' }, (buttons || [{ label: 'Закрыть' }]).map(b =>
    h('button', {
      class: b.primary ? 'primary' : '', onclick: async ev => {
        if (!b.onclick) return close();
        ev.target.disabled = true; err.style.display = 'none';
        try { const keep = await b.onclick(); if (keep !== false) close(); }
        catch (e) { err.textContent = e.message; err.style.display = 'block'; }
        finally { ev.target.disabled = false; }
      }
    }, b.label)));
  const ov = h('div', { class: 'overlay' }, h('div', { class: 'modal' + (wide ? ' wide' : '') }, h('h2', {}, title), err, body, foot));
  ov.addEventListener('mousedown', e => { if (e.target === ov && !b_keep(buttons)) close(); });
  document.body.append(ov);
  return { close, el: ov };
}
const b_keep = b => !!(b && b.some(x => x.sticky));

function field(label, input) { return h('label', { class: 'f' }, h('span', {}, label), input); }
function check(label, checked) { const i = h('input', { type: 'checkbox', checked }); return { el: h('label', { class: 'c' }, i, label), get: () => i.checked }; }

function confirmBox(text, onYes, label = 'Удалить') {
  modal('Подтвердите действие', h('p', {}, text), [{ label: 'Отмена' }, { label, primary: true, onclick: onYes }]);
}

// Лог фоновой задачи (WebSocket с запасным опросом)
function jobModal(jobId, title, onDone) {
  const pre = h('pre', { class: 'log' }, 'Подключение…\n');
  const status = h('span', { class: 'badge warn' }, 'выполняется');
  const m = modal(title, h('div', {}, h('div', { class: 'row', style: 'margin-bottom:8px' }, status), pre), [{ label: 'Закрыть' }], true);
  let finished = false, first = true;
  const finish = async () => {
    if (finished) return; finished = true;
    try {
      const j = await api('GET', '/jobs/' + jobId);
      status.textContent = j.status === 'done' ? 'готово' : 'ошибка';
      status.className = 'badge ' + (j.status === 'done' ? 'ok' : 'err');
      pre.textContent = j.output; pre.scrollTop = pre.scrollHeight;
    } catch (e) { /* ignore */ }
    if (onDone) onDone();
  };
  const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/api/jobs/' + jobId + '/ws');
  ws.onmessage = ev => { if (first) { pre.textContent = ''; first = false; } pre.append(ev.data); pre.scrollTop = pre.scrollHeight; };
  ws.onclose = finish; ws.onerror = finish;
  const origRemove = m.el.remove.bind(m.el);
  m.el.remove = () => { try { ws.close(); } catch (e) { /* */ } origRemove(); };
}

// ---------- каркас ----------
const PAGES = [
  ['dashboard', 'Дашборд', pageDashboard, 'dashboard'],
  ['sites', 'Веб-сайты', pageSites, 'globe'],
  ['cms', 'Автоустановка CMS', pageCMS, 'package'],
  ['php', 'PHP & Модули', pagePHP, 'code'],
  ['db', 'Базы данных', pageDB, 'database'],
  ['pki', 'SSL / PKI', pagePKI, 'shield'],
  ['terminal', 'Терминал', pageTerminal, 'terminal'],
  ['files', 'Файловый менеджер', pageFiles, 'folder'],
  ['settings', 'Настройки', pageSettings, 'sliders'],
];

// Иконки (статические SVG-пути, 24×24, stroke)
const ICONS = {
  dashboard: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18"/>',
  package: '<path d="M21 8l-9-5-9 5v8l9 5 9-5z"/><path d="M3 8l9 5 9-5M12 13v8"/>',
  code: '<path d="M8 8l-5 4 5 4M16 8l5 4-5 4M14 5l-4 14"/>',
  database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>',
  folder: '<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>',
  sliders: '<path d="M4 6h8M18 6h2M4 12h2M12 12h8M4 18h10M20 18h0"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
  moon: '<path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z"/>',
  logout: '<path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/>',
  server: '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01"/>',
};
function icon(name, size = 18) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('width', size); svg.setAttribute('height', size);
  svg.setAttribute('fill', 'none'); svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.8'); svg.setAttribute('stroke-linecap', 'round'); svg.setAttribute('stroke-linejoin', 'round');
  svg.innerHTML = ICONS[name] || '';
  return svg;
}

function theme() {
  const t = localStorage.getItem('theme');
  if (t) document.documentElement.dataset.theme = t;
  else document.documentElement.dataset.theme = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
theme();

function renderShell() {
  const cur = (location.hash.slice(1) || 'dashboard');
  const nav = h('nav', { class: 'nav' }, PAGES.filter(p => ME.user.role === 'admin' || !['terminal', 'files'].includes(p[0])).map(p =>
    h('a', { href: '#' + p[0], class: p[0] === cur ? 'active' : '' }, icon(p[3]), h('span', {}, p[1]))));
  const main = h('main', { class: 'main' });
  const toggleTheme = () => { const t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; localStorage.setItem('theme', t); theme(); };
  const logout = async () => { try { await api('POST', '/logout'); } catch (e) { /* */ } ME = null; renderLogin(); };
  $app.replaceChildren(h('div', { class: 'layout' },
    h('aside', { class: 'side' },
      h('div', { class: 'brand' }, h('div', { class: 'logo' }, icon('server', 18)), h('div', { class: 'brand-name' }, 'Go', h('span', {}, 'ServerPanel'))),
      nav, h('div', { class: 'grow' }),
      h('div', { class: 'user' },
        h('div', { class: 'avatar' }, (ME.user.username[0] || '?').toUpperCase()),
        h('div', { class: 'user-info' }, h('div', { class: 'user-name' }, ME.user.username),
          h('div', { class: 'user-role' }, ME.user.role, ME.dry_run ? h('span', { class: 'chip warn' }, 'dry-run') : null)),
        h('button', { class: 'iconbtn', title: 'Сменить тему', onclick: toggleTheme }, icon('moon', 16)),
        h('button', { class: 'iconbtn', title: 'Выйти', onclick: logout }, icon('logout', 16)))),
    main));
  const page = PAGES.find(p => p[0] === cur) || PAGES[0];
  cleanups.forEach(f => { try { f(); } catch (e) { /* */ } }); cleanups = [];
  Promise.resolve(page[2](main)).catch(e => { main.replaceChildren(h('div', { class: 'err-box' }, e.message)); });
}
window.addEventListener('hashchange', () => { if (ME) renderShell(); });

function renderLogin(needTotp) {
  cleanups.forEach(f => f()); cleanups = [];
  const err = h('div', { class: 'err-box', style: 'display:none' });
  const u = h('input', { autocomplete: 'username', autofocus: true });
  const p = h('input', { type: 'password', autocomplete: 'current-password' });
  const t = h('input', { inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 6 });
  const tf = field('Код 2FA', t); tf.style.display = needTotp ? '' : 'none';
  const go = async () => {
    err.style.display = 'none';
    try {
      await api('POST', '/login', { username: u.value, password: p.value, totp: t.value });
      await boot();
    } catch (e) {
      if (e.data && e.data.need_totp) { tf.style.display = ''; t.focus(); return; }
      err.textContent = e.message; err.style.display = 'block';
    }
  };
  $app.replaceChildren(h('div', { class: 'card login' }, h('h1', {}, 'GoServerPanel'), err,
    field('Логин', u), field('Пароль', p), tf,
    h('button', { class: 'primary', style: 'width:100%', onclick: go }, 'Войти')));
  for (const i of [u, p, t]) i.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
}

async function boot() {
  try { ME = await api('GET', '/me'); } catch (e) { return renderLogin(); }
  renderShell();
}

// ---------- Дашборд ----------
async function pageDashboard(main) {
  const cpu = h('div'), mem = h('div'), disks = h('div'), info = h('div', { class: 'muted small' });
  const svc = h('tbody');
  main.append(h('h1', {}, 'Дашборд'),
    h('div', { class: 'grid' },
      h('div', { class: 'card' }, h('h2', {}, 'Процессор'), cpu),
      h('div', { class: 'card' }, h('h2', {}, 'Память'), mem),
      h('div', { class: 'card' }, h('h2', {}, 'Диски'), disks)),
    h('div', { class: 'card' }, h('div', { class: 'row sp' }, h('h2', {}, 'Службы'), info),
      h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Служба'), h('th', {}, 'Статус'), h('th', {}, ''))), svc)));
  const bar = (v, label) => h('div', {}, h('div', { class: 'big' }, label), h('div', { class: 'bar' }, h('i', { class: v > 90 ? 'crit' : v > 75 ? 'hi' : '', style: 'width:' + Math.min(100, v).toFixed(0) + '%' })));
  const draw = s => {
    cpu.replaceChildren(bar(s.cpu, s.cpu.toFixed(0) + ' %'), h('div', { class: 'muted small' }, 'Load: ' + s.load.map(x => x.toFixed(2)).join(' / ')));
    const mp = s.mem_total ? s.mem_used / s.mem_total * 100 : 0;
    mem.replaceChildren(bar(mp, mp.toFixed(0) + ' %'), h('div', { class: 'muted small' }, fmtBytes(s.mem_used) + ' из ' + fmtBytes(s.mem_total) + (s.swap_total ? ' · swap ' + fmtBytes(s.swap_used) : '')));
    disks.replaceChildren(...(s.disks || []).map(d => { const p = d.total ? d.used / d.total * 100 : 0; return h('div', {}, h('div', { class: 'row sp small' }, h('span', { class: 'mono' }, d.path), h('span', {}, fmtBytes(d.used) + ' / ' + fmtBytes(d.total))), h('div', { class: 'bar' }, h('i', { class: p > 90 ? 'crit' : p > 75 ? 'hi' : '', style: 'width:' + p.toFixed(0) + '%' }))); }));
    info.textContent = s.hostname + ' · uptime ' + fmtUptime(s.uptime);
  };
  const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/api/ws/stats');
  ws.onmessage = e => draw(JSON.parse(e.data));
  cleanups.push(() => ws.close());
  const loadSvc = async () => {
    const list = await api('GET', '/services');
    svc.replaceChildren(...list.map(s => h('tr', {}, h('td', { class: 'mono' }, s.name),
      h('td', {}, h('span', { class: 'badge ' + (s.active === 'active' ? 'ok' : 'err') }, s.active)),
      h('td', { class: 'row' }, ['restart', 'reload', 'stop', 'start'].map(a => h('button', { class: 'sm', onclick: guard(async () => { await api('POST', `/services/${s.name}/${a}`); toast(s.name + ': ' + a + ' ✓'); loadSvc(); }) }, a))))));
    if (!list.length) svc.replaceChildren(h('tr', {}, h('td', { colspan: 3, class: 'muted' }, 'Службы systemd не обнаружены')));
  };
  loadSvc().catch(() => { });
  const t = setInterval(() => loadSvc().catch(() => { }), 10000); cleanups.push(() => clearInterval(t));
}

// ---------- Сайты ----------
async function pageSites(main) {
  const tbody = h('tbody');
  const banner = h('div');
  api('GET', '/nginx').then(n => {
    if (n.installed) return;
    banner.replaceChildren(h('div', { class: 'banner' }, h('div', {}, h('b', {}, 'nginx не установлен'), h('div', { class: 'muted small' }, 'Без него сайты не будут обслуживаться. Установка займёт около минуты.')),
      h('button', { class: 'primary', onclick: guard(async () => { const r = await api('POST', '/nginx/install'); jobModal(r.job, 'Установка nginx', () => renderShell()); }) }, 'Установить nginx')));
  }).catch(() => { });
  main.append(banner, h('div', { class: 'row sp page-h' }, h('h1', {}, 'Веб-сайты'), h('div', { class: 'row' },
    h('button', { onclick: guard(async () => { const r = await api('POST', '/nginx/test'); modal('nginx -t', h('pre', { class: 'log' }, r.output || '(пусто)')); }) }, 'Проверить nginx -t'),
    h('button', { class: 'primary', onclick: () => siteForm() }, '+ Добавить сайт'))),
    h('div', { class: 'card' }, h('table', {}, h('thead', {}, h('tr', {}, ['Домен', 'Тип', 'PHP', 'HTTPS', ''].map(x => h('th', {}, x)))), tbody)));
  const load = async () => {
    const sites = await api('GET', '/sites');
    tbody.replaceChildren(...sites.map(s => h('tr', {},
      h('td', {}, h('b', {}, s.domain), s.aliases?.length ? h('div', { class: 'muted small' }, s.aliases.join(', ')) : null, s.cms ? h('span', { class: 'badge', style: 'margin-left:6px' }, s.cms) : null),
      h('td', {}, (s.proxies?.length ? 'proxy' : 'static') + (s.raw_config ? ' · raw' : '')),
      h('td', {}, s.php_version || '—'),
      h('td', {}, s.cert_id ? h('span', { class: 'badge ok' }, s.force_https ? 'HTTPS ⇒' : 'HTTPS') : '—'),
      h('td', { class: 'row' },
        h('button', { class: 'sm', onclick: () => siteForm(s) }, 'Изменить'),
        h('button', { class: 'sm', onclick: () => siteConfig(s) }, 'Конфиг'),
        h('button', { class: 'sm', onclick: () => siteLogs(s) }, 'Логи'),
        h('button', { class: 'sm danger', onclick: () => confirmSiteDelete(s) }, 'Удалить')))));
    if (!sites.length) tbody.replaceChildren(h('tr', {}, h('td', { colspan: 5, class: 'muted' }, 'Сайтов пока нет')));
  };
  function confirmSiteDelete(s) {
    const purge = check('Также удалить файлы сайта', false);
    modal('Удалить ' + s.domain + '?', h('div', {}, h('p', {}, 'Конфигурация nginx будет удалена.'), purge.el),
      [{ label: 'Отмена' }, { label: 'Удалить', primary: true, onclick: async () => { await api('DELETE', '/sites/' + s.id + (purge.get() ? '?purge=1' : '')); load(); } }]);
  }
  async function siteForm(s) {
    const isNew = !s;
    s = s || { domain: '', aliases: [], root: '', php_version: '', force_https: false, cert_id: '', proxies: [], redirects: [], cache: true, max_body: '64m' };
    const [php, pki] = await Promise.all([api('GET', '/php'), api('GET', '/pki')]);
    const domain = h('input', { value: s.domain, placeholder: 'example.com' });
    const aliases = h('input', { value: (s.aliases || []).join(', '), placeholder: 'www.example.com, ...' });
    const root = h('input', { value: s.root, placeholder: 'пусто = /var/www/<домен>/public_html' });
    const phpSel = h('select', {}, h('option', { value: '' }, 'без PHP'), php.map(v => h('option', { value: v.version, selected: v.version === s.php_version }, 'PHP ' + v.version + (v.installed ? '' : ' (не установлен)'))));
    const certs = (pki.certs || []).filter(c => !c.revoked);
    const certSel = h('select', {}, h('option', { value: '' }, 'без HTTPS'), certs.map(c => h('option', { value: c.serial, selected: c.serial === s.cert_id }, c.domain + ' (до ' + new Date(c.not_after).toLocaleDateString('ru-RU') + ')')));
    const force = check('Принудительно перенаправлять HTTP → HTTPS', s.force_https);
    const cache = check('Кэширование статики (expires 30d)', s.cache);
    const maxBody = h('input', { value: s.max_body || '64m' });
    let proxies = JSON.parse(JSON.stringify(s.proxies || [])), redirects = JSON.parse(JSON.stringify(s.redirects || []));
    const pBox = h('div'), rBox = h('div');
    const drawP = () => pBox.replaceChildren(...proxies.map((p, i) => h('div', { class: 'sub' },
      h('div', { class: 'row' }, h('input', { value: p.path, style: 'width:120px', placeholder: '/', oninput: e => p.path = e.target.value }),
        h('input', { value: (p.upstreams || []).join(', '), style: 'flex:1', placeholder: 'http://127.0.0.1:3000 (несколько через запятую — балансировка)', oninput: e => p.upstreams = e.target.value.split(',').map(x => x.trim()).filter(Boolean) }),
        h('button', { class: 'sm danger', onclick: () => { proxies.splice(i, 1); drawP(); } }, '✕')),
      h('div', { class: 'row' }, check('WebSocket', p.websocket).el, (() => { const sel = h('select', { style: 'width:auto', onchange: e => p.balance = e.target.value }, ['round_robin', 'least_conn', 'ip_hash'].map(b => h('option', { value: b, selected: b === (p.balance || 'round_robin') }, b))); return sel; })()))));
    // check() не отдаёт события — подвесим чтение значения перед отправкой
    const wsChecks = () => [...pBox.querySelectorAll('.sub')].forEach((el, i) => { proxies[i].websocket = el.querySelector('input[type=checkbox]').checked; });
    const drawR = () => rBox.replaceChildren(...redirects.map((r, i) => h('div', { class: 'row', style: 'margin-bottom:6px' },
      h('input', { value: r.from, style: 'width:150px', placeholder: '/old', oninput: e => r.from = e.target.value }),
      h('input', { value: r.to, style: 'flex:1', placeholder: 'https://… или /new', oninput: e => r.to = e.target.value }),
      h('select', { style: 'width:80px', onchange: e => r.code = +e.target.value }, [301, 302, 307, 308].map(c => h('option', { value: c, selected: c === (r.code || 301) }, c))),
      h('button', { class: 'sm danger', onclick: () => { redirects.splice(i, 1); drawR(); } }, '✕'))));
    drawP(); drawR();
    modal(isNew ? 'Новый сайт' : 'Сайт ' + s.domain, h('div', {},
      field('Домен', domain), field('Алиасы', aliases), field('Корневая директория', root),
      h('div', { class: 'row' }, h('div', { style: 'flex:1' }, field('Версия PHP', phpSel)), h('div', { style: 'flex:1' }, field('Сертификат (SSL / PKI)', certSel))),
      force.el, cache.el, field('client_max_body_size', maxBody),
      h('h2', {}, 'Reverse proxy'), pBox, h('button', { class: 'sm', onclick: () => { proxies.push({ path: '/', upstreams: [], websocket: false, balance: 'round_robin' }); drawP(); } }, '+ правило прокси'),
      h('h2', { style: 'margin-top:14px' }, 'Редиректы'), rBox, h('button', { class: 'sm', onclick: () => { redirects.push({ from: '', to: '', code: 301 }); drawR(); } }, '+ редирект')),
      [{ label: 'Отмена' }, {
        label: 'Сохранить', primary: true, onclick: async () => {
          wsChecks();
          const body = { ...s, domain: domain.value, aliases: aliases.value.split(',').map(x => x.trim()).filter(Boolean), root: root.value.trim(), php_version: phpSel.value, cert_id: certSel.value, force_https: force.get(), cache: cache.get(), max_body: maxBody.value, proxies, redirects };
          await (isNew ? api('POST', '/sites', body) : api('PUT', '/sites/' + s.id, body));
          load();
        }
      }], true);
  }
  async function siteConfig(s) {
    const c = await api('GET', `/sites/${s.id}/config`);
    const ta = h('textarea', { spellcheck: 'false' }); ta.value = c.config;
    modal('nginx-конфиг: ' + s.domain, h('div', {},
      h('p', { class: 'muted small' }, c.raw ? 'Используется ВРУЧНУЮ изменённый конфиг. «Вернуть генерируемый» сбросит правки.' : 'Показан сгенерированный конфиг. После сохранения он станет ручным и перестанет обновляться при изменении настроек сайта. Перед применением выполняется nginx -t; при ошибке изменения откатываются.'), ta),
      [{ label: 'Отмена' }, { label: 'Вернуть генерируемый', onclick: async () => { await api('PUT', `/sites/${s.id}/config`, { config: '' }); load(); } },
      { label: 'Сохранить и применить', primary: true, onclick: async () => { await api('PUT', `/sites/${s.id}/config`, { config: ta.value }); load(); } }], true);
  }
  async function siteLogs(s) {
    let kind = 'access';
    const pre = h('pre', { class: 'log' });
    const sel = h('select', { style: 'width:auto', onchange: e => { kind = e.target.value; refresh(); } }, h('option', { value: 'access' }, 'access.log'), h('option', { value: 'error' }, 'error.log'));
    const refresh = guard(async () => { const r = await api('GET', `/sites/${s.id}/logs?kind=${kind}&n=300`); pre.textContent = r.log || '(пусто)'; pre.scrollTop = pre.scrollHeight; });
    modal('Логи: ' + s.domain, h('div', {}, h('div', { class: 'row', style: 'margin-bottom:8px' }, sel, h('button', { class: 'sm', onclick: refresh }, 'Обновить')), pre), [{ label: 'Закрыть' }], true);
    refresh();
  }
  await load();
}

// ---------- CMS ----------
async function pageCMS(main) {
  const [cat, php] = await Promise.all([api('GET', '/cms'), api('GET', '/php')]);
  main.append(h('h1', {}, 'Автоустановка CMS'), h('p', { class: 'muted' }, 'Создаётся БД и пользователь, скачивается архив, пишется конфиг, настраиваются права и виртуальный хост nginx.'),
    h('div', { class: 'grid' }, cat.map(a => h('div', { class: 'card cms' }, h('h2', {}, a.name), h('div', { class: 'muted' }, a.description),
      h('div', {}, a.auto_config ? h('span', { class: 'badge ok' }, 'конфиг авто') : h('span', { class: 'badge' }, 'через мастер CMS')),
      h('button', { class: 'primary', onclick: () => install(a) }, 'Установить')))));
  function install(a) {
    const domain = h('input', { placeholder: 'example.com' }), aliases = h('input', { placeholder: 'www.example.com' });
    const phpSel = h('select', {}, php.filter(v => v.installed).length ? php.filter(v => v.installed).map(v => h('option', { value: v.version }, 'PHP ' + v.version)) : php.map(v => h('option', { value: v.version }, 'PHP ' + v.version + ' (не установлен)')));
    const eng = h('select', {}, h('option', { value: 'mysql' }, 'MySQL / MariaDB'), h('option', { value: 'postgres' }, 'PostgreSQL'));
    modal('Установка ' + a.name, h('div', {}, field('Домен', domain), field('Алиасы (через запятую)', aliases), field('Версия PHP', phpSel), a.id === 'laravel' ? null : field('СУБД', eng)),
      [{ label: 'Отмена' }, {
        label: 'Установить', primary: true, onclick: async () => {
          const r = await api('POST', '/cms/install', { cms: a.id, domain: domain.value, aliases: aliases.value.split(',').map(x => x.trim()).filter(Boolean), php_version: phpSel.value, db_engine: eng.value });
          jobModal(r.job, 'Установка ' + a.name);
        }
      }]);
  }
}

// ---------- PHP ----------
async function pagePHP(main) {
  let ver = null;
  const top = h('div'), bottom = h('div');
  main.append(h('h1', {}, 'PHP & Модули'), top, bottom);
  const loadVersions = async () => {
    const vs = await api('GET', '/php');
    if (!ver) ver = (vs.find(v => v.installed) || vs[0]).version;
    top.replaceChildren(h('div', { class: 'card' }, h('table', {}, h('thead', {}, h('tr', {}, ['Версия', 'Статус', 'Сокет', ''].map(x => h('th', {}, x)))),
      h('tbody', {}, vs.map(v => h('tr', {}, h('td', {}, h('b', {}, 'PHP ' + v.version)), h('td', {}, h('span', { class: 'badge ' + (v.installed ? 'ok' : '') }, v.installed ? 'установлен' : 'нет')), h('td', { class: 'mono small' }, v.socket),
        h('td', { class: 'row' }, v.installed ? h('button', { class: 'sm', onclick: () => { ver = v.version; loadDetail(); } }, 'Настроить') :
          h('button', { class: 'sm primary', onclick: guard(async () => { const r = await api('POST', `/php/${v.version}/install`); jobModal(r.job, 'Установка PHP ' + v.version, loadVersions); }) }, 'Установить'))))))));
    if (vs.find(v => v.version === ver && v.installed)) loadDetail(); else bottom.replaceChildren();
  };
  const loadDetail = async () => {
    const [mods, ini] = await Promise.all([api('GET', `/php/${ver}/modules`), api('GET', `/php/${ver}/ini`)]);
    const inputs = {};
    const act = (m, a) => guard(async () => { const r = await api('POST', `/php/${ver}/modules/${m.name}/${a}`); jobModal(r.job, `PHP ${ver}: ${a} ${m.name}`, loadDetail); });
    bottom.replaceChildren(
      h('div', { class: 'card' }, h('h2', {}, 'php.ini — PHP ' + ver), h('div', { class: 'grid' }, ini.keys.map(k => { inputs[k] = h('input', { value: ini.values[k] || '', placeholder: 'по умолчанию' }); return field(k, inputs[k]); })),
        h('button', { class: 'primary', onclick: guard(async () => { const v = {}; for (const k of ini.keys) v[k] = inputs[k].value; await api('PUT', `/php/${ver}/ini`, { values: v }); toast('Сохранено, PHP-FPM перезапущен'); }) }, 'Сохранить и перезапустить пул')),
      h('div', { class: 'card' }, h('h2', {}, 'Модули — PHP ' + ver), h('table', {}, h('thead', {}, h('tr', {}, ['Модуль', 'Статус', ''].map(x => h('th', {}, x)))),
        h('tbody', {}, mods.map(m => h('tr', {}, h('td', { class: 'mono' }, m.name), h('td', {}, h('span', { class: 'badge ' + (m.loaded ? 'ok' : m.installed ? 'warn' : '') }, m.loaded ? 'загружен' : m.installed ? 'установлен' : 'нет')),
          h('td', { class: 'row' }, !m.installed ? h('button', { class: 'sm primary', onclick: act(m, 'install') }, 'Установить') : [
            m.loaded ? h('button', { class: 'sm', onclick: act(m, 'disable') }, 'Выключить') : h('button', { class: 'sm', onclick: act(m, 'enable') }, 'Включить'),
            h('button', { class: 'sm danger', onclick: act(m, 'remove') }, 'Удалить')])))))));
  };
  await loadVersions();
}

// ---------- Базы данных ----------
async function pageDB(main) {
  let eng = 'mysql';
  const st = await api('GET', '/db');
  const body = h('div');
  const tabs = h('div', { class: 'tabs' });
  main.append(h('h1', {}, 'Базы данных'), tabs, body);
  const drawTabs = () => tabs.replaceChildren(...[['mysql', 'MySQL / MariaDB'], ['postgres', 'PostgreSQL']].map(([k, l]) => h('button', { class: eng === k ? 'on' : '', onclick: () => { eng = k; drawTabs(); load(); } }, l + (st[k]?.installed ? '' : ' (не установлен)'))));
  const showCreds = (title, o) => modal(title, h('div', {}, h('p', { class: 'muted' }, 'Сохраните пароль — повторно он показан не будет.'), h('pre', { class: 'log' }, Object.entries(o).map(([k, v]) => k + ': ' + v).join('\n'))));
  async function load() {
    if (!st[eng]?.installed) {
      const name = eng === 'mysql' ? 'MariaDB (совместима с MySQL)' : 'PostgreSQL';
      body.replaceChildren(h('div', { class: 'card empty' }, icon('database', 36), h('h2', {}, 'Сервер СУБД не установлен'),
        h('p', { class: 'muted' }, 'Панель установит ' + name + ' через apt и включит автозапуск.'),
        h('button', { class: 'primary', onclick: guard(async () => { const r = await api('POST', `/db/${eng}/install`); jobModal(r.job, 'Установка ' + name, () => renderShell()); }) }, 'Установить ' + (eng === 'mysql' ? 'MariaDB' : 'PostgreSQL'))));
      return;
    }
    const [dbs, users, backups] = await Promise.all([api('GET', `/db/${eng}/databases`), api('GET', `/db/${eng}/users`), api('GET', '/dbbackups')]);
    body.replaceChildren(
      h('div', { class: 'card' }, h('div', { class: 'row sp' }, h('h2', {}, 'Базы данных'), h('button', { class: 'primary sm', onclick: createDB }, '+ База')),
        h('table', {}, h('tbody', {}, dbs.map(d => h('tr', {}, h('td', { class: 'mono' }, d), h('td', { class: 'row', style: 'justify-content:flex-end' },
          h('button', { class: 'sm', onclick: guard(async () => { const r = await api('POST', `/db/${eng}/databases/${d}/backup`); jobModal(r.job, 'Бэкап ' + d, load); }) }, 'Бэкап'),
          h('button', { class: 'sm', onclick: () => grant(d, users) }, 'Права'),
          h('button', { class: 'sm danger', onclick: () => confirmBox('Удалить базу ' + d + '? Данные будут потеряны.', async () => { await api('DELETE', `/db/${eng}/databases/${d}`); load(); }) }, 'Удалить'))))))),
      h('div', { class: 'card' }, h('div', { class: 'row sp' }, h('h2', {}, 'Пользователи'), h('button', { class: 'primary sm', onclick: createUser }, '+ Пользователь')),
        h('table', {}, h('tbody', {}, users.map(u => h('tr', {}, h('td', { class: 'mono' }, u.name + (u.host ? '@' + u.host : '')), h('td', { style: 'text-align:right' },
          h('button', { class: 'sm danger', onclick: () => confirmBox('Удалить пользователя ' + u.name + '?', async () => { await api('DELETE', `/db/${eng}/users/${u.name}`); load(); }) }, 'Удалить'))))))),
      h('div', { class: 'card' }, h('h2', {}, 'Резервные копии'), backups.length ? h('table', {}, h('tbody', {}, backups.map(b => h('tr', {}, h('td', { class: 'mono' }, b.file), h('td', { class: 'muted' }, fmtBytes(b.size) + ' · ' + fmtDate(b.time)), h('td', { class: 'row', style: 'justify-content:flex-end' },
        h('a', { class: 'btn sm', href: '/api/dbbackups/' + b.file, style: 'text-decoration:none' }, 'Скачать'),
        h('button', { class: 'sm', onclick: () => restore(b, dbs) }, 'Восстановить')))))) : h('div', { class: 'muted' }, 'Копий пока нет')));
  }
  function createDB() {
    const name = h('input', { placeholder: 'mydb' }), user = h('input', { placeholder: 'пусто — без пользователя' }), pass = h('input', { placeholder: 'пусто — сгенерировать' });
    const coll = h('select', {}, ['utf8mb4_unicode_ci', 'utf8mb4_general_ci', 'utf8mb4_0900_ai_ci', 'utf8mb4_bin', 'utf8_general_ci', 'latin1_swedish_ci'].map(c => h('option', { value: c }, c)));
    modal('Новая база данных', h('div', {}, field('Имя', name), eng === 'mysql' ? field('Кодировка', coll) : null, field('Создать пользователя (владельца)', user), field('Пароль', pass)),
      [{ label: 'Отмена' }, { label: 'Создать', primary: true, onclick: async () => { const r = await api('POST', `/db/${eng}/databases`, { name: name.value, collation: coll.value, user: user.value, password: pass.value }); load(); if (r.user) showCreds('Данные доступа', { 'БД': r.name, 'Пользователь': r.user, 'Пароль': r.password }); } }]);
  }
  function createUser() {
    const name = h('input'), pass = h('input', { placeholder: 'пусто — сгенерировать' });
    modal('Новый пользователь', h('div', {}, field('Имя', name), field('Пароль', pass)),
      [{ label: 'Отмена' }, { label: 'Создать', primary: true, onclick: async () => { const r = await api('POST', `/db/${eng}/users`, { name: name.value, password: pass.value }); load(); showCreds('Данные доступа', { 'Пользователь': r.name, 'Пароль': r.password }); } }]);
  }
  function grant(d, users) {
    const sel = h('select', {}, users.map(u => h('option', { value: u.name }, u.name)));
    modal('Права на ' + d, field('Выдать ALL PRIVILEGES пользователю', sel), [{ label: 'Отмена' }, { label: 'Выдать', primary: true, onclick: async () => { await api('POST', `/db/${eng}/grant`, { db: d, user: sel.value }); toast('Права выданы'); } }]);
  }
  function restore(b, dbs) {
    const sel = h('select', {}, dbs.map(d => h('option', { value: d }, d)));
    modal('Восстановление ' + b.file, h('div', {}, h('p', { class: 'muted' }, 'Дамп будет загружен в выбранную существующую базу.'), field('База', sel)),
      [{ label: 'Отмена' }, { label: 'Восстановить', primary: true, onclick: async () => { const r = await api('POST', `/db/${eng}/databases/${sel.value}/restore`, { file: b.file }); jobModal(r.job, 'Восстановление'); } }]);
  }
  drawTabs(); await load();
}

// ---------- PKI ----------
async function pagePKI(main) {
  const body = h('div');
  main.append(h('h1', {}, 'SSL / PKI'), body);
  async function load() {
    const d = await api('GET', '/pki');
    const caCard = d.ca.exists ?
      h('div', { class: 'card' }, h('h2', {}, 'Корневой сертификат (Root CA)'), h('div', {}, d.ca.subject), h('div', { class: 'muted small' }, 'Действителен до ' + fmtDate(d.ca.not_after)), h('div', { class: 'mono small muted', style: 'word-break:break-all' }, 'SHA-256: ' + d.ca.fingerprint),
        h('div', { class: 'row', style: 'margin-top:10px' }, h('a', { class: 'btn', href: '/api/pki/ca.crt', style: 'text-decoration:none' }, 'Скачать ca.crt'), h('a', { class: 'btn', href: '/api/pki/crl', style: 'text-decoration:none' }, 'Скачать CRL'))) :
      h('div', { class: 'card' }, h('h2', {}, 'Корневой сертификат не создан'), h('p', { class: 'muted' }, 'Создайте собственный Root CA, чтобы выпускать сертификаты для локальной разработки и закрытого контура.'), h('button', { class: 'primary', onclick: createCA }, 'Создать Root CA'));
    const certs = h('div', { class: 'card' }, h('div', { class: 'row sp' }, h('h2', {}, 'Выпущенные сертификаты'), d.ca.exists ? h('button', { class: 'primary sm', onclick: issue }, '+ Выпустить') : null),
      d.certs.length ? h('table', {}, h('thead', {}, h('tr', {}, ['Домен', 'SAN', 'До', 'Статус', ''].map(x => h('th', {}, x)))), h('tbody', {}, d.certs.map(c => h('tr', {},
        h('td', {}, h('b', {}, c.domain)), h('td', { class: 'small muted' }, (c.sans || []).join(', ')), h('td', {}, new Date(c.not_after).toLocaleDateString('ru-RU')),
        h('td', {}, h('span', { class: 'badge ' + (c.revoked ? 'err' : 'ok') }, c.revoked ? 'отозван' : 'действует')),
        h('td', { class: 'row' }, h('a', { class: 'btn sm', href: `/api/pki/certs/${c.serial}/download`, style: 'text-decoration:none' }, 'PEM'),
          c.revoked ? null : h('button', { class: 'sm', onclick: () => confirmBox('Отозвать сертификат ' + c.domain + '? Он будет снят с сайтов.', async () => { await api('POST', `/pki/certs/${c.serial}/revoke`); load(); }, 'Отозвать') }, 'Отозвать'),
          h('button', { class: 'sm danger', onclick: () => confirmBox('Удалить сертификат ' + c.domain + '?', async () => { await api('DELETE', `/pki/certs/${c.serial}`); load(); }) }, 'Удалить')))))) : h('div', { class: 'muted' }, 'Сертификатов нет'));
    body.replaceChildren(caCard, certs);
  }
  function createCA() {
    const cn = h('input', { value: 'GoServerPanel Root CA' }), org = h('input', { placeholder: 'Организация' }), years = h('input', { value: '10', type: 'number' });
    modal('Создание Root CA', h('div', {}, field('Common Name', cn), field('Организация', org), field('Срок, лет', years), h('p', { class: 'muted small' }, 'Генерация RSA-4096 может занять несколько секунд.')),
      [{ label: 'Отмена' }, { label: 'Создать', primary: true, onclick: async () => { await api('POST', '/pki/ca', { cn: cn.value, org: org.value, years: +years.value }); load(); } }]);
  }
  function issue() {
    const dom = h('input', { placeholder: 'dev.local' }), sans = h('input', { placeholder: 'www.dev.local, 192.168.1.10' }), days = h('input', { value: '397', type: 'number' });
    modal('Выпуск сертификата', h('div', {}, field('Домен', dom), field('Дополнительные SAN (через запятую)', sans), field('Срок, дней (до 825)', days)),
      [{ label: 'Отмена' }, { label: 'Выпустить', primary: true, onclick: async () => { await api('POST', '/pki/certs', { domain: dom.value, sans: sans.value.split(',').map(x => x.trim()).filter(Boolean), days: +days.value }); load(); toast('Выпущен. Назначьте его сайту в разделе «Веб-сайты».'); } }]);
  }
  await load();
}

// ---------- Терминал ----------
function loadScript(src) { return new Promise((res, rej) => { const s = document.createElement('script'); s.src = src; s.onload = res; s.onerror = rej; document.head.append(s); }); }
function loadCSS(href) { document.head.append(h('link', { rel: 'stylesheet', href })); }

async function pageTerminal(main) {
  if (!ME.terminal_enabled) { main.append(h('h1', {}, 'Терминал'), h('div', { class: 'card muted' }, 'Терминал отключён в конфигурации.')); return; }
  const box = h('div');
  main.append(h('h1', {}, 'Терминал'), box);
  const pass = h('input', { type: 'password', autocomplete: 'current-password' }), totp = h('input', { inputmode: 'numeric', maxlength: 6, placeholder: 'если включена 2FA' });
  const err = h('div', { class: 'err-box', style: 'display:none' });
  const go = async () => {
    try {
      const r = await api('POST', '/terminal/token', { password: pass.value, totp: totp.value });
      pass.value = ''; startTerm(box, r.token);
    } catch (e) { err.textContent = e.message; err.style.display = 'block'; }
  };
  pass.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  box.append(h('div', { class: 'card', style: 'max-width:420px' }, h('h2', {}, 'Подтвердите личность'), h('p', { class: 'muted small' }, 'Доступ к терминалу даёт полный контроль над сервером (root). Подтвердите пароль для открытия сессии.'), err, field('Пароль', pass), field('Код 2FA', totp), h('button', { class: 'primary', onclick: go }, 'Открыть терминал')));
}

async function startTerm(box, token) {
  const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/api/terminal/ws?token=' + encodeURIComponent(token);
  const status = h('span', { class: 'badge warn' }, 'подключение');
  const holder = h('div');
  box.replaceChildren(h('div', { class: 'row', style: 'margin-bottom:8px' }, status, h('button', { class: 'sm', onclick: () => renderShell() }, 'Новая сессия')), holder);
  const enc = new TextEncoder(), dec = new TextDecoder();
  const ws = new WebSocket(url); ws.binaryType = 'arraybuffer';
  cleanups.push(() => { try { ws.close(); } catch (e) { /* */ } });
  const send = s => { if (ws.readyState === 1) ws.send(enc.encode(s)); };
  const sendResize = (cols, rows) => { if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'resize', cols, rows })); };
  let write, size;

  // Предпочитаем xterm.js, если положен в ui/static/vendor/
  let useX = false;
  if (ME.xterm) { try { await loadScript('/vendor/xterm.js'); loadCSS('/vendor/xterm.css'); useX = typeof window.Terminal === 'function'; } catch (e) { /* запасной эмулятор */ } }
  if (useX) {
    const term = new window.Terminal({ cursorBlink: true, fontSize: 14, theme: { background: '#0d1117' } });
    let fit = null;
    try { await loadScript('/vendor/xterm-addon-fit.js'); fit = new window.FitAddon.FitAddon(); term.loadAddon(fit); } catch (e) { /* без fit */ }
    const el = h('div', { style: 'height:62vh' }); holder.append(el); term.open(el); if (fit) fit.fit();
    term.onData(send); term.onResize(s => sendResize(s.cols, s.rows));
    write = data => term.write(data); size = () => ({ cols: term.cols, rows: term.rows });
    term.focus();
  } else {
    const t = simpleTerm(holder, send);
    write = t.write; size = t.size;
  }
  ws.onopen = () => { status.textContent = 'подключено'; status.className = 'badge ok'; const s = size(); sendResize(s.cols, s.rows); };
  ws.onmessage = ev => { if (typeof ev.data === 'string') write(ev.data); else write(new Uint8Array(ev.data)); };
  ws.onclose = () => { status.textContent = 'сессия закрыта'; status.className = 'badge err'; };
  const onResize = () => { const s = size(); sendResize(s.cols, s.rows); };
  window.addEventListener('resize', onResize); cleanups.push(() => window.removeEventListener('resize', onResize));
}

// Запасной мини-эмулятор терминала (SGR-цвета, \r \n \b, стирание, перемещение курсора).
// Полноэкранные программы (vim, htop) отображаются неточно — для них положите xterm.js в ui/static/vendor/.
function simpleTerm(holder, send) {
  const el = h('div', { class: 'term', tabindex: 0 });
  holder.append(el);
  const dec = new TextDecoder('utf-8');
  let lines = [[]], row = 0, col = 0, cls = '', esc = null, scheduled = false;
  const MAX = 3000;
  const ensure = () => { while (lines.length <= row) lines.push([]); };
  const put = ch => { ensure(); const l = lines[row]; while (l.length < col) l.push([' ', '']); l[col] = [ch, cls]; col++; };
  const newline = () => { row++; ensure(); if (lines.length > MAX) { lines.shift(); row--; } };
  const sgr = params => {
    const ps = params === '' ? [0] : params.split(';').map(Number);
    for (const p of ps) {
      if (p === 0) cls = ''; else if (p === 1) cls += ' b'; else if (p === 4) cls += ' u';
      else if ((p >= 30 && p <= 37) || (p >= 90 && p <= 97)) cls = cls.replace(/ ?c\d+/g, '') + ' c' + p;
      else if (p === 39) cls = cls.replace(/ ?c\d+/g, '');
    }
  };
  const csi = (params, fin) => {
    const n = parseInt(params, 10) || 1;
    switch (fin) {
      case 'm': sgr(params); break;
      case 'K': ensure(); if (params === '2') lines[row] = []; else if (params === '1') { for (let i = 0; i <= col; i++) if (lines[row][i]) lines[row][i] = [' ', '']; } else lines[row].length = Math.min(lines[row].length, col); break;
      case 'J': if (params === '2' || params === '3') { lines = [[]]; row = 0; col = 0; } else if (params === '' || params === '0') { ensure(); lines[row].length = Math.min(lines[row].length, col); lines.length = row + 1; } break;
      case 'H': case 'f': { const [r, c] = params.split(';').map(x => parseInt(x, 10) || 1); if (!params) { /* домой */ } row = Math.max(0, Math.min(lines.length - 1 + 100, r - 1 + (lines.length > 40 ? lines.length - 40 : 0))); col = c - 1; ensure(); break; }
      case 'A': row = Math.max(0, row - n); break;
      case 'B': row += n; ensure(); break;
      case 'C': col += n; break;
      case 'D': col = Math.max(0, col - n); break;
      case 'G': col = n - 1; break;
      case 'P': ensure(); lines[row].splice(col, n); break;
      case '@': ensure(); for (let i = 0; i < n; i++) lines[row].splice(col, 0, [' ', '']); break;
      default: break; // прочие CSI игнорируем
    }
  };
  const feed = str => {
    for (const ch of str) {
      if (esc !== null) {
        esc += ch;
        if (esc === '\x1b') continue;
        if (esc[1] === '[') { if (/[@-~]/.test(ch) && esc.length > 2) { const m = /^\x1b\[[?>]?([0-9;]*)(.)$/.exec(esc); if (m && !/[?>]/.test(esc[2])) csi(m[1], m[2]); esc = null; } }
        else if (esc[1] === ']') { if (ch === '\x07' || esc.endsWith('\x1b\\')) esc = null; }
        else esc = null;
        continue;
      }
      switch (ch) {
        case '\x1b': esc = '\x1b'; break;
        case '\r': col = 0; break;
        case '\n': newline(); break;
        case '\b': col = Math.max(0, col - 1); break;
        case '\x07': break;
        case '\t': { const n = 8 - (col % 8); for (let i = 0; i < n; i++) put(' '); break; }
        default: if (ch >= ' ') put(ch);
      }
    }
    if (!scheduled) { scheduled = true; requestAnimationFrame(render); }
  };
  const render = () => {
    scheduled = false;
    const frag = document.createDocumentFragment();
    lines.forEach((l, r) => {
      let run = '', rc = null;
      const flush = () => { if (run) { frag.append(rc ? h('span', { class: rc.trim() }, run) : document.createTextNode(run)); run = ''; } };
      const len = r === row ? Math.max(l.length, col + 1) : l.length;
      for (let i = 0; i < len; i++) {
        const cell = l[i] || [' ', ''];
        if (r === row && i === col) { flush(); frag.append(h('span', { class: 'cur' }, cell[0])); rc = null; continue; }
        if (cell[1] !== rc) { flush(); rc = cell[1]; }
        run += cell[0];
      }
      flush(); frag.append('\n');
    });
    el.replaceChildren(frag);
    el.scrollTop = el.scrollHeight;
  };
  const keymap = { Enter: '\r', Backspace: '\x7f', Tab: '\t', Escape: '\x1b', ArrowUp: '\x1b[A', ArrowDown: '\x1b[B', ArrowRight: '\x1b[C', ArrowLeft: '\x1b[D', Home: '\x1b[H', End: '\x1b[F', Delete: '\x1b[3~', PageUp: '\x1b[5~', PageDown: '\x1b[6~' };
  el.addEventListener('keydown', e => {
    if (e.metaKey) return;
    let s = null;
    if (e.ctrlKey && !e.altKey && e.key.length === 1) {
      const c = e.key.toLowerCase().charCodeAt(0);
      if (c >= 97 && c <= 122) { if (e.key === 'v' && e.shiftKey === false && false) return; s = String.fromCharCode(c - 96); }
    } else if (keymap[e.key]) s = keymap[e.key];
    else if (e.key.length === 1 && !e.ctrlKey) s = (e.altKey ? '\x1b' : '') + e.key;
    if (s !== null) { e.preventDefault(); send(s); }
  });
  el.addEventListener('paste', e => { e.preventDefault(); send(e.clipboardData.getData('text')); });
  el.focus(); render();
  return {
    write: data => feed(typeof data === 'string' ? data : dec.decode(data, { stream: true })),
    size: () => {
      const probe = h('span', { style: 'position:absolute;visibility:hidden;font:inherit' }, 'W'.repeat(20)); el.append(probe);
      const cw = probe.getBoundingClientRect().width / 20 || 8; probe.remove();
      const lh = parseFloat(getComputedStyle(el).lineHeight) || 16;
      return { cols: Math.max(20, Math.floor((el.clientWidth - 16) / cw)), rows: Math.max(5, Math.floor((el.clientHeight - 16) / lh)) };
    },
  };
}

// ---------- Файлы ----------
async function pageFiles(main) {
  let path = '';
  const body = h('div');
  main.append(h('h1', {}, 'Файловый менеджер'), body);
  const join = (a, b) => (a.endsWith('/') ? a : a + '/') + b;
  const parent = p => { const i = p.lastIndexOf('/'); return i <= 0 ? '/' : p.slice(0, i); };
  async function load(p) {
    path = p ?? path;
    const r = await api('GET', '/files?path=' + encodeURIComponent(path));
    const roots = r.roots || [];
    const crumbs = path ? h('div', { class: 'crumbs row small' }, h('a', { onclick: () => load('') }, '⌂'), path.split('/').filter(Boolean).map((seg, i, arr) => [h('span', { class: 'muted' }, '/'), h('a', { onclick: () => load('/' + arr.slice(0, i + 1).join('/')) }, seg)])) : h('div', { class: 'muted small' }, 'Разрешённые каталоги');
    const rows = path ? [h('tr', {}, h('td', { colspan: 4 }, h('a', { class: 'crumbs', onclick: () => { const up = parent(path); load(roots.length && !up ? '' : up); } }, '↑ ..')))] : [];
    const inputFile = h('input', { type: 'file', multiple: true, style: 'display:none', onchange: guard(async e => { const fd = new FormData(); for (const f of e.target.files) fd.append('file', f); const rr = await fetch('/api/files/upload?dir=' + encodeURIComponent(path), { method: 'POST', headers: { 'X-Requested-With': 'gsp' }, body: fd }); const j = await rr.json(); if (!rr.ok) throw new Error(j.error); toast('Загружено файлов: ' + j.files); load(); }) });
    const tools = path ? h('div', { class: 'row', style: 'margin:10px 0' },
      h('button', { class: 'sm', onclick: () => { const n = h('input', { placeholder: 'имя каталога' }); modal('Новый каталог', field('Имя', n), [{ label: 'Отмена' }, { label: 'Создать', primary: true, onclick: async () => { await api('POST', '/files/mkdir', { path: join(path, n.value) }); load(); } }]); } }, '+ Каталог'),
      h('button', { class: 'sm', onclick: () => { const n = h('input', { placeholder: 'file.txt' }); modal('Новый файл', field('Имя', n), [{ label: 'Отмена' }, { label: 'Создать', primary: true, onclick: async () => { await api('PUT', '/files/write', { path: join(path, n.value), content: '' }); load(); } }]); } }, '+ Файл'),
      h('button', { class: 'sm', onclick: () => inputFile.click() }, '⇧ Загрузить'), inputFile) : null;
    const entries = path ? r.entries : roots.map(x => ({ name: x.name, is_dir: true, abs: true }));
    entries.forEach(e => {
      const full = e.abs ? e.name : join(path, e.name);
      rows.push(h('tr', {}, h('td', {}, e.is_dir ? h('a', { class: 'crumbs', onclick: () => load(full) }, '📁 ' + e.name) : h('a', { class: 'crumbs', onclick: () => edit(full) }, '📄 ' + e.name)),
        h('td', { class: 'muted small' }, e.is_dir ? '' : fmtBytes(e.size)), h('td', { class: 'muted small mono' }, e.mode || ''),
        h('td', { class: 'row', style: 'justify-content:flex-end' }, e.abs ? null : [
          e.is_dir ? null : h('a', { class: 'btn sm', href: '/api/files/download?path=' + encodeURIComponent(full), style: 'text-decoration:none' }, '⬇'),
          h('button', { class: 'sm', onclick: () => { const n = h('input', { value: e.name }); modal('Переименовать', field('Новое имя', n), [{ label: 'Отмена' }, { label: 'OK', primary: true, onclick: async () => { await api('POST', '/files/rename', { from: full, to: join(path, n.value) }); load(); } }]); } }, '✎'),
          h('button', { class: 'sm danger', onclick: () => confirmBox('Удалить ' + full + '?', async () => { await api('DELETE', '/files?path=' + encodeURIComponent(full)); load(); }) }, '🗑')])));
    });
    body.replaceChildren(h('div', { class: 'card' }, crumbs, tools, h('table', {}, h('tbody', {}, rows))));
  }
  async function edit(full) {
    let content;
    try { content = (await api('GET', '/files/read?path=' + encodeURIComponent(full))).content; } catch (e) { return toast(e.message, true); }
    const ta = h('textarea', { spellcheck: 'false', style: 'min-height:55vh' }); ta.value = content;
    modal(full, ta, [{ label: 'Закрыть' }, { label: 'Сохранить', primary: true, sticky: true, onclick: async () => { await api('PUT', '/files/write', { path: full, content: ta.value }); toast('Сохранено'); return false; } }], true);
  }
  await load('');
}

// ---------- Настройки ----------
async function pageSettings(main) {
  const u = ME.user;
  const old = h('input', { type: 'password' }), nw = h('input', { type: 'password' });
  main.append(h('h1', {}, 'Настройки'),
    h('div', { class: 'card' }, h('h2', {}, 'Смена пароля'), h('div', { class: 'grid' }, field('Текущий пароль', old), field('Новый пароль (≥10 символов)', nw)),
      h('button', { class: 'primary', onclick: guard(async () => { await api('POST', '/me/password', { old: old.value, new: nw.value }); old.value = nw.value = ''; toast('Пароль изменён'); }) }, 'Изменить')));
  const tf = h('div', { class: 'card' });
  const drawTF = () => {
    if (u.totp_enabled) {
      const pw = h('input', { type: 'password' }), code = h('input', { maxlength: 6, inputmode: 'numeric' });
      tf.replaceChildren(h('h2', {}, 'Двухфакторная аутентификация'), h('p', {}, h('span', { class: 'badge ok' }, 'включена')), h('div', { class: 'grid' }, field('Пароль', pw), field('Код из приложения', code)),
        h('button', { class: 'danger', onclick: guard(async () => { await api('POST', '/me/2fa/disable', { password: pw.value, code: code.value }); u.totp_enabled = false; drawTF(); }) }, 'Отключить 2FA'));
    } else {
      tf.replaceChildren(h('h2', {}, 'Двухфакторная аутентификация (TOTP)'), h('p', { class: 'muted' }, 'Google Authenticator, Aegis и др.'),
        h('button', { class: 'primary', onclick: guard(async () => {
          const r = await api('POST', '/me/2fa/setup'); const code = h('input', { maxlength: 6, inputmode: 'numeric' });
          tf.replaceChildren(h('h2', {}, 'Настройка 2FA'), h('p', {}, 'Добавьте ключ вручную в приложение-аутентификатор:'), h('pre', { class: 'log' }, r.secret), h('p', { class: 'small muted mono', style: 'word-break:break-all' }, r.uri), field('Код из приложения', code),
            h('button', { class: 'primary', onclick: guard(async () => { await api('POST', '/me/2fa/enable', { code: code.value }); u.totp_enabled = true; drawTF(); toast('2FA включена'); }) }, 'Подтвердить и включить'));
        }) }, 'Включить 2FA'));
    }
  };
  drawTF(); main.append(tf);
  if (u.role !== 'admin') return;
  const ub = h('div', { class: 'card' }), ab = h('div', { class: 'card' });
  main.append(ub, ab);
  const loadUsers = async () => {
    const list = await api('GET', '/users');
    ub.replaceChildren(h('div', { class: 'row sp' }, h('h2', {}, 'Пользователи'), h('button', { class: 'primary sm', onclick: () => {
      const n = h('input'), p = h('input', { type: 'password' }), r = h('select', {}, h('option', { value: 'viewer' }, 'viewer (только чтение)'), h('option', { value: 'admin' }, 'admin'));
      modal('Новый пользователь', h('div', {}, field('Логин', n), field('Пароль (≥10 символов)', p), field('Роль', r)), [{ label: 'Отмена' }, { label: 'Создать', primary: true, onclick: async () => { await api('POST', '/users', { username: n.value, password: p.value, role: r.value }); loadUsers(); } }]);
    } }, '+ Пользователь')),
      h('table', {}, h('tbody', {}, list.map(x => h('tr', {}, h('td', {}, x.username), h('td', {}, h('span', { class: 'badge' }, x.role)), h('td', {}, x.totp_enabled ? h('span', { class: 'badge ok' }, '2FA') : ''), h('td', { style: 'text-align:right' }, x.id === u.id ? null : h('button', { class: 'sm danger', onclick: () => confirmBox('Удалить ' + x.username + '?', async () => { await api('DELETE', '/users/' + x.id); loadUsers(); }) }, 'Удалить')))))));
  };
  const loadAudit = async () => {
    const list = await api('GET', '/audit');
    ab.replaceChildren(h('div', { class: 'row sp' }, h('h2', {}, 'Журнал аудита'), h('button', { class: 'sm', onclick: loadAudit }, 'Обновить')),
      h('table', {}, h('thead', {}, h('tr', {}, ['Время', 'Пользователь', 'IP', 'Действие', 'Детали'].map(x => h('th', {}, x)))), h('tbody', {}, list.map(a => h('tr', {}, h('td', { class: 'small' }, fmtDate(a.time)), h('td', {}, a.user), h('td', { class: 'mono small' }, a.ip), h('td', { class: 'mono small' }, a.action), h('td', { class: 'small muted' }, a.detail))))));
  };
  await Promise.all([loadUsers(), loadAudit()]);
}

boot();
