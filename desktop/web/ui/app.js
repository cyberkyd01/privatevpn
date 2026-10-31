/* PrivateVPN web UI — vanilla ES2020, no framework, no build step.
 *
 * Security rules (ARCHITECTURE §10.6, §13.4, T7):
 *  - no HTML parsing of strings anywhere (no inner/outer HTML assignment, no
 *    adjacent-HTML insertion, no document writes); every DOM node is created
 *    with createElement and every string is inserted as a text node
 *    (textContent) or a plain attribute value;
 *  - every string that comes from the API passes through clean() first:
 *    C0/C1 controls and bidi controls are removed and the length is capped;
 *  - numbers are range-checked and IP strings validated before display;
 *  - the CSRF token lives in this closure only (never in storage).
 */
'use strict';
(() => {
  const API = '/api/v1';
  const SVGNS = 'http://www.w3.org/2000/svg';
  const PAGE = document.body.dataset.page;

  // ===================================================================
  // Sanitisation of untrusted input (§10.6)
  // ===================================================================
  const STRIP = /[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g;

  /** clean returns a display-safe string: controls/bidi removed, trimmed,
   *  capped at `cap` code points (with an ellipsis). Non-strings → ''. */
  function clean(v, cap = 64) {
    if (typeof v !== 'string') return '';
    const s = v.replace(STRIP, '').trim();
    const cps = Array.from(s);
    return cps.length > cap ? cps.slice(0, cap).join('') + '…' : s;
  }
  const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  const int = (v, min, max) => (Number.isInteger(v) && v >= min && v <= max ? v : null);
  const real = (v, min, max) => (typeof v === 'number' && Number.isFinite(v) && v >= min && v <= max ? v : null);
  const bool = (v) => (v === true ? true : v === false ? false : null);

  const V4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
  function isV6(s) {
    if (s.length < 2 || s.length > 45 || !s.includes(':') || !/^[0-9A-Fa-f:.]+$/.test(s)) return false;
    try { return new URL('http://[' + s + ']/').hostname.length > 2; } catch (_) { return false; }
  }
  const v4 = (v) => (typeof v === 'string' && V4.test(v.trim()) ? v.trim() : '');
  const v6 = (v) => (typeof v === 'string' && isV6(v.trim()) ? v.trim() : '');
  const ipAny = (v) => v4(v) || v6(v);
  /** ipPrefix accepts "a.b.c.d" or "a.b.c.d/nn". */
  function ipPrefix(v) {
    if (typeof v !== 'string') return '';
    const parts = v.trim().split('/');
    if (parts.length > 2 || !v4(parts[0])) return '';
    if (parts.length === 1) return parts[0];
    return /^\d{1,2}$/.test(parts[1]) && Number(parts[1]) <= 32 ? parts[0] + '/' + Number(parts[1]) : '';
  }
  const subnet4 = (v) => (typeof v === 'string' && v.includes('/') ? ipPrefix(v) : '');
  /** Identifiers (uuid, base64url public keys) used in URLs and comparisons. */
  const idStr = (v) => (typeof v === 'string' && v.length <= 128 && /^[A-Za-z0-9._~:+/=-]+$/.test(v) ? v : '');
  const enc = encodeURIComponent;

  // ===================================================================
  // DOM helpers
  // ===================================================================
  const $ = (id) => document.getElementById(id);
  const PROPS = new Set(['value', 'checked', 'disabled', 'hidden']);
  const BLOCKED_ATTR = /^(on|href$|src$|srcdoc$|style$|action$|formaction$)/i;

  /** h(tag, props, ...children) creates an element. Strings become text
   *  nodes; attribute values are set with setAttribute (never parsed). */
  function h(tag, props, ...kids) {
    const e = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') e.className = v;
        else if (k === 'text') e.textContent = v;
        else if (k === 'on') for (const [ev, fn] of Object.entries(v)) e.addEventListener(ev, fn);
        else if (PROPS.has(k)) e[k] = v;
        else if (BLOCKED_ATTR.test(k)) throw new Error('blocked attribute ' + k);
        else e.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid === null || kid === undefined || kid === false || kid === '') continue;
      e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return e;
  }

  /** icon returns <svg><use href="/icons.svg#name"></svg>; names are
   *  constants from this file, never data. */
  function icon(name, cls = 'icon') {
    const s = document.createElementNS(SVGNS, 'svg');
    s.setAttribute('class', cls);
    s.setAttribute('aria-hidden', 'true');
    s.setAttribute('focusable', 'false');
    const u = document.createElementNS(SVGNS, 'use');
    u.setAttribute('href', '/icons.svg#' + name);
    s.append(u);
    return s;
  }
  const badge = (text, kind, ic) => h('span', { class: 'badge' + (kind ? ' ' + kind : '') }, ic ? icon(ic) : null, text);

  // ===================================================================
  // Formatting
  // ===================================================================
  const OS_LABEL = { windows: 'Windows', macos: 'macOS', linux: 'Linux', android: 'Android' };
  const OS_ICON = { windows: 'i-os-windows', macos: 'i-os-macos', linux: 'i-os-linux', android: 'i-os-android' };
  const osIcon = (os) => icon(OS_ICON[os] || 'i-os-unknown');
  const plural = (n, one, many) => n + ' ' + (n === 1 ? one : many);

  function fmtDuration(sec) {
    if (sec === null || sec === undefined) return '';
    sec = Math.floor(sec);
    const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
    if (d > 0) return d + 'd ' + hh + 'h';
    if (hh > 0) return hh + 'h ' + m + 'm';
    if (m > 0) return m + 'm ' + s + 's';
    return s + 's';
  }
  /** tsMs accepts unix seconds or milliseconds. */
  const tsMs = (v) => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? (v > 1e11 ? v : v * 1000) : null);
  function fmtAgoMs(ms) {
    if (ms === null || ms === undefined || !Number.isFinite(ms)) return '';
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 5) return 'just now';
    if (s < 60) return s + ' s ago';
    const m = Math.round(s / 60);
    if (m < 60) return m + ' min ago';
    const hh = Math.round(m / 60);
    if (hh < 48) return hh + ' h ago';
    return Math.round(hh / 24) + ' days ago';
  }
  const fmtAgoTs = (ts) => { const ms = tsMs(ts); return ms === null ? '' : fmtAgoMs(Date.now() - ms); };
  function fmtDate(ts) {
    const ms = tsMs(ts);
    if (ms === null) return '';
    const d = new Date(ms);
    if (Number.isNaN(d.getTime())) return '';
    try { return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }); } catch (_) { return d.toISOString(); }
  }
  function fmtBytes(n) {
    if (n === null || n === undefined) return '';
    const u = ['B', 'kB', 'MB', 'GB', 'TB'];
    let i = 0, v = n;
    while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
    return (i === 0 ? String(v) : v.toFixed(v < 10 ? 2 : v < 100 ? 1 : 0)) + ' ' + u[i];
  }
  function fmtOffset(sec) {
    const a = Math.abs(sec);
    return 'UTC' + (sec < 0 ? '-' : '+') + String(Math.floor(a / 3600)).padStart(2, '0') + ':' + String(Math.floor((a % 3600) / 60)).padStart(2, '0');
  }

  const NAT_KEYS = ['none', 'nat', 'cgnat', 'unknown'];
  function natText(nat, wg, ctrl) {
    switch (nat) {
      case 'nat': return 'Reachable on this LAN. For access from the Internet, forward UDP ' + (wg || 51820) + ' and ' + (ctrl || 51821) + ' on your router to this device.';
      case 'cgnat': return 'Reachable on this LAN only (mobile network uses carrier NAT; port forwarding is not possible).';
      case 'none': return 'Directly reachable — no NAT detected in front of this device.';
      default: return 'Reachability from the Internet is unknown.';
    }
  }
  const KEY_WARNING = "Anyone with this key can use this network's gateways — their Internet connection and, where allowed, their local network. Share it only with devices you own or people you trust.";

  // ===================================================================
  // API
  // ===================================================================
  class ApiError extends Error {
    constructor(code, message, status) { super(message); this.code = code; this.status = status; }
  }
  let csrf = '';
  let signingOut = false;

  async function api(method, path, body) {
    const init = { method, headers: {}, credentials: 'same-origin', cache: 'no-store', redirect: 'error' };
    if (method !== 'GET' && csrf) init.headers['X-PVN-CSRF'] = csrf;
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(API + path, init);
    } catch (_) {
      throw new ApiError('offline', 'PrivateVPN is not responding. Is it still running?', 0);
    }
    let data = null;
    try {
      const text = await res.text();
      if (text) data = JSON.parse(text);
    } catch (_) { data = null; }
    if (!res.ok) {
      if (res.status === 401 && PAGE === 'app' && path !== '/session') sessionEnded();
      const code = isObj(data) && typeof data.code === 'string' ? clean(data.code, 40) : 'http_' + res.status;
      const msg = isObj(data) && typeof data.message === 'string' ? clean(data.message, 300) : clean(res.statusText, 80) || 'Request failed';
      throw new ApiError(code, msg, res.status);
    }
    return isObj(data) ? data : {};
  }

  const ERR_TEXT = {
    key_format: "That doesn't look like a PrivateVPN key. Check for typos — it starts with PVN1-.",
    key_mismatch: "This key doesn't belong to this gateway's network.",
    unreachable: 'The gateway did not respond. Check that it is online and reachable from this device.',
    timeout: 'The gateway did not respond in time.',
    keyring_full: 'Your keyring is full (16 networks). Remove one under Networks first.',
    in_use: 'This network is served by your gateway. Turn gateway mode off or switch it to another network first.',
    locked: "You don't have this gateway's key yet.",
    elevation_needed: 'Administrator approval is needed for client mode. Approve the system prompt and try again.',
    clock_skew: "This device's clock differs too much from the gateway's. Check the date and time settings on both.",
    unsupported: 'Not supported on this device.',
    offline: 'PrivateVPN is not responding. Is it still running?',
    rate_limited: 'Too many attempts — wait a moment and try again.',
  };
  const errText = (e) => (e instanceof ApiError ? ERR_TEXT[e.code] || e.message || 'Something went wrong.' : 'Something went wrong.');

  // ===================================================================
  // Toasts and dialogs
  // ===================================================================
  function toast(msg, kind) {
    const box = $('toasts');
    if (!box) return;
    const t = h('div', { class: 'toast' + (kind === 'error' ? ' error' : '') }, msg);
    box.append(t);
    while (box.childElementCount > 4) box.firstElementChild.remove();
    setTimeout(() => t.remove(), kind === 'error' ? 8000 : 4000);
  }

  /** confirmDlg shows the modal dialog and resolves true/false. */
  function confirmDlg({ title, text, extra, ok = 'OK', danger = false }) {
    const dlg = $('dlg');
    if (!dlg || typeof dlg.showModal !== 'function') return Promise.resolve(window.confirm(title));
    $('dlg-title').textContent = title;
    $('dlg-text').textContent = text || '';
    $('dlg-extra').replaceChildren(...(extra || []));
    const okBtn = $('dlg-ok'), cancelBtn = $('dlg-cancel');
    okBtn.textContent = ok;
    okBtn.className = 'btn ' + (danger ? 'danger' : 'primary');
    return new Promise((resolve) => {
      let settled = false;
      const finish = (v) => {
        if (settled) return;
        settled = true;
        okBtn.removeEventListener('click', onOk);
        cancelBtn.removeEventListener('click', onCancel);
        dlg.removeEventListener('close', onCancel);
        if (dlg.open) dlg.close();
        resolve(v);
      };
      const onOk = () => finish(true);
      const onCancel = () => finish(false);
      okBtn.addEventListener('click', onOk);
      cancelBtn.addEventListener('click', onCancel);
      dlg.addEventListener('close', onCancel);
      dlg.showModal();
      (danger ? cancelBtn : okBtn).focus();
    });
  }

  async function copyText(text, msg) {
    try {
      await navigator.clipboard.writeText(text);
      toast(msg || 'Copied to the clipboard.');
    } catch (_) {
      toast('Could not copy — select the text and copy it manually.', 'error');
    }
  }
  async function pasteInto(input) {
    try {
      const t = await navigator.clipboard.readText();
      input.value = t.trim().slice(0, 200);
      input.dispatchEvent(new Event('input'));
    } catch (_) {
      toast('Paste into the field with Ctrl+V or ⌘V.');
    }
    input.focus();
  }

  function setBusy(btn, on) {
    if (!btn) return;
    btn.classList.toggle('busy', !!on);
    btn.disabled = !!on;
  }

  // ===================================================================
  // Login page
  // ===================================================================
  async function bootLogin() {
    const params = new URLSearchParams(location.hash.slice(1));
    const tok = params.get('t');
    if (!tok) return;
    params.delete('t');
    const rest = params.toString();
    // Remove the single-use token from the address bar and history at once.
    history.replaceState(null, '', location.pathname + location.search);
    const msg = $('login-msg'), detail = $('login-detail');
    msg.textContent = 'Signing in…';
    try {
      await api('POST', '/session', { token: tok });
    } catch (e) {
      if (e.code === 'rate_limited') {
        msg.textContent = 'Too many attempts.';
        detail.textContent = 'Wait a moment, then open PrivateVPN from the tray icon again.';
      } else if (e.code === 'offline') {
        msg.textContent = 'PrivateVPN is not responding.';
        detail.textContent = 'Make sure PrivateVPN is running, then open it from the tray icon.';
      } else {
        msg.textContent = 'This sign-in link has expired or was already used.';
        detail.textContent = 'Open PrivateVPN from the tray icon again. Each link works once, for one minute.';
      }
      return;
    }
    // From "/" to "/#…" is a fragment-only navigation (no reload), so with
    // extra parameters (e.g. the tray's unlock=<id>) set the URL and reload.
    if (rest) {
      history.replaceState(null, '', '/#' + rest);
      location.reload();
    } else {
      location.replace('/');
    }
  }

  // ===================================================================
  // App state and normalisation of API data
  // ===================================================================
  // Client states of status.client.state. Once a tunnel exists the engine
  // never removes it by itself (fail closed): "degraded" holds traffic in
  // the tunnel while it reconnects, "blocked" keeps the kill switch's block
  // until the user reconnects or disconnects.
  // Wording for each state: clientLook().
  const CLIENT_STATES = new Set(['idle', 'joining', 'tunnel_up', 'connected', 'degraded', 'blocked']);
  const ACTIVE = new Set(['joining', 'tunnel_up', 'connected', 'degraded', 'blocked']);
  const SEVERITIES = ['error', 'warning', 'info'];
  const SEV_LABEL = { error: 'Problem', warning: 'Warning', info: 'Note' };
  const PROBLEM_ACTIONS = ['disconnect', 'reconnect', 'add_firewall', 'settings'];

  const S = {
    view: 'gateways',
    status: null,
    gateways: [],
    keyring: [],
    settings: null,
    log: [],
    errors: {},
    prompt: '',            // gateway id whose inline key prompt is open
    busy: new Set(),       // gateway ids with a request in flight
    gwBusy: false,         // gateway-mode switch request in flight
    details: null,         // open ⓘ panel
    revealed: new Map(),   // keyring id → { key, timer }
    banners: new Map(),    // key → { kind, text, action }
    selftest: null,
    disconnecting: false,  // client.disconnect in flight (may show an admin prompt)
    firewallBusy: false,   // firewall.add in flight
    ksBusy: false,         // kill-switch settings request in flight
    lastConnectId: '',     // gateway this page last asked to connect to
    pendingUnlock: '',
    pendingUnlockUntil: 0,
    sseOK: false,
    quit: false,
  };

  function normStatus(s) {
    if (!isObj(s)) return null;
    const g = isObj(s.gateway) ? s.gateway : {};
    const c = isObj(s.client) ? s.client : {};
    return {
      version: clean(s.version, 32),
      os: OS_LABEL[s.os] ? s.os : '',
      device_name: clean(s.device_name, 32),
      keyring_count: isObj(s.keyring) ? int(s.keyring.count, 0, 64) : null,
      dual_role: s.dual_role === true,
      problems: normProblems(s.problems),
      gateway: {
        enabled: g.enabled === true,
        network: isObj(g.network) && idStr(g.network.id) ? { id: idStr(g.network.id), label: clean(g.network.label, 32) || 'Unnamed network' } : null,
        clients: int(g.clients, 0, 253),
        uptime_sec: int(g.uptime_sec, 0, 1e10),
        wg_port: int(g.wg_port, 1, 65535),
        ctrl_port: int(g.ctrl_port, 1, 65535),
        subnet: subnet4(g.subnet),
        lan_access: g.lan_access === true,
        // "present" | "missing" | "unknown"; '' when not applicable ("n/a").
        firewall_rule: g.firewall_rule === true || g.firewall_rule === 'present' ? 'present'
          : g.firewall_rule === false || g.firewall_rule === 'missing' ? 'missing'
            : g.firewall_rule === 'unknown' ? 'unknown' : '',
        fingerprint: clean(g.fingerprint, 16).replace(/[^0-9a-fA-F]/g, ''),
        nat: NAT_KEYS.includes(g.nat) ? g.nat : '',
        public_ip: ipAny(g.public_ip),
      },
      client: {
        state: CLIENT_STATES.has(c.state) ? c.state : 'idle',
        gateway_id: idStr(c.gateway_id),
        gateway_name: clean(c.gateway_name, 32),
        network_label: clean(c.network_label, 32),
        assigned_ip: ipPrefix(c.assigned_ip),
        since: int(c.since, 0, 1e14),
        rx: int(c.rx, 0, Number.MAX_SAFE_INTEGER),
        tx: int(c.tx, 0, Number.MAX_SAFE_INTEGER),
        handshake_age_sec: int(c.handshake_age_sec, -1, 1e9),
        degraded_since: int(c.degraded_since, 0, 1e14),
        error: clean(c.error, 300),
        error_code: clean(c.error_code, 40),
        protected: c.protected === true,
        // "on" | "off" (desktop) | "os" (Android: the system setting); '' unknown.
        kill_switch: ['on', 'off', 'os'].includes(c.kill_switch) ? c.kill_switch : '',
        // The engine resumes the last session after a restart/crash.
        resume_pending: c.resume_pending === true,
      },
    };
  }

  /** problemsOf returns the engine's problems plus the "reconnecting after
   *  restart" line while a resume is pending. */
  function problemsOf(st) {
    if (!st) return [];
    const c = st.client;
    if (!c.resume_pending || st.problems.some((p) => p.code === 'resume_pending')) return st.problems;
    const line = {
      code: 'resume_pending', severity: 'info', action: 'disconnect',
      message: 'Reconnecting to ' + (c.gateway_name || 'your last gateway') + ' after restart…' +
        (c.kill_switch === 'on' ? ' Internet traffic stays blocked until the VPN is back, so your real IP is not exposed.' : ''),
    };
    return [...st.problems, line];
  }

  const capFirst = (t) => (t ? t.charAt(0).toUpperCase() + t.slice(1) : t);
  /** normProblems validates status.problems: everything the user should
   *  know is wrong, errors first. Messages are untrusted text. */
  function normProblems(list) {
    if (!Array.isArray(list)) return [];
    const out = list.slice(0, 16).filter(isObj).map((p) => ({
      code: typeof p.code === 'string' && /^[a-z0-9_]{1,40}$/.test(p.code) ? p.code : '',
      severity: SEVERITIES.includes(p.severity) ? p.severity : 'warning',
      message: capFirst(clean(p.message, 400)),
      action: PROBLEM_ACTIONS.includes(p.action) ? p.action : '',
    })).filter((p) => p.message);
    return out.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  }

  /** clientLook describes the client state for display: a headline, a short
   *  form (sidebar pill, badges), a tone (ok | busy | warn | danger | idle),
   *  an icon and one explanatory sentence. */
  function clientLook(c) {
    const gw = c.gateway_name || 'the gateway';
    switch (c.state) {
      case 'connected':
        if (c.protected) {
          return { title: 'Protected', short: 'Protected', tone: 'ok', icon: 'i-shield',
            text: 'All traffic goes through ' + gw + ' — websites see the gateway\'s IP address, not yours.' };
        }
        return { title: 'Connected — not fully protected', short: 'Not fully protected', tone: 'warn', icon: 'i-alert',
          text: 'Connected to ' + gw + ', but some traffic may leave outside the VPN. See the problems listed at the top.' };
      case 'joining':
      case 'tunnel_up':
        return { title: 'Connecting…', short: 'Connecting…', tone: 'busy', icon: 'i-refresh',
          text: c.state === 'tunnel_up' ? 'Tunnel created — waiting for ' + gw + ' to answer.' : 'Contacting ' + gw + '…' };
      case 'degraded':
        return { title: 'Connection interrupted — traffic held, reconnecting', short: 'Interrupted · reconnecting', tone: 'warn', icon: 'i-refresh',
          text: 'Lost contact with ' + gw + '. Your traffic is held inside the tunnel, so nothing goes out with your real IP, while PrivateVPN reconnects automatically.' };
      case 'blocked':
        if (!c.gateway_id && c.resume_pending) {
          return { title: 'Reconnecting after restart — Internet blocked until then', short: 'Reconnecting after restart', tone: 'busy', icon: 'i-lock',
            text: 'PrivateVPN is reconnecting to ' + gw + '. Until the VPN is back, all Internet traffic stays blocked so websites cannot see your real IP. Disconnect to use the Internet without the VPN.' };
        }
        if (!c.gateway_id) {
          return { title: 'Internet blocked to protect your IP', short: 'Internet blocked', tone: 'danger', icon: 'i-lock',
            text: 'The previous VPN session ended unexpectedly and the kill switch is still blocking all Internet traffic. Connect to a gateway, or Disconnect to use the Internet without the VPN.' };
        }
        if (c.kill_switch === 'off') {
          return { title: 'VPN connection failed — traffic may not be protected', short: 'VPN failed', tone: 'danger', icon: 'i-alert',
            text: 'The connection to ' + gw + ' failed and the kill switch is off, so apps may be using your real IP. Reconnect, or Disconnect to use the Internet without the VPN.' };
        }
        return { title: 'Internet blocked to protect your IP', short: 'Internet blocked', tone: 'danger', icon: 'i-lock',
          text: 'The connection to ' + gw + ' failed. All Internet traffic stays blocked so websites cannot see your real IP. Reconnect, or Disconnect to use the Internet without the VPN.' };
      default:
        if (c.resume_pending) {
          return { title: 'Reconnecting after restart…', short: 'Reconnecting after restart', tone: 'busy', icon: 'i-refresh',
            text: 'PrivateVPN is reconnecting to ' + gw + '. Until it does, this device uses its own Internet connection.' };
        }
        return { title: 'Not protected', short: 'Not protected', tone: 'idle', icon: 'i-shield',
          text: 'The VPN is off: this device uses its own Internet connection and websites see your real IP address.' };
    }
  }
  const TONE_CLASS = { ok: 'on', busy: 'busy', warn: 'warn', danger: 'danger', idle: '' };

  function normGateway(g) {
    if (!isObj(g) || !idStr(g.id)) return null;
    const access = ['member', 'locked', 'key_changed'].includes(g.access) ? g.access : 'locked';
    const flags = isObj(g.flags) ? g.flags : {};
    const manual = isObj(g.manual)
      ? { id: idStr(g.manual.id), label: clean(g.manual.label, 32), host: clean(g.manual.host, 253), ctrl_port: int(g.manual.ctrl_port, 1, 65535) }
      : null;
    const endpoints = Array.isArray(g.endpoints)
      ? g.endpoints.slice(0, 3).filter(isObj).map((e) => ({
        ip: ipAny(e.ip),
        ctrl_port: int(e.ctrl_port, 1, 65535),
        wg_port: int(e.wg_port, 1, 65535),
        source: clean(e.source, 16),
        verified: e.verified === true,
      }))
      : [];
    return {
      id: idStr(g.id),
      name: clean(g.name, 32) || (manual && manual.label) || 'Unnamed gateway',
      os: OS_LABEL[g.os] ? g.os : '',
      app_version: clean(g.app_version, 16),
      online: g.online === true,
      last_seen_ms: int(g.last_seen_ms, 0, 1e13),
      client_count: int(g.client_count, 0, 255),
      flags: { accepting: flags.accepting !== false, lan_access: flags.lan_access === true, dual_role: flags.dual_role === true },
      access,
      network: access === 'member' && isObj(g.network) ? { id: idStr(g.network.id), label: clean(g.network.label, 32) || 'Unnamed network' } : null,
      endpoints,
      manual,
      fingerprint: clean(g.fingerprint, 16).replace(/[^0-9a-fA-F]/g, ''),
      first_seen: int(g.first_seen, 0, 1e14),
      is_new: g.is_new === true,
      is_self: g.is_self === true,
    };
  }
  // §13.3 order: members (online first), key_changed, locked; by name within
  // a group. This device's own gateway (not connectable) follows the online
  // members.
  const RANK = (g) => (g.access === 'member' ? (g.is_self ? 1 : g.online ? 0 : 2) : g.access === 'key_changed' ? 3 : 4);
  function sortGateways(list) {
    return list.slice().sort((a, b) => RANK(a) - RANK(b) || a.name.localeCompare(b.name) || (a.id < b.id ? -1 : 1));
  }

  function normKeyEntry(e) {
    if (!isObj(e) || !idStr(e.id)) return null;
    return {
      id: idStr(e.id),
      label: clean(e.label, 32) || 'Unnamed network',
      created_here: e.created_here === true,
      created_at: int(e.created_at, 0, 1e14),
      last_used: int(e.last_used, 0, 1e14),
      gateways_seen: int(e.gateways_seen, 0, 100000),
    };
  }

  function normSettings(s) {
    if (!isObj(s)) return null;
    const g = isObj(s.gateway) ? s.gateway : {};
    const geo = isObj(g.geo) ? g.geo : {};
    const ui = isObj(s.ui) ? s.ui : {};
    const cl = isObj(s.client) ? s.client : {};
    return {
      device_name: clean(s.device_name, 32),
      // null = not reported (the engine has no client settings, e.g. Android).
      client: { kill_switch: bool(cl.kill_switch), allow_lan: bool(cl.allow_lan), auto_reconnect: bool(cl.auto_reconnect) },
      gateway: {
        network_id: idStr(g.network_id),
        wg_port: int(g.wg_port, 1, 65535),
        ctrl_port: int(g.ctrl_port, 1, 65535),
        lan_access: bool(g.lan_access),
        geo_enabled: bool(geo.enabled),
      },
      ui: {
        port: int(ui.port, 1, 65535),
        autostart: bool(ui.autostart),
        theme: ['system', 'light', 'dark'].includes(ui.theme) ? ui.theme : 'system',
      },
    };
  }

  /** parseInfo validates an INFO document (§10.5) per §10.6; null = reject. */
  function parseInfo(raw) {
    if (!isObj(raw) || raw.v !== 1) return null;
    try {
      if (new TextEncoder().encode(JSON.stringify(raw)).length > 1100) return null;
    } catch (_) { return null; }
    const geo = isObj(raw.geo) ? raw.geo : {};
    const tz = isObj(raw.tz) ? raw.tz : {};
    const source = ['geoip', 'manual', 'none'].includes(geo.source) ? geo.source : 'none';
    const lat = real(geo.lat, -90, 90), lon = real(geo.lon, -180, 180);
    const showPos = source !== 'none' && lat !== null && lon !== null;
    return {
      name: clean(raw.name, 32),
      os: OS_LABEL[raw.os] ? raw.os : '',
      os_version: clean(raw.os_version, 32),
      app_version: clean(raw.app_version, 16),
      uptime_sec: int(raw.uptime_sec, 0, 1e10),
      gateway_uptime_sec: int(raw.gateway_uptime_sec, 0, 1e10),
      client_count: int(raw.client_count, 0, 253),
      lan_access: bool(raw.lan_access),
      dual_role: bool(raw.dual_role),
      subnet: subnet4(raw.subnet),
      mtu: int(raw.mtu, 576, 65535),
      wg_port: int(raw.wg_port, 1, 65535),
      ctrl_port: int(raw.ctrl_port, 1, 65535),
      lan_ips: Array.isArray(raw.lan_ips) ? raw.lan_ips.slice(0, 8).map(v4).filter(Boolean) : [],
      public_ip: v4(raw.public_ip),
      public_ip6: v6(raw.public_ip6),
      public_ip_checked_at: int(raw.public_ip_checked_at, 0, 1e11),
      stale: raw.stale === true,
      nat: NAT_KEYS.includes(raw.nat) ? raw.nat : 'unknown',
      geo: {
        source,
        provider: clean(geo.provider, 32),
        country: clean(geo.country, 64),
        country_code: typeof geo.country_code === 'string' && /^[A-Z]{2}$/.test(geo.country_code) ? geo.country_code : '',
        region: clean(geo.region, 64),
        city: clean(geo.city, 64),
        lat: showPos ? lat : null,
        lon: showPos ? lon : null,
        accuracy_km: real(geo.accuracy_km, 0, 20000),
        isp: clean(geo.isp, 64),
        asn: clean(geo.asn, 16),
        checked_at: int(geo.checked_at, 0, 1e11),
      },
      tz: {
        name: clean(tz.name, 64),
        utc_offset_sec: int(tz.utc_offset_sec, -16 * 3600, 16 * 3600),
        abbrev: clean(tz.abbrev, 8),
      },
      now: int(raw.now, 0, 1e11),
    };
  }

  const gwById = (id) => S.gateways.find((g) => g.id === id) || null;
  const krById = (id) => S.keyring.find((e) => e.id === id) || null;
  /** connState returns this device's client state for gateway id, or ''. */
  function connState(id) {
    const c = S.status && S.status.client;
    return c && c.gateway_id === id && ACTIVE.has(c.state) ? c.state : '';
  }
  const servedNetworkId = () => (S.status && S.status.gateway.network ? S.status.gateway.network.id : '');

  // ===================================================================
  // Loading
  // ===================================================================
  async function load(kind, path, apply) {
    try {
      const r = await api('GET', path);
      delete S.errors[kind];
      apply(r);
    } catch (e) {
      S.errors[kind] = errText(e);
    }
  }
  const refreshStatus = () => load('status', '/status', (r) => { S.status = normStatus(r); }).then(renderAfterStatus);
  const refreshGateways = () => load('gateways', '/gateways', (r) => {
    S.gateways = sortGateways((Array.isArray(r.gateways) ? r.gateways : []).map(normGateway).filter(Boolean));
  }).then(renderAfterGateways);
  const refreshKeyring = () => load('keyring', '/keyring', (r) => {
    S.keyring = (Array.isArray(r.entries) ? r.entries : []).map(normKeyEntry).filter(Boolean).slice(0, 64);
  }).then(renderAfterKeyring);
  const refreshSettings = () => load('settings', '/settings', (r) => {
    S.settings = normSettings(r);
    if (S.settings) applyTheme(S.settings.ui.theme);
  }).then(renderAfterSettings);
  const refreshLog = () => load('log', '/log', (r) => {
    S.log = (Array.isArray(r.lines) ? r.lines : []).slice(-1000).map((l) => clean(l, 600)).filter(Boolean);
  }).then(() => renderLog(true));

  function loadAll() {
    return Promise.allSettled([refreshStatus(), refreshGateways(), refreshKeyring(), refreshSettings(), refreshLog()]);
  }

  // The engine's problems (status.problems) replace the old one-off
  // "connection failed" banner: they are listed at the top of every view.
  function renderAfterStatus() { renderProblems(); renderChrome(); renderGateways(); renderKeyring(); renderGatewayMode(); renderStatus(); renderSettings(); renderDetails(); }
  /** renderClientActions re-renders everything that shows a Disconnect /
   *  Reconnect / firewall button (their busy state is global). */
  function renderClientActions() { renderProblems(); renderGateways(); renderStatus(); renderDetailsFoot(true); }
  function renderAfterGateways() { renderGateways(); renderDetails(); tryPendingUnlock(); }
  function renderAfterKeyring() { renderKeyring(); renderGatewayMode(); renderManualNetworks(); }
  function renderAfterSettings() { renderGatewayMode(); renderSettings(); }

  // ===================================================================
  // Chrome: navigation, sidebar, banners
  // ===================================================================
  const VIEWS = ['gateways', 'networks', 'gateway', 'status', 'log', 'settings'];
  const TITLES = { gateways: 'Gateways', networks: 'Networks', gateway: 'Gateway mode', status: 'Status', log: 'Log', settings: 'Settings' };

  function setView(v, replaceHash = true) {
    if (!VIEWS.includes(v)) v = 'gateways';
    S.view = v;
    for (const id of VIEWS) $('view-' + id).hidden = id !== v;
    for (const b of document.querySelectorAll('.nav-item')) {
      const on = b.dataset.view === v;
      b.classList.toggle('active', on);
      if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
    }
    if (replaceHash && location.hash !== '#' + v) history.replaceState(null, '', '#' + v);
    document.title = TITLES[v] + ' · PrivateVPN';
    if (v === 'log') renderLog(true);
    if (v === 'status') refreshStatus();
  }

  function renderChrome() {
    const st = S.status;
    const cpill = $('side-client'), gpill = $('side-gateway');
    const c = st ? st.client : null;
    const cs = c ? c.state : 'idle';
    const look = c ? clientLook(c) : null;
    cpill.className = 'side-pill' + (look && TONE_CLASS[look.tone] ? ' ' + TONE_CLASS[look.tone] : '');
    const ptext = !c ? 'Not connected' : look.short + (cs !== 'idle' && c.gateway_name ? ' · ' + c.gateway_name : '');
    cpill.querySelector('.side-pill-text').textContent = ptext;
    cpill.title = look ? look.title : '';
    const g = st ? st.gateway : null;
    gpill.classList.add('gw');
    gpill.classList.toggle('on', !!(g && g.enabled));
    gpill.querySelector('.side-pill-text').textContent = g && g.enabled ? 'Gateway on · ' + plural(g.clients || 0, 'client', 'clients') : 'Gateway off';
    $('side-version').textContent = st && st.version ? 'Version ' + st.version : '';
  }

  function setBanner(key, banner) {
    if (banner) S.banners.set(key, banner); else S.banners.delete(key);
    renderBanners();
  }
  function renderBanners() {
    const box = $('banners');
    const nodes = [];
    for (const [key, b] of S.banners) {
      nodes.push(h('div', { class: 'banner ' + (b.kind || 'warn'), role: 'alert' },
        icon('i-alert'),
        h('div', { class: 'grow' }, b.text),
        b.action ? h('button', { type: 'button', class: 'btn small', on: { click: b.action.fn } }, b.action.label) : null,
        h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Dismiss', on: { click: () => setBanner(key, null) } }, icon('i-x'))));
    }
    box.replaceChildren(...nodes);
  }

  // ===================================================================
  // Problems panel (status.problems), shown at the top of every view
  // ===================================================================
  /** adminNote is shown while a Disconnect is in flight: removing the
   *  block can need the tunnel helper, i.e. an administrator prompt. */
  function adminNote() {
    const os = S.status && S.status.os;
    const who = OS_LABEL[os] && os !== 'android' ? OS_LABEL[os] : 'Your system';
    return h('p', { class: 'muted small admin-note', role: 'status' }, 'Disconnecting… ' + who + ' may ask for administrator approval.');
  }

  /** disconnectBtn is a Disconnect button bound to the global disconnect
   *  state (spinner while S.disconnecting). */
  function disconnectBtn(cls = 'btn') {
    const b = h('button', { type: 'button', class: cls, on: { click: () => disconnect() } }, 'Disconnect');
    if (S.disconnecting) setBusy(b, true);
    return b;
  }

  /** reconnectTarget: the session's gateway, else the gateway this page
   *  last tried (if it is still a connectable member), else ''. */
  function reconnectTarget() {
    const c = S.status && S.status.client;
    if (c && c.gateway_id) return c.gateway_id;
    const g = S.lastConnectId ? gwById(S.lastConnectId) : null;
    return g && g.access === 'member' && !g.is_self ? g.id : '';
  }
  function reconnectBtn(cls = 'btn primary') {
    const id = reconnectTarget();
    const b = h('button', { type: 'button', class: cls, on: { click: () => reconnect() } }, icon('i-refresh'), id ? 'Reconnect' : 'Choose a gateway');
    if (id && S.busy.has(id)) setBusy(b, true);
    return b;
  }
  function reconnect() {
    const id = reconnectTarget();
    if (id) { connect(id); return; }
    setView('gateways');
    toast('Choose a gateway to connect to.');
  }

  function problemAction(p) {
    switch (p.action) {
      case 'disconnect':
        return disconnectBtn('btn small');
      case 'reconnect':
        return reconnectBtn('btn small primary');
      case 'add_firewall': {
        const b = h('button', { type: 'button', class: 'btn small', on: { click: () => addFirewallRule() } }, 'Add firewall rule');
        if (S.firewallBusy) setBusy(b, true);
        return b;
      }
      case 'settings':
        return h('button', { type: 'button', class: 'btn small', on: { click: () => setView('settings') } }, icon('i-settings'), 'Open Settings');
      default:
        return null;
    }
  }

  let problemsSig = '';
  function renderProblems() {
    const box = $('problems');
    if (!box) return;
    const list = problemsOf(S.status);
    const target = reconnectTarget();
    const sig = JSON.stringify([list, S.disconnecting, S.firewallBusy, target, target && S.busy.has(target), S.status && S.status.os]);
    if (sig === problemsSig) return;
    problemsSig = sig;
    box.hidden = list.length === 0;
    if (!list.length) { box.replaceChildren(); return; }
    const serious = list.filter((p) => p.severity !== 'info').length;
    const head = serious ? plural(serious, 'problem', 'problems') : plural(list.length, 'note', 'notes');
    const items = list.map((p) => {
      const action = problemAction(p);
      return h('li', { class: 'problem ' + p.severity },
        icon(p.severity === 'info' ? 'i-info' : 'i-alert'),
        h('div', { class: 'grow' },
          h('span', { class: 'sev' }, SEV_LABEL[p.severity]),
          h('p', null, p.message),
          p.action === 'disconnect' && S.disconnecting ? adminNote() : null),
        action ? h('div', { class: 'problem-actions' }, action) : null);
    });
    box.replaceChildren(h('h2', { class: 'problems-head' }, head), h('ul', { class: 'problem-list' }, items));
  }

  function sessionEnded() {
    if (signingOut || S.quit) return;
    signingOut = true;
    if (es) { es.close(); es = null; }
    location.replace('/');
  }

  // ===================================================================
  // Gateways view
  // ===================================================================
  const gwCards = new Map();

  function renderGateways() {
    const list = $('gw-list');
    if (!list) return;
    const gws = S.gateways;
    const err = S.errors.gateways;
    $('gw-empty').hidden = gws.length > 0 || !!err;
    setBanner('gateways-error', err ? { kind: 'danger', text: 'The gateway list is unavailable: ' + err, action: { label: 'Retry', fn: refreshGateways } } : null);
    const seen = new Set();
    let prev = null;
    for (const g of gws) {
      seen.add(g.id);
      let c = gwCards.get(g.id);
      if (!c) { c = buildGwCard(g.id); gwCards.set(g.id, c); }
      updateGwCard(c, g);
      const want = prev ? prev.nextSibling : list.firstChild;
      if (want !== c.root) list.insertBefore(c.root, want);
      prev = c.root;
    }
    for (const [id, c] of gwCards) {
      if (!seen.has(id)) { c.root.remove(); gwCards.delete(id); }
    }
    renderConnSummary();
  }

  function buildKeyPrompt(id, where) {
    const p = {};
    p.label = h('span', null, 'Network key');
    p.input = h('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'characters', placeholder: 'PVN1-XXXXX-XXXXX-…', maxlength: '200', 'aria-label': 'Network key' });
    p.err = h('p', { class: 'form-error', hidden: true, role: 'alert' });
    p.submit = h('button', { type: 'submit', class: 'btn primary' }, icon('i-unlock'), 'Unlock & connect');
    const paste = h('button', { type: 'button', class: 'btn ghost', on: { click: () => pasteInto(p.input) } }, icon('i-paste'), 'Paste');
    const cancel = where === 'card' ? h('button', { type: 'button', class: 'btn ghost', on: { click: () => closePrompt() } }, 'Cancel') : null;
    p.input.addEventListener('input', () => showPromptErr(p, ''));
    p.root = h('form', { class: 'key-prompt', novalidate: true, hidden: where === 'card', on: { submit: (e) => { e.preventDefault(); unlockAndConnect(id, p); } } },
      h('label', { class: 'field' }, p.label, p.input),
      h('p', { class: 'muted small' }, 'Find the key on the gateway under Networks → Show key, or ask its owner. You enter it once per network — every gateway of that network then unlocks automatically.'),
      p.err,
      h('div', { class: 'form-actions' }, paste, cancel, p.submit));
    return p;
  }
  function showPromptErr(p, msg) { p.err.textContent = msg; p.err.hidden = !msg; }

  function buildGwCard(id) {
    const c = {};
    c.tile = h('div', { class: 'os-tile' });
    c.name = h('h3', { class: 'gw-name' });
    c.badges = h('span', { class: 'badges' });
    c.meta = h('div', { class: 'gw-meta' });
    c.infoBtn = h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Details', title: 'Details', on: { click: () => openDetails(id) } }, icon('i-info'));
    c.connectBtn = h('button', { type: 'button', class: 'btn primary', on: { click: () => onConnectClick(id, c.connectBtn) } });
    c.prompt = buildKeyPrompt(id, 'card');
    c.root = h('article', { class: 'card gw-card', 'data-id': id },
      h('div', { class: 'gw-row' },
        c.tile,
        h('div', { class: 'grow' }, h('div', { class: 'gw-title' }, c.name, c.badges), c.meta),
        h('div', { class: 'gw-actions' }, c.infoBtn, c.connectBtn)),
      c.prompt.root);
    return c;
  }

  function gwBadges(g) {
    const out = [];
    const cs = connState(g.id);
    if (cs) {
      const look = clientLook(S.status.client);
      out.push(badge(look.short, look.tone === 'ok' ? 'ok' : look.tone === 'danger' ? 'danger' : 'warn', look.tone === 'ok' ? 'i-check' : null));
    }
    if (g.access === 'locked') out.push(badge('Locked', 'lock', 'i-lock'));
    if (g.access === 'key_changed') out.push(badge('Key changed', 'warn', 'i-lock'));
    if (g.is_new && !g.is_self) out.push(badge('New', 'accent'));
    if (g.is_self) out.push(badge('This device'));
    if (g.manual) out.push(badge('Manual'));
    if (!g.online) out.push(badge('Offline'));
    return out;
  }

  function lanEndpoint(g) {
    const e = g.endpoints.find((x) => x.source === 'lan' && x.ip) || null;
    return e;
  }

  function gwMeta(g) {
    const out = [];
    if (g.access === 'member' && g.network) out.push(h('span', null, icon('i-key'), g.network.label));
    else if (g.access === 'key_changed') out.push(h('span', null, icon('i-key'), 'Its key was reset — enter the new key'));
    else out.push(h('span', null, icon('i-lock'), 'Not in your keyring'));
    if (g.client_count !== null) out.push(h('span', null, icon('i-users'), plural(g.client_count, 'client', 'clients')));
    const lan = lanEndpoint(g);
    if (lan) out.push(h('span', null, icon('i-gateways'), 'LAN · ' + lan.ip));
    else if (g.manual) out.push(h('span', null, icon('i-globe'), 'Internet · ' + (g.manual.host || 'manual')));
    if (!g.flags.accepting) out.push(h('span', null, 'Not accepting clients'));
    if (!g.online && g.last_seen_ms !== null) out.push(h('span', null, icon('i-clock'), 'Seen ' + fmtAgoMs(g.last_seen_ms)));
    return out;
  }

  function updateGwCard(c, g) {
    const cs = connState(g.id);
    c.root.className = 'card gw-card' + (g.access !== 'member' ? ' gw-locked' : '') + (g.is_self ? ' self' : '') + (cs === 'connected' ? ' connected' : '');
    c.tile.replaceChildren(osIcon(g.os), h('span', { class: 'dot' + (g.online ? ' on' : ''), title: g.online ? 'Online' : 'Offline' }));
    c.tile.title = OS_LABEL[g.os] || 'Unknown system';
    c.name.textContent = g.name;
    c.name.title = g.name;
    c.badges.replaceChildren(...gwBadges(g));
    c.meta.replaceChildren(...gwMeta(g));
    const btn = c.connectBtn;
    const busy = S.busy.has(g.id) || (!!cs && S.disconnecting);
    if (g.is_self) {
      btn.replaceChildren('This device');
      btn.className = 'btn';
      btn.disabled = true;
    } else if (cs) {
      btn.replaceChildren('Disconnect');
      btn.className = 'btn';
      btn.disabled = busy;
    } else {
      btn.replaceChildren(g.access === 'member' ? icon('i-link') : icon('i-lock'), 'Connect');
      btn.className = 'btn primary';
      btn.disabled = busy;
    }
    btn.classList.toggle('busy', busy);
    c.prompt.label.textContent = 'Network key for “' + g.name + '”';
    c.prompt.root.hidden = S.prompt !== g.id;
  }

  function renderConnSummary() {
    const box = $('conn-summary');
    const st = S.status;
    if (!st || !ACTIVE.has(st.client.state)) { box.replaceChildren(); return; }
    const c = st.client;
    const look = clientLook(c);
    const parts = [];
    if (c.gateway_name) parts.push(c.gateway_name + (c.network_label ? ' (' + c.network_label + ')' : ''));
    if (c.assigned_ip) parts.push(c.assigned_ip);
    if (c.state !== 'blocked' && c.handshake_age_sec !== null && c.handshake_age_sec >= 0) parts.push('handshake ' + fmtAgoMs(c.handshake_age_sec * 1000));
    if (c.gateway_id && c.rx !== null && c.tx !== null) parts.push('↓ ' + fmtBytes(c.rx) + '  ↑ ' + fmtBytes(c.tx));
    const actions = [h('button', { type: 'button', class: 'btn ghost', on: { click: () => setView('status') } }, 'Status')];
    if (c.state === 'blocked') actions.push(reconnectBtn());
    actions.push(disconnectBtn());
    box.replaceChildren(h('div', { class: 'card conn-card ' + look.tone, role: look.tone === 'danger' ? 'alert' : null },
      h('div', { class: 'conn-icon' }, icon(look.icon)),
      h('div', { class: 'grow' },
        h('strong', null, look.title),
        h('p', { class: 'small' }, look.text),
        parts.length ? h('div', { class: 'muted small' }, parts.join(' · ')) : null,
        S.disconnecting ? adminNote() : null),
      h('div', { class: 'conn-actions' }, actions)));
  }

  function openPrompt(id) {
    S.prompt = id;
    renderGateways();
    const c = gwCards.get(id);
    if (c) {
      c.root.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      c.prompt.input.focus();
    }
  }
  function closePrompt() {
    const c = gwCards.get(S.prompt);
    if (c) { c.prompt.input.value = ''; showPromptErr(c.prompt, ''); }
    S.prompt = '';
    renderGateways();
  }

  function onConnectClick(id, btn) {
    const g = gwById(id);
    if (!g || g.is_self) return;
    if (connState(id)) { disconnect(); return; }
    if (g.access !== 'member') { openPrompt(id); return; }
    connect(id);
  }

  async function connect(id) {
    const g = gwById(id);
    S.busy.add(id);
    S.lastConnectId = id;
    renderClientActions();
    try {
      await api('POST', '/client/connect', { gateway_id: id });
      toast('Connecting to ' + (g ? g.name : 'the gateway') + '…');
      setBanner('elevation', null);
    } catch (e) {
      if (e.code === 'locked') {
        if (S.details && S.details.id === id) toast(ERR_TEXT.locked, 'error'); else openPrompt(id);
      } else if (e.code === 'elevation_needed') {
        showElevation();
      } else {
        toast(errText(e), 'error');
      }
    } finally {
      S.busy.delete(id);
      await refreshStatus();
      renderClientActions();
    }
  }

  /** disconnect is the only way the tunnel and the kill switch's block are
   *  removed; it can need an administrator prompt (tunnel helper). */
  async function disconnect() {
    if (S.disconnecting) return;
    S.disconnecting = true;
    renderClientActions();
    try {
      await api('POST', '/client/disconnect');
      toast('Disconnected. This device now uses its own Internet connection and IP address.');
    } catch (e) {
      toast(errText(e), 'error');
    } finally {
      S.disconnecting = false;
      await refreshStatus();
      renderClientActions();
    }
  }

  /** precheckKey validates the §5.1 text form locally (the checksum is
   *  verified by the core); returns an error message or ''. */
  function precheckKey(t) {
    const s = t.replace(/[\s-]/g, '').toUpperCase();
    if (!s) return 'Paste the network key first.';
    if (!s.startsWith('PVN1') || !/^[A-Z2-7]{55}$/.test(s.slice(4))) return ERR_TEXT.key_format;
    return '';
  }

  async function unlockAndConnect(id, p) {
    const text = p.input.value.trim();
    const bad = precheckKey(text);
    if (bad) { showPromptErr(p, bad); p.input.focus(); return; }
    setBusy(p.submit, true);
    let res;
    try {
      res = await api('POST', '/gateways/' + enc(id) + '/unlock', { key_text: text });
    } catch (e) {
      setBusy(p.submit, false);
      showPromptErr(p, errText(e));
      p.input.focus();
      return;
    }
    setBusy(p.submit, false);
    p.input.value = '';
    showPromptErr(p, '');
    if (S.prompt === id) closePrompt();
    toast(res.replaced === true ? 'Key updated in your keyring.' : 'Key saved to your keyring.');
    // The unlock reports the gateway's current list id: a manual entry is
    // listed as "m-<uuid>" until its public key is known, then by that key.
    const gid = idStr(res.gateway_id) || id;
    await Promise.allSettled([refreshGateways(), refreshKeyring()]);
    if (S.details && S.details.id === id) {
      if (gid !== id && gwById(gid)) openDetails(gid); else fetchInfo();
    }
    await connect(gid);
  }

  function tryPendingUnlock() {
    if (!S.pendingUnlock) return;
    if (Date.now() > S.pendingUnlockUntil) { S.pendingUnlock = ''; return; }
    const g = gwById(S.pendingUnlock);
    if (!g) return;
    const id = S.pendingUnlock;
    S.pendingUnlock = '';
    setView('gateways');
    if (g.access === 'member') openDetails(id); else openPrompt(id);
  }

  // --- Add gateway by address ---
  function renderManualNetworks() {
    const sel = $('manual-network');
    const cur = sel.value;
    sel.replaceChildren(h('option', { value: '' }, 'Try my keys automatically'),
      ...S.keyring.map((e) => h('option', { value: e.id }, e.label)));
    sel.value = S.keyring.some((e) => e.id === cur) ? cur : '';
  }

  function wireManualForm() {
    const form = $('form-manual');
    const err = form.querySelector('.form-error');
    const showErr = (m) => { err.textContent = m; err.hidden = !m; };
    $('btn-add-manual').addEventListener('click', () => {
      form.hidden = !form.hidden;
      if (!form.hidden) { renderManualNetworks(); form.elements.label.focus(); }
    });
    form.querySelector('[data-cancel]').addEventListener('click', () => { form.reset(); showErr(''); form.hidden = true; });
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const label = form.elements.label.value.trim();
      const host = form.elements.host.value.trim();
      const portText = form.elements.ctrl_port.value.trim();
      const keyring_id = form.elements.keyring_id.value;
      if (!label) return showErr('Give the gateway a label.');
      if (!/^[A-Za-z0-9.-]{1,253}$/.test(host) && !ipAny(host)) return showErr('Enter a host name (letters, digits, dots, dashes) or an IP address.');
      const body = { label, host };
      if (portText) {
        const port = Number(portText);
        if (!Number.isInteger(port) || port < 1024 || port > 65535) return showErr('The control port must be between 1024 and 65535.');
        body.ctrl_port = port;
      }
      if (keyring_id) body.keyring_id = keyring_id;
      const btn = form.querySelector('[type=submit]');
      setBusy(btn, true);
      try {
        await api('POST', '/gateways/manual', body);
        toast(keyring_id ? 'Gateway added.' : 'Gateway added. Trying your keys…');
        form.reset();
        showErr('');
        form.hidden = true;
        refreshGateways();
      } catch (e) {
        showErr(errText(e));
      } finally {
        setBusy(btn, false);
      }
    });
  }

  // ===================================================================
  // ⓘ details panel (§10.1, §10.6)
  // ===================================================================
  function openDetails(id) {
    closeDetails();
    const d = {
      id, info: null, endpoint: '', fetchedAt: 0, skew: 0, err: '', loading: false,
      sig: '', footSig: '', refs: {}, timers: [], prompt: buildKeyPrompt(id, 'drawer'), lastG: null,
    };
    S.details = d;
    $('drawer').hidden = false;
    $('drawer-backdrop').hidden = false;
    renderDetails(true);
    const g = gwById(id);
    if (g && g.access === 'member') fetchInfo();
    d.timers.push(setInterval(() => {
      const cur = gwById(id);
      if (cur && cur.access === 'member' && !document.hidden) fetchInfo();
    }, 30000));
    d.timers.push(setInterval(tickClock, 1000));
    $('dr-close').focus();
  }

  function closeDetails() {
    const d = S.details;
    if (!d) return;
    d.timers.forEach(clearInterval);
    S.details = null;
    $('drawer').hidden = true;
    $('drawer-backdrop').hidden = true;
    $('dr-body').replaceChildren();
    $('dr-foot').replaceChildren();
  }

  async function fetchInfo() {
    const d = S.details;
    if (!d || d.loading) return;
    const id = d.id;
    d.loading = true;
    renderDetails();
    try {
      const r = await api('GET', '/gateways/' + enc(id) + '/info');
      if (S.details !== d) return;
      const info = parseInfo(r.info);
      if (!info) throw new ApiError('bad_info', 'the gateway sent details that could not be read', 0);
      const fetched = real(r.fetched_at_ms, 1, 1e14) || Date.now();
      d.info = info;
      d.fetchedAt = fetched;
      d.skew = info.now !== null ? info.now * 1000 - fetched : 0;
      d.endpoint = clean(r.endpoint_used, 64);
      d.err = '';
    } catch (e) {
      if (S.details !== d) return;
      d.err = errText(e);
    } finally {
      if (S.details === d) {
        d.loading = false;
        renderDetails();
      }
    }
  }

  function tickClock() {
    const d = S.details;
    if (!d || !d.info || !d.refs.clockTime) return;
    const off = d.info.tz.utc_offset_sec || 0;
    const wall = Date.now() + d.skew + off * 1000;
    if (!(wall > 0 && wall < 253402300799000)) return;
    const iso = new Date(wall).toISOString();
    d.refs.clockTime.textContent = iso.slice(11, 19);
    d.refs.clockDate.textContent = iso.slice(0, 10);
    if (d.refs.fetched && d.fetchedAt) d.refs.fetched.textContent = fmtAgoMs(Date.now() - d.fetchedAt) + (d.endpoint ? ' via ' + d.endpoint : '');
  }

  /** section builds a titled <dl>; rows are [label, value, sub?] and rows
   *  with an empty value are skipped. */
  function section(title, ic, rows, note) {
    const dl = h('dl', { class: 'kv' });
    for (const r of rows) {
      if (!r) continue;
      const [k, v, sub] = r;
      if (v === null || v === undefined || v === '') continue;
      dl.append(h('dt', null, k), h('dd', null, v, sub ? h('span', { class: 'sub' }, sub) : null));
    }
    if (!dl.childElementCount && !note) return null;
    return h('div', { class: 'kv-section' }, h('h3', null, icon(ic), title), note ? h('p', { class: 'kv-note' }, note) : null, dl.childElementCount ? dl : null);
  }

  function renderDetails(force) {
    const d = S.details;
    if (!d) return;
    const g = gwById(d.id) || d.lastG;
    if (!g) { closeDetails(); return; }
    const gone = !gwById(d.id);
    d.lastG = g;
    $('dr-title').textContent = (d.info && d.info.name) || g.name;
    $('dr-os').replaceChildren(osIcon(g.os), h('span', { class: 'dot' + (g.online ? ' on' : '') }));
    const badges = gwBadges(g);
    if (g.access !== 'member') badges.unshift(badge('unverified', 'lock'));
    $('dr-badges').replaceChildren(...badges);
    // Rebuild the body only when something visible changed (the panel
    // refreshes on every list event, ≤ 2/s).
    const sig = JSON.stringify([g, Math.round((g.last_seen_ms || 0) / 5000), d.info, d.err, d.loading, d.endpoint, connState(g.id), gone]);
    if (force || sig !== d.sig) {
      d.sig = sig;
      d.refs = {};
      const body = g.access === 'member' ? memberBody(g, d) : lockedBody(g);
      if (gone) body.unshift(h('div', { class: 'callout small' }, icon('i-info'), h('p', null, 'This gateway is no longer listed. Showing the last known details.')));
      $('dr-body').replaceChildren(...body.filter(Boolean));
      tickClock();
    }
    renderDetailsFoot(force);
  }

  function memberBody(g, d) {
    const i = d.info;
    const out = [];
    if (d.loading && !i) out.push(h('div', { class: 'loading-line' }, 'Asking the gateway for details…'));
    if (d.err) {
      out.push(h('div', { class: 'callout danger small' }, icon('i-alert'),
        h('div', { class: 'grow' }, h('p', null, 'Could not load details: ' + d.err)),
        h('button', { type: 'button', class: 'btn small', on: { click: fetchInfo } }, 'Retry')));
    }
    const wg = (i && i.wg_port) || (g.endpoints[0] && g.endpoints[0].wg_port);
    const ctrl = (i && i.ctrl_port) || (g.endpoints[0] && g.endpoints[0].ctrl_port);
    const osName = OS_LABEL[(i && i.os) || g.os] || '';
    out.push(section('Device', 'i-os-unknown', [
      ['Name', (i && i.name) || g.name],
      ['System', [osName, i ? i.os_version : ''].filter(Boolean).join(' ')],
      ['App version', (i && i.app_version) || g.app_version],
      ['Device uptime', i ? fmtDuration(i.uptime_sec) : ''],
      ['Gateway uptime', i ? fmtDuration(i.gateway_uptime_sec) : ''],
      ['Connected clients', i && i.client_count !== null ? String(i.client_count) : g.client_count !== null ? String(g.client_count) : ''],
      ['Exit path', i ? "Clients exit via this device's own connection" : '', i && i.dual_role ? 'This gateway is itself connected to another gateway; its members still exit directly.' : ''],
    ]));
    const lanAccess = i && i.lan_access !== null ? i.lan_access : g.flags.lan_access;
    const pub = i && i.public_ip ? h('span', null, i.public_ip, i.stale ? ' ' : null, i.stale ? badge('may be out of date', 'warn') : null) : '';
    const pubSub = i ? [i.public_ip6 ? 'IPv6 ' + i.public_ip6 : '', i.public_ip_checked_at ? 'checked ' + fmtAgoTs(i.public_ip_checked_at) : ''].filter(Boolean).join(' · ') : '';
    const reach = [lanEndpoint(g) ? 'LAN' : '', g.manual ? 'Internet (manual)' : ''].filter(Boolean).join(' · ');
    out.push(section('Network', 'i-gateways', [
      ['LAN access', lanAccess ? 'Allowed — members can reach its local network' : 'Internet only'],
      ['Tunnel subnet', i ? i.subnet : ''],
      ['MTU', i && i.mtu ? String(i.mtu) : ''],
      ['Ports', wg && ctrl ? 'WireGuard ' + wg + ' · control ' + ctrl + ' (UDP)' : ''],
      ['LAN IPs', i && i.lan_ips.length ? i.lan_ips.join(', ') : ''],
      ['Public IP', pub, pubSub],
      ['Reachability', reach || (i ? 'Unknown' : ''), i ? natText(i.nat, wg, ctrl) : ''],
    ]));
    if (i) {
      const geo = i.geo;
      const approx = geo.source === 'geoip' ? 'approximate (city-level, from IP)' : geo.source === 'manual' ? 'set manually on the gateway' : '';
      if (geo.source === 'none') {
        out.push(section('Location', 'i-globe', [], 'This gateway does not look up its location.'));
      } else {
        const coords = geo.lat !== null ? geo.lat.toFixed(2) + ', ' + geo.lon.toFixed(2) + (geo.accuracy_km ? ' (±' + Math.round(geo.accuracy_km) + ' km)' : '') : '';
        out.push(section('Location', 'i-globe', [
          ['Country', geo.country ? geo.country + (geo.country_code ? ' (' + geo.country_code + ')' : '') : geo.country_code],
          ['Region', geo.region],
          ['City', geo.city],
          ['Latitude / longitude', coords, coords ? approx : ''],
          ['ISP', geo.isp],
          ['ASN', geo.asn],
          ['Source', [geo.provider, geo.checked_at ? 'checked ' + fmtAgoTs(geo.checked_at) : ''].filter(Boolean).join(' · ')],
        ], approx ? 'Location is ' + approx + '.' : ''));
      }
      out.push(timeSection(i, d));
    }
    const fetched = h('span');
    d.refs.fetched = fetched;
    out.push(section('Identity', 'i-key', [
      ['Fingerprint', g.fingerprint ? h('span', { class: 'code' }, g.fingerprint) : ''],
      ['First seen', fmtDate(g.first_seen)],
      ['Key', g.network ? 'Verified with your key for “' + g.network.label + '”' : 'Verified'],
      ['Status', g.online ? 'Online' : 'Offline' + (g.last_seen_ms !== null ? ' · seen ' + fmtAgoMs(g.last_seen_ms) : '')],
      ['Details fetched', d.fetchedAt ? fetched : ''],
    ], g.is_new ? 'First time this device sees this gateway — if in doubt, compare the fingerprint with its owner.' : ''));
    return out;
  }

  function timeSection(i, d) {
    const time = h('div', { class: 'clock-time' }, '--:--:--');
    const date = h('div', { class: 'clock-date' });
    d.refs.clockTime = time;
    d.refs.clockDate = date;
    const off = i.tz.utc_offset_sec;
    const zone = [i.tz.name || 'Time zone name unknown', off !== null ? fmtOffset(off) + (i.tz.abbrev ? ' (' + i.tz.abbrev + ')' : '') : ''].filter(Boolean).join(' · ');
    const skewSec = Math.round(d.skew / 1000);
    const wrap = h('div', { class: 'kv-section' },
      h('h3', null, icon('i-clock'), 'Local time at the gateway'),
      h('div', { class: 'clock' }, time, date, h('div', { class: 'clock-zone' }, zone)),
      i.now !== null && Math.abs(skewSec) > 60
        ? h('div', { class: 'callout warn small' }, icon('i-alert'), h('p', null, 'Device clock differs by ' + Math.abs(skewSec) + ' s (the gateway is ' + (skewSec > 0 ? 'ahead' : 'behind') + ').'))
        : null);
    return wrap;
  }

  function lockedBody(g) {
    const out = [];
    out.push(h('div', { class: 'callout lock' }, icon('i-lock'),
      h('div', { class: 'grow' },
        h('p', null, h('strong', null, "Enter this gateway's key to see location details and connect")),
        h('p', { class: 'small muted' }, 'This gateway is unverified: anyone on the LAN can announce a gateway with any name. It becomes verified once a key in your keyring matches its announcements.'))));
    if (g.access === 'key_changed') {
      out.push(h('div', { class: 'callout warn small' }, icon('i-alert'),
        h('p', null, 'This gateway used to work with one of your keys — its key was probably reset. Ask its owner for the new key; entering it replaces the old one.')));
    }
    const ep = g.endpoints[0] || null;
    const lan = lanEndpoint(g);
    out.push(section('Announced by the gateway', 'i-gateways', [
      ['Name', g.name],
      ['System', OS_LABEL[g.os] || 'Unknown'],
      ['App version', g.app_version],
      ['Ports', ep && ep.wg_port && ep.ctrl_port ? 'WireGuard ' + ep.wg_port + ' · control ' + ep.ctrl_port + ' (UDP)' : ''],
      ['Connected clients', g.client_count !== null ? String(g.client_count) : ''],
      ['Accepting clients', g.flags.accepting ? 'Yes' : 'No'],
      ['LAN access', g.flags.lan_access ? 'Allowed' : 'Internet only'],
      ['Dual role', g.flags.dual_role ? 'Yes — also connected to another gateway' : 'No'],
      ['LAN address', lan ? lan.ip : ''],
      ['Manual address', g.manual ? g.manual.host + (g.manual.ctrl_port ? ':' + g.manual.ctrl_port : '') : ''],
      ['Last seen', g.online ? 'Online now' : g.last_seen_ms !== null ? fmtAgoMs(g.last_seen_ms) : ''],
    ], 'Public: every PrivateVPN device on the LAN sees these fields.'));
    out.push(section('Identity', 'i-key', [
      ['Fingerprint', g.fingerprint ? h('span', { class: 'code' }, g.fingerprint) : ''],
      ['First seen', fmtDate(g.first_seen)],
      ['Verification', badge('unverified', 'lock', 'i-lock')],
    ]));
    return out;
  }

  function renderDetailsFoot(force) {
    const d = S.details;
    if (!d) return;
    const g = gwById(d.id) || d.lastG;
    if (!g) return;
    const cs = connState(g.id);
    const busy = S.busy.has(g.id) || (!!cs && S.disconnecting);
    const sig = JSON.stringify([g.access, cs, g.is_self, !!g.manual, busy]);
    if (!force && sig === d.footSig) return;
    d.footSig = sig;
    const foot = $('dr-foot');
    foot.classList.toggle('col', g.access !== 'member');
    const nodes = [];
    if (g.access !== 'member' && !g.is_self) {
      d.prompt.label.textContent = 'Network key for “' + g.name + '”';
      d.prompt.root.hidden = false;
      d.prompt.root.classList.add('grow');
      nodes.push(d.prompt.root);
    } else {
      if (g.manual && g.manual.id) {
        const rm = h('button', { type: 'button', class: 'btn ghost', on: { click: () => removeManual(g, rm) } }, icon('i-trash'), 'Remove');
        nodes.push(rm);
      }
      if (!g.is_self) {
        const btn = h('button', { type: 'button', class: cs ? 'btn' : 'btn primary', on: { click: () => onConnectClick(g.id, btn) } }, cs ? 'Disconnect' : 'Connect');
        if (busy) setBusy(btn, true);
        nodes.push(btn);
      }
    }
    if (g.access !== 'member' && g.manual && g.manual.id) {
      const rm = h('button', { type: 'button', class: 'btn ghost', on: { click: () => removeManual(g, rm) } }, icon('i-trash'), 'Remove this manual gateway');
      nodes.push(h('div', { class: 'form-actions start' }, rm));
    }
    foot.replaceChildren(...nodes);
  }

  async function removeManual(g, btn) {
    const ok = await confirmDlg({ title: 'Remove “' + g.name + '”?', text: 'This removes the manually added address. You can add it again later.', ok: 'Remove', danger: true });
    if (!ok) return;
    setBusy(btn, true);
    try {
      await api('DELETE', '/gateways/manual/' + enc(g.manual.id));
      toast('Gateway removed.');
      closeDetails();
      refreshGateways();
    } catch (e) {
      toast(errText(e), 'error');
      setBusy(btn, false);
    }
  }

  // ===================================================================
  // Networks view (keyring)
  // ===================================================================
  const krCards = new Map();

  function renderKeyring() {
    const list = $('kr-list');
    if (!list) return;
    const err = S.errors.keyring;
    $('kr-empty').hidden = S.keyring.length > 0 || !!err;
    setBanner('keyring-error', err ? { kind: 'danger', text: 'The keyring is unavailable: ' + err, action: { label: 'Retry', fn: refreshKeyring } } : null);
    const seen = new Set();
    let prev = null;
    for (const e of S.keyring) {
      seen.add(e.id);
      let c = krCards.get(e.id);
      if (!c) { c = buildKrCard(e.id); krCards.set(e.id, c); }
      updateKrCard(c, e);
      const want = prev ? prev.nextSibling : list.firstChild;
      if (want !== c.root) list.insertBefore(c.root, want);
      prev = c.root;
    }
    for (const [id, c] of krCards) {
      if (!seen.has(id)) { c.root.remove(); krCards.delete(id); hideKey(id); }
    }
  }

  function buildKrCard(id) {
    const c = {};
    c.label = h('h3', { class: 'gw-name' });
    c.badges = h('span', { class: 'badges' });
    c.meta = h('div', { class: 'gw-meta' });
    c.showBtn = h('button', { type: 'button', class: 'btn small', on: { click: () => (S.revealed.has(id) ? hideKey(id) : revealKey(id, c.showBtn)) } });
    const renameBtn = h('button', { type: 'button', class: 'btn small ghost', on: { click: () => startRename(id) } }, icon('i-edit'), 'Rename');
    const removeBtn = h('button', { type: 'button', class: 'btn small ghost', on: { click: () => removeKey(id, removeBtn) } }, icon('i-trash'), 'Remove');
    c.renameInput = h('input', { type: 'text', maxlength: '32', autocomplete: 'off', 'aria-label': 'New label' });
    c.renameErr = h('p', { class: 'form-error', hidden: true });
    c.renameForm = h('form', { class: 'kr-sub', hidden: true, novalidate: true, on: { submit: (ev) => { ev.preventDefault(); saveRename(id, c); } } },
      h('div', { class: 'inline-form' },
        h('label', { class: 'field grow' }, h('span', null, 'Label'), c.renameInput),
        h('button', { type: 'button', class: 'btn ghost', on: { click: () => { c.renameForm.hidden = true; } } }, 'Cancel'),
        h('button', { type: 'submit', class: 'btn primary' }, 'Save')),
      c.renameErr);
    c.reveal = h('div', { class: 'kr-sub', hidden: true });
    c.root = h('article', { class: 'card kr-card' },
      h('div', { class: 'gw-row' },
        h('div', { class: 'kr-icon' }, icon('i-key')),
        h('div', { class: 'grow' }, h('div', { class: 'gw-title' }, c.label, c.badges), c.meta),
        h('div', { class: 'kr-actions' }, c.showBtn, renameBtn, removeBtn)),
      c.renameForm,
      c.reveal);
    return c;
  }

  function updateKrCard(c, e) {
    c.label.textContent = e.label;
    c.label.title = e.label;
    const b = [];
    if (servedNetworkId() === e.id) b.push(badge('Served by this gateway', 'accent', 'i-router'));
    if (e.created_here) b.push(badge('Created here'));
    c.badges.replaceChildren(...b);
    const m = [];
    if (e.created_at) m.push(h('span', null, 'Added ' + fmtDate(e.created_at)));
    if (e.last_used) m.push(h('span', null, 'Last used ' + fmtAgoTs(e.last_used)));
    if (e.gateways_seen !== null) m.push(h('span', null, icon('i-gateways'), plural(e.gateways_seen, 'gateway', 'gateways') + ' seen'));
    c.meta.replaceChildren(...m);
    const rev = S.revealed.get(e.id);
    c.showBtn.replaceChildren(icon(rev ? 'i-eye-off' : 'i-eye'), rev ? 'Hide key' : 'Show key');
    if (rev && !rev.shown) {
      c.reveal.replaceChildren(...keyPanel(e.id, rev.key, () => hideKey(e.id)));
      c.reveal.hidden = false;
      rev.shown = true;
    } else if (!rev && !c.reveal.hidden) {
      c.reveal.replaceChildren();
      c.reveal.hidden = true;
    }
  }

  /** keyPanel shows a key as text + QR with the trust warning (§1). */
  function keyPanel(id, key, onHide) {
    const nodes = [h('div', { class: 'callout warn small' }, icon('i-alert'), h('p', null, KEY_WARNING))];
    let img = null;
    if (id) {
      img = h('img', { class: 'qr', alt: 'QR code of the network key', width: '172', height: '172' });
      img.addEventListener('error', () => { img.hidden = true; });
      img.src = API + '/keyring/' + enc(id) + '/qr.png?ts=' + Date.now();
    }
    nodes.push(h('div', { class: 'reveal' },
      h('div', { class: 'grow' },
        h('div', { class: 'key-text' }, key),
        h('p', { class: 'muted small' }, 'Scan the QR code with PrivateVPN on Android, or paste the text on another device. It is hidden again automatically after two minutes.')),
      img));
    nodes.push(h('div', { class: 'form-actions start' },
      h('button', { type: 'button', class: 'btn small', on: { click: () => copyText(key, 'Key copied to the clipboard.') } }, icon('i-copy'), 'Copy'),
      onHide ? h('button', { type: 'button', class: 'btn small ghost', on: { click: onHide } }, icon('i-eye-off'), 'Hide') : null));
    return nodes;
  }

  function showKey(id, key) {
    hideKey(id, true);
    const timer = setTimeout(() => hideKey(id), 120000);
    S.revealed.set(id, { key, timer, shown: false });
    renderKeyring();
  }
  function hideKey(id, silent) {
    const r = S.revealed.get(id);
    if (!r) return;
    clearTimeout(r.timer);
    S.revealed.delete(id);
    if (!silent) renderKeyring();
  }

  async function revealKey(id, btn) {
    const e = krById(id);
    if (!e) return;
    const ok = await confirmDlg({ title: 'Show the key for “' + e.label + '”?', text: KEY_WARNING, ok: 'Show key' });
    if (!ok) return;
    setBusy(btn, true);
    try {
      const r = await api('POST', '/keyring/' + enc(id) + '/reveal');
      const key = clean(r.key_text, 100);
      if (!key) throw new ApiError('internal', 'no key returned', 0);
      showKey(id, key);
    } catch (err) {
      toast(errText(err), 'error');
    } finally {
      setBusy(btn, false);
    }
  }

  function startRename(id) {
    const c = krCards.get(id), e = krById(id);
    if (!c || !e) return;
    c.renameForm.hidden = false;
    c.renameErr.hidden = true;
    c.renameInput.value = e.label;
    c.renameInput.focus();
    c.renameInput.select();
  }
  async function saveRename(id, c) {
    const label = c.renameInput.value.trim();
    if (!label) { c.renameErr.textContent = 'The label cannot be empty.'; c.renameErr.hidden = false; return; }
    try {
      await api('PATCH', '/keyring/' + enc(id), { label });
      c.renameForm.hidden = true;
      toast('Renamed.');
      refreshKeyring();
    } catch (e) {
      c.renameErr.textContent = errText(e);
      c.renameErr.hidden = false;
    }
  }

  async function removeKey(id, btn) {
    const e = krById(id);
    if (!e) return;
    const ok = await confirmDlg({
      title: 'Remove “' + e.label + '”?',
      text: 'This device forgets the key. Gateways of this network show as locked again until you re-enter it. A connection that uses this network is disconnected.',
      ok: 'Remove', danger: true,
    });
    if (!ok) return;
    setBusy(btn, true);
    try {
      await api('DELETE', '/keyring/' + enc(id));
      toast('Network removed.');
      hideKey(id, true);
      await Promise.allSettled([refreshKeyring(), refreshGateways(), refreshStatus()]);
    } catch (err) {
      toast(errText(err), 'error');
    } finally {
      setBusy(btn, false);
    }
  }

  function wireNetworkForms() {
    const add = $('form-add-key'), create = $('form-create');
    const errOf = (f) => f.querySelector('.form-error');
    const showErr = (f, m) => { const el = errOf(f); el.textContent = m; el.hidden = !m; };
    $('btn-add-key').addEventListener('click', () => { create.hidden = true; add.hidden = !add.hidden; if (!add.hidden) add.elements.key_text.focus(); });
    $('btn-create-network').addEventListener('click', () => { add.hidden = true; create.hidden = !create.hidden; if (!create.hidden) create.elements.label.focus(); });
    for (const f of [add, create]) {
      f.querySelector('[data-cancel]').addEventListener('click', () => { f.reset(); showErr(f, ''); f.hidden = true; });
    }
    add.querySelector('[data-paste]').addEventListener('click', () => pasteInto(add.elements.key_text));
    add.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const key_text = add.elements.key_text.value.trim();
      const label = add.elements.label.value.trim();
      const bad = precheckKey(key_text);
      if (bad) return showErr(add, bad);
      const btn = add.querySelector('[type=submit]');
      setBusy(btn, true);
      try {
        const body = { key_text };
        if (label) body.label = label;
        const r = await api('POST', '/keyring', body);
        toast(r.existing === true ? 'You already have this key.' : 'Key added to your keyring.');
        add.reset();
        showErr(add, '');
        add.hidden = true;
        await Promise.allSettled([refreshKeyring(), refreshGateways()]);
      } catch (e) {
        showErr(add, errText(e));
      } finally {
        setBusy(btn, false);
      }
    });
    create.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const label = create.elements.label.value.trim();
      const btn = create.querySelector('[type=submit]');
      setBusy(btn, true);
      try {
        const r = await api('POST', '/keyring/create', label ? { label } : {});
        create.reset();
        showErr(create, '');
        create.hidden = true;
        await refreshKeyring();
        const id = idStr(r.id), key = clean(r.key_text, 100);
        if (id && key) showKey(id, key);
        toast('Network created.');
      } catch (e) {
        showErr(create, errText(e));
      } finally {
        setBusy(btn, false);
      }
    });
  }

  // ===================================================================
  // Gateway mode view
  // ===================================================================
  const editing = (el) => el === document.activeElement || el.dataset.dirty === '1';

  function renderGatewayMode() {
    if (!$('gwm-switch')) return;
    const st = S.status ? S.status.gateway : null;
    const set = S.settings;
    const enabled = !!(st && st.enabled);
    const sw = $('gwm-switch');
    sw.checked = enabled;
    sw.disabled = S.gwBusy || !st;
    $('gwm-state').textContent = !st
      ? S.errors.status ? 'Status unavailable: ' + S.errors.status : 'Loading…'
      : enabled
        ? 'On · ' + plural(st.clients || 0, 'client', 'clients') + (st.uptime_sec !== null ? ' · up ' + fmtDuration(st.uptime_sec) : '') + (st.network ? ' · serving “' + st.network.label + '”' : '')
        : 'Off — this computer is not sharing its connection.';

    // served network
    const sel = $('gwm-network');
    const cur = (st && st.network && st.network.id) || (set && set.gateway.network_id) || '';
    if (S.keyring.length === 0) {
      sel.replaceChildren(h('option', { value: '' }, 'A new network is created when you turn gateway mode on'));
      sel.disabled = true;
    } else {
      const opts = [];
      if (!cur) opts.push(h('option', { value: '' }, 'Choose a network…'));
      for (const e of S.keyring) opts.push(h('option', { value: e.id }, e.label + (e.created_here ? '' : ' (created elsewhere)')));
      sel.replaceChildren(...opts);
      sel.value = cur;
      sel.disabled = S.gwBusy;
    }

    // name, toggles, ports
    const nameInput = $('form-gw-name').elements.device_name;
    if (!editing(nameInput)) nameInput.value = (set && set.device_name) || (S.status && S.status.device_name) || '';
    const lan = $('gwm-lan');
    lan.checked = set && set.gateway.lan_access !== null ? set.gateway.lan_access : !!(st && st.lan_access);
    const geo = $('gwm-geo');
    geo.checked = set && set.gateway.geo_enabled !== null ? set.gateway.geo_enabled : true;
    const ports = $('form-ports').elements;
    const wg = (set && set.gateway.wg_port) || (st && st.wg_port) || 51820;
    const ctrl = (set && set.gateway.ctrl_port) || (st && st.ctrl_port) || 51821;
    if (!editing(ports.wg_port)) ports.wg_port.value = String(wg);
    if (!editing(ports.ctrl_port)) ports.ctrl_port.value = String(ctrl);

    // reachability
    const dl = $('gwm-reach');
    const rows = [];
    const row = (k, v, sub) => rows.push(h('dt', null, k), h('dd', null, v, sub ? h('span', { class: 'sub' }, sub) : null));
    if (st && st.public_ip) row('Public IP', st.public_ip, 'Members appear on the Internet with this address.');
    if (st && st.nat) row('From the Internet', natText(st.nat, wg, ctrl));
    if (st && st.firewall_rule) {
      if (st.firewall_rule === 'present') {
        row('Firewall rule', badge('Present', 'ok', 'i-check'), 'Windows Firewall allows PrivateVPN to receive UDP on private and domain networks.');
      } else {
        const btn = h('button', { type: 'button', class: 'btn small', on: { click: () => addFirewallRule(btn) } }, 'Add firewall rule');
        row('Firewall rule', h('span', { class: 'badges' }, badge(st.firewall_rule === 'missing' ? 'Missing' : 'Unknown', 'warn', 'i-alert'), btn), 'Without it Windows Firewall blocks members and announcements. Adding it asks for administrator approval once.');
      }
    }
    if (st && enabled && st.fingerprint) row('Fingerprint', h('span', { class: 'code' }, st.fingerprint), 'Members see this in the details panel; they can compare it with you.');
    const ua = navigator.userAgent || '';
    if (/Linux/.test(ua) && !/Android/.test(ua)) {
      const cmd = wg === 51820 && ctrl === 51821 ? 'sudo ufw allow 51820:51822/udp' : 'sudo ufw allow ' + wg + '/udp && sudo ufw allow ' + ctrl + '/udp && sudo ufw allow 51822/udp';
      row('Host firewall', h('span', { class: 'code' }, cmd), 'If members cannot see or reach this gateway and you use ufw, allow its UDP ports.');
    } else if (/Mac OS X|Macintosh/.test(ua)) {
      row('Host firewall', 'macOS may ask whether PrivateVPN may accept incoming connections — choose Allow.');
    }
    if (!rows.length) row('Status', enabled ? 'Checking…' : 'Turn gateway mode on to check reachability.');
    dl.replaceChildren(...rows);

    $('btn-reset-key').disabled = !(st && st.network);
  }

  async function addFirewallRule(btn) {
    if (S.firewallBusy) return;
    S.firewallBusy = true;
    setBusy(btn, true);
    renderProblems();
    try {
      await api('POST', '/firewall/add');
      toast('Firewall rule added.');
    } catch (e) {
      toast(errText(e), 'error');
    } finally {
      S.firewallBusy = false;
      setBusy(btn, false);
      await refreshStatus();
      renderProblems();
    }
  }

  async function putSettings(patch, okMsg) {
    try {
      await api('PUT', '/settings', patch);
      if (okMsg) toast(okMsg);
      return true;
    } catch (e) {
      toast(errText(e), 'error');
      return false;
    } finally {
      await Promise.allSettled([refreshSettings(), refreshStatus()]);
    }
  }

  function wireGatewayMode() {
    const sw = $('gwm-switch');
    sw.addEventListener('change', async () => {
      const want = sw.checked;
      sw.checked = !want; // reflect the real state until the engine confirms
      const st = S.status ? S.status.gateway : null;
      if (want) {
        const name = (S.settings && S.settings.device_name) || (S.status && S.status.device_name) || '';
        const ok = await confirmDlg({
          title: 'Turn on gateway mode?',
          text: "Members' traffic will exit from your Internet connection and carry your public IP.",
          extra: [h('p', { class: 'muted small' }, 'Every PrivateVPN device on this LAN will see this gateway' + (name ? ' (“' + name + '”)' : '') + ', its OS and app version. Only devices with the network key can connect.')],
          ok: 'Turn on',
        });
        if (!ok) return;
      } else if (st && st.clients) {
        const ok = await confirmDlg({ title: 'Turn off gateway mode?', text: plural(st.clients, 'member is', 'members are') + ' connected and will be disconnected.', ok: 'Turn off', danger: true });
        if (!ok) return;
      }
      S.gwBusy = true;
      renderGatewayMode();
      try {
        await api('POST', want ? '/gateway/enable' : '/gateway/disable');
        toast(want ? 'Gateway mode is on.' : 'Gateway mode is off.');
      } catch (e) {
        toast(errText(e), 'error');
      } finally {
        S.gwBusy = false;
        await Promise.allSettled([refreshStatus(), refreshKeyring()]);
      }
    });

    $('gwm-network').addEventListener('change', async (ev) => {
      const id = ev.target.value;
      const e = krById(id);
      if (!e) return;
      const st = S.status ? S.status.gateway : null;
      if (st && st.enabled) {
        const ok = await confirmDlg({ title: 'Serve “' + e.label + '”?', text: 'The gateway restarts and connected members are disconnected. Only holders of this network\'s key can connect afterwards.', ok: 'Switch network' });
        if (!ok) { renderGatewayMode(); return; }
      }
      try {
        await api('POST', '/gateway/network', { keyring_id: id });
        toast('The gateway now serves “' + e.label + '”.');
      } catch (err) {
        toast(errText(err), 'error');
      } finally {
        await Promise.allSettled([refreshStatus(), refreshKeyring()]);
      }
    });

    for (const f of [$('form-gw-name'), $('form-device-name')]) {
      const input = f.elements.device_name;
      input.addEventListener('input', () => { input.dataset.dirty = '1'; });
      f.addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const v = input.value.trim();
        if (!v) { toast('The name cannot be empty.', 'error'); return; }
        if (Array.from(v).length > 32) { toast('The name can have at most 32 characters.', 'error'); return; }
        delete input.dataset.dirty;
        await putSettings({ device_name: v }, 'Name saved.');
      });
    }

    $('gwm-lan').addEventListener('change', (ev) => putSettings({ gateway: { lan_access: ev.target.checked } }, ev.target.checked ? 'Members may now reach your local network.' : 'Members get Internet only.'));
    $('gwm-geo').addEventListener('change', (ev) => putSettings({ gateway: { geo: { enabled: ev.target.checked } } }, ev.target.checked ? 'Location lookup is on.' : 'Location lookup is off.'));

    const pf = $('form-ports');
    for (const n of ['wg_port', 'ctrl_port']) pf.elements[n].addEventListener('input', () => { pf.elements[n].dataset.dirty = '1'; });
    pf.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const wg = Number(pf.elements.wg_port.value), ctrl = Number(pf.elements.ctrl_port.value);
      const okPort = (p) => Number.isInteger(p) && p >= 1024 && p <= 65535;
      if (!okPort(wg) || !okPort(ctrl)) { toast('Ports must be between 1024 and 65535.', 'error'); return; }
      if (wg === ctrl || wg === 51822 || ctrl === 51822) { toast('Use two different ports, neither of them 51822.', 'error'); return; }
      delete pf.elements.wg_port.dataset.dirty;
      delete pf.elements.ctrl_port.dataset.dirty;
      await putSettings({ gateway: { wg_port: wg, ctrl_port: ctrl } }, 'Ports saved.');
    });

    $('btn-reset-key').addEventListener('click', async (ev) => {
      const btn = ev.currentTarget;
      const st = S.status ? S.status.gateway : null;
      const net = st && st.network;
      if (!net) return;
      const ok = await confirmDlg({
        title: 'Reset the key of “' + net.label + '”?',
        text: 'A new key replaces the current one. Every member must enter the new key, and connected members are disconnected now.',
        ok: 'Reset key', danger: true,
      });
      if (!ok) return;
      setBusy(btn, true);
      try {
        const r = await api('POST', '/gateway/reset-key');
        const key = clean(r.key_text, 100);
        const box = $('reset-result');
        if (key) {
          box.replaceChildren(h('div', { class: 'kr-sub' }, h('strong', null, 'New key for “' + net.label + '”'), ...keyPanel(net.id, key, () => box.replaceChildren())));
          setTimeout(() => box.replaceChildren(), 120000);
        }
        toast('Key reset. Give the new key to the devices you keep.');
      } catch (e) {
        toast(errText(e), 'error');
      } finally {
        setBusy(btn, false);
        Promise.allSettled([refreshStatus(), refreshKeyring()]);
      }
    });
  }

  // ===================================================================
  // Status view
  // ===================================================================
  function renderStatus() {
    const cBox = $('st-client'), gBox = $('st-gateway');
    if (!cBox) return;
    const st = S.status;
    if (!st) {
      const msg = S.errors.status ? 'Status unavailable: ' + S.errors.status : 'Loading…';
      cBox.replaceChildren(h('p', { class: 'muted' }, msg));
      gBox.replaceChildren();
      return;
    }
    const c = st.client, g = st.gateway;
    const active = ACTIVE.has(c.state);
    const look = clientLook(c);
    const kv = (rows) => {
      const dl = h('dl', { class: 'kv' });
      for (const [k, v, sub] of rows) if (v !== '' && v !== null && v !== undefined) dl.append(h('dt', null, k), h('dd', null, v, sub ? h('span', { class: 'sub' }, sub) : null));
      return dl;
    };
    const hs = c.handshake_age_sec;
    // A failed session is a big red card: the block stays until the user acts.
    cBox.className = 'card st-client' + (look.tone === 'danger' ? ' alarm' : look.tone === 'warn' ? ' caution' : '');
    if (look.tone === 'danger') cBox.setAttribute('role', 'alert'); else cBox.removeAttribute('role');
    const cNodes = [
      h('div', { class: 'stat-head ' + look.tone },
        h('div', { class: 'conn-icon' }, icon(look.icon)),
        h('div', null, h('h2', null, 'This device'), h('div', { class: 'stat-big' }, look.title))),
      h('p', { class: look.tone === 'danger' ? '' : 'muted' }, look.text),
    ];
    if (c.state === 'blocked') {
      cNodes.push(h('div', { class: 'form-actions start' }, reconnectBtn(), disconnectBtn()));
      if (S.disconnecting) cNodes.push(adminNote());
    }
    if (g.enabled && active && c.gateway_id) {
      cNodes.push(h('div', { class: 'dual callout small' }, icon('i-info'), h('div', null,
        h('p', null, 'You → ' + (c.gateway_name || 'gateway')),
        h('p', null, plural(g.clients || 0, 'client', 'clients') + ' → your connection'))));
    }
    const ksRow = ['Kill switch', c.kill_switch === 'on' ? 'On' : c.kill_switch === 'off' ? 'Off' : '',
      c.kill_switch === 'on' ? 'Blocks all traffic outside the VPN from connecting until you choose Disconnect.'
        : c.kill_switch === 'off' ? 'If the VPN drops, apps use your real IP. Turn it on under Settings.' : ''];
    if (active && c.gateway_id) {
      const interrupted = c.state === 'degraded' || c.state === 'blocked';
      cNodes.push(kv([
        ['Gateway', c.gateway_name],
        ['Network', c.network_label],
        ['Assigned IP', c.assigned_ip],
        ['Connected since', fmtDate(c.since), c.since ? fmtAgoTs(c.since) : ''],
        ['Handshake', hs === null ? '' : hs < 0 ? 'none yet' : fmtAgoMs(hs * 1000)],
        ['Received', c.rx !== null ? fmtBytes(c.rx) : ''],
        ['Sent', c.tx !== null ? fmtBytes(c.tx) : ''],
        ['Interrupted since', interrupted ? fmtDate(c.degraded_since) : '', interrupted && c.degraded_since ? fmtAgoTs(c.degraded_since) : ''],
        ksRow,
      ]));
      if (c.state === 'degraded' && c.degraded_since && Date.now() - tsMs(c.degraded_since) > 600000) {
        cNodes.push(h('div', { class: 'callout warn small' }, icon('i-alert'), h('p', null, 'The gateway has not answered for over 10 minutes. Traffic stays held until it is back — Disconnect to use your own connection (and real IP) again.')));
      }
    } else {
      cNodes.push(kv([ksRow]));
    }
    if (active && c.state !== 'blocked') {
      const test = c.state === 'connected' ? h('button', { type: 'button', class: 'btn ghost', on: { click: () => selftest(test) } }, 'Test connection') : null;
      cNodes.push(h('div', { class: 'form-actions start' }, disconnectBtn(), test));
      if (S.disconnecting) cNodes.push(adminNote());
      if (S.selftest && c.state === 'connected') cNodes.push(h('p', { class: 'small ' + (S.selftest.ok ? 'muted' : 'form-error') }, S.selftest.text));
    } else if (!active) {
      cNodes.push(h('div', { class: 'form-actions start' }, h('button', { type: 'button', class: 'btn primary', on: { click: () => setView('gateways') } }, 'Choose a gateway')));
    }
    cBox.replaceChildren(...cNodes);

    const gNodes = [
      h('div', { class: 'stat-head gw' + (g.enabled ? ' on' : '') },
        h('div', { class: 'conn-icon' }, icon('i-router')),
        h('div', null, h('h2', null, 'Gateway'), h('div', { class: 'stat-big' }, g.enabled ? 'On' : 'Off'))),
    ];
    if (g.enabled) {
      gNodes.push(kv([
        ['Network', g.network ? g.network.label : ''],
        ['Connected clients', g.clients !== null ? String(g.clients) : ''],
        ['Uptime', g.uptime_sec !== null ? fmtDuration(g.uptime_sec) : ''],
        ['Ports', g.wg_port && g.ctrl_port ? 'WireGuard ' + g.wg_port + ' · control ' + g.ctrl_port + ' (UDP)' : ''],
        ['Tunnel subnet', g.subnet],
        ['LAN access', g.lan_access ? 'Allowed' : 'Internet only'],
        ['Public IP', g.public_ip],
        ['From the Internet', g.nat ? natText(g.nat, g.wg_port, g.ctrl_port) : ''],
        ['Firewall rule', { present: 'Present', missing: 'Missing', unknown: 'Unknown' }[g.firewall_rule] || ''],
      ]));
    } else {
      gNodes.push(h('p', { class: 'muted' }, 'This computer is not sharing its connection.'));
    }
    gNodes.push(h('div', { class: 'form-actions start' }, h('button', { type: 'button', class: 'btn ghost', on: { click: () => setView('gateway') } }, 'Gateway settings')));
    gBox.replaceChildren(...gNodes);
  }

  async function selftest(btn) {
    setBusy(btn, true);
    try {
      const r = await api('POST', '/client/selftest');
      const ms = int(r.ms, 0, 600000);
      if (r.dns_ok === true && r.tcp_ok === true) S.selftest = { ok: true, text: 'Internet via gateway: OK' + (ms !== null ? ' (' + ms + ' ms)' : '') };
      else if (r.dns_ok !== true) S.selftest = { ok: false, text: 'Internet via gateway: DNS failed' };
      else S.selftest = { ok: false, text: 'Internet via gateway: no route' };
    } catch (e) {
      S.selftest = { ok: false, text: 'Test failed: ' + errText(e) };
    } finally {
      setBusy(btn, false);
      renderStatus();
    }
  }

  // ===================================================================
  // Log view
  // ===================================================================
  let logPending = false;
  function renderLog(now) {
    if (S.view !== 'log') return;
    if (!now) {
      if (logPending) return;
      logPending = true;
      requestAnimationFrame(() => { logPending = false; renderLog(true); });
      return;
    }
    const box = $('log-box');
    const f = $('log-filter').value.trim().toLowerCase();
    const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    const lines = f ? S.log.filter((l) => l.toLowerCase().includes(f)) : S.log;
    box.textContent = lines.length ? lines.join('\n') : S.errors.log ? 'Log unavailable: ' + S.errors.log : f ? 'No matching lines.' : 'No events yet.';
    if (atBottom) box.scrollTop = box.scrollHeight;
  }
  function appendLog(line) {
    const l = clean(line, 600);
    if (!l) return;
    S.log.push(l);
    if (S.log.length > 1000) S.log.splice(0, S.log.length - 1000);
    renderLog(false);
  }

  // ===================================================================
  // Settings view
  // ===================================================================
  function applyTheme(t) {
    if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
    else delete document.documentElement.dataset.theme;
  }

  function renderSettings() {
    if (!$('form-device-name')) return;
    const set = S.settings;
    const name = $('form-device-name').elements.device_name;
    if (!editing(name)) name.value = (set && set.device_name) || (S.status && S.status.device_name) || '';
    const auto = $('set-autostart');
    auto.checked = !!(set && set.ui.autostart);
    auto.disabled = !set;
    // Kill switch: the setting, else what status reports (default on).
    const sc = S.status ? S.status.client : null;
    const ksSet = set ? set.client.kill_switch : null;
    const ksOn = ksSet !== null ? ksSet : !(sc && sc.kill_switch === 'off');
    const ks = $('set-killswitch'), lan = $('set-allowlan');
    ks.checked = ksOn;
    ks.disabled = !set || ksSet === null || S.ksBusy;
    lan.checked = set && set.client.allow_lan !== null ? set.client.allow_lan : true;
    lan.disabled = !set || set.client.allow_lan === null || !ksOn || S.ksBusy;
    const live = sc && ACTIVE.has(sc.state) && !!sc.gateway_id;
    const note = $('set-ks-note');
    note.hidden = !live;
    note.textContent = live ? 'You are connected: kill switch changes apply the next time you connect.' : '';
    // Reconnect after restart (client.auto_reconnect, default on).
    const ar = $('set-autoreconnect');
    const arSet = set ? set.client.auto_reconnect : null;
    ar.checked = arSet !== null ? arSet : true;
    ar.disabled = !set || arSet === null || S.ksBusy;
    const os = S.status && OS_LABEL[S.status.os] && S.status.os !== 'android' ? OS_LABEL[S.status.os] : 'Windows/macOS/Linux';
    $('set-ar-admin').textContent = 'After a restart your computer stays blocked until PrivateVPN reconnects; ' + os + ' will ask for administrator approval at login.';
    $('set-ar-hint').hidden = !(set && set.ui.autostart === false && ar.checked);
    const theme = (set && set.ui.theme) || 'system';
    for (const r of document.querySelectorAll('#set-theme input')) r.checked = r.value === theme;
    const port = $('form-ui-port').elements.port;
    if (!editing(port)) port.value = set && set.ui.port ? String(set.ui.port) : '';
    const rows = [];
    const row = (k, v) => { if (v) rows.push(h('dt', null, k), h('dd', null, v)); };
    row('Version', S.status && S.status.version);
    row('Web UI', location.host);
    row('Networks in keyring', S.status && S.status.keyring_count !== null ? String(S.status.keyring_count) : '');
    row('Live updates', S.sseOK ? 'Connected' : 'Reconnecting…');
    if (S.errors.settings) row('Settings', 'Unavailable: ' + S.errors.settings);
    $('about').replaceChildren(...rows);
  }

  async function putClientSetting(patch, okMsg) {
    S.ksBusy = true;
    renderSettings();
    try {
      await putSettings({ client: patch }, okMsg);
    } finally {
      S.ksBusy = false;
      renderSettings();
    }
  }

  function wireSettings() {
    $('set-killswitch').addEventListener('change', async (ev) => {
      const want = ev.target.checked;
      if (!want) {
        ev.target.checked = true; // reflect the real state until confirmed and saved
        const ok = await confirmDlg({
          title: 'Turn off the kill switch?',
          text: 'Without it, if the VPN connection drops or PrivateVPN crashes, your traffic goes out directly and websites see your real IP address.',
          extra: [h('p', { class: 'muted small' }, 'While connected, traffic is still held inside the tunnel when the gateway stops answering — but nothing blocks it if the tunnel itself goes away.')],
          ok: 'Turn off', danger: true,
        });
        if (!ok) return;
      }
      await putClientSetting({ kill_switch: want }, want ? 'Kill switch is on.' : 'Kill switch is off — your real IP is exposed if the VPN drops.');
    });
    $('set-allowlan').addEventListener('change', (ev) => putClientSetting({ allow_lan: ev.target.checked },
      ev.target.checked ? 'Local network stays reachable while blocked.' : 'Local network is blocked too while the kill switch is active.'));
    $('set-autoreconnect').addEventListener('change', (ev) => putClientSetting({ auto_reconnect: ev.target.checked },
      ev.target.checked ? 'PrivateVPN reconnects automatically after a restart.' : 'PrivateVPN no longer reconnects by itself after a restart.'));
    $('set-autostart').addEventListener('change', (ev) => putSettings({ ui: { autostart: ev.target.checked } }, ev.target.checked ? 'PrivateVPN starts at login.' : 'PrivateVPN no longer starts at login.'));
    for (const r of document.querySelectorAll('#set-theme input')) {
      r.addEventListener('change', () => {
        if (!r.checked) return;
        applyTheme(r.value);
        putSettings({ ui: { theme: r.value } });
      });
    }
    const pf = $('form-ui-port');
    pf.elements.port.addEventListener('input', () => { pf.elements.port.dataset.dirty = '1'; });
    pf.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const p = Number(pf.elements.port.value);
      if (!Number.isInteger(p) || p < 1024 || p > 65535) { toast('The port must be between 1024 and 65535.', 'error'); return; }
      delete pf.elements.port.dataset.dirty;
      await putSettings({ ui: { port: p } }, 'Saved. The new port is used after PrivateVPN restarts.');
    });
    $('btn-signout').addEventListener('click', async () => {
      try { await api('DELETE', '/session'); } catch (_) { /* signed out anyway */ }
      signingOut = true;
      if (es) es.close();
      location.replace('/');
    });
    $('btn-quit').addEventListener('click', async () => {
      const ok = await confirmDlg({
        title: 'Quit PrivateVPN?',
        text: 'This disconnects this device and removes the kill switch\'s block, turns gateway mode off until the next start and removes the tray icon. PrivateVPN does not reconnect by itself after you quit.',
        extra: S.status && ACTIVE.has(S.status.client.state) ? [h('p', { class: 'muted small' }, 'Your system may ask for administrator approval to remove the block.')] : [],
        ok: 'Quit', danger: true,
      });
      if (!ok) return;
      S.quit = true;
      if (es) es.close();
      try { await api('POST', '/quit'); } catch (_) { /* the server may be gone already */ }
      document.body.replaceChildren(h('main', { class: 'login' }, h('div', { class: 'card login-card' },
        icon('i-shield', 'login-mark'), h('h1', null, 'PrivateVPN has quit'), h('p', { class: 'muted' }, 'You can close this tab.'))));
    });
  }

  // ===================================================================
  // Live events (SSE, §14.3)
  // ===================================================================
  let es = null;
  let esRetry = 0;

  function connectEvents() {
    if (es) es.close();
    es = new EventSource(API + '/events');
    es.onopen = () => { S.sseOK = true; esRetry = 0; renderSettings(); };
    es.onmessage = (m) => {
      let ev;
      try { ev = JSON.parse(m.data); } catch (_) { return; }
      onEvent(ev);
    };
    es.onerror = () => {
      S.sseOK = false;
      renderSettings();
      if (es && es.readyState === EventSource.CLOSED) {
        es = null;
        setTimeout(recoverEvents, Math.min(30000, 2000 * ++esRetry));
      }
    };
  }
  async function recoverEvents() {
    if (S.quit || signingOut) return;
    try {
      const r = await api('GET', '/session');
      if (typeof r.csrf === 'string') csrf = r.csrf;
      connectEvents();
      loadAll();
    } catch (e) {
      if (e.status !== 401) setTimeout(recoverEvents, 5000);
    }
  }

  function onEvent(ev) {
    if (!isObj(ev) || typeof ev.type !== 'string') return;
    switch (ev.type) {
      case 'status':
        if (isObj(ev.status)) { S.status = normStatus(ev.status); delete S.errors.status; renderAfterStatus(); }
        break;
      case 'gateways':
        if (Array.isArray(ev.gateways)) {
          S.gateways = sortGateways(ev.gateways.slice(0, 128).map(normGateway).filter(Boolean));
          delete S.errors.gateways;
          renderAfterGateways();
        }
        break;
      case 'keyring':
        if (Array.isArray(ev.entries)) {
          S.keyring = ev.entries.map(normKeyEntry).filter(Boolean).slice(0, 64);
          delete S.errors.keyring;
          renderAfterKeyring();
          renderGateways();
        }
        break;
      case 'log':
        if (typeof ev.line === 'string') appendLog(ev.line);
        break;
      case 'error': {
        const code = clean(ev.code, 40);
        const text = ERR_TEXT[code] || clean(ev.message, 300) || 'Something went wrong.';
        if (code === 'clock_skew') setBanner('clock', { kind: 'warn', text });
        else toast(text, 'error');
        break;
      }
      case 'elevation_needed':
        showElevation();
        break;
      case 'resync':
        loadAll();
        break;
      default:
        break;
    }
  }

  function showElevation() {
    setBanner('elevation', {
      kind: 'warn',
      text: 'Administrator approval is needed to connect: the system prompt was cancelled or failed. Gateway mode never needs it.',
      action: {
        label: 'Try again',
        fn: () => {
          setBanner('elevation', null);
          const id = S.status && S.status.client.gateway_id;
          if (id) connect(id); else setView('gateways');
        },
      },
    });
  }

  // ===================================================================
  // Boot
  // ===================================================================
  function hashParams() {
    const raw = location.hash.slice(1);
    return raw.includes('=') ? new URLSearchParams(raw) : new URLSearchParams(VIEWS.includes(raw) ? 'v=' + raw : '');
  }

  function wireStatic() {
    for (const b of document.querySelectorAll('.nav-item')) b.addEventListener('click', () => setView(b.dataset.view));
    window.addEventListener('hashchange', () => {
      const v = hashParams().get('v');
      if (v && v !== S.view) setView(v, false);
    });
    $('dr-close').addEventListener('click', closeDetails);
    $('drawer-backdrop').addEventListener('click', closeDetails);
    document.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape' && S.details && !$('dlg').open) closeDetails();
    });
    $('log-filter').addEventListener('input', () => renderLog(true));
    $('btn-log-copy').addEventListener('click', () => copyText(S.log.join('\n'), 'Log copied to the clipboard.'));
    wireManualForm();
    wireNetworkForms();
    wireGatewayMode();
    wireSettings();
    document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshStatus(); });
  }

  async function bootApp() {
    wireStatic();
    const params = hashParams();
    const tok = params.get('t');
    const unlock = idStr(params.get('unlock') || '');
    setView(params.get('v') || 'gateways', false);
    history.replaceState(null, '', location.pathname + '#' + S.view); // drops any token from the URL

    // The CSRF token is held in memory only: a fresh login link gives a new
    // session; otherwise (reload) the current session's token is fetched.
    let ok = false;
    if (tok) {
      try { const r = await api('POST', '/session', { token: tok }); csrf = typeof r.csrf === 'string' ? r.csrf : ''; ok = !!csrf; } catch (_) { ok = false; }
    }
    if (!ok) {
      try {
        const r = await api('GET', '/session');
        csrf = typeof r.csrf === 'string' ? r.csrf : '';
      } catch (e) {
        if (e.status === 401) { sessionEnded(); return; }
        toast(errText(e), 'error');
      }
    }
    if (unlock) { S.pendingUnlock = unlock; S.pendingUnlockUntil = Date.now() + 30000; }
    renderChrome();
    await loadAll();
    connectEvents();
    tryPendingUnlock();

    // Fallbacks: poll while the event stream is down, and keep the live
    // counters (handshake age, bytes) fresh on the Status view.
    setInterval(() => {
      if (document.hidden || S.quit || signingOut) return;
      if (!S.sseOK) { refreshStatus(); refreshGateways(); } else if (S.view === 'status' || (S.status && ACTIVE.has(S.status.client.state))) refreshStatus();
    }, 5000);
    setInterval(() => { if (!document.hidden && S.view === 'gateways') renderGateways(); }, 15000);
  }

  if (PAGE === 'login') bootLogin();
  else if (PAGE === 'app') bootApp();
})();
