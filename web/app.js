(() => {
'use strict';

const $ = s => document.querySelector(s);
const API = {
  btc: 'https://mempool.space/api',
  eth: 'https://eth.blockscout.com/api/v2',
  op: 'https://explorer.optimism.io/api/v2',
  tron: 'https://api.trongrid.io'
};
const CHAIN_NAME = { btc: 'Bitcoin', eth: 'Ethereum', op: 'Optimism', tron: 'Tron' };
const OFAC_LISTS = { btc: ['XBT'], eth: ['ETH', 'USDT', 'USDC'], op: ['ETH', 'USDT', 'USDC'], tron: ['TRX', 'USDT'] };
const TRON_STABLES = { TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t: 'USDT', TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8: 'USDC' };
const SERVICE_TX_THRESHOLD = 5000;
const isEvm = c => c === 'eth' || c === 'op';

// ---------- hulpfuncties ----------
const sleep = ms => new Promise(r => setTimeout(r, ms));
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const short = a => a.length > 14 ? a.slice(0, 6) + '…' + a.slice(-4) : a;
const norm = (chain, a) => isEvm(chain) ? a.toLowerCase() : a;
const keyOf = (chain, a) => chain + ':' + norm(chain, a);
function fmt(v) {
  if (!isFinite(v)) return '?';
  const abs = Math.abs(v);
  if (abs >= 1000) return v.toLocaleString('nl-NL', { maximumFractionDigits: 0 });
  if (abs >= 1) return v.toLocaleString('nl-NL', { maximumFractionDigits: 2 });
  return v.toLocaleString('nl-NL', { maximumSignificantDigits: 4 });
}
const fmtTime = t => t ? new Date(t * 1000).toLocaleString('nl-NL', { dateStyle: 'short', timeStyle: 'short' }) : '?';

function detectChain(a) {
  a = a.trim();
  if (/^0x[a-fA-F0-9]{40}$/.test(a)) return 'eth';
  if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(a)) return 'tron';
  if (/^(bc1[a-z0-9]{25,87}|[13][1-9A-HJ-NP-Za-km-z]{25,34})$/.test(a)) return 'btc';
  return null;
}

const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* opslag niet beschikbaar */ } }
};
let customLabels = store.get('chaintrace.labels', {});

// ---------- lokale OSINT-database (alleen in de Android-app) ----------
const LOCAL_DB = !!window.AndroidBridge?.osintLookup;
const dbCache = new Map();
function dbStats() {
  try { return JSON.parse(window.AndroidBridge.osintStats()); } catch { return null; }
}
function dbLookup(n) {
  if (!LOCAL_DB) return null;
  if (!dbCache.has(n.key)) {
    let r = null;
    try { r = JSON.parse(window.AndroidBridge.osintLookup(n.addr, nodes.get(current?.seedKey)?.addr || '')); } catch { /* bridge niet beschikbaar */ }
    dbCache.set(n.key, r);
  }
  return dbCache.get(n.key);
}
function recordObservations() {
  if (!LOCAL_DB || !current) return;
  const seed = nodes.get(current.seedKey);
  if (!seed) return;
  try {
    window.AndroidBridge.recordObservations(JSON.stringify({
      seed: seed.addr, pattern: current.pattern,
      nodes: [...nodes.values()].map(n => ({ address: n.addr, chain: n.chain, role: n.role, classification: nodeClass(n), flags: n.flags.map(f => f.code), label: labelOf(n) }))
    }));
  } catch { /* niet fataal */ }
}
const CAT_NL = { sanction: 'sanctie', scam: 'scam', phishing: 'phishing', exploit: 'exploit/hack', ransomware: 'ransomware', frozen: 'bevroren', exchange: 'exchange', mixer: 'mixer', darknet: 'darknet', bridge: 'bridge', label: 'label', user: 'eigen label' };

// ---------- HTTP met wachtrij, cache en retry ----------
const MAX_PAR = 3;
let running = 0;
const waiting = [];
const cache = new Map();
let abortCtl = new AbortController();

function acquire() { return new Promise(r => { if (running < MAX_PAR) { running++; r(); } else waiting.push(r); }); }
function release() { const next = waiting.shift(); if (next) next(); else running--; }

// Minimale tijd tussen verzoeken per host; TronGrid zonder API-sleutel is streng.
const HOST_GAP = { 'api.trongrid.io': 1050 }; // gemeten: ~1 verzoek/s wordt geaccepteerd
const hostNext = {};
async function throttle(host) {
  const gap = HOST_GAP[host];
  if (!gap) return;
  const now = Date.now();
  const at = Math.max(now, hostNext[host] || 0);
  hostNext[host] = at + gap;
  if (at > now) await sleep(at - now);
}

function getData(url, asText = false) {
  if (cache.has(url)) return cache.get(url);
  const host = new URL(url).host;
  const p = (async () => {
    await acquire();
    try {
      for (let attempt = 0; attempt < 6; attempt++) {
        await throttle(host);
        const r = await fetch(url, { signal: abortCtl.signal });
        if (r.status === 429 || r.status >= 500) {
          const ra = Number(r.headers.get('retry-after'));
          await sleep(ra > 0 ? Math.min(ra * 1000, 20000) : Math.min(1000 * 2 ** attempt, 15000));
          continue;
        }
        if (r.status === 404 || r.status === 400) return null;
        if (!r.ok) throw new Error(`HTTP ${r.status} van ${new URL(url).host}`);
        return asText ? r.text() : r.json();
      }
      throw new Error('Rate limit bij ' + new URL(url).host);
    } finally { release(); }
  })();
  cache.set(url, p);
  p.catch(() => cache.delete(url));
  return p;
}

// ---------- OSINT-lijsten ----------
const osint = { ofac: new Set(), ofacLoaded: new Set(), scam: null };
async function loadLists(chain) {
  // In de app staan deze lijsten (en meer) al in de lokale database.
  if (LOCAL_DB && (dbStats()?.labels || 0) > 0) return;
  await Promise.all(OFAC_LISTS[chain].map(async sym => {
    if (osint.ofacLoaded.has(sym)) return;
    const txt = await getData(`https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_${sym}.txt`, true).catch(() => null);
    if (!txt) return;
    for (const a of txt.split(/\s+/)) if (a) osint.ofac.add(a.startsWith('0x') ? a.toLowerCase() : a);
    osint.ofacLoaded.add(sym);
  }));
  if (isEvm(chain) && !osint.scam) {
    const arr = await getData('https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json').catch(() => null);
    if (arr) osint.scam = new Set(arr.map(a => a.toLowerCase()));
  }
}

// ---------- ketenspecifiek ophalen → genormaliseerde transfers ----------
async function fetchBtc(addr) {
  const [info, txs] = await Promise.all([
    getData(`${API.btc}/address/${addr}`),
    getData(`${API.btc}/address/${addr}/txs`)
  ]);
  let all = txs || [];
  const conf = all.filter(t => t.status?.confirmed);
  let cursor = conf.length >= 25 ? { last: conf[conf.length - 1].txid } : null;
  if (cursor) {
    const more = await getData(`${API.btc}/address/${addr}/txs/chain/${cursor.last}`).catch(() => null);
    if (more) { all = all.concat(more); cursor = more.length >= 25 ? { last: more[more.length - 1].txid } : null; }
  }
  const { transfers, peelCount } = parseBtcTxs(addr, all);
  const cs = info?.chain_stats;
  return {
    transfers, peelCount, meta: {}, cursor,
    txCount: cs?.tx_count ?? all.length,
    balance: cs ? `${fmt((cs.funded_txo_sum - cs.spent_txo_sum) / 1e8)} BTC` : null
  };
}

function parseBtcTxs(addr, all) {
  const transfers = [];
  let peelCount = 0;
  for (const tx of all) {
    const ins = [...new Set(tx.vin.map(v => v.prevout?.scriptpubkey_address).filter(Boolean))];
    const outs = tx.vout.filter(o => o.scriptpubkey_address).map(o => ({ a: o.scriptpubkey_address, v: o.value / 1e8 }));
    const time = tx.status?.block_time || Math.floor(Date.now() / 1000);
    if (ins.includes(addr)) {
      // uitgaand; outputs terug naar een input-adres behandelen we als wisselgeld
      for (const o of outs) if (!ins.includes(o.a)) transfers.push({ from: addr, to: o.a, value: o.v, asset: 'BTC', time, txid: tx.txid });
      if (outs.length === 2) {
        const total = outs[0].v + outs[1].v;
        if (total > 0 && Math.max(outs[0].v, outs[1].v) / total >= 0.8) peelCount++;
      }
    } else {
      const recv = outs.filter(o => o.a === addr).reduce((s, o) => s + o.v, 0);
      if (recv > 0) for (const i of ins) transfers.push({ from: i, to: addr, value: recv / ins.length, asset: 'BTC', time, txid: tx.txid });
    }
  }
  return { transfers, peelCount };
}

async function fetchEvm(chain, addr) {
  const B = API[chain];
  const [info, counters, txs, tts] = await Promise.all([
    getData(`${B}/addresses/${addr}`).catch(() => null),
    getData(`${B}/addresses/${addr}/counters`).catch(() => null),
    getData(`${B}/addresses/${addr}/transactions`),
    getData(`${B}/addresses/${addr}/token-transfers?type=ERC-20`)
  ]);
  const page = parseEvmPage(txs, tts, info);
  const txCount = Number(counters?.transactions_count || 0) + Number(counters?.token_transfers_count || 0);
  return {
    ...page, txCount: txCount || null,
    balance: info ? `${fmt(Number(info.coin_balance || 0) / 1e18)} ETH` : null
  };
}

function parseEvmPage(txs, tts, info) {
  const meta = {};
  const take = o => {
    if (!o?.hash) return null;
    const k = o.hash.toLowerCase();
    const m = meta[k] || (meta[k] = { tags: [] });
    const tags = [
      ...(o.metadata?.tags || []).map(t => t.name),
      ...(o.public_tags || []).map(t => t.display_name || t.label)
    ].filter(Boolean);
    for (const t of tags) if (!m.tags.includes(t)) m.tags.push(t);
    if (o.name) m.name = o.name;
    if (o.ens_domain_name) m.ens = o.ens_domain_name;
    if (o.is_scam) m.scam = true;
    if (o.is_contract) m.contract = true;
    if (o.reputation && o.reputation !== 'ok') m.reputation = o.reputation;
    return k;
  };
  if (info) take(info);
  const transfers = [];
  for (const tx of txs?.items || []) {
    const f = take(tx.from), t = take(tx.to);
    const v = Number(tx.value) / 1e18;
    if (!f || !t || !(v > 0) || tx.status === 'error') continue;
    transfers.push({
      from: f, to: t, value: v, asset: 'ETH', time: Date.parse(tx.timestamp) / 1000, txid: tx.hash,
      usd: tx.exchange_rate ? v * Number(tx.exchange_rate) : null
    });
  }
  for (const tt of tts?.items || []) {
    const f = take(tt.from), t = take(tt.to);
    if (!f || !t) continue;
    const dec = Number(tt.total?.decimals ?? tt.token?.decimals ?? 18);
    const v = Number(tt.total?.value || 0) / 10 ** dec;
    const rate = tt.token?.exchange_rate;
    const spam = tt.token?.reputation && tt.token.reputation !== 'ok';
    transfers.push({
      from: f, to: t, value: v, asset: tt.token?.symbol || '?', time: Date.parse(tt.timestamp) / 1000,
      txid: tt.transaction_hash, usd: rate && !spam ? v * Number(rate) : null,
      dust: v === 0 || spam || (!rate && /^(USDT|USDC|DAI|WETH|ETH)$/i.test(tt.token?.symbol || ''))
    });
  }
  const cursor = (txs?.next_page_params || tts?.next_page_params) ? { tx: txs?.next_page_params || null, tt: tts?.next_page_params || null } : null;
  return { transfers, meta, cursor };
}

async function fetchTron(addr, fp) {
  const r = await getData(`${API.tron}/v1/accounts/${addr}/transactions/trc20?limit=200${fp ? '&fingerprint=' + encodeURIComponent(fp) : ''}`);
  const transfers = (r?.data || []).map(d => {
    const dec = Number(d.token_info?.decimals ?? 6);
    const v = Number(d.value) / 10 ** dec;
    const sym = d.token_info?.symbol || '?';
    const real = TRON_STABLES[d.token_info?.address];
    return {
      from: d.from, to: d.to, value: v, asset: sym, time: d.block_timestamp / 1000, txid: d.transaction_id,
      usd: real ? v : null,
      // nep-USDT (zelfde symbool, ander contract) en 0-transfers zijn klassiek bij address poisoning
      dust: v === 0 || (!real && /^(USDT|USDC|TUSD)$/i.test(sym))
    };
  });
  return { transfers, meta: {}, txCount: null, balance: null, cursor: r?.meta?.fingerprint ? { fp: r.meta.fingerprint } : null };
}

const despam = d => { for (const t of d.transfers) if (t.value > 1e12) { t.dust = true; t.usd = null; } return d; };

async function fetchAddr(chain, addr) {
  const d = chain === 'btc' ? await fetchBtc(addr) : isEvm(chain) ? await fetchEvm(chain, addr) : await fetchTron(addr);
  // Absurde bedragen (bv. 2^256-"transfers" van nep-tokens) als spam behandelen.
  return despam(d);
}

// Volgende pagina transacties van een adres (voor de verkenner).
async function fetchMore(chain, addr, cursor) {
  if (!cursor) return null;
  if (chain === 'btc') {
    const more = await getData(`${API.btc}/address/${addr}/txs/chain/${cursor.last}`);
    return despam({ ...parseBtcTxs(addr, more || []), meta: {}, cursor: (more || []).length >= 25 ? { last: more[more.length - 1].txid } : null });
  }
  if (isEvm(chain)) {
    const B = API[chain];
    const qs = p => Object.entries(p).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v ?? '')}`).join('&');
    const [txs, tts] = await Promise.all([
      cursor.tx ? getData(`${B}/addresses/${addr}/transactions?${qs(cursor.tx)}`) : null,
      cursor.tt ? getData(`${B}/addresses/${addr}/token-transfers?type=ERC-20&${qs(cursor.tt)}`) : null
    ]);
    return despam(parseEvmPage(txs, tts, null));
  }
  const d = await fetchTron(addr, cursor.fp);
  return despam(d);
}

// Eén transactie in detail (verkenner).
const txCache = new Map();
async function fetchTx(chain, txid) {
  const ck = chain + ':' + txid;
  if (txCache.has(ck)) return txCache.get(ck);
  let r;
  if (chain === 'btc') {
    const tx = await getData(`${API.btc}/tx/${txid}`);
    r = {
      chain, txid, time: tx.status?.block_time || null, confirmed: !!tx.status?.confirmed, fee: `${fmt(tx.fee / 1e8)} BTC`,
      inputs: tx.vin.map(v => ({ addr: v.prevout?.scriptpubkey_address || (v.is_coinbase ? 'coinbase (nieuw gemunt)' : '?'), value: (v.prevout?.value || 0) / 1e8, asset: 'BTC', noLink: !v.prevout?.scriptpubkey_address })),
      outputs: tx.vout.map(o => ({ addr: o.scriptpubkey_address || (o.scriptpubkey_type === 'op_return' ? 'OP_RETURN (data)' : o.scriptpubkey_type), value: o.value / 1e8, asset: 'BTC', noLink: !o.scriptpubkey_address }))
    };
  } else if (isEvm(chain)) {
    const tx = await getData(`${API[chain]}/transactions/${txid}`);
    const v = Number(tx.value || 0) / 1e18;
    const transfers = [];
    if (v > 0) transfers.push({ from: tx.from?.hash?.toLowerCase(), to: tx.to?.hash?.toLowerCase(), value: v, asset: 'ETH' });
    for (const tt of tx.token_transfers || []) {
      const dec = Number(tt.total?.decimals ?? tt.token?.decimals ?? 18);
      transfers.push({ from: tt.from?.hash?.toLowerCase(), to: tt.to?.hash?.toLowerCase(), value: Number(tt.total?.value || 0) / 10 ** dec, asset: tt.token?.symbol || '?' });
    }
    r = {
      chain, txid, time: tx.timestamp ? Date.parse(tx.timestamp) / 1000 : null, confirmed: tx.status === 'ok', failed: tx.status === 'error',
      fee: tx.fee?.value ? `${fmt(Number(tx.fee.value) / 1e18)} ETH` : null, method: tx.method || null,
      from: tx.from?.hash?.toLowerCase(), to: tx.to?.hash?.toLowerCase(), transfers
    };
  } else {
    // TronGrid heeft geen keyless tx-detail met tokentransfers: gebruik wat we al van adressen kennen.
    const transfers = [];
    for (const n of [...nodes.values(), ...ghosts.values()]) for (const t of n.data?.transfers || []) {
      if (t.txid === txid && !transfers.some(x => x.from === t.from && x.to === t.to && x.value === t.value)) transfers.push(t);
    }
    r = { chain, txid, time: transfers[0]?.time || null, confirmed: true, transfers, partial: true };
    return r; // niet cachen: kan aanvullen naarmate meer adressen geladen zijn
  }
  txCache.set(ck, r);
  return r;
}

// ---------- grafiekmodel ----------
const nodes = new Map();
const edges = new Map();
const metaStore = {};
let current = null; // { seedKey, chain, role, pattern, opts }
let stopped = false;

const EXCHANGE_RE = /binance|coinbase|kraken|okx|okex|bybit|kucoin|bitfinex|huobi|htx|gate\.io|gate\b|bitget|mexc|crypto\.com|bitvavo|gemini|bitstamp|upbit|poloniex|exchange|hot ?wallet|deposit/i;
const MIXER_RE = /tornado|mixer|sinbad|blender|wasabi|samourai|railgun/i;
const BAD_RE = /phish|scam|hack|exploit|drainer|fake|heist|ponzi/i;
const BRIDGE_RE = /bridge|wormhole|stargate|across|hop protocol|multichain|synapse/i;

function getNode(chain, addr) {
  const k = keyOf(chain, addr);
  let n = nodes.get(k);
  if (!n) {
    n = ghosts.get(k);
    if (n) { ghosts.delete(k); delete n.ghost; n.depth = n.depth ?? 0; }
    else n = { key: k, chain, addr: norm(chain, addr), role: null, flags: [], data: null, expanded: false, depth: 0, hint: null };
    nodes.set(k, n);
  }
  return n;
}

// Adressen die in de verkenner bekeken worden maar (nog) niet in het web staan.
const ghosts = new Map();
function peekNode(chain, addr) {
  const k = keyOf(chain, addr);
  if (nodes.has(k)) return nodes.get(k);
  if (!ghosts.has(k)) {
    const g = { key: k, chain, addr: norm(chain, addr), role: null, flags: [], data: null, expanded: false, depth: null, hint: null, ghost: true };
    ghosts.set(k, g);
    lightAnalyze(g);
  }
  return ghosts.get(k);
}

// Voeg een adres toe aan het web en verbind het met adressen die er al staan.
function addToGraph(n) {
  const g = getNode(n.chain, n.addr);
  const linked = [];
  const scan = (src) => {
    for (const t of src?.data?.transfers || []) {
      if (t.dust) continue;
      const fk = keyOf(g.chain, t.from), tk = keyOf(g.chain, t.to);
      if ((fk === g.key || tk === g.key) && nodes.has(fk) && nodes.has(tk) && fk !== tk) {
        addEdge(g.chain, t.from, t.to, t);
        linked.push(fk === g.key ? tk : fk);
      }
    }
  };
  scan(g);
  for (const o of nodes.values()) if (o !== g && o.data) scan(o);
  const par = linked.map(k => nodes.get(k)).filter(Boolean).sort((a, b) => (a.depth ?? 9) - (b.depth ?? 9))[0];
  if (par && !g.seed) { g.parent = g.parent || par.key; g.depth = Math.min(g.depth || 99, (par.depth ?? 0) + 1); }
  lightAnalyze(g);
  render(false);
  return g;
}

function labelOf(n) {
  if (customLabels[n.key]) return customLabels[n.key];
  const known = window.KNOWN_LABELS[n.addr] || window.KNOWN_LABELS[Object.keys(window.KNOWN_LABELS).find(k => k.toLowerCase() === n.addr) || ''];
  if (known) return known.name;
  const m = metaStore[n.key];
  if (m?.tags?.length) return m.tags[0];
  const db = dbLookup(n);
  const dl = db?.labels.find(l => l.category === 'user') || db?.labels.find(l => !['sanction', 'frozen', 'label'].includes(l.category)) || db?.labels.find(l => l.category === 'label');
  if (dl) return dl.label;
  if (m?.ens) return m.ens;
  if (m?.name) return m.name;
  return null;
}

function addFlag(n, code, level, text) {
  if (!n.flags.some(f => f.code === code)) n.flags.push({ code, level, text });
}

// Lichte analyse: alleen lokale lijsten en metadata, zonder extra API-call.
function lightAnalyze(n) {
  const lower = n.addr.toLowerCase();
  if (osint.ofac.has(n.addr) || osint.ofac.has(lower)) addFlag(n, 'sanction', 'high', 'Op OFAC-sanctielijst');
  if (isEvm(n.chain) && osint.scam?.has(lower)) addFlag(n, 'scamlist', 'high', 'Op ScamSniffer-blacklist');
  const m = metaStore[n.key];
  const known = window.KNOWN_LABELS[n.addr];
  const text = [customLabels[n.key], known?.name, ...(m?.tags || []), m?.name].filter(Boolean).join(' ');
  if (m?.scam) addFlag(n, 'scamlist', 'high', 'Door Blockscout als scam gemarkeerd');
  if (m?.reputation) addFlag(n, 'reputation', 'med', `Reputatie: ${m.reputation}`);
  if (MIXER_RE.test(text)) addFlag(n, 'mixer', 'high', 'Mixer / privacy-dienst');
  else if (BAD_RE.test(text)) addFlag(n, 'badtag', 'high', 'Publiek label wijst op fraude/hack');
  if (known?.type === 'exchange' || EXCHANGE_RE.test(text)) addFlag(n, 'exchange', 'info', 'Exchange — cash-out-punt, bevriezing/informatieverzoek mogelijk');
  if (BRIDGE_RE.test(text)) addFlag(n, 'bridge', 'med', 'Bridge — geld gaat naar een andere keten');
  if (m?.contract || known?.type === 'contract') addFlag(n, 'contract', 'info', 'Smart contract');
  const db = dbLookup(n);
  if (!db) return;
  const src = l => `${l.label} — bron: ${l.source}`;
  for (const l of db.labels) {
    switch (l.category) {
      case 'sanction': addFlag(n, 'sanction', 'high', 'OFAC-sanctielijst (lokale DB)'); break;
      case 'scam': case 'phishing': case 'exploit': addFlag(n, 'scamlist', 'high', src(l)); break;
      case 'ransomware': addFlag(n, 'ransomware', 'high', src(l)); break;
      case 'frozen': addFlag(n, 'frozen', 'high', `Door Tether bevroren${l.detail ? ' — ' + l.detail : ''} (USDT-blacklist)`); break;
      case 'mixer': addFlag(n, 'mixer', 'high', src(l)); break;
      case 'darknet': addFlag(n, 'darknet', 'high', src(l)); break;
      case 'exchange': addFlag(n, 'exchange', 'info', `Exchange: ${l.label} — cash-out-punt`); break;
      case 'bridge': addFlag(n, 'bridge', 'med', `Bridge: ${l.label}`); break;
    }
  }
  const obs = db.observations || [];
  const asPerp = obs.find(o => o.role === 'perp' || ['perp', 'sanction'].includes(o.classification));
  if (asPerp) addFlag(n, 'seenbefore', 'high', `Eerder als dader/verdacht gezien in zaak ${short(asPerp.caseSeed)} (${new Date(asPerp.seen).toLocaleDateString('nl-NL')})`);
  else if (obs.length) addFlag(n, 'seenbefore', 'med', `Al eerder gezien in ${obs.length} andere zaak/zaken`);
}

function fullAnalyze(n) {
  lightAnalyze(n);
  const d = n.data;
  if (!d) return;
  const own = n.addr;
  const ins = d.transfers.filter(t => t.to === own && t.from !== own && !t.dust);
  const outs = d.transfers.filter(t => t.from === own && t.to !== own && !t.dust);
  const times = d.transfers.map(t => t.time).filter(Boolean);
  const spanDays = times.length ? (Math.max(...times) - Math.min(...times)) / 86400 : 999;
  if ((d.txCount && d.txCount >= SERVICE_TX_THRESHOLD) || (d.transfers.length >= 45 && spanDays < 1)) {
    addFlag(n, 'service', 'info', `Zeer actief (${d.txCount ? fmt(d.txCount) + ' tx' : 'veel tx per dag'}) — waarschijnlijk exchange/dienst`);
  }
  const senders = new Set(ins.map(t => t.from)), receivers = new Set(outs.map(t => t.to));
  if (senders.size >= 10) addFlag(n, 'fanin', 'med', `Fan-in: ${senders.size} verschillende afzenders (verzameladres)`);
  if (receivers.size >= 10) addFlag(n, 'fanout', 'med', `Fan-out: ${receivers.size} ontvangers (verspreiding/layering)`);
  if (ins.length >= 2 && outs.length) {
    const outTimes = outs.map(t => t.time).sort((a, b) => a - b);
    const quick = ins.filter(t => outTimes.some(o => o >= t.time && o - t.time <= 3600)).length;
    if (quick / ins.length >= 0.6) addFlag(n, 'passthrough', 'med', `Doorsluisadres: ${Math.round(100 * quick / ins.length)}% binnen 1 uur doorgestort`);
  }
  if (d.peelCount >= 3) addFlag(n, 'peel', 'med', `Peel chain-patroon (${d.peelCount} splitsingen)`);
  const dust = d.transfers.filter(t => t.dust && t.to === own).length;
  if (dust) addFlag(n, 'dust', 'info', `${dust} nul-/nep-tokentransfer(s) ontvangen (poisoning-kenmerk)`);
}

const isEndpoint = n => n.flags.some(f => ['exchange', 'service', 'mixer', 'sanction', 'contract', 'bridge'].includes(f.code));

function fingerprint(chain, a) {
  const s = isEvm(chain) ? a.toLowerCase().slice(2) : chain === 'tron' ? a.slice(1) : a.replace(/^bc1/, '');
  return s.slice(0, 4) + '|' + s.slice(-4);
}

// Zoek adresparen die op elkaar lijken (zelfde begin en eind): address poisoning.
function detectLookalikes(n, cps) {
  const byFp = new Map();
  for (const cp of cps) {
    const fp = fingerprint(n.chain, cp);
    if (!byFp.has(fp)) byFp.set(fp, new Set());
    byFp.get(fp).add(cp);
  }
  const found = [];
  for (const set of byFp.values()) {
    if (set.size < 2) continue;
    const arr = [...set];
    for (const a of arr) {
      const other = arr.find(x => x !== a);
      const dusty = n.data.transfers.some(t => t.dust && (t.from === a || t.to === a));
      found.push({ addr: a, other, dusty });
    }
  }
  return found;
}

function addEdge(chain, from, to, t) {
  const k = `${keyOf(chain, from)}>${keyOf(chain, to)}`;
  let e = edges.get(k);
  if (!e) { e = { key: k, source: keyOf(chain, from), target: keyOf(chain, to), assets: {}, count: 0, usd: 0, first: Infinity, last: 0, txs: [] }; edges.set(k, e); }
  if (e.txs.some(x => x.txid === t.txid && x.asset === t.asset && x.value === t.value)) return;
  e.assets[t.asset] = (e.assets[t.asset] || 0) + t.value;
  e.count++;
  e.usd += t.usd || 0;
  e.first = Math.min(e.first, t.time);
  e.last = Math.max(e.last, t.time);
  if (e.txs.length < 50) e.txs.push({ txid: t.txid, value: t.value, asset: t.asset, time: t.time });
}

function mergeMeta(chain, meta) {
  for (const [k, m] of Object.entries(meta || {})) {
    const key = chain + ':' + k;
    const cur = metaStore[key] || (metaStore[key] = { tags: [] });
    for (const t of m.tags) if (!cur.tags.includes(t)) cur.tags.push(t);
    Object.assign(cur, { ...m, tags: cur.tags });
  }
}

// Haalt transacties van een adres op (eenmalig), voegt metadata samen en analyseert het adres.
async function loadData(n) {
  if (n.data) return n.data;
  try {
    n.data = await fetchAddr(n.chain, n.addr);
  } catch (err) {
    if (err.name !== 'AbortError') addFlag(n, 'error', 'info', 'Ophalen mislukt: ' + err.message);
    return null;
  }
  mergeMeta(n.chain, n.data.meta);
  fullAnalyze(n);
  return n.data;
}

async function expand(n, depth, dir) {
  if (stopped || n.expanded) return [];
  n.expanded = true;
  n.depth = Math.min(n.depth || depth, depth);
  setStatus(`Ophalen ${short(n.addr)} (hop ${depth})…`);
  if (!await loadData(n)) { scheduleRender(); return []; }
  if (depth > 0 && isEndpoint(n)) { scheduleRender(); return []; }

  const { opts, pattern } = current;
  const pat = window.PATTERNS[pattern];
  const agg = new Map();
  for (const t of n.data.transfers) {
    let d, cp;
    if (t.from === n.addr && t.to !== n.addr) { d = 'out'; cp = t.to; }
    else if (t.to === n.addr && t.from !== n.addr) { d = 'in'; cp = t.from; }
    else continue;
    if (dir !== 'both' && d !== dir) continue;
    const k = d + '|' + cp;
    const a = agg.get(k) || { d, cp, rank: 0, count: 0, dustOnly: true, list: [] };
    a.rank += t.usd ?? (n.chain === 'btc' ? t.value : 0);
    a.count++;
    if (!t.dust) a.dustOnly = false;
    a.list.push(t);
    agg.set(k, a);
  }

  const looks = detectLookalikes(n, [...new Set([...agg.values()].map(a => a.cp))]);
  const lookSet = new Set(looks.map(l => l.addr));
  const wantDust = pat.focus.includes('lookalike') || pat.focus.includes('dust');
  const pick = d => [...agg.values()]
    .filter(a => a.d === d && (!a.dustOnly || (wantDust && lookSet.has(a.cp))))
    .sort((x, y) => (lookSet.has(y.cp) - lookSet.has(x.cp)) || (y.rank - x.rank) || (y.count - x.count))
    .slice(0, opts.fanout);

  const next = [];
  for (const a of [...pick('out'), ...pick('in')]) {
    if (nodes.size >= opts.maxNodes && !nodes.has(keyOf(n.chain, a.cp))) break;
    const isNew = !nodes.has(keyOf(n.chain, a.cp));
    const cn = getNode(n.chain, a.cp);
    if (isNew) { cn.depth = depth + 1; cn.parent = n.key; }
    for (const t of a.list) if (!t.dust || lookSet.has(a.cp)) addEdge(n.chain, t.from, t.to, t);
    lightAnalyze(cn);
    if (!cn.role) {
      if (depth === 0 && a.d === 'out' && current.role === 'victim' && !isEndpoint(cn)) cn.hint = 'suspect';
      if (depth === 0 && a.d === 'in' && current.role === 'perp' && !isEndpoint(cn)) cn.hint = 'victim2';
    }
    const look = looks.find(l => l.addr === a.cp);
    if (look) {
      addFlag(cn, 'lookalike', look.dusty ? 'high' : 'med',
        `Lijkt op ${short(look.other)} (zelfde begin/eind) — ${look.dusty ? 'waarschijnlijk vergiftigingsadres' : 'vergelijk zorgvuldig'}`);
      if (look.dusty) cn.hint = 'suspect';
    }
    // Upstream (inkomend) volgen we niet verder: dat zijn bronnen/slachtoffers, niet de geldroute.
    if (a.d === 'out' && depth + 1 < opts.depth && !isEndpoint(cn)) next.push({ n: cn, depth: depth + 1, dir: 'out' });
  }
  scheduleRender();
  return next;
}

async function runTrace(addr, chain, role, pattern, opts) {
  abortCtl.abort();
  abortCtl = new AbortController();
  stopped = false;
  resetGraph();
  current = { chain, role, pattern, opts, seedKey: keyOf(chain, addr), started: new Date().toISOString() };
  dbCache.clear();
  loadNotes();
  setBusy(true);
  setStatus('OSINT-lijsten laden (OFAC, ScamSniffer)…');
  await loadLists(chain);
  const seed = getNode(chain, addr);
  seed.role = role;
  seed.seed = true;
  lightAnalyze(seed);
  scheduleRender();
  let level = [{ n: seed, depth: 0, dir: window.PATTERNS[pattern].dir[role] }];
  while (level.length && !stopped) {
    const results = await Promise.all(level.map(x => expand(x.n, x.depth, x.dir)));
    level = results.flat().filter(x => !x.n.expanded);
  }
  // Automatisch de herkomst van het geld zoeken: startwallets en exchange-instroom.
  if (!stopped) await traceOrigins(seed, { depth: role === 'perp' ? Math.max(3, opts.depth) : 2, fanIn: Math.max(4, opts.fanout) });
  setBusy(false);
  render(true);
  renderPlaybook();
  renderSummary();
  if (!stopped) recordObservations();
  setStatus(stopped ? 'Gestopt.' : `Klaar: ${nodes.size} adressen, ${edges.size} geldstromen. Tik op een adres voor details.`);
}

// ---------- herkomst: startwallets en instroom via exchanges ----------
// Vanaf een adres stroomopwaarts langs inkomend geld tot een exchange/dienst (instroompunt)
// of een wallet zonder eerdere instroom (startwallet = mogelijk slachtoffer of geldbron).
const origins = { rootKey: null, starts: new Map(), cashIn: [] };
const CASHIN_TYPES = { exchange: 'Exchange', service: 'Exchange/dienst (hoog volume)', mixer: 'Mixer', bridge: 'Bridge', contract: 'Smart contract', sanction: 'Gesanctioneerd adres' };

function cashInType(n) {
  for (const code of Object.keys(CASHIN_TYPES)) if (n.flags.some(f => f.code === code)) return code;
  return null;
}

async function traceOrigins(root, { depth = 3, fanIn = 5 } = {}) {
  origins.rootKey = root.key;
  origins.starts = new Map();
  origins.cashIn = [];
  const sent = new Map(); // key → transfers van dit adres richting het vorige adres in de keten
  const seen = new Set([root.key]);
  const limit = (current?.opts.maxNodes || 80) + 80;
  let level = [{ n: root, hop: 0, child: null }];
  while (level.length && !stopped) {
    const results = await Promise.all(level.map(x => originStep(x, root, depth, fanIn, seen, sent, limit)));
    level = results.flat();
  }
  scheduleRender();
  renderOrigins();
}

function addStart(n, reason, sent) {
  if (origins.starts.has(n.key)) return;
  const txs = sent.get(n.key)?.txs || [];
  const assets = {};
  for (const t of txs) assets[t.asset] = (assets[t.asset] || 0) + t.value;
  const times = txs.map(t => t.time).filter(Boolean);
  origins.starts.set(n.key, {
    key: n.key, addr: n.addr, chain: n.chain, reason, to: sent.get(n.key)?.to, assets,
    usd: txs.reduce((s, t) => s + (t.usd || 0), 0), count: txs.length,
    first: times.length ? Math.min(...times) : null, last: times.length ? Math.max(...times) : null
  });
  if (!n.role && !n.flags.some(f => f.level === 'high')) n.hint = 'victim2';
  addFlag(n, 'startwallet', 'med', `Startwallet: ${reason} — mogelijk slachtoffer of geldbron`);
}

async function originStep({ n, hop, child }, root, depth, fanIn, seen, sent, limit) {
  if (stopped) return [];
  setStatus(`Herkomst zoeken: hop ${hop}, ${origins.starts.size} startwallets, ${origins.cashIn.length} instroom-tx…`);
  // Op de maximale diepte niet meer ophalen: alleen labels bepalen of het een exchange is.
  const atEdge = hop > 0 && hop >= depth;
  const d = atEdge ? n.data : await loadData(n);
  const type = hop > 0 ? cashInType(n) : null;
  if (type) {
    // Instroompunt gevonden: elke transactie van deze dienst naar de volgende wallet vastleggen.
    const name = labelOf(n) || CASHIN_TYPES[type];
    for (const t of sent.get(n.key)?.txs || []) {
      origins.cashIn.push({ type, name, from: n.key, to: child.key, chain: n.chain, txid: t.txid, time: t.time, value: t.value, asset: t.asset, usd: t.usd });
    }
    if (child !== root) addStart(child, `gefinancierd vanuit ${name}`, sent);
    return [];
  }
  if (hop === 0 && !d) return [];
  if (atEdge) { addStart(n, 'maximale zoekdiepte bereikt', sent); return []; }
  if (!d) { addStart(n, 'niet verder te volgen (ophalen mislukt)', sent); return []; }
  const agg = new Map();
  for (const t of d.transfers) {
    if (t.to !== n.addr || t.from === n.addr || t.dust) continue;
    // Alleen geld met waarde volgen: onbekende tokens zonder koers zijn meestal spam/airdrops.
    if (n.chain !== 'btc' && t.usd == null) continue;
    const a = agg.get(t.from) || { cp: t.from, rank: 0, list: [] };
    a.rank += t.usd ?? (n.chain === 'btc' ? t.value : 0);
    a.list.push(t);
    agg.set(t.from, a);
  }
  const senders = [...agg.values()].sort((x, y) => (y.rank - x.rank) || (y.list.length - x.list.length)).slice(0, fanIn);
  if (hop > 0 && !senders.length) { addStart(n, 'geen eerdere instroom gevonden', sent); return []; }
  if (hop >= depth) { if (hop > 0) addStart(n, 'maximale zoekdiepte bereikt', sent); return []; }
  const next = [];
  for (const a of senders) {
    if (nodes.size >= limit && !nodes.has(keyOf(n.chain, a.cp))) break;
    const isNew = !nodes.has(keyOf(n.chain, a.cp));
    const cn = getNode(n.chain, a.cp);
    if (isNew) { cn.depth = hop + 1; cn.parent = n.key; cn.upstream = true; }
    for (const t of a.list) addEdge(n.chain, t.from, t.to, t);
    lightAnalyze(cn);
    if (seen.has(cn.key)) continue;
    seen.add(cn.key);
    sent.set(cn.key, { to: n.key, txs: a.list });
    next.push({ n: cn, hop: hop + 1, child: n });
  }
  scheduleRender();
  return next;
}

function txUrl(chain, id) {
  return { btc: `https://mempool.space/tx/${id}`, eth: `https://etherscan.io/tx/${id}`, op: `https://optimistic.etherscan.io/tx/${id}`, tron: `https://tronscan.org/#/transaction/${id}` }[chain];
}

const assetText = assets => Object.entries(assets).sort((a, b) => b[1] - a[1]).slice(0, 2).map(([s, v]) => `${fmt(v)} ${s}`).join(' + ') || '—';

function renderOrigins() {
  const starts = [...origins.starts.values()].sort((a, b) => (b.usd - a.usd) || ((a.first || 0) - (b.first || 0)));
  const cash = [...origins.cashIn].sort((a, b) => (a.time || 0) - (b.time || 0));
  $('#origins').hidden = !origins.rootKey;
  $('#originCount').textContent = starts.length + cash.length;
  $('#startCount').textContent = starts.length;
  $('#cashCount').textContent = cash.length;
  $('#startList').innerHTML = starts.map((r, i) => {
    const n = nodes.get(r.key);
    return `<li data-k="${esc(r.key)}"><b>${esc((n && labelOf(n)) || short(r.addr))}</b> · ${esc(assetText(r.assets))}
      <small>${esc(r.addr)}</small><small>${esc(r.reason)}${r.first ? ' · ' + fmtTime(r.first) : ''}</small></li>`;
  }).join('') || '<li class="muted">Geen startwallets gevonden.</li>';
  $('#cashList').innerHTML = cash.map(r => `<li data-k="${esc(r.to)}">
      <b>${esc(r.name)}</b> → ${esc(short(nodes.get(r.to)?.addr || '?'))} · ${fmt(r.value)} ${esc(r.asset)}
      <small>${fmtTime(r.time)}</small>
      <small><a href="${esc(txUrl(r.chain, r.txid))}" target="_blank" rel="noopener noreferrer">${esc(r.txid)}</a></small></li>`).join('')
    || '<li class="muted">Geen instroom via exchanges gevonden binnen de zoekdiepte.</li>';
  for (const li of document.querySelectorAll('#startList li[data-k], #cashList li[data-k]')) {
    li.addEventListener('click', ev => {
      if (ev.target.tagName === 'A') return;
      focusNode(li.dataset.k);
      openNode(nodes.get(li.dataset.k));
    });
  }
}

function originsCsv() {
  const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const rows = [['soort', 'naam/label', 'adres', 'naar adres', 'tx-hash', 'tijdstip (UTC)', 'bedrag', 'asset', 'reden'].map(q).join(',')];
  const iso = t => t ? new Date(t * 1000).toISOString() : '';
  for (const r of origins.cashIn) {
    rows.push([CASHIN_TYPES[r.type], r.name, nodes.get(r.from)?.addr, nodes.get(r.to)?.addr, r.txid, iso(r.time), r.value, r.asset, ''].map(q).join(','));
  }
  for (const r of origins.starts.values()) {
    const n = nodes.get(r.key);
    rows.push(['Startwallet', n ? labelOf(n) : '', r.addr, nodes.get(r.to)?.addr, '', iso(r.first), Object.values(r.assets)[0] ?? '', Object.keys(r.assets)[0] ?? '', r.reason].map(q).join(','));
  }
  return rows.join('\r\n');
}

// ---------- notities ----------
let notes = { case: '', nodes: {} };
const notesKey = () => current ? 'chaintrace.notes.' + current.seedKey : null;
function loadNotes() {
  notes = (notesKey() && store.get(notesKey(), null)) || { case: '', nodes: {} };
  $('#caseNote').value = notes.case || '';
  $('#notesBox').hidden = !current;
}
function saveNotes() { if (notesKey()) store.set(notesKey(), notes); }

// ---------- weergave ----------
let cy = null;
let layoutName = 'web';
let renderTimer = null;

const COLORS = { victim: '#3fa7ff', victim2: '#8cc8ff', perp: '#ff4d5e', suspect: '#ff9f43', exchange: '#2ecc71', sanction: '#b0004f', plain: '#6b7785' };

function nodeClass(n) {
  if (n.role) return n.role;
  if (n.flags.some(f => ['sanction', 'scamlist', 'mixer', 'badtag', 'ransomware', 'frozen', 'darknet'].includes(f.code))) return 'sanction';
  if (n.flags.some(f => f.code === 'seenbefore' && f.level === 'high')) return 'suspect';
  if (n.flags.some(f => f.code === 'lookalike' && f.level === 'high')) return 'perp';
  if (n.flags.some(f => ['exchange', 'service'].includes(f.code))) return 'exchange';
  if (n.hint === 'suspect' || n.flags.some(f => ['passthrough', 'fanin', 'peel', 'lookalike'].includes(f.code))) return 'suspect';
  if (n.hint === 'victim2') return 'victim2';
  return 'plain';
}

function edgeLabel(e) {
  const parts = Object.entries(e.assets).sort((a, b) => b[1] - a[1]).slice(0, 2).map(([s, v]) => `${fmt(v)} ${s}`);
  return parts.join(' + ') + (e.count > 1 ? ` (${e.count}×)` : '');
}

const THEMES = {
  dark: { bg: '#0f1419', panel: '#171e26', text: '#e6edf3', muted: '#8b98a5', line: '#2b3742', edge: '#41505e', seedBorder: '#ffffff' },
  light: { bg: '#ffffff', panel: '#f3f5f8', text: '#111827', muted: '#5b6673', line: '#d9dee5', edge: '#9aa5b1', seedBorder: '#111827' }
};

function cyStyle(themeName) {
  const t = THEMES[themeName];
  return [
    { selector: 'node', style: {
      'background-color': 'data(color)', label: 'data(label)', color: t.text, 'font-size': 10,
      'text-valign': 'bottom', 'text-wrap': 'wrap', 'text-margin-y': 4, 'text-outline-color': t.bg, 'text-outline-width': 2,
      width: 'data(size)', height: 'data(size)', 'border-width': 2, 'border-color': t.bg
    } },
    { selector: 'node[?seed]', style: { 'border-width': 4, 'border-color': t.seedBorder, 'font-weight': 'bold', 'font-size': 12 } },
    { selector: 'node[?flagged]', style: { 'border-color': '#ff4d5e', 'border-style': 'double', 'border-width': 4 } },
    { selector: 'node[?noted]', style: { 'background-image-opacity': 1, 'underlay-color': '#f5c518', 'underlay-opacity': 0.35, 'underlay-padding': 5, 'underlay-shape': 'ellipse' } },
    { selector: 'node:selected', style: { 'overlay-color': '#4ea1ff', 'overlay-opacity': 0.25, 'overlay-padding': 6 } },
    { selector: 'edge', style: {
      width: 'data(w)', 'line-color': t.edge, 'target-arrow-color': t.edge, 'target-arrow-shape': 'triangle',
      'curve-style': 'bezier', label: 'data(label)', 'font-size': 8, color: t.muted, 'text-rotation': 'autorotate',
      'text-background-color': t.bg, 'text-background-opacity': 0.85, 'text-background-padding': 2
    } },
    { selector: 'edge.hot', style: { 'line-color': '#ff9f43', 'target-arrow-color': '#ff9f43' } },
    { selector: 'edge.upstream', style: { 'line-style': 'dashed', 'line-color': '#3fa7ff', 'target-arrow-color': '#3fa7ff' } },
    { selector: 'edge:selected', style: { 'line-color': '#4ea1ff', 'target-arrow-color': '#4ea1ff' } }
  ];
}

function initCy() {
  cy = cytoscape({
    container: $('#cy'),
    minZoom: 0.1, maxZoom: 3,
    style: cyStyle('dark')
  });
  cy.on('tap', 'node', ev => {
    const n = nodes.get(ev.target.id());
    if (isMobile()) showPeek(n); else openNode(n);
  });
  cy.on('tap', 'edge', ev => openEdge(edges.get(ev.target.id())));
  cy.on('tap', ev => { if (ev.target === cy) { hidePeek(); if (!isMobile()) closeExplorer(); } });
}

function scheduleRender() {
  clearTimeout(renderTimer);
  renderTimer = setTimeout(() => render(false), 350);
}

function render(final) {
  if (!cy) initCy();
  $('#empty').hidden = nodes.size > 0;
  const maxUsd = Math.max(1, ...[...edges.values()].map(e => e.usd || Object.values(e.assets)[0] || 0));
  cy.batch(() => {
    for (const n of nodes.values()) {
      const cls = nodeClass(n);
      const label = labelOf(n);
      const data = {
        id: n.key, label: (notes.nodes[n.key] ? '✎ ' : '') + (label ? `${label}\n${short(n.addr)}` : short(n.addr)), color: COLORS[cls],
        size: n.seed ? 44 : isEndpoint(n) ? 34 : 26, seed: !!n.seed, flagged: n.flags.some(f => f.level === 'high'), noted: !!notes.nodes[n.key]
      };
      const el = cy.getElementById(n.key);
      if (el.nonempty()) el.data(data);
      else {
        const parent = n.parent && cy.getElementById(n.parent);
        const p = parent?.nonempty() ? parent.position() : { x: 0, y: 0 };
        cy.add({ group: 'nodes', data, position: { x: p.x + (Math.random() - 0.5) * 120, y: p.y + (Math.random() - 0.5) * 120 } });
      }
    }
    for (const e of edges.values()) {
      if (!nodes.has(e.source) || !nodes.has(e.target)) continue;
      const v = e.usd || Object.values(e.assets)[0] || 0;
      const data = { id: e.key, source: e.source, target: e.target, label: edgeLabel(e), w: 1 + 6 * Math.sqrt(v / maxUsd) };
      const el = cy.getElementById(e.key);
      if (el.nonempty()) el.data(data); else cy.add({ group: 'edges', data });
      const tgt = nodes.get(e.target);
      cy.getElementById(e.key).toggleClass('hot', ['perp', 'suspect', 'sanction'].includes(nodeClass(tgt)));
      cy.getElementById(e.key).toggleClass('upstream', !!nodes.get(e.source)?.upstream);
    }
    cy.nodes().forEach(el => { if (!nodes.has(el.id())) el.remove(); });
  });
  runLayout(final);
  renderFindings();
  $('#btnExportPng').disabled = $('#btnExportJson').disabled = $('#btnPdf').disabled = nodes.size === 0;
  $('#findingsBox').hidden = nodes.size === 0;
  renderOrigins();
}

let graphStale = false;
function runLayout(fit) {
  if (!cy || cy.nodes().length === 0) return;
  // Web niet zichtbaar (telefoon, andere tab): later schikken als het weer in beeld komt.
  if (!document.getElementById('cy').offsetWidth) { graphStale = true; return; }
  const opts = layoutName === 'flow'
    ? { name: 'breadthfirst', directed: true, roots: current ? [current.seedKey] : undefined, spacingFactor: 1.2, animate: false }
    : { name: 'cose', animate: false, randomize: !!fit, nodeRepulsion: () => 9000, idealEdgeLength: () => 110, gravity: 0.3, numIter: 600 };
  cy.layout({ ...opts, fit: true, padding: 40 }).run();
  if (fit) cy.fit(undefined, 40);
}

function renderFindings() {
  const order = { high: 0, med: 1, info: 2 };
  const pat = current ? window.PATTERNS[current.pattern] : null;
  const list = [];
  for (const n of nodes.values()) for (const f of n.flags) {
    if (f.code === 'contract' || f.code === 'error') continue;
    const focus = pat?.focus.includes(f.code) ? -0.5 : 0;
    list.push({ n, f, score: order[f.level] + focus });
  }
  list.sort((a, b) => a.score - b.score);
  $('#findCount').textContent = list.length;
  $('#findings').innerHTML = list.slice(0, 80).map((x, i) =>
    `<li class="${x.f.level}" data-i="${i}">${esc(x.f.text)}<small>${esc(labelOf(x.n) || '')} ${esc(x.n.addr)}</small></li>`).join('');
  $('#findings').querySelectorAll('li').forEach(li => li.addEventListener('click', () => {
    const n = list[+li.dataset.i].n;
    focusNode(n.key);
    openNode(n);
  }));
}

function renderPlaybook() {
  if (!current) return;
  const pat = window.PATTERNS[current.pattern];
  const exch = [...nodes.values()].filter(n => n.flags.some(f => f.code === 'exchange' || f.code === 'service'));
  const steps = [...pat.steps];
  if (exch.length) steps.splice(1, 0, `Gevonden cash-out-punten: ${exch.slice(0, 5).map(n => esc(labelOf(n) || short(n.addr))).join(', ')}.`);
  $('#playbookList').innerHTML = steps.map(s => `<li>${s}</li>`).join('');
  $('#playbook').hidden = false;
}

function focusNode(key) {
  if (cy && graphStale && $('#cy').offsetWidth) { cy.resize(); graphStale = false; runLayout(true); }
  const el = cy?.getElementById(key);
  if (!el || el.empty()) return;
  cy.$(':selected').unselect();
  el.select();
  cy.animate({ center: { eles: el }, zoom: Math.max(cy.zoom(), 1) }, { duration: 300 });
}

// ---------- detailpaneel ----------
function osintLinks(n) {
  const a = encodeURIComponent(n.addr);
  const q = encodeURIComponent(`"${n.addr}"`);
  const ex = {
    btc: [['mempool.space', `https://mempool.space/address/${a}`], ['Blockchair', `https://blockchair.com/bitcoin/address/${a}`], ['OXT', `https://oxt.me/address/${a}`]],
    eth: [['Etherscan', `https://etherscan.io/address/${a}`], ['Blockscout', `https://eth.blockscout.com/address/${a}`]],
    op: [['Optimism explorer', `https://explorer.optimism.io/address/${a}`], ['OP Etherscan', `https://optimistic.etherscan.io/address/${a}`]],
    tron: [['Tronscan', `https://tronscan.org/#/address/${a}`]]
  }[n.chain];
  return [
    ...ex,
    ['Chainabuse', `https://www.chainabuse.com/address/${a}`],
    ['Breadcrumbs', `https://www.breadcrumbs.app/reports/${a}`],
    ['Arkham', `https://intel.arkm.com/explorer/address/${a}`],
    ['Google', `https://www.google.com/search?q=${q}`],
    ['X / Twitter', `https://x.com/search?q=${q}&f=live`],
    ['Reddit', `https://www.reddit.com/search/?q=${q}`],
    ['GitHub', `https://github.com/search?q=${q}&type=code`],
    ['Telegram (Google)', `https://www.google.com/search?q=${encodeURIComponent('site:t.me "' + n.addr + '"')}`]
  ];
}

function dbSection(n) {
  if (!LOCAL_DB) return '';
  const db = dbLookup(n);
  const labels = db?.labels || [], obs = db?.observations || [];
  return `<h4>Lokale OSINT-database</h4>
    ${labels.length ? `<dl class="kv">${labels.map(l => `<dt>${esc(CAT_NL[l.category] || l.category)}</dt><dd>${esc(l.label)}<br><small class="muted">${esc(l.source)}${l.detail ? ' · ' + esc(l.detail) : ''}</small></dd>`).join('')}</dl>` : '<div class="muted small">Geen labels in de lokale database.</div>'}
    ${obs.length ? `<div class="small" style="margin-top:6px">Eerder gezien in: ${obs.map(o => `${esc(short(o.caseSeed))} (${esc(o.role || o.classification || '?')}, ${new Date(o.seen).toLocaleDateString('nl-NL')})`).join(', ')}</div>` : ''}`;
}

// ---------- verkenner: adressen en transacties doorklikken (zoals Reactor/Chainalysis) ----------
const nav = { stack: [], i: -1 };
const isMobile = () => matchMedia('(max-width: 820px)').matches;
const ROLE_TXT = { victim: 'Slachtoffer', perp: 'Dader', suspect: 'Verdacht', victim2: 'Mogelijk slachtoffer', exchange: 'Exchange / dienst', sanction: 'Sanctie / scamlijst', plain: 'Onbekend' };

function openView(v, { replace = false } = {}) {
  if (replace && nav.i >= 0) nav.stack[nav.i] = v;
  else {
    nav.stack = nav.stack.slice(0, nav.i + 1);
    nav.stack.push(v);
    nav.i++;
    try { history.pushState({ ctv: nav.i }, ''); } catch { /* file:// */ }
  }
  hidePeek();
  $('#detail').hidden = false;
  setTab('detail');
  $('#detailBody').scrollTop = 0;
  $('#detail').scrollTop = 0;
  renderView();
}
const openAddr = (chain, addr, tab) => openView({ type: 'addr', chain, addr: norm(chain, addr), tab: tab || 'tx', filter: 'all', limit: 40, cpLimit: 40 });
const openNode = n => { if (n) openAddr(n.chain, n.addr); };
const openTx = (chain, txid) => openView({ type: 'tx', chain, txid });
const openEdge = e => { if (e) openView({ type: 'edge', key: e.key }); };
const curView = () => nav.stack[nav.i];
const stillCurrent = v => curView() === v && !$('#detail').hidden;
function refreshView() { if (nav.i >= 0 && !$('#detail').hidden) renderView(); }

function goBack() {
  if (nav.i <= 0) { closeExplorer(); return; }
  if (history.state?.ctv === nav.i) history.back();
  else { nav.i--; renderView(); }
}
function closeExplorer() {
  const st = history.state?.ctv;
  if (nav.i >= 0 && st != null && st === nav.i) history.go(-(st + 1));
  else hideDetail();
}
function hideDetail() {
  $('#detail').hidden = true;
  nav.stack = []; nav.i = -1;
  if (document.body.dataset.tab === 'detail') setTab(nodes.size ? 'graph' : 'form');
}
window.addEventListener('popstate', ev => {
  const i = ev.state?.ctv;
  if (i != null && nav.stack[i]) { nav.i = i; $('#detail').hidden = false; setTab('detail'); renderView(); }
  else hideDetail();
});

function viewTitle(v) {
  if (!v) return '';
  if (v.type === 'addr') { const n = peekNode(v.chain, v.addr); return labelOf(n) || short(v.addr); }
  if (v.type === 'tx') return 'Tx ' + short(v.txid);
  return 'Geldstroom';
}
const viewChain = v => v.type === 'edge' ? nodes.get(edges.get(v.key)?.source)?.chain : v.chain;

function navBar() {
  const prev = nav.stack[nav.i - 1];
  return `<div class="xnav">
    ${prev ? `<button type="button" class="xback" data-nav="back">‹ ${esc(viewTitle(prev))}</button>` : `<button type="button" class="xback" data-nav="close">‹ Terug</button>`}
    <span class="xpos">${nav.i + 1} / ${nav.stack.length}</span>
    <button type="button" class="xclose" data-nav="close" aria-label="Sluiten">×</button>
  </div>`;
}

function addrChip(chain, addr, { noLink = false } = {}) {
  if (noLink || !addr) return `<span class="alink nolink">${esc(addr || '?')}</span>`;
  const k = keyOf(chain, addr);
  const n = nodes.get(k) || ghosts.get(k);
  const cls = n ? nodeClass(n) : 'plain';
  const lab = n ? labelOf(n) : null;
  const inWeb = nodes.has(k);
  return `<button type="button" class="alink" data-addr="${esc(addr)}" title="${esc(addr)}"><i class="dot ${cls}"></i><span class="an">${esc(lab || short(addr))}</span>${lab ? `<small>${esc(short(addr))}</small>` : ''}${inWeb ? '<em class="inweb" title="Staat in het web">◉ web</em>' : ''}</button>`;
}
const txChip = txid => `<button type="button" class="txlink" data-tx="${esc(txid)}">${esc(short(txid))}</button>`;
const sumAssets = list => { const a = {}; for (const t of list) a[t.asset] = (a[t.asset] || 0) + t.value; return a; };

function renderView() {
  const v = curView();
  if (!v) return;
  const body = $('#detailBody');
  body.dataset.chain = viewChain(v) || '';
  if (v.type === 'addr') body.innerHTML = addrViewHtml(v);
  else if (v.type === 'tx') body.innerHTML = txViewHtml(v);
  else body.innerHTML = edgeViewHtml(v);
  const note = $('#nodeNote');
  if (note) {
    const n = peekNode(v.chain, v.addr);
    let t = null;
    note.addEventListener('input', ev => {
      clearTimeout(t);
      t = setTimeout(() => {
        const val = ev.target.value.trim();
        if (val) notes.nodes[n.key] = val; else delete notes.nodes[n.key];
        saveNotes();
        if (!n.ghost) render(false);
      }, 400);
    });
  }
}

// --- adrespagina ---
function addrViewHtml(v) {
  const n = peekNode(v.chain, v.addr);
  if (!n.data && !n.loadTried) {
    n.loadTried = true;
    loadData(n).finally(() => { if (stillCurrent(v)) renderView(); if (!n.ghost) render(false); });
  }
  const m = metaStore[n.key] || {};
  const label = labelOf(n);
  const cls = nodeClass(n);
  const own = n.addr;
  const d = n.data;
  const real = d ? d.transfers.filter(t => !t.dust) : [];
  const ins = real.filter(t => t.to === own && t.from !== own), outs = real.filter(t => t.from === own && t.to !== own);
  const times = real.map(t => t.time).filter(Boolean);
  const loading = !d && !n.flags.some(f => f.code === 'error');
  const tabs = [['tx', `Transacties${d ? ` <span class="badge">${d.transfers.filter(t => t.from !== t.to).length}${d.cursor ? '+' : ''}</span>` : ''}`], ['cp', 'Tegenpartijen'], ['osint', 'OSINT & notitie']];

  let content = '';
  if (v.tab === 'osint') content = osintHtml(n, m);
  else if (loading) content = '<div class="xloading"><span class="spin"></span> Transacties ophalen…</div>';
  else if (!d) content = `<p class="muted">Ophalen mislukt. ${esc(n.flags.find(f => f.code === 'error')?.text || '')}</p><button type="button" class="ghost wide" data-act="retry">Opnieuw proberen</button>`;
  else if (v.tab === 'cp') content = cpListHtml(n, v);
  else content = txListHtml(n, v);

  return `${navBar()}
    <div class="xhead"><i class="dot big ${cls}"></i><div class="xhead-t"><h3>${esc(label || short(n.addr))}</h3>
      <div class="mono">${esc(n.addr)} <button type="button" class="mini" data-act="copy">Kopieer</button></div></div></div>
    <div class="tags"><span class="tag">${CHAIN_NAME[n.chain]}</span><span class="tag">${ROLE_TXT[cls]}</span>${n.ghost ? '<span class="tag">Niet in het web</span>' : ''}
      ${n.flags.filter(f => f.code !== 'error').map(f => `<span class="tag ${f.level}">${esc(f.text)}</span>`).join('')}</div>
    <div class="xstats">
      <div><span>Saldo</span><b>${esc(d?.balance || '—')}</b></div>
      <div><span>Transacties</span><b>${d?.txCount ? fmt(d.txCount) : d ? fmt(d.transfers.length) + (d.cursor ? '+' : '') : '…'}</b></div>
      <div><span>Ontvangen*</span><b class="in">${d ? esc(assetText(sumAssets(ins))) : '…'}</b></div>
      <div><span>Verzonden*</span><b class="out">${d ? esc(assetText(sumAssets(outs))) : '…'}</b></div>
      <div class="wide"><span>Actief (geladen)</span><b>${times.length ? `${fmtTime(Math.min(...times))} – ${fmtTime(Math.max(...times))}` : '—'}</b></div>
    </div>
    <div class="xactions">
      ${n.ghost ? '<button type="button" class="primary" data-act="add">+ Toevoegen aan web</button>' : '<button type="button" class="primary" data-act="show">Toon in web</button>'}
      <button type="button" class="ghost" data-act="expand">Volg geld verder</button>
      <button type="button" class="ghost" data-act="origins">Herkomst zoeken</button>
      <details class="menu xmore"><summary class="ghost">Meer…</summary><div class="menu-items">
        <button type="button" data-act="perp">${n.role === 'perp' ? 'Dader-markering weghalen' : 'Markeer als dader'}</button>
        <button type="button" data-act="victim">${n.role === 'victim' ? 'Slachtoffer-markering weghalen' : 'Markeer als slachtoffer'}</button>
        <button type="button" data-act="label">Label toevoegen</button>
        ${!n.ghost && !n.seed ? '<button type="button" data-act="remove">Verwijder uit web</button>' : ''}
      </div></details>
    </div>
    <div class="xtabs">${tabs.map(([k, t]) => `<button type="button" class="${v.tab === k ? 'active' : ''}" data-tab="${k}">${t}</button>`).join('')}</div>
    <div class="xcontent">${content}</div>`;
}

function txListHtml(n, v) {
  const own = n.addr;
  const d = n.data;
  let list = d.transfers.filter(t => t.from !== t.to && (t.from === own || t.to === own));
  const dustCount = list.filter(t => t.dust).length;
  if (!v.showDust) list = list.filter(t => !t.dust);
  if (v.filter === 'in') list = list.filter(t => t.to === own);
  if (v.filter === 'out') list = list.filter(t => t.from === own);
  list.sort((a, b) => (b.time || 0) - (a.time || 0));
  const shown = list.slice(0, v.limit);
  const rows = shown.map(t => {
    const dir = t.from === own ? 'out' : 'in';
    const cp = dir === 'out' ? t.to : t.from;
    return `<div class="xrow ${dir}${t.dust ? ' dust' : ''}">
      <div class="xrow-top"><span class="dir ${dir}">${dir === 'out' ? '↑ Uit' : '↓ In'}</span>${addrChip(n.chain, cp)}</div>
      <div class="xrow-sub"><b>${fmt(t.value)} ${esc(t.asset)}</b>${t.usd ? ` <span class="muted">≈ $${fmt(t.usd)}</span>` : ''}${t.dust ? ' <span class="tag med">spam/nul</span>' : ''}
        <span class="muted">· ${fmtTime(t.time)} ·</span> ${txChip(t.txid)}</div>
    </div>`;
  }).join('');
  const more = list.length > shown.length
    ? `<button type="button" class="ghost wide" data-more="show">Toon meer (${list.length - shown.length})</button>`
    : d.cursor ? `<button type="button" class="ghost wide" data-more="fetch" ${n.loadingMore ? 'disabled' : ''}>${n.loadingMore ? 'Laden…' : 'Oudere transacties laden'}</button>` : '';
  return `<div class="xfilter">
      ${[['all', 'Alles'], ['in', '↓ In'], ['out', '↑ Uit']].map(([k, t]) => `<button type="button" class="chip ${v.filter === k ? 'active' : ''}" data-filter="${k}">${t}</button>`).join('')}
      ${dustCount ? `<button type="button" class="chip ${v.showDust ? 'active' : ''}" data-filter="dust">Spam (${dustCount})</button>` : ''}
    </div>
    ${rows || '<p class="muted">Geen transacties in deze selectie.</p>'}
    ${more}
    <p class="hint">* Op basis van de geladen transacties. Tik op een adres of transactie om erheen te gaan.</p>`;
}

function cpListHtml(n, v) {
  const own = n.addr;
  const agg = new Map();
  for (const t of n.data.transfers) {
    if (t.dust || t.from === t.to) continue;
    const dir = t.from === own ? 'out' : t.to === own ? 'in' : null;
    if (!dir) continue;
    const cp = dir === 'out' ? t.to : t.from;
    const a = agg.get(cp) || { cp, in: [], out: [], usd: 0, last: 0 };
    a[dir].push(t);
    a.usd += t.usd || (n.chain === 'btc' ? t.value * 1e4 : 0);
    a.last = Math.max(a.last, t.time || 0);
    agg.set(cp, a);
  }
  const all = [...agg.values()].sort((x, y) => (y.usd - x.usd) || ((y.in.length + y.out.length) - (x.in.length + x.out.length)));
  const shown = all.slice(0, v.cpLimit);
  const rows = shown.map(a => {
    const inWeb = nodes.has(keyOf(n.chain, a.cp));
    return `<div class="xrow">
      <div class="xrow-top">${addrChip(n.chain, a.cp)}${inWeb ? '' : `<button type="button" class="mini add" data-add="${esc(a.cp)}" title="Toevoegen aan web">+ web</button>`}</div>
      <div class="xrow-sub">${a.in.length ? `<span class="in">↓ ${esc(assetText(sumAssets(a.in)))}</span> ` : ''}${a.out.length ? `<span class="out">↑ ${esc(assetText(sumAssets(a.out)))}</span> ` : ''}
        <span class="muted">· ${a.in.length + a.out.length} tx · ${fmtTime(a.last)}</span></div>
    </div>`;
  }).join('');
  return `${rows || '<p class="muted">Geen tegenpartijen gevonden.</p>'}
    ${all.length > shown.length ? `<button type="button" class="ghost wide" data-more="cp">Toon meer (${all.length - shown.length})</button>` : ''}
    ${n.data.cursor ? `<button type="button" class="ghost wide" data-more="fetch" ${n.loadingMore ? 'disabled' : ''}>${n.loadingMore ? 'Laden…' : 'Oudere transacties laden'}</button>` : ''}`;
}

function osintHtml(n, m) {
  const lower = n.addr.toLowerCase();
  return `<dl class="kv">
      <dt>OFAC-sanctie</dt><dd>${osint.ofac.has(n.addr) || osint.ofac.has(lower) ? '⚠️ JA' : 'nee'}</dd>
      ${isEvm(n.chain) ? `<dt>ScamSniffer</dt><dd>${osint.scam?.has(lower) ? '⚠️ op blacklist' : osint.scam ? 'niet gevonden' : 'lijst niet geladen'}</dd>` : ''}
      ${m.tags?.length ? `<dt>Publieke labels</dt><dd>${m.tags.map(esc).join(', ')}</dd>` : ''}
      ${m.ens ? `<dt>ENS</dt><dd>${esc(m.ens)}</dd>` : ''}
      ${m.name ? `<dt>Contractnaam</dt><dd>${esc(m.name)}</dd>` : ''}
      ${window.KNOWN_LABELS[n.addr] ? `<dt>Bekend label</dt><dd>${esc(window.KNOWN_LABELS[n.addr].name)}</dd>` : ''}
      <dt>Hop</dt><dd>${n.ghost ? 'niet in het web' : (n.depth ?? 0) + (n.expanded ? '' : ' (nog niet verder gevolgd)')}</dd>
    </dl>
    ${dbSection(n)}
    <h4>OSINT-bronnen</h4>
    <div class="links">${osintLinks(n).map(([t, u]) => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(t)}</a>`).join('')}</div>
    <h4>Notitie</h4>
    <textarea id="nodeNote" class="note" rows="3" placeholder="Bijv. bevestigd door slachtoffer, aangifte nr., contact exchange…">${esc(notes.nodes[n.key] || '')}</textarea>`;
}

// --- transactiepagina ---
function txViewHtml(v) {
  if (!v.data && !v.err && !v.loading) {
    v.loading = true;
    fetchTx(v.chain, v.txid).then(r => { v.data = r; }).catch(err => { v.err = err.message; })
      .finally(() => { v.loading = false; if (stillCurrent(v)) renderView(); });
  }
  const r = v.data;
  const head = `${navBar()}
    <div class="xhead"><span class="xicon">⇄</span><div class="xhead-t"><h3>Transactie</h3>
      <div class="mono">${esc(v.txid)} <button type="button" class="mini" data-act="copytx">Kopieer</button></div></div></div>`;
  if (v.err) return `${head}<p class="muted">Ophalen mislukt: ${esc(v.err)}</p><button type="button" class="ghost wide" data-act="retrytx">Opnieuw proberen</button>`;
  if (!r) return `${head}<div class="xloading"><span class="spin"></span> Transactie ophalen…</div>`;
  const status = r.failed ? '<span class="tag high">Mislukt</span>' : r.confirmed ? '<span class="tag info">Bevestigd</span>' : '<span class="tag med">Onbevestigd</span>';
  const ext = `<div class="links"><a href="${esc(txUrl(r.chain, r.txid))}" target="_blank" rel="noopener noreferrer">Bekijk op ${r.chain === 'btc' ? 'mempool.space' : r.chain === 'tron' ? 'Tronscan' : 'Etherscan'}</a></div>`;
  let body = '';
  if (r.chain === 'btc') {
    const io = (list, title) => `<h4>${title} <span class="badge">${list.length}</span></h4>
      ${list.map(x => `<div class="xrow"><div class="xrow-top">${addrChip('btc', x.addr, { noLink: x.noLink })}<b class="amt">${fmt(x.value)} BTC</b></div></div>`).join('')}`;
    body = `<div class="xio"><div>${io(r.inputs, 'Van (inputs)')}</div><div>${io(r.outputs, 'Naar (outputs)')}</div></div>`;
  } else {
    body = `${r.from ? `<h4>Afzender → ontvanger</h4><div class="xrow"><div class="xrow-top">${addrChip(r.chain, r.from)}</div><div class="xrow-top">→ ${addrChip(r.chain, r.to)}</div></div>` : ''}
      <h4>Overboekingen <span class="badge">${r.transfers.length}</span></h4>
      ${r.transfers.map(t => `<div class="xrow"><div class="xrow-top">${addrChip(r.chain, t.from)}</div><div class="xrow-top">→ ${addrChip(r.chain, t.to)}</div><div class="xrow-sub"><b>${fmt(t.value)} ${esc(t.asset)}</b></div></div>`).join('') || '<p class="muted">Geen waarde-overboekingen.</p>'}
      ${r.partial ? '<p class="hint">Tron: alleen overboekingen van adressen die de app al geladen heeft. Zie Tronscan voor alles.</p>' : ''}`;
  }
  return `${head}
    <div class="tags"><span class="tag">${CHAIN_NAME[r.chain]}</span>${status}</div>
    <dl class="kv"><dt>Tijd</dt><dd>${fmtTime(r.time)}</dd>${r.fee ? `<dt>Fee</dt><dd>${esc(r.fee)}</dd>` : ''}${r.method ? `<dt>Methode</dt><dd>${esc(r.method)}</dd>` : ''}</dl>
    ${body}${ext}`;
}

// --- geldstroom (lijn in het web) ---
function edgeViewHtml(v) {
  const e = edges.get(v.key);
  if (!e) return `${navBar()}<p class="muted">Deze geldstroom staat niet meer in het web.</p>`;
  const s = nodes.get(e.source), t = nodes.get(e.target);
  return `${navBar()}
    <div class="xhead"><span class="xicon">→</span><div class="xhead-t"><h3>Geldstroom</h3><div class="muted small">${esc(edgeLabel(e))}${e.usd ? ` · ≈ $${fmt(e.usd)}` : ''}</div></div></div>
    <div class="xrow"><div class="xrow-top"><span class="dir out">Van</span>${addrChip(s.chain, s.addr)}</div><div class="xrow-top"><span class="dir in">Naar</span>${addrChip(t.chain, t.addr)}</div></div>
    <dl class="kv"><dt>Eerste</dt><dd>${fmtTime(e.first)}</dd><dt>Laatste</dt><dd>${fmtTime(e.last)}</dd><dt>Aantal</dt><dd>${e.count}</dd></dl>
    <h4>Transacties</h4>
    ${[...e.txs].sort((a, b) => (b.time || 0) - (a.time || 0)).map(x => `<div class="xrow"><div class="xrow-sub"><b>${fmt(x.value)} ${esc(x.asset)}</b> <span class="muted">· ${fmtTime(x.time)} ·</span> ${txChip(x.txid)}</div></div>`).join('')}`;
}

async function loadMoreTx(n) {
  if (!n.data?.cursor || n.loadingMore) return;
  n.loadingMore = true;
  refreshView();
  try {
    const d = await fetchMore(n.chain, n.addr, n.data.cursor);
    if (d) {
      const sig = t => `${t.txid}|${t.from}|${t.to}|${t.asset}|${t.value}`;
      const seen = new Set(n.data.transfers.map(sig));
      for (const t of d.transfers) if (!seen.has(sig(t))) { seen.add(sig(t)); n.data.transfers.push(t); }
      n.data.cursor = d.cursor;
      n.data.peelCount = (n.data.peelCount || 0) + (d.peelCount || 0);
      mergeMeta(n.chain, d.meta);
      fullAnalyze(n);
      const v = curView();
      if (v?.type === 'addr') v.limit += 40;
    }
  } catch (err) {
    if (err.name !== 'AbortError') setStatus('Meer laden mislukt: ' + err.message, true);
  }
  n.loadingMore = false;
  refreshView();
}

function ensureCase(n) {
  if (!current) {
    current = { chain: n.chain, role: 'victim', pattern: 'generic', opts: readOpts(), seedKey: n.key, started: new Date().toISOString() };
    loadNotes();
  }
}

function onDetailClick(ev) {
  const b = ev.target.closest('button, [data-addr]');
  if (!b || !$('#detailBody').contains(b)) return;
  const v = curView();
  const chain = $('#detailBody').dataset.chain;
  if (b.dataset.nav === 'back') return goBack();
  if (b.dataset.nav === 'close') return closeExplorer();
  if (b.dataset.addr) return openAddr(chain, b.dataset.addr);
  if (b.dataset.tx) return openTx(chain, b.dataset.tx);
  if (!v) return;
  if (b.dataset.tab) { v.tab = b.dataset.tab; return renderView(); }
  if (b.dataset.filter) {
    if (b.dataset.filter === 'dust') v.showDust = !v.showDust; else v.filter = b.dataset.filter;
    v.limit = 40;
    return renderView();
  }
  if (b.dataset.more === 'show') { v.limit += 60; return renderView(); }
  if (b.dataset.more === 'cp') { v.cpLimit += 60; return renderView(); }
  if (b.dataset.more === 'fetch') return loadMoreTx(peekNode(v.chain, v.addr));
  if (b.dataset.add) {
    const n = peekNode(v.chain, v.addr);
    ensureCase(n);
    if (n.ghost) addToGraph(n);
    addToGraph(peekNode(v.chain, b.dataset.add));
    setStatus(`Toegevoegd aan het web: ${short(b.dataset.add)}`);
    return renderView();
  }
  if (b.dataset.act) {
    b.closest('details')?.removeAttribute('open');
    if (v.type === 'tx') {
      if (b.dataset.act === 'copytx') copyText(v.txid);
      if (b.dataset.act === 'retrytx') { v.err = null; txCache.delete(v.chain + ':' + v.txid); renderView(); }
      return;
    }
    nodeAction(peekNode(v.chain, v.addr), b.dataset.act);
  }
}

async function copyText(s) {
  try { await navigator.clipboard.writeText(s); setStatus('Gekopieerd.'); } catch { prompt('Kopieer:', s); }
}

// Op de telefoon: eerst een klein kaartje onder in het web, zodat je het web blijft zien.
function showPeek(n) {
  if (!n) return;
  const cls = nodeClass(n);
  $('#peek').innerHTML = `<div class="peek-t"><i class="dot ${cls}"></i><div><b>${esc(labelOf(n) || short(n.addr))}</b><small>${esc(ROLE_TXT[cls])} · ${esc(short(n.addr))}</small></div></div>
    <div class="peek-a"><button type="button" class="ghost" data-peek="expand">Volg verder</button><button type="button" class="primary" data-peek="open">Details ›</button></div>`;
  $('#peek').dataset.key = n.key;
  $('#peek').hidden = false;
}
function hidePeek() { const p = $('#peek'); if (p) p.hidden = true; }

async function nodeAction(n, act) {
  if (act === 'copy') return copyText(n.addr);
  if (act === 'retry') { n.loadTried = false; n.flags = n.flags.filter(f => f.code !== 'error'); return refreshView(); }
  if (act === 'show') { setTab('graph'); focusNode(n.key); return; }
  if (act === 'add') { ensureCase(n); addToGraph(n); setStatus('Toegevoegd aan het web.'); return refreshView(); }
  if (n.ghost && ['perp', 'victim', 'expand', 'origins'].includes(act)) { ensureCase(n); n = addToGraph(n); }
  if (act === 'perp' || act === 'victim') { n.role = n.role === act ? null : act; render(false); refreshView(); recordObservations(); return; }
  if (act === 'label') {
    const v = prompt('Label voor dit adres (leeg = verwijderen):', customLabels[n.key] || '');
    if (v === null) return;
    if (v.trim()) customLabels[n.key] = v.trim(); else delete customLabels[n.key];
    store.set('chaintrace.labels', customLabels);
    if (LOCAL_DB) { try { window.AndroidBridge.saveUserLabel(n.chain, n.addr, v.trim()); } catch { /* niet fataal */ } dbCache.delete(n.key); }
    n.flags = n.flags.filter(f => f.code !== 'exchange');
    lightAnalyze(n);
    if (!n.ghost) render(false);
    refreshView(); return;
  }
  if (act === 'remove') {
    if (n.seed) return;
    nodes.delete(n.key);
    for (const [k, e] of edges) if (e.source === n.key || e.target === n.key) edges.delete(k);
    cy.getElementById(n.key).remove();
    closeExplorer(); render(false); return;
  }
  if (act === 'origins') {
    stopped = false;
    setBusy(true);
    await traceOrigins(n, { depth: 3, fanIn: Math.max(4, current.opts.fanout) });
    setBusy(false);
    render(true);
    renderSummary();
    setStatus(`Herkomst: ${origins.starts.size} startwallets, ${origins.cashIn.length} instroom-transacties.`);
    refreshView();
    return;
  }
  if (act === 'expand') {
    stopped = false;
    setBusy(true);
    n.expanded = false;
    current.opts.maxNodes = Math.max(current.opts.maxNodes, nodes.size + current.opts.fanout * 2);
    await expand(n, n.depth || 0, 'both');
    setBusy(false);
    render(false);
    setStatus(`${nodes.size} adressen, ${edges.size} geldstromen.`);
    refreshView();
  }
}

// ---------- tabbladen (telefoon) en zoeken ----------
function setTab(tab) {
  document.body.dataset.tab = tab;
  document.querySelectorAll('.tabbar button').forEach(b => b.classList.toggle('active', b.dataset.go === tab));
  $('#tabDetail').disabled = nav.i < 0;
  if (tab === 'graph' && cy) requestAnimationFrame(() => { cy.resize(); if (graphStale) { graphStale = false; runLayout(true); } });
}

function exploreQuery(q) {
  q = q.trim();
  if (!q) return;
  const ch = detectChain(q);
  if (ch) {
    const chain = isEvm(ch) && current && isEvm(current.chain) ? current.chain : ch;
    return openAddr(chain, q);
  }
  if (/^0x[0-9a-fA-F]{64}$/.test(q)) return openTx(current && isEvm(current.chain) ? current.chain : 'eth', q.toLowerCase());
  if (/^[0-9a-fA-F]{64}$/.test(q)) return openTx(current?.chain === 'tron' ? 'tron' : 'btc', q.toLowerCase());
  setStatus('Niet herkend als adres of transactie-hash.', true);
  setTab('form');
}

// ---------- export / import ----------
function saveFile(name, mime, dataUrlOrText, isDataUrl) {
  if (window.AndroidBridge?.saveFile) {
    const b64 = isDataUrl ? dataUrlOrText.split(',')[1] : btoa(unescape(encodeURIComponent(dataUrlOrText)));
    window.AndroidBridge.saveFile(name, mime, b64);
    return;
  }
  const a = document.createElement('a');
  a.href = isDataUrl ? dataUrlOrText : URL.createObjectURL(new Blob([dataUrlOrText], { type: mime }));
  a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
}

const stamp = () => new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-');

function exportJson() {
  const seed = nodes.get(current?.seedKey);
  const dossier = {
    tool: 'ChainTrace', version: 1, exported: new Date().toISOString(),
    case: current && { chain: current.chain, role: current.role, pattern: window.PATTERNS[current.pattern].name, patternKey: current.pattern, seed: seed?.addr, started: current.started },
    nodes: [...nodes.values()].map(n => ({ key: n.key, chain: n.chain, address: n.addr, label: labelOf(n), role: n.role, classification: nodeClass(n), hop: n.depth, flags: n.flags, seed: !!n.seed, hint: n.hint, parent: n.parent, upstream: !!n.upstream })),
    edges: [...edges.values()].map(e => ({ ...e, first: e.first === Infinity ? null : e.first })),
    origins: { rootKey: origins.rootKey, starts: [...origins.starts.values()], cashIn: origins.cashIn },
    notes,
    customLabels
  };
  saveFile(`chaintrace-${short(seed?.addr || 'dossier').replace('…', '_')}-${stamp()}.json`, 'application/json', JSON.stringify(dossier, null, 2), false);
}

function graphImage(themeName, maxWidth) {
  const t = THEMES[themeName];
  if (themeName !== 'dark') cy.style(cyStyle(themeName));
  cy.$(':selected').unselect();
  const bb = cy.elements().boundingBox();
  const scale = Math.max(1, Math.min(4, maxWidth / Math.max(bb.w, 1), 9000 / Math.max(bb.h, 1)));
  const uri = cy.png({ full: true, scale, bg: t.bg, padding: 30 });
  if (themeName !== 'dark') cy.style(cyStyle('dark'));
  return uri;
}

function loadImage(src) {
  return new Promise((ok, fail) => { const img = new Image(); img.onload = () => ok(img); img.onerror = fail; img.src = src; });
}

// Rapport als één afbeelding: kop, grafiek, legenda, bevindingen, herkomst en notities.
async function composeReport(opts) {
  const t = THEMES[opts.theme];
  const W = 2400, PAD = 70, INNER = W - 2 * PAD;
  const canvas = document.createElement('canvas');
  canvas.width = W;
  canvas.height = 16000;
  const ctx = canvas.getContext('2d');
  const FONT = 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
  const MONO = 'ui-monospace, Consolas, "Roboto Mono", monospace';
  const font = (size, weight = 400, mono = false) => { ctx.font = `${weight} ${size}px ${mono ? MONO : FONT}`; };
  const text = (s, x, y, color = t.text) => { ctx.fillStyle = color; ctx.fillText(s, x, y); };
  const wrap = (s, x, y, maxW, lh, color = t.text) => {
    ctx.fillStyle = color;
    let line = '';
    for (const word of String(s).split(/\s+/)) {
      const test = line ? line + ' ' + word : word;
      if (ctx.measureText(test).width > maxW && line) { ctx.fillText(line, x, y); y += lh; line = word; } else line = test;
    }
    if (line) { ctx.fillText(line, x, y); y += lh; }
    return y;
  };
  const fit = (s, maxW) => {
    s = String(s);
    if (ctx.measureText(s).width <= maxW) return s;
    while (s.length > 4 && ctx.measureText(s + '…').width > maxW) s = s.slice(0, -1);
    return s + '…';
  };
  const roundRect = (x, y, w, h, r, fill) => { ctx.fillStyle = fill; ctx.beginPath(); ctx.roundRect(x, y, w, h, r); ctx.fill(); };
  const heading = (s, y) => { font(30, 700); text(s.toUpperCase(), PAD, y, t.muted); ctx.fillStyle = t.line; ctx.fillRect(PAD, y + 16, INNER, 2); return y + 60; };

  ctx.fillStyle = t.bg;
  ctx.fillRect(0, 0, W, canvas.height);
  ctx.textBaseline = 'alphabetic';

  // kop
  const seed = nodes.get(current?.seedKey);
  const pat = current ? window.PATTERNS[current.pattern] : null;
  roundRect(0, 0, W, 300, 0, t.panel);
  ctx.fillStyle = '#4ea1ff';
  ctx.fillRect(0, 0, 14, 300);
  font(56, 800); text('ChainTrace — onderzoeksrapport', PAD, 100);
  font(30, 400);
  text(`${pat?.name || 'Trace'} · ${current?.role === 'perp' ? 'startadres: dader' : 'startadres: slachtoffer'} · ${CHAIN_NAME[current?.chain] || ''}`, PAD, 158, t.muted);
  font(32, 500, true); text(seed?.addr || '', PAD, 214);
  font(26, 400); text(`Gegenereerd ${new Date().toLocaleString('nl-NL')}`, PAD, 262, t.muted);
  const highs = [...nodes.values()].reduce((s, n) => s + n.flags.filter(f => f.level === 'high').length, 0);
  const stats = [[nodes.size, 'adressen'], [edges.size, 'geldstromen'], [highs, 'rode vlaggen'], [origins.starts.size, 'startwallets']];
  stats.forEach(([v, l], i) => {
    const x = W - PAD - (stats.length - i) * 230 + 30;
    font(60, 800); text(fmt(v), x, 150, i === 2 && v ? '#ff4d5e' : t.text);
    font(24, 400); text(l, x, 192, t.muted);
  });
  let y = 360;

  // grafiek
  const img = await loadImage(graphImage(opts.theme, INNER * 1.5));
  const gScale = Math.min(INNER / img.width, 1800 / img.height);
  const gw = img.width * gScale, gh = img.height * gScale;
  roundRect(PAD - 10, y - 10, INNER + 20, gh + 20, 24, t.panel);
  ctx.drawImage(img, PAD + (INNER - gw) / 2, y, gw, gh);
  y += gh + 50;

  // legenda
  font(26, 400);
  let lx = PAD;
  for (const [cls, name] of [['victim', 'Slachtoffer'], ['victim2', 'Mogelijk slachtoffer / startwallet'], ['perp', 'Dader'], ['suspect', 'Verdacht'], ['exchange', 'Exchange / dienst'], ['sanction', 'Sanctie / scamlijst'], ['plain', 'Onbekend']]) {
    ctx.fillStyle = COLORS[cls]; ctx.beginPath(); ctx.arc(lx + 12, y - 9, 12, 0, Math.PI * 2); ctx.fill();
    text(name, lx + 34, y, t.muted);
    lx += 34 + ctx.measureText(name).width + 44;
  }
  ctx.strokeStyle = '#3fa7ff'; ctx.lineWidth = 4; ctx.setLineDash([12, 8]);
  ctx.beginPath(); ctx.moveTo(lx, y - 9); ctx.lineTo(lx + 50, y - 9); ctx.stroke(); ctx.setLineDash([]);
  text('herkomst (stroomopwaarts)', lx + 64, y, t.muted);
  y += 70;

  // herkomst: instroom via exchanges
  if (opts.origins && origins.rootKey) {
    y = heading(`Instroom via exchanges en diensten (${origins.cashIn.length})`, y);
    const cash = [...origins.cashIn].sort((a, b) => (a.time || 0) - (b.time || 0)).slice(0, 40);
    if (!cash.length) { font(26); text('Geen instroom via exchanges gevonden binnen de zoekdiepte.', PAD, y, t.muted); y += 50; }
    else {
      const cols = [[PAD, 'Exchange / dienst', 380], [PAD + 400, 'Tijdstip', 260], [PAD + 680, 'Bedrag', 300], [PAD + 1000, 'Naar wallet', 330], [PAD + 1350, 'Transactie-hash', INNER - 1350]];
      font(24, 700); cols.forEach(([x, h]) => text(h, x, y, t.muted)); y += 14;
      for (const [i, r] of cash.entries()) {
        if (i % 2 === 0) roundRect(PAD - 12, y + 6, INNER + 24, 46, 8, t.panel);
        y += 40;
        font(25, 600); text(fit(r.name, cols[0][2]), cols[0][0], y);
        font(25); text(fmtTime(r.time), cols[1][0], y);
        text(fit(`${fmt(r.value)} ${r.asset}`, cols[2][2]), cols[2][0], y);
        font(22, 400, true); text(short(nodes.get(r.to)?.addr || '?'), cols[3][0], y);
        font(19, 400, true); text(fit(r.txid, cols[4][2]), cols[4][0], y, t.muted);
        y += 6;
      }
      y += 50;
    }
    y = heading(`Startwallets — mogelijke slachtoffers / geldbronnen (${origins.starts.size})`, y);
    const starts = [...origins.starts.values()].sort((a, b) => (b.usd - a.usd)).slice(0, 30);
    if (!starts.length) { font(26); text('Geen startwallets gevonden.', PAD, y, t.muted); y += 50; }
    for (const [i, r] of starts.entries()) {
      const n = nodes.get(r.key);
      if (i % 2 === 0) roundRect(PAD - 12, y - 32, INNER + 24, 50, 8, t.panel);
      font(22, 400, true); text(r.addr, PAD, y);
      font(25, 600); text(fit(assetText(r.assets), 360), PAD + 1060, y);
      font(24); text(fit(`${(n && labelOf(n)) ? labelOf(n) + ' · ' : ''}${r.reason}${r.first ? ' · ' + fmtTime(r.first) : ''}`, INNER - 1440), PAD + 1440, y, t.muted);
      y += 52;
    }
    y += 40;
  }

  // bevindingen
  if (opts.findings) {
    const order = { high: 0, med: 1, info: 2 };
    const list = [];
    for (const n of nodes.values()) for (const f of n.flags) if (!['contract', 'error', 'startwallet'].includes(f.code)) list.push({ n, f });
    list.sort((a, b) => order[a.f.level] - order[b.f.level]);
    y = heading(`Bevindingen (${list.length})`, y);
    const lvlColor = { high: '#ff4d5e', med: '#ff9f43', info: '#2ecc71' };
    for (const { n, f } of list.slice(0, 24)) {
      ctx.fillStyle = lvlColor[f.level]; ctx.fillRect(PAD, y - 30, 8, 40);
      font(26, 500); text(fit(f.text, 1300), PAD + 28, y);
      font(21, 400, true); text(fit(`${labelOf(n) ? labelOf(n) + ' · ' : ''}${n.addr}`, INNER - 1360), PAD + 1360, y, t.muted);
      y += 54;
    }
    if (list.length > 24) { font(24); text(`… en ${list.length - 24} meer (zie dossier-JSON)`, PAD + 28, y, t.muted); y += 50; }
    y += 30;
  }

  // notities
  const nodeNotes = Object.entries(notes.nodes).filter(([k]) => nodes.has(k));
  if (opts.notes && (notes.case || nodeNotes.length)) {
    y = heading('Notities', y);
    if (notes.case) { font(27); for (const para of notes.case.split(/\n+/)) y = wrap(para, PAD, y, INNER, 40); y += 20; }
    for (const [k, v] of nodeNotes) {
      const n = nodes.get(k);
      font(23, 600, true); text(`✎ ${labelOf(n) ? labelOf(n) + ' · ' : ''}${n.addr}`, PAD, y, t.muted); y += 40;
      font(26); for (const para of v.split(/\n+/)) y = wrap(para, PAD + 34, y, INNER - 34, 38);
      y += 18;
    }
    y += 20;
  }

  // voet
  ctx.fillStyle = t.line; ctx.fillRect(PAD, y, INNER, 2); y += 46;
  font(22);
  y = wrap('Gemaakt met ChainTrace (open source, zonder login). Data: mempool.space, Blockscout, TronGrid, OFAC (0xB10C), ScamSniffer, GraphSense, Ransomwhere, Forta, Etherscan-labels, Tether-blacklist. Heuristieken en labels zijn aanwijzingen, geen bewijs; controleer transacties in een block explorer.', PAD, y, INNER, 32, t.muted);
  y += 40;

  const out = document.createElement('canvas');
  out.width = W;
  out.height = Math.ceil(y);
  out.getContext('2d').drawImage(canvas, 0, 0);
  return out.toDataURL('image/png');
}

async function exportReport(kind) {
  if (!cy || !nodes.size) return;
  const opts = {
    theme: $('#expTheme').value,
    origins: $('#expOrigins').checked, findings: $('#expFindings').checked, notes: $('#expNotes').checked
  };
  setStatus('Afbeelding maken…');
  try {
    const uri = kind === 'graph' ? graphImage(opts.theme, 4000) : await composeReport(opts);
    saveFile(`chaintrace-${kind === 'graph' ? 'web' : 'rapport'}-${stamp()}.png`, 'image/png', uri, true);
    setStatus('Afbeelding opgeslagen.');
  } catch (err) {
    setStatus('Exporteren mislukt: ' + err.message, true);
  }
  $('#exportDialog').close();
}

// ---------- samenvatting in gewone taal ----------
const BAD_CODES = ['sanction', 'scamlist', 'ransomware', 'frozen', 'mixer', 'darknet', 'badtag'];
const CLASS_NL = { victim: 'Slachtoffer', perp: 'Dader', suspect: 'Verdacht', victim2: 'Mogelijk slachtoffer', exchange: 'Exchange / dienst', sanction: 'Waarschuwingslijst', plain: 'Onbekend' };
const nameList = arr => [...new Set(arr)].slice(0, 4).join(', ') + (new Set(arr).size > 4 ? ' e.a.' : '');

function summaryLines() {
  const seed = nodes.get(current?.seedKey);
  if (!seed) return [];
  const all = [...nodes.values()];
  const out = [];
  const down = all.filter(n => !n.upstream && !n.seed);
  out.push({ text: `Vanaf het adres van ${current.role === 'perp' ? 'de dader' : 'het slachtoffer'} is het geld gevolgd langs ${down.length} adressen.` });
  const exch = down.filter(n => n.flags.some(f => f.code === 'exchange' || f.code === 'service'));
  if (exch.length) {
    out.push({ cls: 'good', text: `Het geld komt uit bij ${exch.length} exchange(s) of dienst(en): ${nameList(exch.map(n => labelOf(n) || 'onbekende dienst ' + short(n.addr)))}. Daar kan de politie opvragen wie de rekeninghouder is en om bevriezing vragen.` });
  } else {
    out.push({ text: 'Er is nog geen exchange gevonden waar het geld uitkomt. Tik op een oranje adres en kies "Verder traceren" om dieper te zoeken.' });
  }
  const bad = all.filter(n => n.flags.some(f => BAD_CODES.includes(f.code)));
  if (bad.length) out.push({ cls: 'warn', text: `${bad.length} adres(sen) staan op een waarschuwingslijst (sanctie, scam, ransomware, mixer of door Tether bevroren).` });
  const look = all.filter(n => n.flags.some(f => f.code === 'lookalike' && f.level === 'high'));
  if (look.length) out.push({ cls: 'warn', text: `${look.length} adres(sen) lijken sterk op een ander adres: mogelijk "address poisoning".` });
  const before = all.filter(n => n.flags.some(f => f.code === 'seenbefore'));
  if (before.length) out.push({ cls: 'warn', text: `${before.length} adres(sen) kwamen al voor in een eerder onderzoek op dit apparaat.` });
  if (origins.starts.size) out.push({ text: `${origins.starts.size} startwallet(s) gevonden waar geld vandaan kwam${current.role === 'perp' ? ': mogelijke andere slachtoffers' : ''}.` });
  if (origins.cashIn.length) out.push({ text: `${origins.cashIn.length} storting(en) kwamen rechtstreeks van een exchange of dienst (${nameList(origins.cashIn.map(r => r.name))}). Transactie-hash en tijdstip staan in het rapport.` });
  return out;
}

function renderSummary() {
  const lines = summaryLines();
  $('#summary').hidden = !lines.length;
  $('#summaryList').innerHTML = lines.map(l => `<li class="${l.cls || ''}">${esc(l.text)}</li>`).join('');
}

// ---------- PDF-rapport ----------
const pdfSafe = v => String(v ?? '').replace(/…/g, '...').replace(/→/g, '->').replace(/[—–]/g, '-').replace(/×/g, 'x').replace(/[“”]/g, '"').replace(/[‘’]/g, "'").replace(/[^\x00-\xFF]/g, '');
const utc = t => t ? new Date(t * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : '';

async function exportPdf() {
  if (!window.jspdf || !nodes.size || !current) return;
  setStatus('PDF-rapport maken…');
  try {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ unit: 'mm', format: 'a4' });
    const W = 210, M = 14, S = pdfSafe;
    const seed = nodes.get(current.seedKey);
    const pat = window.PATTERNS[current.pattern];
    const cls = n => nodeClass(n);
    const name = n => (n && labelOf(n)) || '';
    let y = 0;

    doc.setFillColor(23, 30, 38); doc.rect(0, 0, W, 36, 'F');
    doc.setFillColor(78, 161, 255); doc.rect(0, 0, 3, 36, 'F');
    doc.setTextColor(255); doc.setFont('helvetica', 'bold'); doc.setFontSize(18);
    doc.text('ChainTrace onderzoeksrapport', M, 14);
    doc.setFont('helvetica', 'normal'); doc.setFontSize(9.5); doc.setTextColor(190);
    doc.text(S(`${pat.name}  |  ${CHAIN_NAME[current.chain]}  |  gemaakt op ${new Date().toLocaleString('nl-NL')}`), M, 21.5);
    doc.setFont('courier', 'normal'); doc.setFontSize(10); doc.setTextColor(255);
    doc.text(seed.addr, M, 29.5);
    y = 46;

    const room = need => { if (y + need > 284) { doc.addPage(); y = 18; } };
    const heading = t => {
      room(22);
      doc.setFont('helvetica', 'bold'); doc.setFontSize(12); doc.setTextColor(20);
      doc.text(S(t), M, y);
      doc.setDrawColor(78, 161, 255); doc.setLineWidth(0.5); doc.line(M, y + 1.6, W - M, y + 1.6);
      y += 7.5;
    };
    const para = (t, size = 9.5, color = 45, indent = 0) => {
      doc.setFont('helvetica', 'normal'); doc.setFontSize(size); doc.setTextColor(color);
      for (const line of doc.splitTextToSize(S(t), W - 2 * M - indent)) { room(6); doc.text(line, M + indent, y); y += size * 0.46; }
      y += 1.6;
    };
    const mono = { font: 'courier', fontSize: 6.3 };
    const table = (head, body, columnStyles = {}) => {
      doc.autoTable({
        startY: y, head: [head], body: body.map(r => r.map(S)), margin: { left: M, right: M, bottom: 16 },
        styles: { font: 'helvetica', fontSize: 7.5, cellPadding: 1.3, overflow: 'linebreak', textColor: 30, lineColor: 225, lineWidth: 0.1 },
        headStyles: { fillColor: [23, 30, 38], textColor: 255, fontSize: 7.5 },
        alternateRowStyles: { fillColor: [244, 246, 249] }, columnStyles
      });
      y = doc.lastAutoTable.finalY + 8;
    };
    const none = t => para(t, 9, 110);

    heading('Zaakgegevens');
    table(['Gegeven', 'Waarde'], [
      ['Onderzocht adres', seed.addr],
      ['Dit adres is van', current.role === 'perp' ? 'de (vermoedelijke) dader' : 'het slachtoffer'],
      ['Soort fraude', pat.name],
      ['Blockchain', CHAIN_NAME[current.chain]],
      ['Onderzoek uitgevoerd', new Date(current.started || Date.now()).toLocaleString('nl-NL')],
      ['Omvang', `${nodes.size} adressen, ${edges.size} geldstromen`]
    ], { 0: { cellWidth: 42, fontStyle: 'bold' } });

    heading('Samenvatting');
    for (const l of summaryLines()) para('-  ' + l.text);
    y += 3;

    // grafiek (als JPEG om het bestand klein te houden)
    const img = await loadImage(graphImage('light', 2600));
    const cv = document.createElement('canvas');
    cv.width = img.width; cv.height = img.height;
    const cx = cv.getContext('2d');
    cx.fillStyle = '#fff'; cx.fillRect(0, 0, cv.width, cv.height); cx.drawImage(img, 0, 0);
    const gs = Math.min((W - 2 * M) / img.width, 150 / img.height);
    const gw = img.width * gs, gh = img.height * gs;
    room(gh + 24);
    heading('Geldstromen in beeld');
    doc.setDrawColor(215); doc.setLineWidth(0.2); doc.rect(M, y, W - 2 * M, gh + 2);
    doc.addImage(cv.toDataURL('image/jpeg', 0.9), 'JPEG', M + (W - 2 * M - gw) / 2, y + 1, gw, gh);
    y += gh + 6;
    para('Blauw = slachtoffer, lichtblauw = mogelijk slachtoffer/startwallet, rood = dader, oranje = verdacht, groen = exchange of dienst, paars = waarschuwingslijst, grijs = onbekend. Gestippelde blauwe lijnen tonen waar het geld vandaan kwam.', 8, 110);
    y += 3;

    const suspectCls = ['perp', 'suspect', 'sanction'];
    const suspects = [...nodes.values()].filter(n => suspectCls.includes(cls(n)));
    heading(`Verdachte adressen (${suspects.length})`);
    if (!suspects.length) none('Geen adressen als verdacht aangemerkt.');
    else table(['Adres', 'Naam / label', 'Beoordeling', 'Waarom'], suspects.map(n => [
      n.addr, name(n), CLASS_NL[cls(n)],
      [n.hint === 'suspect' && current.role === 'victim' && n.depth === 1 ? 'Ontving geld rechtstreeks van het slachtoffer' : '', ...n.flags.filter(f => !['contract', 'error'].includes(f.code)).map(f => f.text)].filter(Boolean).join('; ')
    ]), { 0: { ...mono, cellWidth: 52 }, 1: { cellWidth: 30 }, 2: { cellWidth: 24 } });

    const txRows = (filter, limit = 400) => {
      const rows = [];
      for (const e of edges.values()) {
        const a = nodes.get(e.source), b = nodes.get(e.target);
        if (!a || !b || !filter(a, b)) continue;
        for (const t of e.txs) rows.push({ t, a, b });
      }
      return rows.sort((x, z) => (x.t.time || 0) - (z.t.time || 0)).slice(0, limit);
    };
    const txCols = { 0: { cellWidth: 24 }, 1: { ...mono, cellWidth: 38 }, 2: { ...mono, cellWidth: 38 }, 3: { cellWidth: 24 }, 4: { ...mono } };
    const txBody = rows => rows.map(({ t, a, b }) => [utc(t.time), (name(a) ? name(a) + ' ' : '') + a.addr, (name(b) ? name(b) + ' ' : '') + b.addr, `${fmt(t.value)} ${t.asset}`, t.txid]);

    const susTx = txRows((a, b) => !a.upstream && (a.seed || suspectCls.includes(cls(a)) || suspectCls.includes(cls(b))));
    heading(`Verdachte transacties (${susTx.length})`);
    para('Alle transacties van het onderzochte adres en van of naar verdachte adressen. Met de transactie-hash kan iedereen de betaling controleren in een block explorer.', 8.5, 110);
    if (!susTx.length) none('Geen transacties gevonden.');
    else table(['Tijdstip', 'Van', 'Naar', 'Bedrag', 'Transactie-hash'], txBody(susTx), txCols);

    const isExch = n => n.flags.some(f => f.code === 'exchange' || f.code === 'service');
    const outTx = txRows((a, b) => !a.upstream && !b.upstream && isExch(b) && !isExch(a));
    heading(`Uitbetaling via exchanges - cash-out (${outTx.length})`);
    para('Hier verlaat het geld de blockchain. Met deze gegevens kan de politie bij de exchange de rekeninghouder opvragen of om bevriezing vragen.', 8.5, 110);
    if (!outTx.length) none('Geen stortingen bij een exchange gevonden binnen de zoekdiepte.');
    else table(['Tijdstip', 'Van', 'Naar (exchange)', 'Bedrag', 'Transactie-hash'], txBody(outTx), txCols);

    const cash = [...origins.cashIn].sort((a, b) => (a.time || 0) - (b.time || 0));
    heading(`Geld afkomstig van exchanges - instroom (${cash.length})`);
    if (!cash.length) none('Geen instroom vanuit een exchange gevonden binnen de zoekdiepte.');
    else table(['Tijdstip', 'Exchange / dienst', 'Naar wallet', 'Bedrag', 'Transactie-hash'],
      cash.map(r => [utc(r.time), `${r.name} ${nodes.get(r.from)?.addr || ''}`, nodes.get(r.to)?.addr || '', `${fmt(r.value)} ${r.asset}`, r.txid]), txCols);

    const starts = [...origins.starts.values()].sort((a, b) => b.usd - a.usd);
    heading(`Startwallets - mogelijke slachtoffers of geldbronnen (${starts.length})`);
    para('Adressen waar het geld begon: zonder eerdere instroom, of rechtstreeks gevuld vanuit een exchange. Bij fraude zijn dit vaak andere slachtoffers.', 8.5, 110);
    if (!starts.length) none('Geen startwallets gevonden.');
    else table(['Adres', 'Naam / label', 'Verstuurd', 'Eerste betaling', 'Toelichting'],
      starts.map(r => [r.addr, name(nodes.get(r.key)), assetText(r.assets), utc(r.first), r.reason]),
      { 0: { ...mono, cellWidth: 52 }, 1: { cellWidth: 26 }, 2: { cellWidth: 28 }, 3: { cellWidth: 26 } });

    heading(`Alle adressen in dit onderzoek (${nodes.size})`);
    table(['Adres', 'Naam / label', 'Beoordeling', 'Stap', 'Notitie'],
      [...nodes.values()].sort((a, b) => (a.depth || 0) - (b.depth || 0)).map(n => [n.addr, name(n), (n.seed ? 'Startadres - ' : '') + CLASS_NL[cls(n)], (n.upstream ? '-' : '') + (n.depth || 0), notes.nodes[n.key] || '']),
      { 0: { ...mono, cellWidth: 56 }, 1: { cellWidth: 34 }, 2: { cellWidth: 32 }, 3: { cellWidth: 10 } });

    if (notes.case) {
      heading('Notities bij deze zaak');
      for (const line of notes.case.split(/\n+/)) para(line);
      y += 3;
    }

    heading('Vervolgstappen');
    pat.steps.forEach((st, i) => para(`${i + 1}.  ${st}`));
    y += 3;

    heading('Toelichting');
    para('Dit rapport is automatisch gemaakt met ChainTrace (open source) op basis van openbare blockchaingegevens (mempool.space, Blockscout, TronGrid) en openbare lijsten (OFAC, ScamSniffer, GraphSense, Ransomwhere, Forta, Etherscan-labels, Tether-blacklist). De beoordelingen "verdacht", "mogelijk slachtoffer" en "exchange" zijn aanwijzingen op basis van patronen en labels, geen bewijs. Controleer transacties altijd met de transactie-hash in een block explorer. Per adres zijn alleen de meest recente transacties onderzocht.', 8.5, 90);

    const pages = doc.getNumberOfPages();
    for (let i = 1; i <= pages; i++) {
      doc.setPage(i);
      doc.setFont('helvetica', 'normal'); doc.setFontSize(7.5); doc.setTextColor(140);
      doc.text(S(`ChainTrace  |  ${short(seed.addr)}  |  ${new Date().toLocaleDateString('nl-NL')}`), M, 291);
      doc.text(`Pagina ${i} van ${pages}`, W - M, 291, { align: 'right' });
    }
    saveFile(`chaintrace-rapport-${stamp()}.pdf`, 'application/pdf', doc.output('datauristring'), true);
    setStatus(`PDF-rapport opgeslagen (${pages} pagina's).`);
    return doc;
  } catch (err) {
    setStatus('PDF maken mislukt: ' + err.message, true);
    throw err;
  }
}

function importJson(text) {
  const d = JSON.parse(text);
  if (d.tool !== 'ChainTrace') throw new Error('Geen ChainTrace-dossier');
  abortCtl.abort(); abortCtl = new AbortController();
  resetGraph();
  current = { chain: d.case?.chain || d.nodes[0]?.chain, role: d.case?.role || 'victim', pattern: d.case?.patternKey || 'generic',
    seedKey: d.nodes.find(n => n.seed)?.key, started: d.case?.started, opts: readOpts() };
  Object.assign(customLabels, d.customLabels || {});
  for (const x of d.nodes) {
    const n = getNode(x.chain, x.address);
    Object.assign(n, { role: x.role, flags: x.flags || [], seed: x.seed, depth: x.hop, hint: x.hint, parent: x.parent, upstream: x.upstream, expanded: true });
  }
  for (const e of d.edges) edges.set(e.key, { ...e, first: e.first ?? Infinity });
  origins.rootKey = d.origins?.rootKey || null;
  origins.starts = new Map((d.origins?.starts || []).map(r => [r.key, r]));
  origins.cashIn = d.origins?.cashIn || [];
  loadNotes();
  if (d.notes) { notes = { case: d.notes.case || '', nodes: d.notes.nodes || {} }; $('#caseNote').value = notes.case; saveNotes(); }
  render(true);
  renderPlaybook();
  renderSummary();
  setStatus(`Dossier geladen: ${nodes.size} adressen.`);
}

// ---------- UI ----------
function resetGraph() {
  nodes.clear(); edges.clear(); ghosts.clear();
  hidePeek();
  origins.rootKey = null; origins.starts = new Map(); origins.cashIn = [];
  if (cy) cy.elements().remove();
  hideDetail();
  $('#playbook').hidden = true;
  $('#summary').hidden = true;
}

function setStatus(t, err = false) { const s = $('#status'); s.textContent = t; s.classList.toggle('err', err); }
function setBusy(b) { $('#btnTrace').disabled = b; $('#btnStop').hidden = !b; }

function readOpts() {
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, Number(v) || lo));
  return { depth: clamp($('#depth').value, 1, 4), fanout: clamp($('#fanout').value, 2, 25), maxNodes: clamp($('#maxNodes').value, 10, 300) };
}

function updateChainHint() {
  const a = $('#addr').value.trim();
  const sel = $('#chain').value;
  const det = detectChain(a);
  $('#chainHint').textContent = !a ? 'Bitcoin, Ethereum en Tron worden automatisch herkend'
    : det ? `✓ Dit is een ${CHAIN_NAME[det]}-adres` + (sel !== 'auto' ? ` · gekozen keten: ${CHAIN_NAME[sel]}` : '')
    : 'Dit lijkt geen geldig Bitcoin-, Ethereum- of Tron-adres. Controleer of je het hele adres hebt gekopieerd.';
  $('#chainHint').classList.toggle('bad', !!a && !det);
}

function applyPatternDefaults() {
  const p = window.PATTERNS[$('#pattern').value];
  $('#patternInfo').textContent = p.info;
  $('#depth').value = p.depth;
  $('#fanout').value = p.fanout;
}

function setup() {
  const pats = Object.entries(window.PATTERNS).sort((a, b) => (b[0] === 'generic') - (a[0] === 'generic'));
  $('#pattern').innerHTML = pats.map(([k, p]) => `<option value="${k}">${esc(k === 'generic' ? 'Weet ik niet / iets anders' : p.name)}</option>`).join('');
  applyPatternDefaults();
  const roleHint = () => {
    $('#roleHint').textContent = document.querySelector('input[name=role]:checked').value === 'perp'
      ? 'De app zoekt waar de dader het geld heen stuurde én wie er nog meer geld naartoe stuurde.'
      : 'De app volgt waar het geld van het slachtoffer naartoe is gegaan.';
  };
  document.querySelectorAll('input[name=role]').forEach(r => r.addEventListener('change', roleHint));
  roleHint();
  const recent = store.get('chaintrace.recent', []);
  const fillRecent = () => { $('#recentAddrs').innerHTML = recent.map(a => `<option value="${esc(a)}">`).join(''); };
  fillRecent();
  $('#btnPaste').addEventListener('click', async () => {
    let txt = '';
    try { txt = window.AndroidBridge?.readClipboard ? window.AndroidBridge.readClipboard() : await navigator.clipboard.readText(); } catch { /* geen toegang */ }
    txt = (txt || '').trim();
    if (!txt) { setStatus('Plakken lukt hier niet automatisch. Houd het veld ingedrukt en kies Plakken.', true); return; }
    $('#addr').value = txt;
    updateChainHint();
    setStatus('');
  });
  $('#btnPdf').addEventListener('click', () => exportPdf().catch(() => {}));
  $('#btnPdf2').addEventListener('click', () => exportPdf().catch(() => {}));
  $('#moreMenu').addEventListener('click', ev => { if (ev.target.closest('.menu-items')) setTimeout(() => { $('#moreMenu').open = false; }, 0); });
  document.addEventListener('click', ev => { if (!ev.target.closest('#moreMenu')) $('#moreMenu').open = false; });
  $('#pattern').addEventListener('change', applyPatternDefaults);
  $('#addr').addEventListener('input', updateChainHint);
  $('#chain').addEventListener('change', updateChainHint);

  $('#traceForm').addEventListener('submit', ev => {
    ev.preventDefault();
    const addr = $('#addr').value.trim();
    const det = detectChain(addr);
    let chain = $('#chain').value;
    if (chain === 'auto') chain = det;
    if (!chain) { setStatus('Dit adres wordt niet herkend. Controleer of je het hele adres hebt geplakt.', true); return; }
    const ri = recent.indexOf(addr);
    if (ri >= 0) recent.splice(ri, 1);
    recent.unshift(addr);
    recent.length = Math.min(recent.length, 8);
    store.set('chaintrace.recent', recent);
    fillRecent();
    if (det && (isEvm(det) !== isEvm(chain) || (!isEvm(det) && det !== chain))) { setStatus(`Adres past niet bij ${CHAIN_NAME[chain]}.`, true); return; }
    const role = document.querySelector('input[name=role]:checked').value;
    const pattern = $('#pattern').value;
    try { history.replaceState(null, '', `?addr=${encodeURIComponent(addr)}&chain=${chain}&role=${role}&pattern=${pattern}`); } catch { /* file:// */ }
    if (isMobile()) setTab('graph');
    runTrace(addr, chain, role, pattern, readOpts()).catch(err => {
      setBusy(false);
      if (err.name !== 'AbortError') setStatus('Fout: ' + err.message, true);
    });
  });
  $('#btnStop').addEventListener('click', () => { stopped = true; abortCtl.abort(); setBusy(false); setStatus('Gestopt.'); render(true); });
  $('#detailBody').addEventListener('click', onDetailClick);
  $('#btnExportJson').addEventListener('click', exportJson);
  $('#btnExportPng').addEventListener('click', () => $('#exportDialog').showModal());
  $('#btnExpReport').addEventListener('click', () => exportReport('report'));
  $('#btnExpGraph').addEventListener('click', () => exportReport('graph'));
  $('#btnExpClose').addEventListener('click', () => $('#exportDialog').close());
  $('#btnOriginsCsv').addEventListener('click', () => saveFile(`chaintrace-herkomst-${stamp()}.csv`, 'text/csv', '\ufeff' + originsCsv(), false));
  $('#caseNote').addEventListener('input', ev => { notes.case = ev.target.value; saveNotes(); });
  $('#fileImport').addEventListener('change', async ev => {
    const f = ev.target.files[0];
    if (!f) return;
    try { importJson(await f.text()); if (isMobile()) setTab('graph'); } catch (err) { setStatus('Import mislukt: ' + err.message, true); }
    ev.target.value = '';
  });
  const setLayout = name => {
    layoutName = name;
    $('#btnLayoutWeb').classList.toggle('active', name === 'web');
    $('#btnLayoutFlow').classList.toggle('active', name === 'flow');
    runLayout(true);
  };
  $('#btnLayoutWeb').addEventListener('click', () => setLayout('web'));
  $('#btnLayoutFlow').addEventListener('click', () => setLayout('flow'));
  $('#btnFit').addEventListener('click', () => cy?.fit(undefined, 40));

  setupDbDialog();

  // Tabbalk (telefoon), zoeken in de verkenner en het kaartje onder in het web.
  document.querySelectorAll('.tabbar button').forEach(b => b.addEventListener('click', () => {
    if (b.dataset.go === 'detail' && nav.i < 0) return;
    if (b.dataset.go === 'detail') $('#detail').hidden = false;
    setTab(b.dataset.go);
  }));
  $('#exploreForm').addEventListener('submit', ev => {
    ev.preventDefault();
    const q = $('#exploreQ').value;
    $('#exploreQ').blur();
    exploreQuery(q);
  });
  $('#peek').addEventListener('click', ev => {
    const b = ev.target.closest('[data-peek]');
    const n = nodes.get($('#peek').dataset.key);
    if (!b || !n) return;
    if (b.dataset.peek === 'open') openNode(n);
    else { hidePeek(); nodeAction(n, 'expand'); }
  });
  if (!isMobile()) document.querySelector('.legend-wrap').open = true;
  setTab('form');

  const q = new URLSearchParams(location.search);
  if (q.get('addr')) {
    $('#addr').value = q.get('addr');
    if (q.get('chain')) $('#chain').value = q.get('chain');
    if (q.get('pattern') && window.PATTERNS[q.get('pattern')]) { $('#pattern').value = q.get('pattern'); applyPatternDefaults(); }
    if (q.get('role') === 'perp') $('#rolePerp').checked = true;
    updateChainHint();
  }
}

// ---------- databasescherm ----------
let dbPoll = null;
function renderDbStats() {
  const s = dbStats();
  if (!s) return;
  const mb = (s.bytes / 1048576).toFixed(1);
  $('#dbSummary').innerHTML = `<b>${fmt(s.addresses)}</b> adressen met <b>${fmt(s.labels)}</b> labels · ${mb} MB<br>
    Eigen waarnemingen: ${fmt(s.observedAddresses)} adressen in ${fmt(s.cases)} zaken<br>
    Laatste update: ${s.lastRun ? new Date(s.lastRun).toLocaleString('nl-NL') : 'nog nooit'}${s.running ? ' · <b>bijwerken…</b>' : ''} · daarna dagelijks automatisch`;
  $('#dbSources').innerHTML = s.sources.map(x => `<tr><td><a href="${esc(x.url)}" target="_blank" rel="noopener noreferrer">${esc(x.name)}</a></td>
    <td class="num">${fmt(x.count)}</td><td class="st ${esc(x.status)}" title="${esc(x.error || '')}">${esc(x.status)}${x.error ? ' ⚠' : ''}</td>
    <td>${x.lastSync ? new Date(x.lastSync).toLocaleDateString('nl-NL') : '—'}</td></tr>`).join('');
  $('#btnDbSync').disabled = s.running;
}
function setupDbDialog() {
  if (!LOCAL_DB) return;
  $('#btnDb').hidden = false;
  const dlg = $('#dbDialog');
  $('#btnDb').addEventListener('click', () => {
    renderDbStats();
    dlg.showModal();
    clearInterval(dbPoll);
    dbPoll = setInterval(renderDbStats, 2000);
  });
  dlg.addEventListener('close', () => clearInterval(dbPoll));
  $('#btnDbClose').addEventListener('click', () => dlg.close());
  $('#btnDbSync').addEventListener('click', () => { window.AndroidBridge.osintSyncNow(); setTimeout(renderDbStats, 800); });
  let t = null;
  $('#dbSearch').addEventListener('input', ev => {
    clearTimeout(t);
    t = setTimeout(() => {
      let rows = [];
      try { rows = JSON.parse(window.AndroidBridge.osintSearch(ev.target.value)); } catch { /* leeg */ }
      $('#dbResults').innerHTML = rows.map((r, i) => `<li data-i="${i}"><span class="tag">${esc(CAT_NL[r.category] || r.category)}</span> ${esc(r.label)}<small>${esc(r.address)} · ${esc(r.source)}</small></li>`).join('')
        || (ev.target.value.trim().length >= 3 ? '<li class="muted">Niets gevonden.</li>' : '');
      $('#dbResults').querySelectorAll('li[data-i]').forEach(li => li.addEventListener('click', () => {
        $('#addr').value = rows[+li.dataset.i].address;
        $('#chain').value = 'auto';
        updateChainHint();
        dlg.close();
      }));
    }, 250);
  });
}

setup();
// Testhaak voor automatische checks (bijv. via adb/DevTools).
window.ChainTrace = { openAddr, openTx, nav, ghosts, runTrace, nodes, edges, detectChain, origins, traceOrigins, composeReport, exportPdf, summaryLines, notes: () => notes };
})();
