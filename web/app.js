(() => {
'use strict';

const $ = s => document.querySelector(s);
const API = {
  btc: 'https://mempool.space/api',
  eth: 'https://eth.blockscout.com/api/v2',
  op: 'https://explorer.optimism.io/api/v2',
  tron: 'https://api.trongrid.io',
  ltc: 'https://litecoinspace.org/api',
  avax: 'https://api.routescan.io/v2/network/mainnet/evm/43114/etherscan/api',
  zksync: 'https://block-explorer-api.mainnet.zksync.io',
  sol: 'https://solana-rpc.publicnode.com'
};
const CHAIN_NAME = { btc: 'Bitcoin', eth: 'Ethereum', op: 'Optimism', tron: 'Tron', ltc: 'Litecoin', avax: 'Avalanche', zksync: 'zkSync Era', sol: 'Solana' };
const SYM = { btc: 'BTC', ltc: 'LTC', eth: 'ETH', op: 'ETH', zksync: 'ETH', avax: 'AVAX', sol: 'SOL', tron: 'TRX' };
const EVM_LISTS = ['ETH', 'USDT', 'USDC'];
const OFAC_LISTS = { btc: ['XBT'], ltc: ['LTC'], eth: EVM_LISTS, op: EVM_LISTS, avax: EVM_LISTS, zksync: EVM_LISTS, tron: ['TRX', 'USDT'], sol: ['SOL'] };
const TRON_STABLES = { TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t: 'USDT', TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8: 'USDC' };
const SERVICE_TX_THRESHOLD = 5000;
const isEvm = c => c === 'eth' || c === 'op' || c === 'avax' || c === 'zksync';
const isUtxo = c => c === 'btc' || c === 'ltc';
const isBlockscout = c => c === 'eth' || c === 'op';

// ---------- hulpfuncties ----------
const sleep = ms => new Promise(r => setTimeout(r, ms));
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const short = a => a.length > 14 ? a.slice(0, 6) + '…' + a.slice(-4) : a;
const norm = (chain, a) => isEvm(chain) ? a.toLowerCase() : a;
const keyOf = (chain, a) => chain + ':' + norm(chain, a);
function fmt(v) {
  if (!isFinite(v)) return '?';
  const abs = Math.abs(v);
  if (abs >= 1000) return v.toLocaleString(window.CT_LOCALE, { maximumFractionDigits: 0 });
  if (abs >= 1) return v.toLocaleString(window.CT_LOCALE, { maximumFractionDigits: 2 });
  return v.toLocaleString(window.CT_LOCALE, { maximumSignificantDigits: 4 });
}
const fmtTime = t => t ? new Date(t * 1000).toLocaleString(window.CT_LOCALE, { dateStyle: 'short', timeStyle: 'short' }) : '?';

function detectChain(a) {
  a = a.trim();
  if (/^0x[a-fA-F0-9]{40}$/.test(a)) return 'eth';
  if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(a)) return 'tron';
  if (/^(bc1[a-z0-9]{25,87}|[13][1-9A-HJ-NP-Za-km-z]{25,34})$/.test(a)) return 'btc';
  if (/^(ltc1[a-z0-9]{25,87}|[LM][1-9A-HJ-NP-Za-km-z]{26,33})$/.test(a)) return 'ltc';
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a)) return 'sol';
  return null;
}

const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* opslag niet beschikbaar */ } }
};
let customLabels = store.get('chaintrace.labels', {});
let teamLabels = {}; // gedeelde labels van de teamserver (optioneel)

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
  if (!LOCAL_DB || !current || demoMode) return;
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
const HOST_GAP = { 'api.trongrid.io': 1050, 'api.routescan.io': 550, 'solana-rpc.publicnode.com': 250, 'api.mainnet-beta.solana.com': 270 }; // gemeten: ~1 verzoek/s wordt geaccepteerd
const hostNext = {};
async function throttle(host) {
  const gap = HOST_GAP[host];
  if (!gap) return;
  const now = Date.now();
  const at = Math.max(now, hostNext[host] || 0);
  hostNext[host] = at + gap;
  if (at > now) await sleep(at - now);
}

// Android: Solana-verzoeken via de app zelf naar de officiële Solana-server. Die heeft de volledige geschiedenis,
// maar weigert verzoeken uit een browser. De gratis openbare server (publicnode) kent maar ±1,5 dag geschiedenis.
const SOL_OFFICIAL = 'https://api.mainnet-beta.solana.com';
let nativeSol = !!window.AndroidBridge?.solRpc;
let nativeSolErr = ''; // laatste reden waarom de officiële server niet lukte
const solCbs = new Map();
let solCbN = 0;
window.ChainTraceSolCb = (id, code, text) => { const f = solCbs.get(id); if (f) { solCbs.delete(id); f({ code, text }); } };
function nativeSolPost(body) {
  return new Promise((res, rej) => {
    const id = 's' + (++solCbN);
    const t = setTimeout(() => { solCbs.delete(id); rej(new Error('Geen antwoord van de Solana-server')); }, 35000);
    solCbs.set(id, r => { clearTimeout(t); res(r); });
    window.AndroidBridge.solRpc(id, JSON.stringify(body));
  });
}
const solViaApp = () => nativeSol && API.sol === SOL_DEFAULT;

function getData(url, asText = false, tries = 6, body = null) {
  const ck = body ? url + '|' + JSON.stringify(body) : url;
  if (cache.has(ck)) return cache.get(ck);
  const host = new URL(url).host;
  const p = (async () => {
    await acquire();
    try {
      for (let attempt = 0; attempt < tries; attempt++) {
        if (body && url === SOL_DEFAULT && solViaApp()) {
          await throttle('api.mainnet-beta.solana.com');
          try {
            const n = await nativeSolPost(body);
            if (n.code === 200) {
              const j = JSON.parse(n.text);
              if (j.error?.code === 429) { await sleep(Math.min(1500 * 2 ** attempt, 15000)); continue; }
              if (j.error?.code !== 403) return j;
            }
            // Haperend (mobiel) netwerk of druk: opnieuw proberen in plaats van op te geven.
            if (n.code === 0 || n.code === 429 || n.code >= 500) {
              nativeSolErr = n.code === 0 ? 'geen verbinding (' + String(n.text).slice(0, 60) + ')' : 'HTTP ' + n.code;
              if (attempt < tries - 1) { await sleep(Math.min(1500 * 2 ** attempt, 15000)); continue; }
            }
            if (n.code === 403 || (n.code === 200 && n.text.includes('"code":403'))) { nativeSol = false; nativeSolErr = 'de officiële Solana-server weigert dit netwerk (403)'; }
          } catch (e) { nativeSolErr = e.message; }
        }
        await throttle(host);
        // Eigen time-out: sommige API's laten een verzoek eindeloos hangen.
        const ctl = new AbortController(), outer = abortCtl.signal;
        const onAbort = () => ctl.abort();
        outer.addEventListener('abort', onAbort, { once: true });
        let timedOut = false;
        const timer = setTimeout(() => { timedOut = true; ctl.abort(); }, tries <= 2 ? 15000 : 30000);
        let r;
        const headers = {};
        if (body) headers['Content-Type'] = 'application/json';
        if (host === 'api.trongrid.io' && tronKey()) headers['TRON-PRO-API-KEY'] = tronKey();
        try { r = await fetch(url, body ? { method: 'POST', headers, body: JSON.stringify(body), signal: ctl.signal } : { headers, signal: ctl.signal }); }
        catch (err) { if (timedOut) throw new Error('Geen antwoord van ' + host); throw err; }
        finally { clearTimeout(timer); outer.removeEventListener('abort', onAbort); }
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
  cache.set(ck, p);
  p.catch(() => cache.delete(ck));
  return p;
}

// ---------- OSINT-lijsten ----------
const osint = { ofac: new Set(), ofacLoaded: new Set(), scam: null };
async function loadLists(chain) {
  // In de app staan deze lijsten (en meer) al in de lokale database.
  if (demoMode || (LOCAL_DB && (dbStats()?.labels || 0) > 0)) return;
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
async function fetchBtc(addr, chain = 'btc', pages = 2) {
  const B = API[chain];
  const [info, txs] = await Promise.all([
    getData(`${B}/address/${addr}`),
    getData(`${B}/address/${addr}/txs`)
  ]);
  let all = txs || [];
  const conf = all.filter(t => t.status?.confirmed);
  let cursor = conf.length >= 25 ? { last: conf[conf.length - 1].txid } : null;
  for (let p = 1; p < pages && cursor; p++) {
    const more = await getData(`${B}/address/${addr}/txs/chain/${cursor.last}`).catch(() => null);
    if (!more) break;
    all = all.concat(more);
    cursor = more.length >= 25 ? { last: more[more.length - 1].txid } : null;
  }
  const { transfers, peelCount, coInputs, changeLinks } = parseBtcTxs(addr, all, SYM[chain]);
  const cs = info?.chain_stats;
  return {
    transfers, peelCount, coInputs, changeLinks, meta: {}, cursor,
    txCount: cs?.tx_count ?? all.length,
    balance: cs ? `${fmt((cs.funded_txo_sum - cs.spent_txo_sum) / 1e8)} ${SYM[chain]}` : null
  };
}

function parseBtcTxs(addr, all, sym = 'BTC') {
  const transfers = [];
  const coInputs = [];
  const changeLinks = [];
  let peelCount = 0;
  for (const tx of all) {
    const ins = [...new Set(tx.vin.map(v => v.prevout?.scriptpubkey_address).filter(Boolean))];
    if (ins.length >= 2 && ins.length <= MAX_GROUP && coInputs.length < 60) coInputs.push(ins);
    // Wisselgeld: bij precies 2 nieuwe outputs is het wisselgeld vaak het adres van hetzelfde type als de inputs,
    // en/of het bedrag dat níet rond is. Alleen als de signalen niet tegenstrijdig zijn.
    const outsAll = tx.vout.filter(o => o.scriptpubkey_address && !ins.includes(o.scriptpubkey_address));
    if (ins.length && ins.length <= MAX_GROUP && outsAll.length === 2 && tx.vout.length === 2 && changeLinks.length < 60) {
      const inTypes = new Set(tx.vin.map(v => v.prevout?.scriptpubkey_type).filter(Boolean));
      let byType = null;
      if (inTypes.size === 1) { const m = outsAll.filter(o => inTypes.has(o.scriptpubkey_type)); if (m.length === 1) byType = m[0]; }
      const round = o => o.value % 100000 === 0;
      let byRound = null;
      if (outsAll.filter(round).length === 1) byRound = outsAll.find(o => !round(o));
      const pick = byType && byRound ? (byType === byRound ? byType : null) : (byType || byRound);
      if (pick) changeLinks.push([ins[0], pick.scriptpubkey_address]);
    }
    const outs = tx.vout.filter(o => o.scriptpubkey_address).map(o => ({ a: o.scriptpubkey_address, v: o.value / 1e8 }));
    const time = tx.status?.block_time || Math.floor(Date.now() / 1000);
    if (ins.includes(addr)) {
      // uitgaand; outputs terug naar een input-adres behandelen we als wisselgeld
      for (const o of outs) if (!ins.includes(o.a)) transfers.push({ from: addr, to: o.a, value: o.v, asset: sym, time, txid: tx.txid });
      if (outs.length === 2) {
        const total = outs[0].v + outs[1].v;
        if (total > 0 && Math.max(outs[0].v, outs[1].v) / total >= 0.8) peelCount++;
      }
    } else {
      const recv = outs.filter(o => o.a === addr).reduce((s, o) => s + o.v, 0);
      if (recv > 0) for (const i of ins) transfers.push({ from: i, to: addr, value: recv / ins.length, asset: sym, time, txid: tx.txid });
    }
  }
  return { transfers, peelCount, coInputs, changeLinks };
}

async function fetchEvm(chain, addr) {
  const B = API[chain];
  // Interne overboekingen zijn optioneel: bij zeer drukke adressen kan die API traag zijn.
  const internal = Promise.race([getData(`${B}/addresses/${addr}/internal-transactions`, false, 1).catch(() => null), sleep(4000).then(() => null)]);
  const [info, counters, txs, tts, its] = await Promise.all([
    getData(`${B}/addresses/${addr}`, false, 2).catch(() => null),
    getData(`${B}/addresses/${addr}/counters`, false, 2).catch(() => null),
    getData(`${B}/addresses/${addr}/transactions`),
    getData(`${B}/addresses/${addr}/token-transfers?type=ERC-20`),
    internal
  ]);
  const page = parseEvmPage(txs, tts, info);
  page.transfers.push(...parseInternal(its?.items));
  if (its?.next_page_params) page.cursor = { ...(page.cursor || {}), it: its.next_page_params };
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

async function fetchTron(addr, fp, fpTrx, more = false) {
  const [r, acc, nat] = await Promise.all([
    more && !fp ? null : getData(`${API.tron}/v1/accounts/${addr}/transactions/trc20?limit=200${fp ? '&fingerprint=' + encodeURIComponent(fp) : ''}`),
    more ? null : getData(`${API.tron}/v1/accounts/${addr}`, false, 2).catch(() => null),
    more && !fpTrx ? null : fetchTronNative(addr, fpTrx)
  ]);
  const a = acc?.data?.[0];
  let balance = null;
  if (a) {
    const usdt = (a.trc20 || []).map(o => o.TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t).find(Boolean);
    balance = `${fmt((a.balance || 0) / 1e6)} TRX` + (usdt ? ` + ${fmt(Number(usdt) / 1e6)} USDT` : '');
  }
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
  transfers.push(...(nat?.transfers || []));
  const cur = { fp: r?.meta?.fingerprint || null, fpTrx: nat?.fp || null };
  return { transfers, meta: {}, txCount: null, balance, cursor: cur.fp || cur.fpTrx ? cur : null };
}

const despam = d => { for (const t of d.transfers) if (t.value > 1e12) { t.dust = true; t.usd = null; } return d; };

async function fetchAddr(chain, addr, opts = {}) {
  if (demoMode || isDemoAddr(addr)) return demoData(addr);
  const d = isUtxo(chain) ? await fetchBtc(addr, chain, opts.pages || 2) : isBlockscout(chain) ? await fetchEvm(chain, addr)
    : chain === 'avax' ? await fetchRoutescan(chain, addr) : chain === 'zksync' ? await fetchZksync(addr)
    : chain === 'sol' ? await fetchSol(addr, null, { pages: opts.pages >= 4 ? 5 : 2, want: opts.pages >= 4 ? 10 : 4 }) : await fetchTron(addr);
  // Absurde bedragen (bv. 2^256-"transfers" van nep-tokens) als spam behandelen.
  return despam(d);
}

// Volgende pagina transacties van een adres (voor de verkenner).
async function fetchMore(chain, addr, cursor) {
  if (!cursor || demoMode) return null;
  if (isUtxo(chain)) {
    const more = await getData(`${API[chain]}/address/${addr}/txs/chain/${cursor.last}`);
    return despam({ ...parseBtcTxs(addr, more || [], SYM[chain]), meta: {}, cursor: (more || []).length >= 25 ? { last: more[more.length - 1].txid } : null });
  }
  if (chain === 'avax') return despam(await fetchRoutescan(chain, addr, cursor.page));
  if (chain === 'zksync') return despam(await fetchZksync(addr, cursor.page));
  if (chain === 'sol') return despam(await fetchSol(addr, cursor.before));
  if (isEvm(chain)) {
    const B = API[chain];
    const qs = p => Object.entries(p).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v ?? '')}`).join('&');
    const [txs, tts, its] = await Promise.all([
      cursor.tx ? getData(`${B}/addresses/${addr}/transactions?${qs(cursor.tx)}`) : null,
      cursor.tt ? getData(`${B}/addresses/${addr}/token-transfers?type=ERC-20&${qs(cursor.tt)}`) : null,
      cursor.it ? getData(`${B}/addresses/${addr}/internal-transactions?${qs(cursor.it)}`, false, 1).catch(() => null) : null
    ]);
    const page = parseEvmPage(txs, tts, null);
    page.transfers.push(...parseInternal(its?.items));
    if (its?.next_page_params) page.cursor = { ...(page.cursor || {}), it: its.next_page_params };
    return despam(page);
  }
  const d = await fetchTron(addr, cursor.fp, cursor.fpTrx, true);
  return despam(d);
}

// Eén transactie in detail (verkenner).
const txCache = new Map();
async function fetchTx(chain, txid) {
  const ck = chain + ':' + txid;
  if (txCache.has(ck)) return txCache.get(ck);
  let r;
  const known = () => {
    const transfers = [];
    for (const n of [...nodes.values(), ...ghosts.values()]) for (const t of n.data?.transfers || []) {
      if (t.txid === txid && !transfers.some(x => x.from === t.from && x.to === t.to && x.value === t.value)) transfers.push(t);
    }
    return { chain, txid, time: transfers[0]?.time || null, confirmed: true, transfers, partial: true };
  };
  if (demoMode || /^0xdec0de/.test(txid)) return known();
  if (isUtxo(chain)) {
    const tx = await getData(`${API[chain]}/tx/${txid}`);
    if (!tx) return known();
    const S = SYM[chain];
    r = {
      chain, txid, time: tx.status?.block_time || null, confirmed: !!tx.status?.confirmed, fee: `${fmt(tx.fee / 1e8)} ${S}`,
      inputs: tx.vin.map(v => ({ addr: v.prevout?.scriptpubkey_address || (v.is_coinbase ? 'coinbase (nieuw gemunt)' : '?'), value: (v.prevout?.value || 0) / 1e8, asset: S, noLink: !v.prevout?.scriptpubkey_address })),
      outputs: tx.vout.map(o => ({ addr: o.scriptpubkey_address || (o.scriptpubkey_type === 'op_return' ? 'OP_RETURN (data)' : o.scriptpubkey_type), value: o.value / 1e8, asset: S, noLink: !o.scriptpubkey_address }))
    };
  } else if (chain === 'sol') {
    const res = await getData(API.sol, false, 6, solRpc('getTransaction', [txid, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }]));
    const tx = res?.result;
    if (!tx) return known();
    r = { chain, txid, time: tx.blockTime || null, confirmed: true, failed: !!tx.meta?.err, fee: `${fmt((tx.meta?.fee || 0) / 1e9)} SOL`, transfers: solTransfers(tx, txid) };
  } else if (chain === 'zksync') {
    const [tx, tr] = await Promise.all([getData(`${API.zksync}/transactions/${txid}`), getData(`${API.zksync}/transactions/${txid}/transfers?limit=100`)]);
    if (!tx) return known();
    r = {
      chain, txid, time: tx.receivedAt ? Date.parse(tx.receivedAt) / 1000 : null, confirmed: tx.status !== 'failed', failed: tx.status === 'failed',
      from: tx.from?.toLowerCase(), to: tx.to?.toLowerCase(), transfers: (tr?.items || []).map(zkTransfer).filter(Boolean)
    };
  } else if (chain === 'avax') {
    return known();
  } else if (isEvm(chain)) {
    const tx = await getData(`${API[chain]}/transactions/${txid}`);
    if (!tx) return known();
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
    return known(); // niet cachen: kan aanvullen naarmate meer adressen geladen zijn
  }
  txCache.set(ck, r);
  return r;
}

// ---------- extra ketens: Avalanche (Routescan), zkSync Era, Solana ----------
const rsArr = r => Array.isArray(r?.result) ? r.result : [];
const AVAX_STABLES = { '0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e': 'USDC', '0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7': 'USDT', '0xa7d7079b0fead91f3e65f86e8915cb59c1a4c664': 'USDC.e', '0xc7198437980c041c805a1edcba50c1ce5db95118': 'USDT.e' };
const STABLE_RE = /^(USDT|USDC|USDC\.e|USDT\.e|USDt|DAI|TUSD|BUSD)$/i;

async function fetchRoutescan(chain, addr, page = 1) {
  const B = API[chain];
  const q = action => `${B}?module=account&action=${action}&address=${addr}&page=${page}&offset=100&sort=desc`;
  const [txs, tts, bal, its] = await Promise.all([
    getData(q('txlist')), getData(q('tokentx')),
    page === 1 ? getData(`${B}?module=account&action=balance&address=${addr}`, false, 2).catch(() => null) : null,
    getData(q('txlistinternal'), false, 2).catch(() => null)
  ]);
  const transfers = [];
  for (const t of rsArr(its)) {
    const v = Number(t.value) / 1e18;
    if (!(v > 0) || t.isError === '1' || !t.to) continue;
    transfers.push({ from: t.from.toLowerCase(), to: t.to.toLowerCase(), value: v, asset: SYM[chain], time: Number(t.timeStamp), txid: t.hash, internal: true });
  }
  for (const t of rsArr(txs)) {
    const v = Number(t.value) / 1e18;
    if (!(v > 0) || t.isError === '1' || !t.to) continue;
    transfers.push({ from: t.from.toLowerCase(), to: t.to.toLowerCase(), value: v, asset: SYM[chain], time: Number(t.timeStamp), txid: t.hash });
  }
  for (const t of rsArr(tts)) {
    const v = Number(t.value) / 10 ** Number(t.tokenDecimal || 18);
    const sym = t.tokenSymbol || '?';
    const real = AVAX_STABLES[(t.contractAddress || '').toLowerCase()];
    transfers.push({
      from: t.from.toLowerCase(), to: t.to.toLowerCase(), value: v, asset: real || sym, time: Number(t.timeStamp), txid: t.hash,
      usd: real ? v : null, dust: v === 0 || (!real && STABLE_RE.test(sym))
    });
  }
  const full = rsArr(txs).length >= 100 || rsArr(tts).length >= 100 || rsArr(its).length >= 100;
  return {
    transfers, meta: {}, txCount: null, cursor: full ? { page: page + 1 } : null,
    balance: bal?.result != null && /^\d+$/.test(bal.result) ? `${fmt(Number(bal.result) / 1e18)} ${SYM[chain]}` : null
  };
}

function zkTransfer(t) {
  if (!t || t.type === 'fee' || !t.from || !t.to) return null;
  const tok = t.token || {};
  const v = Number(t.amount || 0) / 10 ** Number(tok.decimals ?? 18);
  const sym = tok.symbol || '?';
  const priced = tok.usdPrice && (tok.liquidity || 0) > 100000;
  return {
    from: t.from.toLowerCase(), to: t.to.toLowerCase(), value: v, asset: sym.length > 12 ? sym.slice(0, 12) + '…' : sym,
    time: Date.parse(t.timestamp) / 1000, txid: t.transactionHash, usd: priced ? v * tok.usdPrice : null,
    dust: v === 0 || (!priced && (STABLE_RE.test(sym) || /claim|visit|reward|\.(site|com|io|xyz)/i.test(sym)))
  };
}
async function fetchZksync(addr, page = 1) {
  const B = API.zksync;
  const [tr, info] = await Promise.all([
    getData(`${B}/address/${addr}/transfers?limit=100&page=${page}`),
    page === 1 ? getData(`${B}/address/${addr}`, false, 2).catch(() => null) : null
  ]);
  const transfers = (tr?.items || []).map(zkTransfer).filter(Boolean);
  const eth = info?.balances && Object.values(info.balances).find(b => b.token?.symbol === 'ETH');
  return {
    transfers, meta: {}, txCount: tr?.meta?.totalItems || null,
    cursor: tr?.meta && tr.meta.currentPage < tr.meta.totalPages ? { page: page + 1 } : null,
    balance: eth ? `${fmt(Number(eth.balance) / 1e18)} ETH` : null
  };
}

// Solana: handtekeningen per adres, daarna de transacties in één batch-verzoek.
const SOL_MINTS = { EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: 'USDC', Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB: 'USDT', So11111111111111111111111111111111111111112: 'wSOL' };
const solRpc = (method, params) => ({ jsonrpc: '2.0', id: 1, method, params });
function solTransfers(tx, sig) {
  if (!tx) return [];
  const keys = tx.transaction.message.accountKeys.map(k => k.pubkey || k);
  const tok = {};
  for (const b of [...(tx.meta?.preTokenBalances || []), ...(tx.meta?.postTokenBalances || [])]) {
    tok[keys[b.accountIndex]] = { owner: b.owner, mint: b.mint, dec: b.uiTokenAmount?.decimals ?? 0 };
  }
  const ins = [...tx.transaction.message.instructions, ...(tx.meta?.innerInstructions || []).flatMap(i => i.instructions)];
  const out = [];
  const time = tx.blockTime || Math.floor(Date.now() / 1000);
  for (const i of ins) {
    const p = i.parsed, info = p?.info;
    if (!info) continue;
    if (i.program === 'system' && (p.type === 'transfer' || p.type === 'transferWithSeed') && info.lamports > 0) {
      out.push({ from: info.source, to: info.destination, value: info.lamports / 1e9, asset: 'SOL', time, txid: sig });
    } else if ((i.program === 'spl-token' || i.program === 'spl-token-2022') && (p.type === 'transfer' || p.type === 'transferChecked')) {
      const src = tok[info.source], dst = tok[info.destination];
      const mint = info.mint || src?.mint || dst?.mint;
      const dec = info.tokenAmount?.decimals ?? src?.dec ?? dst?.dec ?? 0;
      const v = info.tokenAmount ? Number(info.tokenAmount.uiAmount || 0) : Number(info.amount || 0) / 10 ** dec;
      const sym = SOL_MINTS[mint] || (mint ? mint.slice(0, 4) + '…' : '?');
      const real = sym === 'USDC' || sym === 'USDT';
      out.push({
        from: src?.owner || info.authority || info.multisigAuthority || info.source, to: dst?.owner || info.destination,
        value: v, asset: sym, time, txid: sig, usd: real ? v : null, dust: v === 0
      });
    }
  }
  return out.filter(t => t.from && t.to && t.from !== t.to);
}
async function fetchSolPage(addr, before) {
  const B = API.sol;
  const opts = { limit: solLimit() };
  if (before) opts.before = before;
  const [sigRes, balRes] = await Promise.all([
    getData(B, false, 6, solRpc('getSignaturesForAddress', [addr, opts])),
    before ? null : getData(B, false, 2, solRpc('getBalance', [addr])).catch(() => null)
  ]);
  const sigs = (sigRes?.result || []).filter(s => !s.err);
  let txs = [];
  if (sigs.length) {
    // De gratis RPC staat geen batches met getTransaction toe: één voor één (getempo via HOST_GAP).
    // Via de app: recente transacties bij de snelle openbare server, oudere bij de officiële server (beide tegelijk).
    const recent = Date.now() / 1000 - 28 * 3600;
    const urlFor = x => solViaApp() && x.blockTime > recent ? SOL_DEFAULT + '/' : B;
    txs = await Promise.all(sigs.map(x => getData(urlFor(x), false, 4, solRpc('getTransaction', [x.signature, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }]))
      .then(r => r?.result || (urlFor(x) !== B ? getData(B, false, 4, solRpc('getTransaction', [x.signature, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }])).then(r2 => r2?.result || null) : null))
      .catch(() => null)));
  }
  if (sigs.length && txs.every(t => !t)) throw new Error('de Solana-server gaf geen transacties terug');
  const transfers = [];
  sigs.forEach((s, i) => { for (const t of solTransfers(txs[i], s.signature)) if (t.from === addr || t.to === addr) transfers.push(t); });
  const all = sigRes?.result || [];
  return {
    transfers, meta: {}, txCount: null,
    cursor: all.length >= Math.min(10, solLimit()) ? { before: all[all.length - 1].signature } : null,
    balance: balRes?.result?.value != null ? `${fmt(balRes.result.value / 1e9)} SOL` : null,
    scanned: all.length
  };
}
// Solana: doorzoeken (meerdere pagina's) tot er genoeg echte overboekingen zijn.
// Veel adressen hebben vooral swaps, NFT-acties of spam; in de recentste 20 zit dan soms geen enkele overboeking.
async function fetchSol(addr, before, { pages = 1, want = 8 } = {}) {
  const out = await fetchSolPage(addr, before);
  let p = 1;
  const real = () => out.transfers.filter(t => !t.dust).length;
  while (out.cursor && p < pages && real() < want && !abortCtl.signal.aborted) {
    const more = await fetchSolPage(addr, out.cursor.before).catch(() => null);
    if (!more) break;
    out.transfers.push(...more.transfers);
    out.scanned += more.scanned;
    out.cursor = more.cursor;
    p++;
  }
  return out;
}
// Is dit een token-rekening (bijv. USDT-rekening) in plaats van een wallet? Dan de eigenaar teruggeven.
async function solOwnerOf(addr) {
  try {
    const r = await getData(API.sol, false, 2, solRpc('getAccountInfo', [addr, { encoding: 'jsonParsed' }]));
    const d = r?.result?.value?.data;
    if (d?.program === 'spl-token' && d.parsed?.type === 'account' && d.parsed.info?.owner) return { owner: d.parsed.info.owner, mint: d.parsed.info.mint };
  } catch { /* gewoon het adres zelf gebruiken */ }
  return null;
}

// Welke EVM-keten? Een 0x-adres kan op meerdere ketens bestaan: tel snel de activiteit per keten.
async function probeEvm(addr) {
  // Blockscout telt zeer drukke adressen niet (geeft 0): dan kijken of er transacties zijn.
  const bsCount = async c => {
    const k = await getData(`${API[c]}/addresses/${addr}/counters`, false, 2).catch(() => null);
    const n = Number(k?.transactions_count || 0) + Number(k?.token_transfers_count || 0);
    if (n) return n;
    const t = await getData(`${API[c]}/addresses/${addr}/transactions`, false, 2).catch(() => null);
    return t?.items?.length ? -1 : 0;
  };
  const probes = {
    eth: () => bsCount('eth'),
    op: () => bsCount('op'),
    avax: () => getData(`${API.avax}?module=account&action=txlist&address=${addr}&page=1&offset=1`, false, 2).then(r => rsArr(r).length ? -1 : 0),
    zksync: () => getData(`${API.zksync}/address/${addr}/transfers?limit=1`, false, 2).then(r => Number(r?.meta?.totalItems || 0))
  };
  const out = {};
  await Promise.all(Object.entries(probes).map(async ([c, f]) => { try { out[c] = await f(); } catch { out[c] = 0; } }));
  return Object.keys(probes).filter(c => out[c]).map(chain => ({ chain, count: out[chain] }));
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
  if (teamLabels[n.key]) return teamLabels[n.key];
  const known = window.KNOWN_LABELS[n.addr] || window.KNOWN_LABELS[Object.keys(window.KNOWN_LABELS).find(k => k.toLowerCase() === n.addr) || ''];
  if (known) return known.name;
  const m = metaStore[n.key];
  if (m?.tags?.length) return m.tags[0];
  const db = dbLookup(n);
  const dl = db?.labels.find(l => l.category === 'user') || db?.labels.find(l => !['sanction', 'frozen', 'label'].includes(l.category)) || db?.labels.find(l => l.category === 'label');
  if (dl) return dl.label;
  if (m?.ens) return m.ens;
  if (m?.name) return m.name;
  if (n.depositOf) { const ex = nodes.get(n.depositOf) || ghosts.get(n.depositOf); const nm = ex && exName(labelOf(ex)); if (nm) return `Stortingsadres bij ${nm}`; }
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
  const text = [customLabels[n.key], teamLabels[n.key], known?.name, ...(m?.tags || []), m?.name].filter(Boolean).join(' ');
  if (m?.scam) addFlag(n, 'scamlist', 'high', 'Door Blockscout als scam gemarkeerd');
  if (m?.reputation) addFlag(n, 'reputation', 'med', `Reputatie: ${m.reputation}`);
  if (MIXER_RE.test(text)) addFlag(n, 'mixer', 'high', 'Mixer / privacy-dienst');
  else if (BAD_RE.test(text)) addFlag(n, 'badtag', 'high', 'Publiek label wijst op fraude/hack');
  // Bridges en decentrale exchanges (DEX) hebben geen klantgegevens: niet als exchange tellen.
  const notCex = BRIDGE_RE.test(text) || /decentrali[sz]ed|\bdex\b|swap|router|aggregator|settler/i.test(text);
  if (known?.type === 'exchange' || (EXCHANGE_RE.test(text) && !notCex)) addFlag(n, 'exchange', 'info', 'Exchange — cash-out-punt, bevriezing/informatieverzoek mogelijk');
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
  if (asPerp) addFlag(n, 'seenbefore', 'high', `Eerder als dader/verdacht gezien in zaak ${short(asPerp.caseSeed)} (${new Date(asPerp.seen).toLocaleDateString(window.CT_LOCALE)})`);
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

const timeOrderOn = () => current?.opts?.timeOrder !== false;
const isEndpoint = n => n.flags.some(f => ['exchange', 'service', 'mixer', 'sanction', 'contract', 'bridge'].includes(f.code));

function fingerprint(chain, a) {
  const s = isEvm(chain) ? a.toLowerCase().slice(2) : chain === 'tron' ? a.slice(1) : a.replace(/^(bc1|ltc1)/, '');
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
    n.data = await fetchAddr(n.chain, n.addr, { pages: n.seed ? 4 : 2 });
    n.data.fetchedAt = Date.now();
    n.data.source = demoMode || isDemoAddr(n.addr) ? 'voorbeeldgegevens' : sourceOf(n.chain);
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
  // Startadres: altijd beide kanten tonen (wie stuurde geld, wie ontving het); verder volgen gebeurt alleen uitgaand.
  if (depth === 0) dir = 'both';
  const agg = new Map();
  for (const t of n.data.transfers) {
    let d, cp;
    if (t.from === n.addr && t.to !== n.addr) { d = 'out'; cp = t.to; }
    else if (t.to === n.addr && t.from !== n.addr) { d = 'in'; cp = t.from; }
    else continue;
    if (dir !== 'both' && d !== dir) continue;
    // Alleen geld volgen dat vertrok nadat het geld hier binnenkwam (10 min. speling voor bloktijden).
    if (d === 'out' && timeOrderOn() && n.minTime && t.time < n.minTime - 600) continue;
    const k = d + '|' + cp;
    const a = agg.get(k) || { d, cp, rank: 0, count: 0, dustOnly: true, list: [] };
    a.rank += t.usd ?? (isUtxo(n.chain) ? t.value : 0);
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
    if (a.d === 'out') {
      const tm = Math.min(...a.list.filter(t => !t.dust).map(t => t.time || Infinity));
      if (isFinite(tm)) cn.minTime = cn.minTime ? Math.min(cn.minTime, tm) : tm;
    }
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
  await crossFollow(n, depth, next);
  scheduleRender();
  return next;
}

async function runTrace(addr, chain, role, pattern, opts) {
  abortCtl.abort();
  abortCtl = new AbortController();
  stopped = false;
  resetGraph();
  demoMode = norm(chain, addr) === DEMO.victim || norm(chain, addr) === DEMO.scammer;
  $('#formBox').open = false;
  let tokenNote = '';
  if (chain === 'sol') {
    nativeSol = !!window.AndroidBridge?.solRpc; nativeSolErr = '';
    setStatus('Solana-adres controleren…');
    const o = await solOwnerOf(addr);
    if (o) { tokenNote = `Ingevoerd adres is een ${SOL_MINTS[o.mint] || 'token'}-rekening; onderzocht is de wallet van de eigenaar (${short(o.owner)}). `; addr = o.owner; }
  }
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
  let hop = 0;
  const steps = opts.depth + 1;
  while (level.length && !stopped) {
    setProgress(hop, steps, `Stap ${hop + 1} van ${steps}: geld volgen`);
    const results = await Promise.all(level.map(x => expand(x.n, x.depth, x.dir)));
    level = results.flat().filter(x => !x.n.expanded);
    hop++;
  }
  // Automatisch de herkomst van het geld zoeken: startwallets en exchange-instroom.
  setProgress(steps - 1, steps, `Stap ${steps} van ${steps}: herkomst zoeken`);
  if (!stopped) await traceOrigins(seed, { depth: role === 'perp' ? Math.max(3, opts.depth) : 2, fanIn: Math.max(4, opts.fanout) });
  setProgress(null);
  setBusy(false);
  render(true);
  renderPlaybook();
  renderSummary();
  if (!stopped) recordObservations();
  const seedErr = !stopped && nodes.get(current?.seedKey)?.flags.find(f => f.code === 'error');
  if (seedErr && edges.size === 0) setStatus(`${seedErr.text}. Controleer de internetverbinding (of de Solana-server/TronGrid-sleutel onder Instellingen) en probeer het opnieuw.`, true);
  else if (!stopped && edges.size === 0 && chain === 'sol' && nativeSolErr && window.AndroidBridge?.solRpc) setStatus(tokenNote + `De officiële Solana-server (volledige geschiedenis) was niet bereikbaar: ${nativeSolErr}. Probeer het opnieuw, bij voorkeur via wifi.`, true);
  else if (!stopped && edges.size === 0 && chain === 'sol' && seed.data && !seed.data.scanned && !solViaApp() && API.sol === SOL_DEFAULT) setStatus(tokenNote + 'Geen transacties gevonden. De gratis openbare Solana-server kent alleen de laatste ±1,5 dag. Gebruik de Android-app (volledige geschiedenis) of vul onder Instellingen een eigen Solana-server in (bijv. gratis bij Helius).', true);
  else if (!stopped && edges.size === 0 && chain === 'sol' && seed.data) setStatus(tokenNote + `${seed.data.scanned || 0} recente transacties bekeken, maar geen overboekingen van SOL, USDC of USDT gevonden (bijvoorbeeld alleen swaps, NFT's of spam). Open het adres in de verkenner en tik op "Oudere transacties laden".`);
  else setStatus(stopped ? 'Gestopt.' : tokenNote + `Klaar: ${nodes.size} adressen, ${edges.size} geldstromen. Tik op een adres voor details.`);
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
    // Herkomst: alleen geld dat binnenkwam vóórdat dit adres doorstuurde naar de volgende stap.
    if (timeOrderOn() && n.maxTime && t.time > n.maxTime + 600) continue;
    // Alleen geld met waarde volgen: onbekende tokens zonder koers zijn meestal spam/airdrops.
    if (!isUtxo(n.chain) && t.usd == null) continue;
    const a = agg.get(t.from) || { cp: t.from, rank: 0, list: [] };
    a.rank += t.usd ?? (isUtxo(n.chain) ? t.value : 0);
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
    { const tm = Math.max(...a.list.map(t => t.time || 0)); if (tm) cn.maxTime = Math.max(cn.maxTime || 0, tm); }
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
  return { btc: `https://mempool.space/tx/${id}`, eth: `https://etherscan.io/tx/${id}`, op: `https://optimistic.etherscan.io/tx/${id}`, tron: `https://tronscan.org/#/transaction/${id}`,
    ltc: `https://litecoinspace.org/tx/${id}`, avax: `https://snowtrace.io/tx/${id}`, zksync: `https://explorer.zksync.io/tx/${id}`, sol: `https://solscan.io/tx/${id}` }[chain];
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
  const badC = n.flags.filter(f => ['sanction', 'scamlist', 'mixer', 'badtag', 'ransomware', 'frozen', 'darknet'].includes(f.code)).map(f => f.code);
  if (badC.length && !(badC.every(c => c === 'frozen') && n.flags.some(f => f.code === 'exchange'))) return 'sanction';
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
      width: 'data(size)', height: 'data(size)', 'border-width': 2, 'border-color': t.bg, 'text-max-width': 170, 'min-zoomed-font-size': 6
    } },
    { selector: 'node[?wallet]', style: {
      'background-color': '#4ea1ff', 'background-opacity': 0.07, 'border-style': 'dashed', 'border-width': 2, 'border-color': '#4ea1ff',
      shape: 'round-rectangle', label: 'data(label)', 'text-valign': 'top', 'text-halign': 'center', 'text-margin-y': -4, 'font-size': 10, color: t.muted, padding: 14
    } },
    { selector: 'node', style: { 'font-size': isMobile() ? 13 : 10, 'text-max-width': isMobile() ? 140 : 170 } },
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
    { selector: 'edge.cross', style: { 'line-style': 'dashed', 'line-color': '#b06cff', 'target-arrow-color': '#b06cff', width: 3 } },
    { selector: 'edge.swap', style: { 'line-color': '#20c997', 'target-arrow-color': '#20c997' } },
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
  updateProgress();
  detectDeposits();
  $('#empty').hidden = nodes.size > 0;
  const maxUsd = Math.max(1, ...[...edges.values()].map(e => e.usd || Object.values(e.assets)[0] || 0));
  cy.batch(() => {
    for (const n of nodes.values()) {
      const cls = nodeClass(n);
      const label = labelOf(n);
      const data = {
        id: n.key, label: (notes.nodes[n.key] ? '✎ ' : '') + (label ? `${label}\n${short(n.addr)}` : short(n.addr)), color: COLORS[cls],
        size: (n.seed ? 44 : isEndpoint(n) ? 34 : 26) * (isMobile() ? 1.45 : 1), seed: !!n.seed, flagged: n.flags.some(f => f.level === 'high'), noted: !!notes.nodes[n.key]
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
      cy.getElementById(e.key).toggleClass('cross', !!e.cross).toggleClass('swap', !!e.swap);
    }
    cy.nodes().forEach(el => { if (!nodes.has(el.id()) && !el.data('wallet')) el.remove(); });
    syncWalletGroups();
  });
  runLayout(final);
  renderFindings();
  $('#btnExportPng').disabled = $('#btnExportJson').disabled = $('#btnPdf').disabled = nodes.size === 0;
  $('#findingsBox').hidden = nodes.size === 0;
  renderOrigins();
  if (current) renderRoutes();
  renderTimeline();
}

let graphStale = false;
const PHONE_MIN_ZOOM = 0.7;
// Inzoomen op de geldroute (startadres + routes); op de telefoon met een minimale zoom.
function fitRoute() {
  if (!cy || !cy.nodes().length) return;
  const keys = new Set([current?.seedKey]);
  for (const r of moneyRoutes(5).routes) for (const e of r.steps) { keys.add(e.source); keys.add(e.target); }
  const els = cy.nodes().filter(n => keys.has(n.id()));
  cy.fit(els.length > 1 ? els : cy.nodes(), 30);
  if (isMobile() && cy.zoom() < PHONE_MIN_ZOOM) {
    const seed = cy.getElementById(current?.seedKey);
    cy.zoom({ level: PHONE_MIN_ZOOM, position: seed.nonempty() ? seed.position() : els.boundingBox ? { x: els.boundingBox().x1 + els.boundingBox().w / 2, y: els.boundingBox().y1 + els.boundingBox().h / 2 } : undefined });
    if (seed.nonempty()) cy.center(seed);
  }
}
function runLayout(fit) {
  if (!cy || cy.nodes().length === 0) return;
  // Web niet zichtbaar (telefoon, andere tab): later schikken als het weer in beeld komt.
  if (!document.getElementById('cy').offsetWidth) { graphStale = true; return; }
  const opts = layoutName === 'flow'
    ? { name: 'breadthfirst', directed: true, roots: current ? [current.seedKey] : undefined, spacingFactor: 1.2, animate: false }
    : { name: 'cose', animate: false, randomize: !!fit, nodeRepulsion: () => 14000, idealEdgeLength: () => 130, gravity: 0.3, numIter: 800, nodeDimensionsIncludeLabels: true };
  // Wallet-groepen tijdelijk losmaken: de lay-out rekent slecht met groepen. Daarna de leden compact
  // rond hun middelpunt leggen en de groep weer vormen.
  const kids = cy.nodes().filter(n => !!n.data('parent'));
  const parentOf = new Map(kids.map(n => [n.id(), n.data('parent')]));
  kids.move({ parent: null });
  const walletEls = cy.nodes('[?wallet]');
  cy.elements().not(walletEls).layout({ ...opts, fit: false, padding: 40 }).run();
  const byWallet = new Map();
  for (const [id, w] of parentOf) { if (!byWallet.has(w)) byWallet.set(w, []); byWallet.get(w).push(cy.getElementById(id)); }
  for (const [w, els] of byWallet) {
    const cx = els.reduce((s, e) => s + e.position('x'), 0) / els.length, cyy = els.reduce((s, e) => s + e.position('y'), 0) / els.length;
    const r = 22 + 9 * els.length;
    els.forEach((e, i) => { const a = (2 * Math.PI * i) / els.length; e.position({ x: cx + r * Math.cos(a), y: cyy + r * Math.sin(a) }); });
    if (cy.getElementById(w).nonempty()) els.forEach(e => e.move({ parent: w }));
  }
  cy.fit(undefined, 40);
  // Bij heel weinig adressen niet extreem inzoomen.
  if (cy.zoom() > 1.4) { cy.zoom(1.4); cy.center(); }
  // Telefoon: nooit zo ver uitzoomen dat adressen te klein worden om aan te tikken; dan liever de route tonen.
  if (isMobile() && cy.zoom() < PHONE_MIN_ZOOM) fitRoute();
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
  const exch = [...nodes.values()].filter(n => endKind(n) === 'exchange');
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
    tron: [['Tronscan', `https://tronscan.org/#/address/${a}`]],
    ltc: [['litecoinspace', `https://litecoinspace.org/address/${a}`], ['Blockchair', `https://blockchair.com/litecoin/address/${a}`]],
    avax: [['Snowtrace', `https://snowtrace.io/address/${a}`]],
    zksync: [['zkSync explorer', `https://explorer.zksync.io/address/${a}`]],
    sol: [['Solscan', `https://solscan.io/account/${a}`], ['Solana Explorer', `https://explorer.solana.com/address/${a}`]]
  }[n.chain] || [];
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
    ${obs.length ? `<div class="small" style="margin-top:6px">Eerder gezien in: ${obs.map(o => `${esc(short(o.caseSeed))} (${esc(o.role || o.classification || '?')}, ${new Date(o.seen).toLocaleDateString(window.CT_LOCALE)})`).join(', ')}</div>` : ''}`;
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
    // In de Android-app regelt de terugknop zelf de navigatie (ChainTraceBack); in de browser via de geschiedenis.
    if (!IN_APP) try { history.pushState({ ctv: nav.i }, ''); } catch { /* file:// */ }
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

const IN_APP = !!window.AndroidBridge;
let skipPop = false;
function goBack() {
  if (nav.i <= 0) { closeExplorer(); return; }
  if (!IN_APP && history.state?.ctv === nav.i) history.back();
  else { nav.i--; renderView(); }
}
function closeExplorer() {
  const st = history.state?.ctv;
  // Meteen sluiten; de geschiedenis wordt daarna opgeruimd zonder dat die "pop" iets nieuws dichtdoet.
  hideDetail();
  if (!IN_APP && st != null) { skipPop = true; history.go(-(st + 1)); }
}
// Android-terugknop: eerst wat open staat sluiten, dan pas de app.
window.ChainTraceBack = () => {
  const dlg = document.querySelector('dialog[open]');
  if (dlg) { dlg.close(); return true; }
  if (tour.on) { stopTour(); return true; }
  if ($('#moreMenu').open) { $('#moreMenu').open = false; return true; }
  if ($('#peek') && !$('#peek').hidden) { hidePeek(); return true; }
  if (nav.i > 0) { nav.i--; renderView(); return true; }
  if (nav.i === 0) { hideDetail(); return true; }
  if (isMobile() && document.body.dataset.tab !== 'form') { setTab('form'); return true; }
  return false;
};
function hideDetail() {
  $('#detail').hidden = true;
  nav.stack = []; nav.i = -1;
  if (document.body.dataset.tab === 'detail') setTab(nodes.size ? 'graph' : 'form');
}
window.addEventListener('popstate', ev => {
  if (skipPop) { skipPop = false; return; }
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
  // Koersen in euro bijladen voor dit adres of deze transactie (één keer per munt/periode).
  { const v0 = curView(); const n0 = v0?.type === 'addr' ? (nodes.get(keyOf(v0.chain, v0.addr)) || ghosts.get(keyOf(v0.chain, v0.addr))) : null;
    if (n0?.data) ensurePrices(n0.data.transfers).then(ch => { if (ch && curView() === v0) renderView(); }); }
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
  const real = d ? valuedOrAll(d.transfers) : [];
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
    <div class="tags"><span class="tag">${CHAIN_NAME[n.chain]}</span><button type="button" class="tag help" data-help="${cls}">${ROLE_TXT[cls]} <i>?</i></button>${n.ghost ? '<span class="tag">Niet in het web</span>' : ''}
      ${n.flags.filter(f => f.code !== 'error').map(f => HELP[f.code] ? `<button type="button" class="tag help ${f.level}" data-help="${f.code}">${esc(f.text)} <i>?</i></button>` : `<span class="tag ${f.level}">${esc(f.text)}</span>`).join('')}</div>
    ${clusterHtml(n)}
    ${(() => { const st = plainStory(n); return st.length ? `<div class="story" data-speak-box><div class="story-h"><b>In gewone taal</b>${speakBtn('self')}</div>${st.map(x => `<p>${esc(x)}</p>`).join('')}</div>` : ''; })()}
    <div class="xstats">
      <div><span>Saldo</span><b>${esc(d?.balance || '—')}</b></div>
      <div><span>Transacties</span><b>${d?.txCount ? fmt(d.txCount) : d ? fmt(d.transfers.length) + (d.cursor ? '+' : '') : '…'}</b></div>
      <div><span>Ontvangen*</span><b class="in">${d ? esc(assetText(sumAssets(ins))) : '…'}</b></div>
      <div><span>Verzonden*</span><b class="out">${d ? esc(assetText(sumAssets(outs))) : '…'}</b></div>
      <div class="wide"><span>Actief (geladen)</span><b>${times.length ? `${fmtTime(Math.min(...times))} – ${fmtTime(Math.max(...times))}` : '—'}</b></div>
    </div>
    <div class="xactions">
      ${n.ghost ? '<button type="button" class="primary" data-act="add">+ Toevoegen aan web</button>' : '<button type="button" class="primary" data-act="show">Toon in web</button>'}
      ${endKind(n) === 'exchange' && !n.ghost ? `<button type="button" class="primary letter" data-letter="${esc(n.key)}">✉ Brief aan ${esc(exName(labelOf(n)) || 'deze exchange')}</button>` : ''}
      <button type="button" class="ghost" data-act="expand">Waar ging het geld heen?</button>
      <button type="button" class="ghost" data-act="origins">Waar kwam het vandaan?</button>
      <button type="button" class="ghost ${isWatched(n) ? 'watching' : ''}" data-act="watch">${isWatched(n) ? '🔕 Niet meer volgen' : '🔔 Volg dit adres'}</button>
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
  const noValue = list.filter(t => !hasValue(t)).length;
  const valueOnly = v.valueOnly !== false && noValue < list.length;
  if (valueOnly) list = list.filter(hasValue);
  if (v.filter === 'in') list = list.filter(t => t.to === own);
  if (v.filter === 'out') list = list.filter(t => t.from === own);
  list.sort((a, b) => (b.time || 0) - (a.time || 0));
  const shown = list.slice(0, v.limit);
  const rows = shown.map(t => {
    const dir = t.from === own ? 'out' : 'in';
    const cp = dir === 'out' ? t.to : t.from;
    return `<div class="xrow ${dir}${t.dust ? ' dust' : ''}">
      <div class="xrow-top"><span class="dir ${dir}">${dir === 'out' ? '↑ Uit' : '↓ In'}</span>${addrChip(n.chain, cp)}</div>
      <div class="xrow-sub"><b>${fmt(t.value)} ${esc(t.asset)}</b>${eurOf(t) ? ` <span class="muted">≈ ${fmtEur(eurOf(t))}</span>` : t.usd ? ` <span class="muted">≈ $${fmt(t.usd)}</span>` : ''}${t.dust ? ' <span class="tag med">spam/nul</span>' : ''}
        <span class="muted">· ${fmtTime(t.time)} ·</span> ${txChip(t.txid)}</div>
    </div>`;
  }).join('');
  const more = list.length > shown.length
    ? `<button type="button" class="ghost wide" data-more="show">Toon meer (${list.length - shown.length})</button>`
    : d.cursor ? `<button type="button" class="ghost wide" data-more="fetch" ${n.loadingMore ? 'disabled' : ''}>${n.loadingMore ? 'Laden…' : 'Oudere transacties laden'}</button>` : '';
  return `<div class="xfilter">
      ${[['all', 'Alles'], ['in', '↓ In'], ['out', '↑ Uit']].map(([k, t]) => `<button type="button" class="chip ${v.filter === k ? 'active' : ''}" data-filter="${k}">${t}</button>`).join('')}
      ${noValue && noValue < (dustCount + list.length + noValue) ? `<button type="button" class="chip ${valueOnly ? '' : 'active'}" data-filter="novalue">Tokens zonder koers (${noValue})</button>` : ''}
      ${dustCount ? `<button type="button" class="chip ${v.showDust ? 'active' : ''}" data-filter="dust">Spam (${dustCount})</button>` : ''}
    </div>
    ${rows || '<p class="muted">Geen transacties in deze selectie.</p>'}
    ${more}
    <p class="hint">* Op basis van de geladen transacties. Tik op een adres of transactie om erheen te gaan.</p>`;
}

function cpListHtml(n, v) {
  const own = n.addr;
  const agg = new Map();
  for (const t of valuedOrAll(n.data.transfers)) {
    if (t.from === t.to) continue;
    const dir = t.from === own ? 'out' : t.to === own ? 'in' : null;
    if (!dir) continue;
    const cp = dir === 'out' ? t.to : t.from;
    const a = agg.get(cp) || { cp, in: [], out: [], usd: 0, last: 0 };
    a[dir].push(t);
    a.usd += t.usd || (isUtxo(n.chain) ? t.value * 1e4 : 0);
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
    ${endKind(n) === 'exchange' ? contactHtml(exContact(n)) : ''}
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
  const ext = `<div class="links"><a href="${esc(txUrl(r.chain, r.txid))}" target="_blank" rel="noopener noreferrer">Bekijk op ${({ btc: 'mempool.space', ltc: 'litecoinspace', tron: 'Tronscan', avax: 'Snowtrace', zksync: 'zkSync explorer', sol: 'Solscan', op: 'OP Etherscan' })[r.chain] || 'Etherscan'}</a></div>`;
  let body = '';
  if (isUtxo(r.chain) && r.inputs) {
    const io = (list, title) => `<h4>${title} <span class="badge">${list.length}</span></h4>
      ${list.map(x => `<div class="xrow"><div class="xrow-top">${addrChip(r.chain, x.addr, { noLink: x.noLink })}<b class="amt">${fmt(x.value)} ${SYM[r.chain]}</b></div></div>`).join('')}`;
    body = `<div class="xio"><div>${io(r.inputs, 'Van (inputs)')}</div><div>${io(r.outputs, 'Naar (outputs)')}</div></div>`;
  } else {
    body = `${r.from ? `<h4>Afzender → ontvanger</h4><div class="xrow"><div class="xrow-top">${addrChip(r.chain, r.from)}</div><div class="xrow-top">→ ${addrChip(r.chain, r.to)}</div></div>` : ''}
      <h4>Overboekingen <span class="badge">${r.transfers.length}</span></h4>
      ${r.transfers.map(t => `<div class="xrow"><div class="xrow-top">${addrChip(r.chain, t.from)}</div><div class="xrow-top">→ ${addrChip(r.chain, t.to)}</div><div class="xrow-sub"><b>${fmt(t.value)} ${esc(t.asset)}</b></div></div>`).join('') || '<p class="muted">Geen waarde-overboekingen.</p>'}
      ${r.partial ? '<p class="hint">Hier staan alleen de overboekingen van adressen die de app al geladen heeft. Gebruik de link hieronder voor de volledige transactie.</p>' : ''}`;
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
    ${[...e.txs].sort((a, b) => (b.time || 0) - (a.time || 0)).map(x => `<div class="xrow"><div class="xrow-sub"><b>${fmt(x.value)} ${esc(x.asset)}</b>${eurOf(x) ? ` <span class="muted">≈ ${fmtEur(eurOf(x))}</span>` : ''}${x.via ? ` <span class="tag info">${esc(x.via)}</span>` : ''} <span class="muted">· ${fmtTime(x.time)} ·</span> ${txChip(x.txid)}</div></div>`).join('')}`;
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
      if (d.coInputs?.length) { n.data.coInputs = [...(n.data.coInputs || []), ...d.coInputs]; invalidateClusters(); }
      if (d.changeLinks?.length) { n.data.changeLinks = [...(n.data.changeLinks || []), ...d.changeLinks]; invalidateClusters(); }
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
    if (b.dataset.filter === 'dust') v.showDust = !v.showDust;
    else if (b.dataset.filter === 'novalue') v.valueOnly = v.valueOnly === false;
    else v.filter = b.dataset.filter;
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
    <div class="peek-a"><button type="button" class="ghost" data-peek="expand">Volg het geld</button><button type="button" class="primary" data-peek="open">Details ›</button></div>`;
  $('#peek').dataset.key = n.key;
  $('#peek').hidden = false;
}
function hidePeek() { const p = $('#peek'); if (p) p.hidden = true; }

async function nodeAction(n, act) {
  if (act === 'copy') return copyText(n.addr);
  if (act === 'retry') { n.loadTried = false; n.flags = n.flags.filter(f => f.code !== 'error'); return refreshView(); }
  if (act === 'show') { setTab('graph'); focusNode(n.key); return; }
  if (act === 'watch') { await toggleWatch(n); refreshView(); return; }
  if (act === 'wallet') { addWalletToGraph(n); refreshView(); return; }
  if (act === 'walletwatch') { await toggleWalletWatch(n); refreshView(); return; }
  if (act === 'walletfollow') { await followWallet(n); refreshView(); return; }
  if (act === 'add') { ensureCase(n); addToGraph(n); setStatus('Toegevoegd aan het web.'); return refreshView(); }
  if (n.ghost && ['perp', 'victim', 'expand', 'origins'].includes(act)) { ensureCase(n); n = addToGraph(n); }
  if (act === 'perp' || act === 'victim') { n.role = n.role === act ? null : act; render(false); refreshView(); recordObservations(); return; }
  if (act === 'label') {
    const v = prompt('Label voor dit adres (leeg = verwijderen):', customLabels[n.key] || '');
    if (v === null) return;
    if (v.trim()) customLabels[n.key] = v.trim(); else delete customLabels[n.key];
    store.set('chaintrace.labels', customLabels);
    teamPushLabel(n, v.trim());
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
    renderSummary();
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
  if (/^[0-9a-fA-F]{64}$/.test(q)) return openTx(['tron', 'ltc'].includes(current?.chain) ? current.chain : 'btc', q.toLowerCase());
  if (/^[1-9A-HJ-NP-Za-km-z]{86,88}$/.test(q)) return openTx('sol', q);
  setStatus('Niet herkend als adres of transactie-hash.', true);
  setTab('form');
}

// ---------- export / import ----------
// Na opslaan: "Delen" aanbieden (Android-deelmenu, of de deelfunctie van de browser op een telefoon).
function offerShare(name, mime, dataUrl) {
  const b64 = dataUrl.split(',')[1];
  const canWeb = !!(navigator.canShare && window.File);
  if (!window.AndroidBridge?.shareFile && !canWeb) return;
  const bar = $('#shareBar');
  bar.hidden = false;
  $('#shareText').textContent = `${name} is opgeslagen.`;
  $('#shareBtn').onclick = async () => {
    if (window.AndroidBridge?.shareFile) { window.AndroidBridge.shareFile(name, mime, b64); return; }
    const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const file = new File([bin], name, { type: mime });
    if (navigator.canShare({ files: [file] })) navigator.share({ files: [file], title: name }).catch(() => {});
  };
  $('#shareClose').onclick = () => { bar.hidden = true; };
  clearTimeout(offerShare.t);
  offerShare.t = setTimeout(() => { bar.hidden = true; }, 30000);
}

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
  const dossier = buildDossier();
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
  font(26, 400); text(`Gegenereerd ${new Date().toLocaleString(window.CT_LOCALE)}`, PAD, 262, t.muted);
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
  const exch = down.filter(n => endKind(n) === 'exchange');
  if (exch.length) {
    out.push({ cls: 'good', text: `Het geld komt uit bij ${exch.length} exchange(s) of dienst(en): ${nameList(exch.map(n => labelOf(n) || 'onbekende dienst ' + short(n.addr)))}. Daar kan de politie opvragen wie de rekeninghouder is en om bevriezing vragen.` });
  } else {
    out.push({ text: 'Er is nog geen exchange gevonden waar het geld uitkomt. Tik op een oranje adres en kies "Waar ging het geld heen?" om dieper te zoeken.' });
  }
  const bad = all.filter(n => n.flags.some(f => BAD_CODES.includes(f.code)));
  if (bad.length) out.push({ cls: 'warn', text: `${bad.length} adres(sen) staan op een waarschuwingslijst (sanctie, scam, ransomware, mixer of door Tether bevroren).` });
  const look = all.filter(n => n.flags.some(f => f.code === 'lookalike' && f.level === 'high'));
  if (look.length) out.push({ cls: 'warn', text: `${look.length} adres(sen) lijken sterk op een ander adres: mogelijk "address poisoning".` });
  const before = all.filter(n => n.flags.some(f => f.code === 'seenbefore'));
  if (before.length) out.push({ cls: 'warn', text: `${before.length} adres(sen) kwamen al voor in een eerder onderzoek op dit apparaat.` });
  const deps = [...nodes.values()].filter(n => n.depositOf);
  if (deps.length) out.push({ cls: 'good', text: `${deps.length} stortingsadres(sen) van klanten bij een exchange gevonden: ${nameList(deps.map(n => labelOf(n) || short(n.addr)))}. Dit zijn de sterkste aanknopingspunten voor de brief aan de exchange.` });
  const ws = walletSummary();
  if (ws.wallets) out.push({ text: `${ws.addrs} adressen zijn samengevoegd tot ${ws.wallets} wallet(s): ze werden samen als bron gebruikt, dus vrijwel zeker dezelfde eigenaar.` });
  if (origins.starts.size) out.push({ text: `${origins.starts.size} startwallet(s) gevonden waar geld vandaan kwam${current.role === 'perp' ? ': mogelijke andere slachtoffers' : ''}.` });
  if (origins.cashIn.length) out.push({ text: `${origins.cashIn.length} storting(en) kwamen rechtstreeks van een exchange of dienst (${nameList(origins.cashIn.map(r => r.name))}). Transactie-hash en tijdstip staan in het rapport.` });
  return out;
}

function renderSummary() {
  autosave();
  renderFormSummary();
  renderOverview();
  renderTaint();
  pricesForCase();
  renderDemoBanner();
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
    const W = 210, M = 14, S = v => pdfSafe(tr(String(v ?? '')));
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
    doc.text(S(`${pat.name}  |  ${CHAIN_NAME[current.chain]}  |  gemaakt op ${new Date().toLocaleString(window.CT_LOCALE)}`), M, 21.5);
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
      ['Onderzoek uitgevoerd', new Date(current.started || Date.now()).toLocaleString(window.CT_LOCALE)],
      ['Omvang', `${nodes.size} adressen, ${edges.size} geldstromen`]
    ], { 0: { cellWidth: 42, fontStyle: 'bold' } });

    heading('Samenvatting');
    for (const l of summaryLines()) para('-  ' + l.text);
    y += 3;

    const wl = new Map();
    for (const n of nodes.values()) { const c = clusterOf(n.key); if (c && c.members.filter(k => nodes.has(k)).length >= 2) wl.set(c.id, c.members); }
    if (wl.size) {
      heading('Wallets (zelfde eigenaar)');
      para('Deze adressen zijn samen als bron (input) in dezelfde transactie gebruikt en horen daarom vrijwel zeker bij dezelfde eigenaar.', 8.5, 110);
      table(['Wallet', 'Adressen'], [...wl.values()].map((m, i) => [`Wallet ${i + 1} (${m.length})`, m.map(k => k.split(':')[1]).join('\n')]), { 0: { cellWidth: 30 }, 1: mono });
    }

    const mr = moneyRoutes(6);
    if (mr.routes.length) {
      heading(mr.reached ? 'Het geld stap voor stap' : 'Het geld stap voor stap (nog niet bij een exchange)');
      mr.routes.forEach((r, i) => {
        const kind = endKind(r.end);
        para(`Route ${i + 1}: eindigt bij ${labelOf(r.end) || (kind ? END_NL[kind] : r.end.addr)}`, 10, 20);
        r.steps.forEach((e, j) => {
          const st = stepText(e);
          para(`${j + 1}. ${st.when}: ${st.text}`, 9, 45, 4);
          para(`van ${nodes.get(e.source).addr}  naar ${nodes.get(e.target).addr}`, 7, 120, 8);
        });
        y += 2;
      });
    }

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
    const amtEur = t => `${fmt(t.value)} ${t.asset}${eurOf(t) ? '\n' + fmtEur(eurOf(t)) : ''}`;
    const txBody = rows => rows.map(({ t, a, b }) => [utc(t.time), (name(a) ? name(a) + ' ' : '') + a.addr, (name(b) ? name(b) + ' ' : '') + b.addr, amtEur(t), t.txid]);

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

    // Verdeling van het geld van het slachtoffer
    const ta = taintAnalysis();
    if (ta?.total > 0) {
      heading('Waar is het geld van het slachtoffer gebleven?');
      para(`Het slachtoffer verstuurde in totaal ${fmtEur(ta.total)} (waarde in euro op de dag van elke betaling). Verdeling volgens de proportionele methode (haircut): bij menging met ander geld gaat bij elke betaling naar verhouding een deel mee. Dit is een schatting op basis van de geladen transacties.`, 8.5, 60);
      const rowsT = [];
      for (const r of ta.rows) {
        rowsT.push([r.label, fmtEur(r.eur), Math.round(100 * r.eur / ta.total) + '%', '']);
        for (const i of r.items.slice(0, 6)) rowsT.push(['', fmtEur(i.eur), '', i.n ? `${name(i.n) ? name(i.n) + '\n' : ''}${i.n.addr}` : i.k.split(':')[1]]);
      }
      table(['Bestemming', 'Bedrag', 'Deel', 'Adres'], rowsT, { 0: { cellWidth: 52, fontStyle: 'bold' }, 1: { cellWidth: 24 }, 2: { cellWidth: 14 }, 3: mono });
    }

    // Tijdlijn van de geldroute (chronologisch)
    const rk = routeEdgeKeys();
    const tl = [];
    for (const e of edges.values()) if (rk.has(e.key)) for (const t of e.txs) tl.push({ t, e });
    if (tl.length) {
      tl.sort((a, b) => (a.t.time || 0) - (b.t.time || 0));
      heading(`Tijdlijn van de geldroute (${tl.length})`);
      table(['Tijdstip', 'Van', 'Naar', 'Bedrag', 'Transactie-hash'], tl.slice(0, 300).map(({ t, e }) => [
        utc(t.time), `${name(nodes.get(e.source)) ? name(nodes.get(e.source)) + '\n' : ''}${nodes.get(e.source).addr}`,
        `${name(nodes.get(e.target)) ? name(nodes.get(e.target)) + '\n' : ''}${nodes.get(e.target).addr}`, amtEur(t), t.txid
      ]), { 0: { cellWidth: 24 }, 1: mono, 2: mono, 3: { cellWidth: 22 }, 4: mono });
    }

    heading('Vervolgstappen');
    pat.steps.forEach((st, i) => para(`${i + 1}.  ${st}`));
    y += 3;

    heading('Toelichting');
    para('Dit rapport is automatisch gemaakt met ChainTrace (open source) op basis van openbare blockchaingegevens (mempool.space, Blockscout, TronGrid) en openbare lijsten (OFAC, ScamSniffer, GraphSense, Ransomwhere, Forta, Etherscan-labels, Tether-blacklist). De beoordelingen "verdacht", "mogelijk slachtoffer" en "exchange" zijn aanwijzingen op basis van patronen en labels, geen bewijs. Controleer transacties altijd met de transactie-hash in een block explorer. Per adres zijn alleen de meest recente transacties onderzocht.', 8.5, 90);

    // Verantwoording: waar komen de gegevens vandaan en hoe controleer je dat er niets is veranderd?
    const ev = evidenceDossier();
    const evText = JSON.stringify(ev, null, 2);
    const hash = await sha256Hex(evText);
    const evName = `chaintrace-dossier-${hash.slice(0, 12)}.json`;
    heading('Verantwoording en controle');
    para(`Bij dit rapport hoort het dossierbestand "${evName}" met alle adressen, geldstromen en instellingen. De SHA-256-vingerafdruk van dat bestand is:`, 8.5, 60);
    doc.setFont('courier', 'normal'); doc.setFontSize(8); doc.setTextColor(20); room(6); doc.text(hash, M, y); y += 6;
    para('Wie het bestand later controleert (bijv. met "sha256sum" of "certutil -hashfile <bestand> SHA256"), moet exact deze code krijgen. Een andere code betekent dat het bestand is gewijzigd.', 8.5, 90);
    table(['Gegeven', 'Waarde'], [
      ['Programma', `ChainTrace ${APP_VERSION} (open source)`],
      ['Rapport gemaakt (UTC)', new Date().toISOString().slice(0, 16).replace('T', ' ')],
      ['Instellingen', `stappen ${current.opts.depth}, tegenpartijen ${current.opts.fanout}, max. adressen ${current.opts.maxNodes}, tijdvolgorde ${timeOrderOn() ? 'aan' : 'uit'}`],
      ['Tijdvolgorde', timeOrderOn() ? 'Alleen geld gevolgd dat vertrok nadat het op het adres binnenkwam.' : 'Uit: alle uitgaande betalingen gevolgd.']
    ], { 0: { cellWidth: 42, fontStyle: 'bold' } });
    heading(`Bronnen per adres (${ev.provenance.length})`);
    table(['Adres', 'Keten', 'Bron', 'Opgehaald (UTC)', 'Geladen', 'Volledig?'], ev.provenance.map(p => [
      p.address, CHAIN_NAME[p.chain] || p.chain, p.source, p.fetchedAt ? p.fetchedAt.slice(0, 16).replace('T', ' ') : '-', String(p.transfersLoaded),
      p.moreHistoryAvailable ? 'nee, alleen recentste' : 'ja'
    ]), { 0: { ...mono, cellWidth: 52 }, 1: { cellWidth: 18 }, 2: { cellWidth: 34 }, 3: { cellWidth: 24 }, 4: { cellWidth: 14 } });

    const pages = doc.getNumberOfPages();
    for (let i = 1; i <= pages; i++) {
      doc.setPage(i);
      doc.setFont('helvetica', 'normal'); doc.setFontSize(7.5); doc.setTextColor(140);
      doc.text(S(`ChainTrace ${APP_VERSION}  |  ${short(seed.addr)}  |  ${new Date().toLocaleDateString(window.CT_LOCALE)}  |  SHA-256 ${hash.slice(0, 12)}…`), M, 291);
      doc.text(S(`Pagina ${i} van ${pages}`), W - M, 291, { align: 'right' });
    }
    const pdfName = `chaintrace-rapport-${stamp()}.pdf`;
    const pdfData = doc.output('datauristring');
    saveFile(pdfName, 'application/pdf', pdfData, true);
    offerShare(pdfName, 'application/pdf', pdfData);
    saveFile(evName, 'application/json', evText, false);
    setStatus(`PDF-rapport en dossierbestand opgeslagen (${pages} pagina's).`);
    return doc;
  } catch (err) {
    setStatus('PDF maken mislukt: ' + err.message, true);
    throw err;
  }
}

function importJson(text, { merge = false } = {}) {
  const d = typeof text === 'string' ? JSON.parse(text) : text;
  if (d.tool !== 'ChainTrace') throw new Error('Geen ChainTrace-dossier');
  if (merge && current) {
    // Samenvoegen in het huidige web (zaak: meerdere onderzoeken samen).
    for (const x of d.nodes) {
      const isNew = !nodes.has(x.key);
      const n = getNode(x.chain, x.address);
      if (isNew) Object.assign(n, { flags: x.flags || [], depth: x.hop, hint: x.hint, parent: x.parent, upstream: x.upstream, expanded: true });
      else for (const f of x.flags || []) addFlag(n, f.code, f.level, f.text);
      if (x.seed && !n.role) n.role = d.case?.role || 'victim';
      else if (x.role && !n.role) n.role = x.role;
      if (x.label && !labelOf(n)) metaStore[n.key] = { ...(metaStore[n.key] || {}), tags: [x.label] };
    }
    for (const e of d.edges) if (!edges.has(e.key)) edges.set(e.key, { ...e, first: e.first ?? Infinity });
    return;
  }
  abortCtl.abort(); abortCtl = new AbortController();
  demoMode = false;
  resetGraph();
  current = { chain: d.case?.chain || d.nodes[0]?.chain, role: d.case?.role || 'victim', pattern: d.case?.patternKey || 'generic',
    seedKey: d.nodes.find(n => n.seed)?.key, started: d.case?.started, opts: readOpts() };
  Object.assign(customLabels, d.customLabels || {});
  for (const x of d.nodes) {
    const n = getNode(x.chain, x.address);
    Object.assign(n, { role: x.role, flags: x.flags || [], seed: x.seed, depth: x.hop, hint: x.hint, parent: x.parent, upstream: x.upstream, expanded: true });
    if (x.label && !labelOf(n)) metaStore[n.key] = { ...(metaStore[n.key] || {}), tags: [x.label] };
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
function setBusy(b) {
  $('#btnTrace').disabled = b; $('#btnStop').hidden = !b; if (!b) setProgress(null);
  // Android: scherm aan houden tijdens het ophalen, anders breekt het systeem de verbindingen af.
  try { window.AndroidBridge?.keepAwake?.(!!b); } catch { /* oudere app */ }
}
// Voortgangsbalk: stap i van n (met een kleine tussenstand op basis van geladen adressen).
let progressStep = null;
function setProgress(i, n, label) {
  const box = $('#progress');
  if (i == null) { box.hidden = true; progressStep = null; return; }
  progressStep = { i, n, label };
  box.hidden = false;
  $('#progressLabel').textContent = label;
  updateProgress();
}
function updateProgress() {
  if (!progressStep) return;
  const loaded = [...nodes.values()].filter(x => x.data).length;
  const { i, n } = progressStep;
  const frac = Math.min(0.9, loaded / Math.max(4, (current?.opts?.fanout || 6) * (i + 1)));
  $('#progressFill').style.width = Math.min(100, 100 * (i + frac) / n) + '%';
  $('#progressCount').textContent = `${loaded} adressen opgehaald`;
}

function readOpts() {
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, Number(v) || lo));
  return { depth: clamp($('#depth').value, 1, 4), fanout: clamp($('#fanout').value, 2, 25), maxNodes: clamp($('#maxNodes').value, 10, 300), timeOrder: $('#timeOrder').checked };
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
    if (!smartFill(txt, 'paste')) { $('#addr').value = txt; updateChainHint(); }
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
    if (!chain) {
      const x = extractFromText(addr);
      if (x?.kind === 'tx') { openTx(x.chain || (current?.chain === 'tron' ? 'tron' : 'btc'), x.value); setStatus('Dit is een transactie: tik in de verkenner op het adres dat je wilt onderzoeken.'); return; }
      if (x?.kind === 'addr') { smartFill(addr, 'paste'); setStatus('Adres uit de tekst gehaald. Tik nog een keer op Start.'); return; }
      setStatus('Dit adres wordt niet herkend. Controleer of je het hele adres hebt geplakt.', true); return;
    }
    const ri = recent.indexOf(addr);
    if (ri >= 0) recent.splice(ri, 1);
    recent.unshift(addr);
    recent.length = Math.min(recent.length, 8);
    store.set('chaintrace.recent', recent);
    fillRecent();
    if (det && (isEvm(det) !== isEvm(chain) || (!isEvm(det) && det !== chain))) { setStatus(`Adres past niet bij ${CHAIN_NAME[chain]}.`, true); return; }
    const role = document.querySelector('input[name=role]:checked').value;
    const pattern = $('#pattern').value;
    const resubmit = () => { const e = new Event('submit', { cancelable: true }); e.chainPicked = true; $('#traceForm').dispatchEvent(e); };
    try { history.replaceState(null, '', `?addr=${encodeURIComponent(addr)}&chain=${chain}&role=${role}&pattern=${pattern}`); } catch { /* file:// */ }
    if ($('#chain').value === 'auto' && det === 'eth' && norm('eth', addr) !== DEMO.victim && !ev.chainPicked) {
      setStatus('Kijken op welke blockchain dit adres actief is…');
      probeEvm(addr).then(found => {
        if (found.length <= 1) { $('#chain').value = found[0]?.chain || 'eth'; resubmit(); $('#chain').value = 'auto'; return; }
        setStatus('');
        $('#chainPick').hidden = false;
        $('#chainPick').innerHTML = `<p>Dit adres is actief op meerdere blockchains. Welke wil je onderzoeken?</p>${found.map(f =>
          `<button type="button" class="ghost" data-pick="${f.chain}">${esc(CHAIN_NAME[f.chain])}${f.count > 0 ? ` · ${fmt(f.count)} tx` : ''}</button>`).join('')}`;
      });
      return;
    }
    $('#chainPick').hidden = true;
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
  $('#caseNote').addEventListener('input', ev => { notes.case = ev.target.value; saveNotes(); autosave(); });
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
  $('#btnRoute').addEventListener('click', () => { if (document.querySelector('#timeline') && !$('#timeline').hidden) setGraphView('web'); fitRoute(); });

  setupDbDialog();
  setupSimple();
  setupFeatures();
  setupV19();
  setupV20();
  setupUI21();
  setupV22();
  setupTeam();

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
  // Legenda standaard dicht: anders bedekt hij een deel van het web.
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
    Laatste update: ${s.lastRun ? new Date(s.lastRun).toLocaleString(window.CT_LOCALE) : 'nog nooit'}${s.running ? ' · <b>bijwerken…</b>' : ''} · daarna dagelijks automatisch`;
  $('#dbSources').innerHTML = s.sources.map(x => `<tr><td><a href="${esc(x.url)}" target="_blank" rel="noopener noreferrer">${esc(x.name)}</a></td>
    <td class="num">${fmt(x.count)}</td><td class="st ${esc(x.status)}" title="${esc(x.error || '')}">${esc(x.status)}${x.error ? ' ⚠' : ''}</td>
    <td>${x.lastSync ? new Date(x.lastSync).toLocaleDateString(window.CT_LOCALE) : '—'}</td></tr>`).join('');
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

// ---------- eenvoud: uitleg, geldroute, brief aan exchange, slim invoeren ----------
const HELP = {
  address: ['Walletadres', 'Een soort rekeningnummer voor crypto. Iedereen kan zonder naam zoveel adressen aanmaken als hij wil. Pas bij een exchange is te achterhalen van wie een adres is.'],
  tx: ['Transactie (tx-hash)', 'Elke overboeking heeft een unieke code: de transactie-hash. Daarmee kan iedereen, ook de politie of een exchange, precies die overboeking terugvinden. Zet hem altijd in je aangifte.'],
  hop: ['Stap (hop)', 'Elke keer dat geld naar een volgend adres gaat, is één stap. Hoe meer stappen, hoe minder zeker het is dat het nog hetzelfde geld is.'],
  victim: ['Slachtoffer', 'Het adres waar het geld van het slachtoffer vandaan kwam (of dat je zelf als slachtoffer hebt gemarkeerd).'],
  victim2: ['Mogelijk slachtoffer', 'Iemand die geld naar de dader stuurde. Dat kan een ander slachtoffer zijn. Het is een aanwijzing, geen zekerheid.'],
  perp: ['Dader', 'Een adres dat je als dader hebt gemarkeerd, of dat sterk lijkt op een valstrik-adres.'],
  suspect: ['Verdacht', 'Dit adres ontving geld van het slachtoffer, of gedraagt zich verdacht (geld snel doorsturen, van veel mensen ontvangen). Het is een aanwijzing, geen bewijs.'],
  plain: ['Onbekend', 'Over dit adres is (nog) niets bijzonders bekend.'],
  exchange: ['Exchange', 'Een bedrijf waar mensen crypto kopen en verkopen, zoals Binance, Coinbase of Bitvavo. Klanten moeten zich daar met een ID registreren. Daarom kan de politie bij een exchange opvragen van wie een account is, en vragen het geld te bevriezen. Dit is meestal het belangrijkste spoor.'],
  service: ['Zeer druk adres', 'Dit adres doet zoveel transacties dat het vrijwel zeker van een bedrijf is (vaak een exchange of betaaldienst), niet van één persoon.'],
  sanction: ['Waarschuwingslijst', 'Dit adres staat op een lijst met verboden of bekende criminele partijen, zoals de sanctielijst van de Amerikaanse overheid (OFAC) of een scamlijst.'],
  scamlist: ['Scamlijst', 'Dit adres is eerder door anderen gemeld als oplichting, phishing of hack.'],
  badtag: ['Fraude-label', 'Een openbare blockchain-verkenner heeft dit adres een label gegeven dat op fraude of een hack wijst.'],
  ransomware: ['Ransomware', 'Dit adres is gebruikt om losgeld te ontvangen voor gegijzelde computers.'],
  frozen: ['Bevroren door Tether', 'Tether (het bedrijf achter USDT) heeft dit adres geblokkeerd. Het geld kan daar niet meer weg. Tether werkt samen met politie.'],
  darknet: ['Darknet', 'Dit adres hoort bij een verborgen marktplaats op internet waar illegale spullen worden verkocht.'],
  mixer: ['Mixer', 'Een dienst die geld van veel mensen door elkaar husselt, zodat je niet meer ziet waar het vandaan komt. Na een mixer is het spoor meestal niet verder te volgen.'],
  bridge: ['Bridge', 'Een dienst die geld overzet naar een andere blockchain (bijvoorbeeld van Ethereum naar Tron). Het spoor gaat dan verder op die andere blockchain.'],
  contract: ['Smart contract', 'Een programma op de blockchain, geen persoon. Bijvoorbeeld een online wisselkantoor (DEX) of een munt. Geld dat erin gaat, komt er vaak elders weer uit.'],
  startwallet: ['Startwallet', 'Het verste adres waar het geld naar terug te volgen was. Als de dader geld kreeg van zo\'n adres, kan dat een ander slachtoffer zijn.'],
  passthrough: ['Doorsluisadres', 'Geld komt binnen en gaat binnen een uur weer weg. Oplichters doen dat om het spoor moeilijker te volgen te maken.'],
  fanin: ['Verzameladres', 'Dit adres ontvangt geld van veel verschillende mensen. Bij oplichting kan dat betekenen dat er meer slachtoffers zijn.'],
  fanout: ['Verspreidadres', 'Dit adres stuurt geld naar veel verschillende adressen. Zo wordt het geld opgeknipt om het spoor te verbergen.'],
  peel: ['Peel chain', 'Steeds een klein deel afsplitsen en de rest doorsturen naar een nieuw adres. Een bekende witwastruc bij Bitcoin.'],
  lookalike: ['Lijkt-op-adres (address poisoning)', 'Oplichters maken een adres dat aan het begin en eind hetzelfde is als een adres dat je vaker gebruikt. Wie dan een adres uit de geschiedenis kopieert, stuurt het geld per ongeluk naar de oplichter. Vergelijk daarom altijd het hele adres.'],
  dust: ['Spam / nul-transacties', 'Overboekingen van 0 of met nepmunten. Vaak bedoeld om een lijkt-op-adres in de geschiedenis van het slachtoffer te zetten.'],
  seenbefore: ['Eerder gezien', 'Dit adres kwam al voor in een ander onderzoek op dit apparaat.'],
  deposit: ['Stortingsadres', 'Bij een exchange krijgt elke klant een eigen stortingsadres. Wat daar binnenkomt, zet de exchange door naar een groot verzameladres (hot wallet). Een adres dat bijna al zijn geld naar één exchange doorstuurt, is daarom meestal het stortingsadres van één klant. Met dit adres kan de exchange de klant direct vinden.'],
  cluster: ['Zelfde wallet of beheerder', 'Eén persoon kan veel adressen hebben. De app voegt adressen samen met vier eigen regels: (1) Bitcoin/Litecoin-adressen die samen als bron (input) in één transactie zitten; (2) het wisselgeld-adres van zo\'n transactie; (3) adressen die op hetzelfde klant-stortingsadres bij een exchange storten; (4) een nieuw adres dat eerst een klein bedrag voor transactiekosten krijgt van een adres uit het onderzoek en daarna tokens doorstuurt. Slachtoffers, exchanges en CoinJoin-transacties worden nooit samengevoegd. De regels staan onder Instellingen.'],
  overlap: ['Komt vaker voor', 'Dit adres komt voor in meerdere onderzoeken van dezelfde zaak. Dat is een belangrijk verband: bijvoorbeeld dezelfde oplichter bij verschillende slachtoffers.'],
  reputation: ['Reputatie', 'De blockchain-verkenner waarschuwt dat dit adres of deze munt niet te vertrouwen is.']
};
const HELP_ORDER = ['address', 'tx', 'hop', 'exchange', 'mixer', 'bridge', 'contract', 'sanction', 'frozen', 'startwallet', 'suspect', 'victim2', 'passthrough', 'fanin', 'fanout', 'peel', 'lookalike', 'dust', 'service'];

function showHelp(key) {
  const h = HELP[key];
  if (!h) return;
  $('#helpBody').innerHTML = `<h2>${esc(h[0])}</h2><p>${esc(h[1])}</p>`;
  $('#helpDlg').showModal();
}
function showGlossary() {
  $('#helpBody').innerHTML = `<h2>Woordenlijst</h2>${HELP_ORDER.map(k => `<h3>${esc(HELP[k][0])}</h3><p>${esc(HELP[k][1])}</p>`).join('')}`;
  $('#helpDlg').showModal();
}

// --- uitleg van één adres in gewone taal ---
const bal0 = b => !b || /^0([.,]0+)? /.test(b);
function plainStory(n) {
  const out = [];
  const has = c => n.flags.some(f => f.code === c);
  const lab = labelOf(n);
  if (n.role === 'victim') out.push('Dit is het adres van het slachtoffer.');
  if (n.role === 'perp') out.push('Dit adres is gemarkeerd als dader.');
  if (has('exchange')) out.push(`Dit adres hoort bij ${lab || 'een exchange'}. Hier kan de politie opvragen van wie het account is, en vragen het geld te bevriezen. Maak hiervoor de brief aan de exchange.`);
  else if (has('service')) out.push('Dit adres is zó actief dat het vrijwel zeker van een bedrijf is (exchange of betaaldienst). Ook hier kan de politie gegevens opvragen.');
  else if (has('mixer')) out.push('Dit is een mixer: hier wordt geld onherkenbaar gemaakt. Verder volgen lukt meestal niet.');
  else if (has('bridge')) out.push('Via dit adres is geld naar een andere blockchain gegaan. Het spoor gaat daar verder.');
  else if (has('contract')) out.push('Dit is een programma (smart contract), geen persoon.');
  const exch = has('exchange');
  const bad = n.flags.filter(f => BAD_CODES.includes(f.code) && !(exch && f.code === 'frozen'));
  if (exch && has('frozen')) out.push('Tether heeft USDT op dit exchange-adres geblokkeerd. Bij een groot exchange-adres zegt dat iets over de exchange, niet per se over jouw zaak.');
  if (bad.length) out.push(`Let op: dit adres staat op een waarschuwingslijst (${bad.map(f => HELP[f.code]?.[0] || f.code).join(', ')}).`);
  if (n.flags.some(f => f.code === 'lookalike' && f.level === 'high')) out.push('Dit adres lijkt sterk op een ander adres: waarschijnlijk een valstrik (address poisoning).');
  const d = n.data;
  if (d) {
    const real = valuedOrAll(d.transfers).filter(t => t.from !== t.to);
    const ins = real.filter(t => t.to === n.addr), outs = real.filter(t => t.from === n.addr);
    const s = new Set(ins.map(t => t.from)).size, r = new Set(outs.map(t => t.to)).size;
    const times = real.map(t => t.time).filter(Boolean);
    const when = times.length ? ` tussen ${fmtDay(Math.min(...times))} en ${fmtDay(Math.max(...times))}` : '';
    if (ins.length || outs.length) {
      out.push(`Het adres ontving ${ins.length ? assetText(sumAssets(ins)) + ` van ${s} afzender${s === 1 ? '' : 's'}` : 'niets'} en stuurde ${outs.length ? assetText(sumAssets(outs)) + ` naar ${r} ontvanger${r === 1 ? '' : 's'}` : 'niets door'}${when}${d.cursor ? ' (in de laatst geladen transacties)' : ''}.`);
    } else out.push('Er zijn geen overboekingen met waarde gevonden.');
    if (!outs.length && ins.length && !isEndpoint(n)) out.push('Er is (nog) niets doorgestuurd: het geld staat hier mogelijk nog.');
    if (d.balance && !bal0(d.balance) && !isEndpoint(n)) out.push(`Er staat nu nog ${d.balance} op dit adres.`);
  }
  if (n.depositOf) { const ex = nodes.get(n.depositOf) || ghosts.get(n.depositOf); out.push(`Dit is waarschijnlijk het persoonlijke stortingsadres van één klant bij ${exName(labelOf(ex)) || 'de exchange'}. Met dit adres kan de exchange de klant direct vinden: zet het in de brief.`); }
  { const sw = swapsOf(n); if (sw.length) out.push(`Dit adres wisselde ${sw.length}× munten om, bijvoorbeeld ${fmt(sw[0].from.value)} ${sw[0].from.asset} → ${fmt(sw[0].to.value)} ${sw[0].to.asset}. Het geld gaat daarna verder in de nieuwe munt.`); }
  if (has('passthrough')) out.push('Geld bleef hier meestal korter dan een uur: typisch een doorsluisadres van oplichters.');
  if (has('fanin') && !isEndpoint(n)) out.push('Veel verschillende mensen stuurden geld naar dit adres: mogelijk zijn er meer slachtoffers.');
  if (has('startwallet')) out.push('Hier begint het geld voor zover te volgen: mogelijk een ander slachtoffer of de bron van het geld.');
  if (has('seenbefore')) out.push('Dit adres kwam al voor in een eerder onderzoek op dit apparaat.');
  if (n.ghost) out.push('Dit adres staat nog niet in je web. Tik op "Toevoegen aan web" om het mee te nemen in het rapport.');
  else if (!isEndpoint(n) && !n.expanded && !n.seed) out.push('Tik op "Waar ging het geld heen?" om verder te zoeken.');
  return out;
}
const fmtDay = t => t ? new Date(t * 1000).toLocaleDateString(window.CT_LOCALE, { day: 'numeric', month: 'short', year: 'numeric' }) : '?';

// --- de geldroute: van het startadres tot waar het geld uitkomt ---
// Waarde van een geldstroom: dollars als bekend, anders BTC/ETH ruw omgerekend; onbekende tokens tellen niet.
const NATIVE_USD = { BTC: 60000, ETH: 3000, LTC: 80, AVAX: 25, SOL: 150, TRX: 0.25 };
const edgeVal = e => e.usd || Object.entries(e.assets).reduce((s, [a, v]) => s + (NATIVE_USD[a] || 0) * v, 0);
function moneyRoutes(max = 5) {
  const seed = nodes.get(current?.seedKey);
  if (!seed) return { routes: [], reached: false };
  const all = [...edges.values()].filter(e => nodes.has(e.source) && nodes.has(e.target));
  // Eerst alleen geld met waarde volgen (spam-tokens zonder koers vertroebelen de route); lukt dat niet, dan alles.
  const valued = all.filter(e => edgeVal(e) > 0);
  const r = routesOver(seed, valued, max);
  return r.routes.length || valued.length === all.length ? r : routesOver(seed, all, max);
}

function routesOver(seed, list, max) {
  const outs = new Map();
  for (const e of list) {
    if (!outs.has(e.source)) outs.set(e.source, []);
    outs.get(e.source).push(e);
  }
  for (const l of outs.values()) l.sort((a, b) => edgeVal(b) - edgeVal(a));
  const prev = new Map([[seed.key, null]]);
  const q = [seed.key];
  while (q.length) {
    const k = q.shift();
    if (k !== seed.key && isEndpoint(nodes.get(k))) continue;
    for (const e of outs.get(k) || []) if (!prev.has(e.target)) { prev.set(e.target, e); q.push(e.target); }
  }
  const pathTo = k => { const steps = []; let e; while ((e = prev.get(k))) { steps.unshift(e); k = e.source; } return steps; };
  let targets = [...prev.keys()].filter(k => k !== seed.key && isEndpoint(nodes.get(k)));
  const reached = targets.length > 0;
  if (!reached) targets = [...prev.keys()].filter(k => k !== seed.key && ![...prev.values()].some(e => e && e.source === k));
  const routes = targets.map(k => ({ end: nodes.get(k), steps: pathTo(k) })).filter(r => r.steps.length)
    .sort((a, b) => ((endKind(b.end) === 'exchange') - (endKind(a.end) === 'exchange'))
      || (edgeVal(b.steps[b.steps.length - 1]) - edgeVal(a.steps[a.steps.length - 1])) || (a.steps.length - b.steps.length));
  return { routes: routes.slice(0, max), reached, total: routes.length };
}

const whoIs = n => n.seed ? (current?.role === 'perp' ? 'de dader' : 'het slachtoffer')
  : (labelOf(n) || `adres ${short(n.addr)}`) + ({ suspect: ' (verdacht)', perp: ' (dader)', sanction: ' (waarschuwingslijst)', victim2: ' (mogelijk slachtoffer)' }[nodeClass(n)] || '');
const cap = s => s.charAt(0).toUpperCase() + s.slice(1);
function stepText(e) {
  const s = nodes.get(e.source), t = nodes.get(e.target);
  const when = fmtDay(e.first) === fmtDay(e.last) ? fmtDay(e.first) : `${fmtDay(e.first)} t/m ${fmtDay(e.last)}`;
  const eur = e.txs.reduce((a, x) => a + (eurOf(x) || 0), 0);
  const amt = edgeLabel(e) + (eur > 0 ? ` (≈ ${fmtEur(eur)})` : '');
  if (e.cross) return { when, text: `${cap(whoIs(s))} zette ${amt} via ${e.cross === true ? 'een bridge' : e.cross} over naar ${whoIs(t)} op ${CHAIN_NAME[t.chain]}.` };
  if (e.swap) return { when, text: `${cap(whoIs(s))} wisselde om via ${e.swap === true ? 'een DEX' : e.swap} en stuurde ${amt} naar ${whoIs(t)}.` };
  return { when, text: `${cap(whoIs(s))} stuurde ${amt} naar ${whoIs(t)}.` };
}
const hasF = (n, c) => n.flags.some(f => f.code === c);
const endKind = n => hasF(n, 'exchange') ? 'exchange' : hasF(n, 'mixer') ? 'mixer' : hasF(n, 'bridge') ? 'bridge'
  : hasF(n, 'sanction') ? 'sanction' : hasF(n, 'contract') ? 'contract' : hasF(n, 'service') ? 'exchange' : null;
const END_NL = { exchange: 'exchange', mixer: 'mixer', bridge: 'bridge', contract: 'smart contract', sanction: 'waarschuwingslijst' };

function renderRoutes() {
  const box = $('#routeBox');
  const { routes, reached, total } = moneyRoutes();
  box.hidden = !routes.length;
  if (!routes.length) return;
  const intro = reached
    ? `<p class="hint">Zo is het geld gelopen tot waar het uitkwam${total > routes.length ? ` (de ${routes.length} grootste van ${total} routes)` : ''}. Tik op een stap om dat adres te bekijken.</p>`
    : '<p class="hint">Het geld is in dit onderzoek nog niet bij een exchange aangekomen. Dit zijn de verste adressen. Tik op het laatste adres en kies "Waar ging het geld heen?" om verder te zoeken.</p>';
  $('#routeList').innerHTML = intro + routes.map((r, i) => {
    const kind = endKind(r.end);
    const lab = labelOf(r.end);
    const endName = lab || (kind ? 'een ' + END_NL[kind] : `adres ${short(r.end.addr)}`);
    return `<div class="route-card ${kind || 'open'}">
      <div class="route-h"><span class="route-n">${i + 1}</span> Eindigt bij <b>${esc(endName)}</b>${kind ? ` <button type="button" class="tag help" data-help="${kind}">${lab ? esc(END_NL[kind]) + ' ' : ''}?</button>` : ''}</div>
      <ol class="route-steps">${r.steps.map(e => { const s = stepText(e); return `<li data-k="${esc(e.target)}"><small>${esc(s.when)}</small>${esc(s.text)}</li>`; }).join('')}</ol>
      ${kind === 'exchange' ? `<button type="button" class="primary" data-letter="${esc(r.end.key)}">✉ Brief aan ${esc(exName(labelOf(r.end)) || 'deze exchange')} maken</button>` : ''}
    </div>`;
  }).join('');
}

// --- brief aan een exchange (bevriezen + gegevens bewaren) ---
let letterNode = null;
function letterData(ex) {
  const seed = nodes.get(current?.seedKey);
  const inc = [...edges.values()].filter(e => e.target === ex.key && nodes.has(e.source));
  const srcs = [...new Set(inc.map(e => e.source).filter(k => k !== seed?.key))].map(k => nodes.get(k));
  const deposits = srcs.filter(n => n.depositOf === ex.key).map(n => n.addr);
  const possible = srcs.filter(n => n.depositOf !== ex.key).map(n => n.addr);
  // Ook stortingsadressen die nog niet direct aan dit exchange-adres in het web hangen.
  for (const n of nodes.values()) if (n.depositOf === ex.key && !deposits.includes(n.addr)) deposits.push(n.addr);
  const txs = inc.flatMap(e => e.txs).sort((a, b) => (a.time || 0) - (b.time || 0)).slice(0, 25);
  let reached = 0;
  const ta = taintAnalysis();
  if (ta) for (const r of ta.rows) for (const i of r.items) if (i.n && (i.n.key === ex.key || i.n.depositOf === ex.key)) reached += i.eur;
  return { ex, name: exName(labelOf(ex)) || 'Exchange', seed, deposits, possible, txs, reached };
}
// "Binance: Hot Wallet 14" -> "Binance"
const exName = s => { if (!s) return ''; const c = s.replace(/\s*([:|(]|\s[–-]\s).*$/, '').replace(/\s*(hot|cold|deposit)?\s*wallet.*$/i, '').replace(/\s+\d+$/, '').trim(); return c || s; };
function letterText(d, f, lang) {
  const chain = CHAIN_NAME[d.ex.chain];
  const num = v => v.toLocaleString(lang === 'nl' ? window.CT_LOCALE : 'en-US', { maximumFractionDigits: 8 });
  const txl = d.txs.map(t => `- ${utc(t.time)} | ${num(t.value)} ${t.asset} | tx ${t.txid}`).join('\n') || '-';
  const dep = d.deposits.map(a => `- ${a}`).join('\n');
  const pos = d.possible.map(a => `- ${a}`).join('\n');
  const cs = f.caseNo || '[zaaknummer]', nm = f.name || '[naam, organisatie]', ml = f.mail || '[e-mailadres]';
  if (lang === 'nl') return `Onderwerp: Verzoek tot bevriezing van tegoeden en bewaren van gegevens – ${d.name} – zaak ${cs}

Geachte afdeling Compliance / Law Enforcement van ${d.name},

Wij onderzoeken een zaak van oplichting waarbij cryptovaluta van het slachtoffer zijn weggenomen. Uit blockchain-onderzoek blijkt dat het geld naar ${d.name} is gestuurd.

Blockchain: ${chain}
Adres van ${current?.role === 'perp' ? 'de vermoedelijke dader' : 'het slachtoffer'}: ${d.seed?.addr || '-'}
Adres bij ${d.name} dat het geld ontving:
- ${d.ex.addr}
${dep ? `Stortingsadres(sen) van uw klant (zeer waarschijnlijk; het geld werd vrijwel volledig naar uw adres doorgezet):\n${dep}\n` : ''}${pos ? `Mogelijk stortingsadres van uw klant:\n${pos}\n` : ''}
Transacties:
${txl}
${d.reached > 0 ? `\nGeschat bedrag van het slachtoffer dat bij ${d.name} binnenkwam: ${fmtEur(d.reached)} (proportionele methode, waarde op de dag van betaling).\n` : ''}
Wij verzoeken u vriendelijk:
1. de tegoeden en het/de betrokken account(s) zo snel mogelijk te bevriezen;
2. alle accountgegevens te bewaren (KYC/identiteit, IP-adressen, gekoppelde bankrekeningen, transactiegeschiedenis);
3. ons te laten weten welke gegevens u kunt verstrekken en welke juridische procedure u daarvoor nodig heeft.

Zaak- / aangiftenummer: ${cs}
Contact: ${nm}, ${ml}

Met vriendelijke groet,
${nm}`;
  return `Subject: Request to freeze funds and preserve account data – ${d.name} – case ${cs}

Dear ${d.name} Compliance / Law Enforcement Response Team,

We are investigating a fraud case in which cryptocurrency was taken from the victim. Blockchain analysis shows that the funds were sent to ${d.name}.

Blockchain: ${chain}
${current?.role === 'perp' ? 'Suspect' : 'Victim'} address: ${d.seed?.addr || '-'}
Address at ${d.name} that received the funds:
- ${d.ex.addr}
${dep ? `Deposit address(es) of your customer (very likely; the funds were forwarded almost entirely to your address):\n${dep}\n` : ''}${pos ? `Possible deposit address(es) of your customer:\n${pos}\n` : ''}
Transactions:
${txl}
${d.reached > 0 ? `\nEstimated amount of the victim's funds that reached ${d.name}: EUR ${Math.round(d.reached).toLocaleString('en-GB')} (proportional/haircut method, value on the day of payment).\n` : ''}
We kindly request that you:
1. freeze the funds and the related account(s) as soon as possible;
2. preserve all account data (KYC/identity, login IP addresses, linked bank accounts, transaction history);
3. let us know which information you can provide and which legal procedure you require.

Case / report number: ${cs}
Contact: ${nm}, ${ml}

Kind regards,
${nm}`;
}
function openLetter(ex) {
  if (!ex) return;
  letterNode = ex;
  const f = store.get('chaintrace.letter', {});
  $('#lName').value = f.name || '';
  $('#lMail').value = f.mail || '';
  $('#lCase').value = (store.get('chaintrace.letterCase.' + current?.seedKey, null)) || '';
  $('#letterTitle').textContent = `Brief aan ${exName(labelOf(ex)) || 'exchange'}`;
  $('#lSearch').href = `https://www.google.com/search?q=${encodeURIComponent(`${exName(labelOf(ex)) || 'crypto exchange'} law enforcement request`)}`;
  $('#lShare').hidden = !(window.AndroidBridge?.shareText || navigator.share);
  const usdt = letterData(ex).txs.some(t => /^USDT/.test(t.asset));
  $('#lContact').innerHTML = (contactHtml(exContact(ex)) || '<p class="hint">Voor deze exchange is (nog) geen officieel meldpunt bekend: gebruik "Zoek het contactadres".</p>') + (usdt ? contactHtml(TETHER_CONTACT) : '');
  fillLetter();
  $('#letterDlg').showModal();
}
function fillLetter() {
  if (!letterNode) return;
  const f = { name: $('#lName').value.trim(), mail: $('#lMail').value.trim(), caseNo: $('#lCase').value.trim() };
  store.set('chaintrace.letter', { name: f.name, mail: f.mail });
  if (current) store.set('chaintrace.letterCase.' + current.seedKey, f.caseNo);
  $('#lText').value = letterText(letterData(letterNode), f, $('#lLang').value);
}
function copyPlain(text) {
  if (window.AndroidBridge?.writeClipboard) { window.AndroidBridge.writeClipboard(text); setStatus('Gekopieerd.'); return Promise.resolve(); }
  return navigator.clipboard.writeText(text).then(() => setStatus('Gekopieerd.')).catch(() => prompt('Kopieer:', text));
}

// --- slim invoeren: adres of transactie uit willekeurige tekst halen ---
function extractFromText(text) {
  text = String(text || '');
  const cands = [];
  const re = /0x[a-fA-F0-9]{64}|0x[a-fA-F0-9]{40}|\bT[1-9A-HJ-NP-Za-km-z]{33}\b|\b(?:bc1|ltc1)[a-zA-HJ-NP-Z0-9]{25,87}\b|\b[13LM][1-9A-HJ-NP-Za-km-z]{25,34}\b|\b[a-fA-F0-9]{64}\b|\b[1-9A-HJ-NP-Za-km-z]{86,88}\b|\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g;
  let m;
  while ((m = re.exec(text))) cands.push(m[0]);
  for (const c of cands) { const a = /^(bc1|ltc1)/i.test(c) ? c.toLowerCase() : c; if (detectChain(a)) return { kind: 'addr', value: a, chain: detectChain(a) }; }
  for (const c of cands) if (/^[1-9A-HJ-NP-Za-km-z]{86,88}$/.test(c)) return { kind: 'tx', value: c, chain: 'sol' };
  for (const c of cands) if (/^(0x)?[a-fA-F0-9]{64}$/.test(c)) return { kind: 'tx', value: c.toLowerCase(), chain: c.startsWith('0x') ? 'eth' : null };
  return null;
}
function smartFill(raw, source) {
  const r = extractFromText(raw);
  if (!r) return false;
  $('#addr').value = r.value;
  updateChainHint();
  if (r.kind === 'tx') {
    $('#chainHint').textContent = 'Dit is een transactie, geen adres. Tik op Start: je ziet dan wie betaalde en wie ontving, en tikt het adres aan dat je wilt onderzoeken.';
    $('#chainHint').classList.remove('bad');
  } else if (raw.trim() !== r.value) {
    $('#chainHint').textContent = `✓ ${CHAIN_NAME[r.chain]}-adres gevonden in ${source === 'qr' ? 'de QR-code' : 'de tekst'}`;
  }
  return true;
}
async function readQrFromFile(file) {
  if (!file || !window.jsQR) return null;
  const url = URL.createObjectURL(file);
  try {
    const img = await loadImage(url);
    const s = Math.min(1, 1600 / Math.max(img.width, img.height));
    const cv = document.createElement('canvas');
    cv.width = Math.round(img.width * s); cv.height = Math.round(img.height * s);
    const cx = cv.getContext('2d', { willReadFrequently: true });
    cx.drawImage(img, 0, 0, cv.width, cv.height);
    const data = cx.getImageData(0, 0, cv.width, cv.height);
    return window.jsQR(data.data, cv.width, cv.height)?.data || null;
  } finally { URL.revokeObjectURL(url); }
}

function setupSimple() {
  document.addEventListener('click', ev => {
    const h = ev.target.closest('[data-help]');
    if (h) { ev.preventDefault(); ev.stopPropagation(); showHelp(h.dataset.help); return; }
    const l = ev.target.closest('[data-letter]');
    if (l) { openLetter(nodes.get(l.dataset.letter)); return; }
  }, true);
  $('#btnHelpClose').addEventListener('click', () => $('#helpDlg').close());
  $('#btnGlossary').addEventListener('click', showGlossary);
  $('#routeList').addEventListener('click', ev => {
    const li = ev.target.closest('li[data-k]');
    if (!li) return;
    focusNode(li.dataset.k);
    openNode(nodes.get(li.dataset.k));
  });
  // brief
  for (const id of ['#lName', '#lMail', '#lCase']) $(id).addEventListener('input', fillLetter);
  $('#lLang').addEventListener('change', fillLetter);
  $('#btnLetterClose').addEventListener('click', () => $('#letterDlg').close());
  $('#lCopy').addEventListener('click', () => copyPlain($('#lText').value));
  $('#lShare').addEventListener('click', () => {
    const text = $('#lText').value, subject = text.split('\n')[0].replace(/^(Subject|Onderwerp): /, '');
    if (window.AndroidBridge?.shareText) window.AndroidBridge.shareText(subject, text);
    else navigator.share?.({ title: subject, text }).catch(() => {});
  });
  // grote letters
  const applyBig = on => { document.body.classList.toggle('big', on); $('#btnBig').textContent = on ? 'Normale letters' : 'Grote letters'; setTimeout(() => cy?.resize(), 50); };
  applyBig(!!store.get('chaintrace.big', false));
  $('#btnBig').addEventListener('click', () => { const on = !document.body.classList.contains('big'); store.set('chaintrace.big', on); applyBig(on); });
  // slim plakken en QR
  $('#addr').addEventListener('paste', ev => {
    const txt = ev.clipboardData?.getData('text') || '';
    if (txt && !detectChain(txt.trim())) { ev.preventDefault(); if (!smartFill(txt, 'paste')) { $('#addr').value = txt.trim(); updateChainHint(); } }
  });
  $('#addr').addEventListener('blur', () => { const v = $('#addr').value; if (v && !detectChain(v.trim())) smartFill(v, 'paste'); });
  $('#btnQr').addEventListener('click', () => $('#qrFile').click());
  $('#qrFile').addEventListener('change', async ev => {
    const f = ev.target.files[0];
    ev.target.value = '';
    if (!f) return;
    setStatus('QR-code lezen…');
    let txt = null;
    try { txt = await readQrFromFile(f); } catch { /* onleesbaar */ }
    if (txt && smartFill(txt, 'qr')) setStatus('');
    else setStatus(txt ? `QR-code gelezen, maar er staat geen adres in: ${txt.slice(0, 60)}` : 'Geen QR-code gevonden. Probeer een scherpere foto, of knip alleen de QR-code uit.', true);
  });
}

// ---------- voorbeeldzaak: verzonnen gegevens, de echte analyse draait erop ----------
const DEMO = (() => {
  const idx = { V: 1, A: 2, W1: 3, W2: 4, B: 5, C: 6, X: 7, M: 8, E: 9, D: 10, G: 11 };
  const ad = k => '0xdec0de' + '0'.repeat(32) + idx[k].toString(16).padStart(2, '0');
  const base = Date.UTC(2026, 9, 1, 9, 0) / 1000;
  const at = (day, min = 0) => base + day * 86400 + min * 60;
  let n = 0;
  const T = [];
  const add = (f, t, v, asset, time) => T.push({ from: ad(f), to: ad(t), value: v, asset, time, txid: '0xdec0de' + (++n).toString(16).padStart(58, '0'), usd: asset === 'ETH' ? v * 3000 : v });
  add('E', 'V', 2, 'ETH', at(0)); add('E', 'V', 5000, 'USDT', at(0, 5));
  add('V', 'A', 1.5, 'ETH', at(2)); add('A', 'B', 1.5, 'ETH', at(2, 30));
  add('W1', 'A', 3000, 'USDT', at(3)); add('A', 'B', 3000, 'USDT', at(3, 40));
  add('V', 'A', 4000, 'USDT', at(4)); add('A', 'B', 4000, 'USDT', at(4, 20));
  add('W2', 'A', 1.2, 'ETH', at(5)); add('A', 'B', 1.2, 'ETH', at(5, 15));
  add('V', 'A', 0.5, 'ETH', at(7)); add('A', 'B', 0.5, 'ETH', at(7, 30));
  add('B', 'C', 2.5, 'ETH', at(8)); add('B', 'C', 7000, 'USDT', at(8, 10));
  add('C', 'X', 2.5, 'ETH', at(8, 70)); add('C', 'X', 7000, 'USDT', at(8, 75));
  add('B', 'D', 0.7, 'ETH', at(9)); add('D', 'M', 0.7, 'ETH', at(9, 45));
  // Wegwerpadres G: eerst een beetje ETH voor transactiekosten van B, daarna USDT door naar hetzelfde stortingsadres C.
  add('B', 'G', 0.004, 'ETH', at(7, 120)); add('B', 'G', 1500, 'USDT', at(7, 150)); add('G', 'C', 1500, 'USDT', at(7, 200)); add('C', 'X', 1500, 'USDT', at(7, 260));
  const meta = {
    [ad('X')]: { tags: ['Voorbeeld-Exchange: Hot Wallet (fictief)'] },
    [ad('E')]: { tags: ['Voorbeeld-Exchange: Inkoop (fictief)'] },
    [ad('M')]: { tags: ['Voorbeeld-Mixer (fictief)'] }
  };
  const data = {};
  for (const k of Object.keys(idx)) {
    const a = ad(k);
    data[a] = { transfers: T.filter(t => t.from === a || t.to === a), meta, txCount: ['X', 'E', 'M'].includes(k) ? 250000 : null, balance: k === 'V' ? '0,5 ETH' : '0 ETH', cursor: null };
  }
  return { victim: ad('V'), scammer: ad('A'), data };
})();
let demoMode = false;
const isDemoAddr = a => /^0xdec0de0{32}/i.test(a || '');
const demoData = addr => structuredClone(DEMO.data[addr.toLowerCase()] || { transfers: [], meta: {}, txCount: 0, balance: null, cursor: null });

function startDemo() {
  setTab('form');
  $('#addr').value = DEMO.victim;
  $('#roleVictim').checked = true;
  $('#pattern').value = 'pig';
  applyPatternDefaults();
  $('#depth').value = 4;
  updateChainHint();
  $('#traceForm').requestSubmit();
}
function renderDemoBanner() { $('#demoBanner').hidden = !(demoMode && nodes.size); }

// ---------- voorlezen ----------
const canSpeak = () => !!(window.AndroidBridge?.speak || 'speechSynthesis' in window);
let speaking = false;
function speak(text) {
  text = tr(String(text || '')).replace(/\s+/g, ' ').replace(/0x[0-9a-f]{6,}…?[0-9a-f]*/gi, 'een adres').trim();
  if (!text) return;
  speaking = true;
  const lang = window.CT_LANG === 'en' ? 'en' : 'nl';
  if (window.AndroidBridge?.speakLang) { window.AndroidBridge.speakLang(text, lang); return; }
  if (window.AndroidBridge?.speak) { window.AndroidBridge.speak(text); return; }
  speechSynthesis.cancel();
  const u = new SpeechSynthesisUtterance(text);
  u.lang = window.CT_LOCALE;
  const v = speechSynthesis.getVoices().find(x => x.lang?.toLowerCase().startsWith(lang));
  if (v) u.voice = v;
  u.onend = () => { speaking = false; };
  speechSynthesis.speak(u);
}
function stopSpeak() {
  speaking = false;
  if (window.AndroidBridge?.stopSpeaking) window.AndroidBridge.stopSpeaking();
  else if ('speechSynthesis' in window) speechSynthesis.cancel();
}
const speakBtn = target => canSpeak() ? `<button type="button" class="speak" data-speak="${target}" aria-label="Lees voor">🔊 Lees voor</button>` : '';
function speakTarget(t, btn) {
  if (speaking) { stopSpeak(); return; }
  const box = t === 'self' ? btn.closest('[data-speak-box]') : $(t);
  if (!box) return;
  const clone = box.cloneNode(true);
  clone.querySelectorAll('button.speak, .tag i, small').forEach(e => e.remove());
  speak(clone.innerText);
}

// ---------- Mijn zaken: onderzoeken automatisch bewaren, per zaak ----------
const idb = (() => {
  let dbp = null;
  const open = () => dbp || (dbp = new Promise((res, rej) => {
    const r = indexedDB.open('chaintrace', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  }));
  const run = (mode, fn) => open().then(db => new Promise((res, rej) => {
    const tx = db.transaction('kv', mode);
    const req = fn(tx.objectStore('kv'));
    tx.oncomplete = () => res(req?.result);
    tx.onerror = () => rej(tx.error);
  }));
  return {
    get: k => run('readonly', s => s.get(k)),
    set: (k, v) => run('readwrite', s => s.put(v, k)),
    del: k => run('readwrite', s => s.delete(k))
  };
})();
const cases = {
  list: () => store.get('chaintrace.cases', []),
  save: l => store.set('chaintrace.cases', l),
  currentId: () => store.get('chaintrace.case', null),
  setCurrent: id => store.set('chaintrace.case', id)
};
const caseById = id => cases.list().find(c => c.id === id);
// ---------- Teamserver (optioneel): samenwerken en zaken delen ----------
// Zonder ingestelde server doet dit niets: de app werkt dan volledig zelfstandig zoals voorheen.
let teamSameOrigin = false;
const team = {
  cfg: () => store.get('chaintrace.team', {}),
  setCfg: c => store.set('chaintrace.team', c),
  base: () => ((team.cfg().url || (teamSameOrigin ? location.origin : '')) + '').replace(/\/+$/, ''),
  on: () => !!(team.base() && team.cfg().token),
  me: () => team.cfg().username || '',
  isTeam: c => !!c?.team,
  canEdit: c => !c?.team || c.team.role !== 'view'
};
async function teamApi(method, path, body, { auth = true, base } = {}) {
  const url = (base || team.base()) + '/api/' + path;
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (auth && team.cfg().token) headers.Authorization = 'Bearer ' + team.cfg().token;
  let r;
  try { r = await fetch(url, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined, cache: 'no-store' }); }
  catch { throw new Error('Teamserver niet bereikbaar. Controleer het adres en de internetverbinding.'); }
  let j = {};
  try { j = await r.json(); } catch { /* geen JSON */ }
  if (r.status === 401 && auth && team.cfg().token) { const c = team.cfg(); delete c.token; team.setCfg(c); renderTeamState(); }
  if (!r.ok) throw new Error(j.error || `Fout van de teamserver (${r.status})`);
  return j;
}
const teamCaseId = sid => 't_' + sid;
function teamItem(i) {
  return { seedKey: i.seedKey, chain: i.chain, addr: i.addr, role: i.role, pattern: i.pattern || '', title: i.title || short(i.addr || i.seedKey), saved: i.updated, size: i.size || 0, by: i.updatedBy };
}
// Haal de teamzaken op en zet ze naast de eigen (lokale) zaken.
async function teamSync() {
  if (!team.on()) return;
  const { cases: list } = await teamApi('GET', 'cases');
  const base = team.base();
  const l = cases.list().filter(c => !(c.team && c.team.srv === base && !list.some(s => teamCaseId(s.id) === c.id)));
  for (const s of list) {
    const id = teamCaseId(s.id);
    const c = l.find(x => x.id === id);
    const v = { id, name: s.name, created: s.created, updated: s.updated, items: s.items.map(teamItem), team: { id: s.id, srv: base, role: s.role, owner: s.owner, members: s.members } };
    if (c) Object.assign(c, v); else l.push(v);
  }
  cases.save(l);
  if (!caseById(cases.currentId())) cases.setCurrent(null);
  renderCaseBar();
  if ($('#caseDlg').open) renderCases();
}
async function teamLoadLabels() {
  if (!team.on()) return;
  try {
    const { labels } = await teamApi('GET', 'labels');
    teamLabels = {};
    for (const x of labels) teamLabels[keyOf(x.chain, x.address)] = x.label;
    for (const n of nodes.values()) if (teamLabels[n.key]) lightAnalyze(n);
    if (nodes.size) { render(false); refreshView(); }
  } catch { /* volgende keer */ }
}
function teamPushLabel(n, label) {
  if (!team.on()) return;
  if (label) teamLabels[n.key] = label; else delete teamLabels[n.key];
  teamApi('PUT', 'labels', { chain: n.chain, address: n.addr, label }).catch(e => setStatus(e.message, true));
}
let teamLoaded = null; // { caseId, seedKey, at, sig } — het geopende teamonderzoek (at = versie op de server)
const dossierSig = d => JSON.stringify({ ...d, exported: 0 });
async function teamPushItem(c, item, dossier, retry = 0) {
  if (!team.on() || !c.team || c.team.srv !== team.base() || !team.canEdit(c)) return;
  const same = teamLoaded && teamLoaded.caseId === c.id && teamLoaded.seedKey === item.seedKey;
  const sig = dossierSig(dossier);
  if (same && teamLoaded.sig === sig) return; // niets veranderd (bijv. alleen geopend)
  const path = `cases/${encodeURIComponent(c.team.id)}/items/${encodeURIComponent(item.seedKey)}`;
  try {
    const r = await teamApi('PUT', path, { base: same ? teamLoaded.at : undefined,
      meta: { chain: item.chain, addr: item.addr, role: item.role, pattern: item.pattern, title: item.title, size: item.size }, dossier });
    teamLoaded = { caseId: c.id, seedKey: item.seedKey, at: r.updated, sig };
    setTeamSync('ok');
  } catch (e) {
    // Een teamgenoot heeft intussen opgeslagen: diens versie samenvoegen met de onze en opnieuw opslaan.
    if (/Intussen/.test(e.message) && retry < 2 && current?.seedKey === item.seedKey) {
      const r = await teamApi('GET', path);
      importJson(r.dossier, { merge: true });
      render(true); renderSummary(); refreshView();
      teamLoaded = { caseId: c.id, seedKey: item.seedKey, at: r.updated, sig: '' };
      setStatus(`Samengevoegd met de wijzigingen van ${r.updatedBy || 'een teamgenoot'}.`);
      const merged = buildDossier();
      return teamPushItem(c, { ...item, size: nodes.size }, merged, retry + 1);
    }
    setTeamSync('err', e.message);
  }
}
function setTeamSync(state, msg) {
  const el = $('#teamSync');
  if (!el) return;
  el.hidden = !team.on() || !caseById(cases.currentId())?.team;
  el.className = 'team-sync ' + state;
  el.textContent = state === 'ok' ? '☁ gedeeld' : state === 'err' ? '⚠ niet gedeeld' : '☁';
  el.title = msg || (state === 'ok' ? 'Opgeslagen op de teamserver' : '');
}
async function teamOpenItem(c, seedKey) {
  const r = await teamApi('GET', `cases/${encodeURIComponent(c.team.id)}/items/${encodeURIComponent(seedKey)}`);
  try { await idb.set(`dossier:${c.id}:${seedKey}`, r.dossier); } catch { /* alleen cache */ }
  teamLoaded = { caseId: c.id, seedKey, at: r.updated, sig: dossierSig(r.dossier) };
  return r.dossier;
}
// Lokale zaak naar de teamserver brengen.
async function teamUpload(c) {
  const { case: s } = await teamApi('POST', 'cases', { name: c.name });
  let n = 0;
  for (const i of c.items) {
    const d = await idb.get(`dossier:${c.id}:${i.seedKey}`);
    if (!d) continue;
    await teamApi('PUT', `cases/${encodeURIComponent(s.id)}/items/${encodeURIComponent(i.seedKey)}`, { meta: { chain: i.chain, addr: i.addr, role: i.role, pattern: i.pattern, title: i.title, size: i.size }, dossier: d });
    await idb.set(`dossier:${teamCaseId(s.id)}:${i.seedKey}`, d).catch(() => {});
    n++;
  }
  const wasCurrent = cases.currentId() === c.id;
  for (const i of c.items) idb.del(`dossier:${c.id}:${i.seedKey}`).catch(() => {});
  cases.save(cases.list().filter(x => x.id !== c.id));
  await teamSync();
  if (wasCurrent) cases.setCurrent(teamCaseId(s.id));
  caseSel = teamCaseId(s.id);
  renderCaseBar(); renderCases();
  return n;
}
// Periodiek kijken of teamgenoten iets hebben gewijzigd.
let teamPolledAt = 0, teamLabelsAt = 0, teamPollBusy = false;
async function teamPoll() {
  if (!team.on() || teamPollBusy || document.hidden) return;
  teamPollBusy = true;
  try {
    const ch = await teamApi('GET', 'changes?since=' + teamPolledAt);
    if (ch.cases.length) {
      await teamSync();
      if (teamLoaded && current && !current.merged) {
        const c = caseById(teamLoaded.caseId);
        const it = c?.items.find(i => i.seedKey === teamLoaded.seedKey);
        if (it && it.by && it.by !== team.me() && it.saved > teamLoaded.at && current.seedKey === it.seedKey) {
          teamLoaded.at = it.saved;
          showTeamNotice(`${it.by} heeft dit onderzoek bijgewerkt.`, () => openCaseItem(c.id, it.seedKey));
        }
      }
      if ($('#caseDlg').open && caseSel?.startsWith('t_')) renderTeamPanel(caseById(caseSel));
    }
    if (ch.labelsUpdated > teamLabelsAt) { teamLabelsAt = ch.labelsUpdated; await teamLoadLabels(); }
    teamPolledAt = ch.now - 1000;
  } catch { /* stil: volgende keer opnieuw */ }
  teamPollBusy = false;
}
function showTeamNotice(text, onReload) {
  const b = $('#teamNotice');
  $('#teamNoticeText').textContent = text;
  b.hidden = false;
  $('#teamNoticeReload').onclick = () => { b.hidden = true; onReload(); };
  $('#teamNoticeClose').onclick = () => { b.hidden = true; };
}
const teamLink = (kind, tok) => `${team.base()}/#${kind}=${tok}`;
const ROLE_NAME = { owner: 'eigenaar', edit: 'mag bewerken', view: 'mag alleen kijken' };
const ACT_TXT = { create: 'zaak aangemaakt', rename: 'naam gewijzigd', add: 'onderzoek toegevoegd', update: 'onderzoek bijgewerkt', remove: 'onderzoek verwijderd',
  member: 'lid toegevoegd', 'member-removed': 'lid verwijderd', link: 'deellink gemaakt', 'link-revoked': 'deellink ingetrokken', comment: 'opmerking', join: 'doet mee via deellink' };
const when = t => new Date(t).toLocaleString(window.CT_LOCALE, { dateStyle: 'short', timeStyle: 'short' });
async function renderTeamPanel(c) {
  const box = $('#caseTeam');
  if (!c) { box.hidden = true; return; }
  box.hidden = false;
  if (!c.team) {
    box.innerHTML = team.on()
      ? `<p class="small muted">Deze zaak staat alleen op dit apparaat.</p><button type="button" class="ghost wide" data-team="upload">☁ Delen met mijn team (naar teamserver)</button>`
      : `<p class="small muted">Samenwerken? Koppel de app aan een ChainTrace-teamserver om zaken te delen met collega's.</p><button type="button" class="ghost wide" data-team="connect">☁ Teamserver koppelen</button>`;
    return;
  }
  if (!team.on() || c.team.srv !== team.base()) { box.innerHTML = `<p class="small muted">Teamzaak op ${esc(c.team.srv)}. Log in op die teamserver om mee te werken.</p><button type="button" class="ghost wide" data-team="connect">☁ Inloggen</button>`; return; }
  const owner = c.team.role === 'owner', canEdit = c.team.role !== 'view';
  box.innerHTML = `<p class="small muted">☁ Teamzaak · jij ${esc(ROLE_NAME[c.team.role] || c.team.role)} · eigenaar ${esc(c.team.owner || '?')}</p><div class="muted small">Laden…</div>`;
  let com = [], act = [], links = [];
  try {
    const sid = encodeURIComponent(c.team.id);
    [com, act, links] = await Promise.all([
      teamApi('GET', `cases/${sid}/comments`).then(r => r.comments),
      teamApi('GET', `cases/${sid}/activity`).then(r => r.activity),
      owner ? teamApi('GET', `cases/${sid}/links`).then(r => r.links) : []
    ]);
  } catch (e) { box.innerHTML = `<p class="small err">${esc(e.message)}</p>`; return; }
  if (caseSel !== c.id) return;
  box.innerHTML = `<h4>Wie werkt mee?</h4>
    <div class="team-members">${(c.team.members || []).map(m => `<span class="chip">${esc(m.username)} <small>${esc(ROLE_NAME[m.role] || m.role)}</small>${owner && m.role !== 'owner' ? `<button type="button" class="chip-x" data-team="kick" data-user="${esc(m.username)}" aria-label="Verwijderen">×</button>` : ''}</span>`).join('')}</div>
    ${owner ? `<div class="team-row"><input id="teamAddName" type="text" placeholder="gebruikersnaam collega" autocomplete="off" spellcheck="false"><select id="teamAddRole"><option value="edit">mag bewerken</option><option value="view">mag alleen kijken</option></select><button type="button" class="ghost" data-team="add">Toevoegen</button></div>
    <h4>Delen via een link</h4>
    <div class="lbtns"><button type="button" class="ghost" data-team="link-view">🔗 Link: alleen kijken (zonder account)</button><button type="button" class="ghost" data-team="link-edit">🔗 Link: meewerken (met account)</button></div>
    ${links.length ? `<div class="small muted team-links">${links.map(l => `<div>${l.role === 'view' ? 'Alleen kijken' : 'Meewerken'} · ${esc(l.hint || '')} · ${when(l.created)} <button type="button" class="linkbtn" data-team="revoke" data-link="${esc(l.id)}">intrekken</button></div>`).join('')}</div>` : ''}` : ''}
    <h4>Opmerkingen</h4>
    <div class="team-comments">${com.map(x => `<div class="team-comment"><b>${esc(x.by || '?')}</b> <small class="muted">${when(x.created)}</small><div>${esc(x.text)}</div></div>`).join('') || '<p class="small muted">Nog geen opmerkingen.</p>'}</div>
    ${canEdit ? `<div class="team-row"><input id="teamComment" type="text" placeholder="Opmerking voor het team…"><button type="button" class="ghost" data-team="comment">Plaatsen</button></div>` : ''}
    <details class="team-act"><summary>Activiteit</summary>${act.slice(0, 30).map(a => `<div class="small">${when(a.created)} · <b>${esc(a.by || '?')}</b> ${esc(ACT_TXT[a.action] || a.action)}${a.detail ? ': ' + esc(a.detail) : ''}</div>`).join('')}</details>`;
}
async function teamPanelClick(ev) {
  const b = ev.target.closest('[data-team]');
  if (!b) return;
  const c = caseById(caseSel);
  const sid = c?.team && encodeURIComponent(c.team.id);
  try {
    switch (b.dataset.team) {
      case 'connect': openTeam(); return;
      case 'upload': {
        if (!confirm(`Zaak "${c.name}" naar de teamserver brengen? Daarna kun je collega's toevoegen en via een link delen.`)) return;
        b.disabled = true; b.textContent = 'Bezig…';
        const n = await teamUpload(c);
        setStatus(`Zaak gedeeld: ${n} onderzoek(en) staan nu op de teamserver.`);
        return;
      }
      case 'add': {
        const u = $('#teamAddName').value.trim();
        if (!u) return;
        await teamApi('POST', `cases/${sid}/members`, { username: u, role: $('#teamAddRole').value });
        await teamSync(); break;
      }
      case 'kick':
        if (!confirm(`${b.dataset.user} uit deze zaak verwijderen?`)) return;
        await teamApi('DELETE', `cases/${sid}/members/${encodeURIComponent(b.dataset.user)}`);
        await teamSync(); break;
      case 'link-view': case 'link-edit': {
        const role = b.dataset.team === 'link-view' ? 'view' : 'edit';
        const { token } = await teamApi('POST', `cases/${sid}/links`, { role });
        const url = teamLink(role === 'view' ? 'view' : 'join', token);
        const text = role === 'view' ? `Bekijk zaak "${c.name}" in ChainTrace (alleen kijken): ${url}` : `Werk mee aan zaak "${c.name}" in ChainTrace: ${url}`;
        if (window.AndroidBridge?.shareText) window.AndroidBridge.shareText(text);
        else if (navigator.share && isMobile()) navigator.share({ text }).catch(() => copyPlain(url));
        else await copyPlain(url);
        setStatus(role === 'view' ? 'Link gekopieerd: iedereen met deze link kan de zaak bekijken.' : 'Link gekopieerd: collega\'s met een account doen mee na inloggen.');
        break;
      }
      case 'revoke':
        await teamApi('DELETE', `cases/${sid}/links/${encodeURIComponent(b.dataset.link)}`); break;
      case 'comment': {
        const t = $('#teamComment').value.trim();
        if (!t) return;
        await teamApi('POST', `cases/${sid}/comments`, { text: t, seedKey: current?.seedKey || null }); break;
      }
    }
    renderTeamPanel(caseById(caseSel));
  } catch (e) { setStatus(e.message, true); alert(e.message); renderTeamPanel(caseById(caseSel)); }
}

// --- teamdialoog: koppelen, inloggen, beheer ---
function renderTeamState() {
  const on = team.on(), cfg = team.cfg();
  $('#teamUrl').value = cfg.url || (teamSameOrigin ? location.origin : '');
  $('#teamUrlBox').hidden = teamSameOrigin && !cfg.url;
  $('#teamLoginBox').hidden = on;
  $('#teamInBox').hidden = !on;
  $('#teamWho').textContent = on ? `${cfg.username} @ ${team.base().replace(/^https?:\/\//, '')}` : '';
  $('#teamAdminBox').hidden = !(on && cfg.admin);
  $('#btnTeam').textContent = on ? `☁ Team: ${cfg.username}` : '☁ Team';
  setTeamSync('');
}
async function openTeam() {
  renderTeamState();
  $('#teamMsg').textContent = '';
  $('#teamSetupBox').hidden = true;
  $('#teamDlg').showModal();
  if (!team.on() && team.base()) teamCheckSetup(team.base());
}
async function teamCheckSetup(base) {
  try {
    const info = await teamApi('GET', 'info', undefined, { auth: false, base });
    if (info.server !== 'chaintrace') throw new Error('Dit is geen ChainTrace-teamserver.');
    $('#teamSetupBox').hidden = !info.setupNeeded;
    return info;
  } catch (e) { $('#teamMsg').textContent = e.message; return null; }
}
function teamUrlInput() {
  let u = $('#teamUrl').value.trim().replace(/\/+$/, '');
  if (!u && teamSameOrigin) return location.origin;
  if (u && !/^https?:\/\//i.test(u)) u = 'https://' + u;
  return u;
}
async function teamLogin(setup = false) {
  const base = teamUrlInput();
  const msg = $('#teamMsg');
  if (!base) { msg.textContent = 'Vul het adres van de teamserver in.'; return; }
  if (location.protocol === 'https:' && /^http:/i.test(base) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(base)) { msg.textContent = 'Deze app kan alleen met een https://-teamserver verbinden.'; return; }
  const username = $('#teamUser').value.trim(), password = $('#teamPass').value;
  msg.textContent = 'Bezig…';
  try {
    const body = { username, password };
    if (setup) body.code = $('#teamCode').value.trim();
    const r = await teamApi('POST', setup ? 'setup' : 'login', body, { auth: false, base });
    team.setCfg({ url: base === location.origin && teamSameOrigin ? '' : base, token: r.token, username: r.username, admin: r.admin });
    $('#teamPass').value = ''; $('#teamCode').value = '';
    msg.textContent = '';
    renderTeamState();
    await teamSync(); await teamLoadLabels();
    teamPolledAt = Date.now();
    setStatus(`Ingelogd op de teamserver als ${r.username}.`);
    if (teamPendingJoin) { const t = teamPendingJoin; teamPendingJoin = null; await teamJoin(t); }
    else $('#teamDlg').close();
  } catch (e) { msg.textContent = e.message; }
}
async function teamLogout() {
  try { await teamApi('POST', 'logout'); } catch { /* lokaal toch uitloggen */ }
  const c = team.cfg(); delete c.token; delete c.admin; team.setCfg(c);
  teamLabels = {};
  // teamzaken blijven niet op het apparaat staan na uitloggen
  const keep = cases.list().filter(x => !x.team);
  for (const x of cases.list().filter(x => x.team)) for (const i of x.items) idb.del(`dossier:${x.id}:${i.seedKey}`).catch(() => {});
  cases.save(keep);
  if (!caseById(cases.currentId())) cases.setCurrent(null);
  renderCaseBar(); renderTeamState();
  setStatus('Uitgelogd van de teamserver.');
}
let teamPendingJoin = null;
async function teamJoin(token) {
  if (!team.on()) { teamPendingJoin = token; openTeam(); $('#teamMsg').textContent = 'Log in om mee te werken aan de gedeelde zaak.'; return; }
  try {
    const { caseId } = await teamApi('POST', 'join', { token });
    await teamSync();
    $('#teamDlg').close();
    caseSel = teamCaseId(caseId);
    cases.setCurrent(caseSel); renderCaseBar();
    renderCases(); $('#caseDlg').showModal();
    setStatus('Je werkt nu mee aan deze zaak.');
  } catch (e) { setStatus(e.message, true); alert(e.message); }
}
// Alleen-kijken-link: zonder account de onderzoeken van de zaak samen in één web openen.
async function teamView(token) {
  try {
    const base = team.base() || location.origin;
    const { case: c } = await teamApi('GET', 'shared/' + encodeURIComponent(token), undefined, { auth: false, base });
    const ds = [];
    for (const i of c.items) { try { ds.push((await teamApi('GET', `shared/${encodeURIComponent(token)}/items/${encodeURIComponent(i.seedKey)}`, undefined, { auth: false, base })).dossier); } catch { /* overslaan */ } }
    if (!ds.length) { setStatus(`Gedeelde zaak "${c.name}" bevat nog geen onderzoeken.`); return; }
    importJson(ds[0]);
    for (const d of ds.slice(1)) importJson(d, { merge: true });
    current.merged = true; current.readOnly = true;
    $('#formBox').open = false;
    render(true); renderSummary(); refreshView();
    setStatus(`Gedeelde zaak "${c.name}" (alleen kijken): ${ds.length} onderzoek(en), ${nodes.size} adressen.`);
    if (isMobile()) setTab('graph');
  } catch (e) { setStatus(e.message, true); }
}
function teamHash() {
  const m = location.hash.match(/^#(join|view)=([A-Za-z0-9_-]{16,})$/);
  if (!m) return;
  history.replaceState(null, '', location.pathname + location.search);
  if (m[1] === 'view') teamView(m[2]); else teamJoin(m[2]);
}
async function setupTeam() {
  $('#btnTeam').addEventListener('click', openTeam);
  $('#teamClose').addEventListener('click', () => $('#teamDlg').close());
  $('#teamLogin').addEventListener('click', () => teamLogin(false));
  $('#teamSetup').addEventListener('click', () => teamLogin(true));
  $('#teamPass').addEventListener('keydown', ev => { if (ev.key === 'Enter') teamLogin(!$('#teamSetupBox').hidden); });
  $('#teamUrl').addEventListener('change', () => { const b = teamUrlInput(); if (b) teamCheckSetup(b); });
  $('#teamLogout').addEventListener('click', teamLogout);
  $('#teamSyncNow').addEventListener('click', async () => { try { await teamSync(); await teamLoadLabels(); $('#teamMsg').textContent = 'Bijgewerkt.'; } catch (e) { $('#teamMsg').textContent = e.message; } });
  $('#teamAddUser').addEventListener('click', async () => {
    try {
      await teamApi('POST', 'users', { username: $('#teamNewUser').value.trim(), password: $('#teamNewPass').value, admin: $('#teamNewAdmin').checked });
      $('#teamMsg').textContent = `Account ${$('#teamNewUser').value.trim()} aangemaakt. Geef de gebruikersnaam en het wachtwoord door aan je collega.`;
      $('#teamNewUser').value = ''; $('#teamNewPass').value = ''; $('#teamNewAdmin').checked = false;
    } catch (e) { $('#teamMsg').textContent = e.message; }
  });
  $('#teamPwChange').addEventListener('click', async () => {
    const old = prompt('Huidig wachtwoord:'); if (!old) return;
    const nw = prompt('Nieuw wachtwoord (minstens 8 tekens):'); if (!nw) return;
    try { const r = await teamApi('POST', 'me/password', { old, new: nw }); team.setCfg({ ...team.cfg(), token: r.token }); $('#teamMsg').textContent = 'Wachtwoord gewijzigd.'; }
    catch (e) { $('#teamMsg').textContent = e.message; }
  });
  $('#caseTeam').addEventListener('click', teamPanelClick);
  $('#caseTeam').addEventListener('keydown', ev => { if (ev.key === 'Enter' && ev.target.id === 'teamComment') teamPanelClick({ target: $('[data-team="comment"]') }); });
  window.addEventListener('hashchange', teamHash);
  // Webversie die door de teamserver zelf wordt geleverd: automatisch herkennen.
  if (/^https?:$/.test(location.protocol) && location.hostname !== 'appassets.androidplatform.net') {
    try {
      const r = await fetch('api/info', { cache: 'no-store' });
      const j = r.ok && (r.headers.get('content-type') || '').includes('json') ? await r.json() : null;
      teamSameOrigin = j?.server === 'chaintrace';
    } catch { /* gewone statische host */ }
  }
  $('#btnTeam').hidden = false;
  renderTeamState();
  teamHash();
  if (team.on()) {
    teamPolledAt = Date.now();
    teamSync().catch(() => {}); teamLoadLabels();
  }
  setInterval(teamPoll, 20000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) teamPoll(); });
}

function newCase(name) {
  const c = { id: 'c' + Date.now().toString(36), name: name || `Zaak van ${new Date().toLocaleDateString(window.CT_LOCALE, { day: 'numeric', month: 'long', year: 'numeric' })}`, created: Date.now(), items: [] };
  cases.save([c, ...cases.list()]);
  cases.setCurrent(c.id);
  renderCaseBar();
  return c;
}
function buildDossier() {
  const seed = nodes.get(current?.seedKey);
  return {
    tool: 'ChainTrace', version: 1, exported: new Date().toISOString(),
    case: current && { chain: current.chain, role: current.role, pattern: window.PATTERNS[current.pattern].name, patternKey: current.pattern, seed: seed?.addr, started: current.started },
    nodes: [...nodes.values()].map(n => ({ key: n.key, chain: n.chain, address: n.addr, label: labelOf(n), role: n.role, classification: nodeClass(n), hop: n.depth, flags: n.flags, seed: !!n.seed, hint: n.hint, parent: n.parent, upstream: !!n.upstream })),
    edges: [...edges.values()].map(e => ({ ...e, first: e.first === Infinity ? null : e.first })),
    origins: { rootKey: origins.rootKey, starts: [...origins.starts.values()], cashIn: origins.cashIn },
    notes,
    customLabels
  };
}
let saveTimer = null;
function autosave() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    if (!current || demoMode || current.merged || current.readOnly || !nodes.size) return;
    const seed = nodes.get(current.seedKey);
    if (!seed || isDemoAddr(seed.addr)) return;
    let c = caseById(cases.currentId());
    if (c && !team.canEdit(c)) c = null; // alleen-kijken-teamzaak: in een eigen zaak bewaren
    c = c || newCase();
    const item = { seedKey: current.seedKey, chain: current.chain, addr: seed.addr, role: current.role, pattern: window.PATTERNS[current.pattern].name,
      title: labelOf(seed) || short(seed.addr), saved: Date.now(), size: nodes.size };
    const dossier = buildDossier();
    try { await idb.set(`dossier:${c.id}:${current.seedKey}`, dossier); } catch { return; }
    const list = cases.list();
    c = list.find(x => x.id === c.id);
    c.items = [item, ...c.items.filter(i => i.seedKey !== item.seedKey)];
    c.updated = Date.now();
    cases.save(list);
    renderCaseBar();
    if (c.team) teamPushItem(c, item, dossier);
  }, 1500);
}
function renderCaseBar() {
  const c = caseById(cases.currentId());
  $('#caseName').textContent = c ? c.name : 'nog geen zaak';
  $('#caseCount').textContent = c ? `${c.items.length} onderzoek${c.items.length === 1 ? '' : 'en'}` : '';
  setTeamSync(c?.team ? 'ok' : '');
}
let caseSel = null;
function renderCases() {
  const list = cases.list();
  if (!caseSel || !list.some(c => c.id === caseSel)) caseSel = cases.currentId() || list[0]?.id || null;
  const c = list.find(x => x.id === caseSel);
  $('#caseList').innerHTML = list.map(x => `<button type="button" class="case-item ${x.id === caseSel ? 'active' : ''}" data-case="${x.id}">
      <b>${x.team ? '☁ ' : ''}${esc(x.name)}</b><small>${x.items.length} onderzoek${x.items.length === 1 ? '' : 'en'} · ${new Date(x.updated || x.created).toLocaleDateString(window.CT_LOCALE)}${x.id === cases.currentId() ? ' · <em>huidige zaak</em>' : ''}</small></button>`).join('')
    || '<p class="muted">Nog geen zaken. Een onderzoek wordt automatisch bewaard zodra het klaar is.</p>';
  $('#caseDetail').hidden = !c;
  if (!c) return;
  $('#caseTitle').textContent = c.name;
  $('#caseItems').innerHTML = c.items.map(i => `<div class="xrow"><div class="xrow-top"><i class="dot ${i.role === 'perp' ? 'perp' : 'victim'}"></i><b>${esc(i.title)}</b><span class="muted small">${esc(CHAIN_NAME[i.chain] || i.chain)}</span></div>
      <div class="xrow-sub muted">${i.role === 'perp' ? 'Dader' : 'Slachtoffer'} · ${esc(i.pattern)} · ${i.size} adressen · bewaard ${new Date(i.saved).toLocaleString(window.CT_LOCALE, { dateStyle: 'short', timeStyle: 'short' })}${i.by ? ` door ${esc(i.by)}` : ''}</div>
      <div class="lbtns"><button type="button" class="ghost" data-open="${esc(i.seedKey)}">Openen</button>${team.canEdit(c) ? `<button type="button" class="ghost" data-del="${esc(i.seedKey)}">Verwijderen</button>` : ''}</div></div>`).join('')
    || '<p class="muted">Deze zaak heeft nog geen onderzoeken. Start een onderzoek: het wordt hier automatisch bewaard.</p>';
  $('#caseMerge').disabled = c.items.length < 2;
  $('#caseRename').hidden = !team.canEdit(c);
  $('#caseUse').hidden = !team.canEdit(c);
  $('#caseDelete').hidden = !!c.team && c.team.role !== 'owner';
  renderTeamPanel(c);
}
// Dossier van een onderzoek: lokaal, of van de teamserver.
async function caseDossier(c, seedKey) {
  if (c?.team && team.on() && c.team.srv === team.base()) { try { return await teamOpenItem(c, seedKey); } catch (e) { setStatus(e.message, true); } }
  return idb.get(`dossier:${c?.id}:${seedKey}`);
}
async function openCaseItem(caseId, seedKey, merge = false) {
  const d = await caseDossier(caseById(caseId), seedKey);
  if (!d) { setStatus('Dit onderzoek kon niet worden geladen.', true); return; }
  importJson(d, { merge });
}
async function mergeCase(c) {
  const ds = [];
  for (const i of c.items) { const d = await caseDossier(c, i.seedKey); if (d) ds.push(d); }
  if (!ds.length) return;
  importJson(ds[0]);
  for (const d of ds.slice(1)) importJson(d, { merge: true });
  // Adressen die in meerdere onderzoeken voorkomen: belangrijke verbanden.
  const seen = new Map();
  for (const d of ds) for (const x of new Set(d.nodes.map(n => n.key))) seen.set(x, (seen.get(x) || 0) + 1);
  let overlap = 0;
  for (const [k, cnt] of seen) if (cnt > 1 && nodes.has(k)) { addFlag(nodes.get(k), 'overlap', 'high', `Komt voor in ${cnt} onderzoeken van deze zaak`); overlap++; }
  current.merged = true;
  render(true); renderSummary();
  setStatus(`${ds.length} onderzoeken samen in één web: ${nodes.size} adressen, ${overlap} adres(sen) komen in meer dan één onderzoek voor.`);
  if (isMobile()) setTab('graph');
}

// ---------- gevolgde adressen: melding bij nieuwe beweging ----------
const watch = {
  get() {
    if (window.AndroidBridge?.getWatchlist) { try { return JSON.parse(window.AndroidBridge.getWatchlist() || '[]'); } catch { return []; } }
    return store.get('chaintrace.watch', []);
  },
  set(l) {
    if (window.AndroidBridge?.saveWatchlist) window.AndroidBridge.saveWatchlist(JSON.stringify(l));
    else store.set('chaintrace.watch', l);
    renderWatchBanner();
  }
};
const watchKey = (chain, addr) => keyOf(chain, addr);
const isWatched = n => watch.get().some(w => watchKey(w.chain, w.addr) === n.key);

// Een korte "vingerafdruk" van de activiteit: verandert als er een nieuwe transactie is.
async function watchSig(chain, addr) {
  const g = (u, body) => getData(u + (body ? '' : (u.includes('?') ? '&' : '?') + '_t=' + Date.now()), false, 2, body);
  if (isUtxo(chain)) { const r = await g(`${API[chain]}/address/${addr}`); return String((r?.chain_stats?.tx_count || 0) + (r?.mempool_stats?.tx_count || 0)); }
  if (isBlockscout(chain)) { const c = await g(`${API[chain]}/addresses/${addr}/counters`); return `${c?.transactions_count || 0}/${c?.token_transfers_count || 0}`; }
  if (chain === 'avax') {
    const [a, b] = await Promise.all([g(`${API.avax}?module=account&action=txlist&address=${addr}&page=1&offset=1&sort=desc`), g(`${API.avax}?module=account&action=tokentx&address=${addr}&page=1&offset=1&sort=desc`)]);
    return `${rsArr(a)[0]?.hash || ''}/${rsArr(b)[0]?.hash || ''}`;
  }
  if (chain === 'zksync') { const r = await g(`${API.zksync}/address/${addr}/transfers?limit=1`); return String(r?.meta?.totalItems || 0); }
  if (chain === 'sol') { const r = await g(API.sol, { ...solRpc('getSignaturesForAddress', [addr, { limit: 1 }]), id: Date.now() }); return r?.result?.[0]?.signature || ''; }
  const r = await g(`${API.tron}/v1/accounts/${addr}/transactions/trc20?limit=1`);
  return r?.data?.[0]?.transaction_id || '';
}
async function toggleWatch(n) {
  const l = watch.get();
  const i = l.findIndex(w => watchKey(w.chain, w.addr) === n.key);
  if (i >= 0) { l.splice(i, 1); watch.set(l); setStatus('Dit adres wordt niet meer gevolgd.'); return; }
  let sig = '';
  try { sig = await watchSig(n.chain, n.addr); } catch { /* volgende controle legt de basis vast */ }
  l.push({ chain: n.chain, addr: n.addr, label: labelOf(n) || '', caseName: caseById(cases.currentId())?.name || '', added: Date.now(), sig, lastCheck: Date.now(), changed: false });
  watch.set(l);
  try { window.AndroidBridge?.watchEnabled?.(); } catch { /* geen melding-rechten */ }
  setStatus('Dit adres wordt nu gevolgd. Je krijgt een melding als er weer geld beweegt.');
}
let watchBusy = false;
async function checkWatches(manual = false) {
  if (watchBusy) return;
  const l = watch.get();
  if (!l.length) { if (manual) setStatus('Je volgt nog geen adressen.'); return; }
  watchBusy = true;
  let changed = 0;
  for (const w of l) {
    try {
      const sig = await sigOf(w);
      if (w.sig && sig && sig !== w.sig) { w.changed = true; w.lastChange = Date.now(); changed++; }
      if (sig) w.sig = sig;
      w.lastCheck = Date.now();
    } catch { /* volgende keer opnieuw */ }
  }
  // De lijst kan intussen (door de achtergrondtaak) gewijzigd zijn: alleen onze velden terugschrijven.
  const fresh = watch.get();
  for (const f of fresh) { const m = l.find(w => w.chain === f.chain && w.addr === f.addr); if (m) Object.assign(f, { sig: m.sig, lastCheck: m.lastCheck, changed: f.changed || m.changed, lastChange: m.lastChange || f.lastChange }); }
  watch.set(fresh);
  watchBusy = false;
  if (manual) setStatus(changed ? `Nieuwe beweging op ${changed} adres(sen)!` : 'Gecontroleerd: geen nieuwe beweging.');
  if ($('#watchDlg').open) renderWatches();
}
function renderWatchBanner() {
  const n = watch.get().filter(w => w.changed).length;
  $('#watchBanner').hidden = !n;
  $('#watchBannerText').textContent = `Nieuwe beweging op ${n} gevolgd${n === 1 ? ' adres' : 'e adressen'}`;
}
function renderWatches() {
  const l = watch.get();
  $('#watchList').innerHTML = l.map((w, i) => `<div class="xrow ${w.changed ? 'wnew' : ''}">
      <div class="xrow-top"><b>${w.members ? '👛 ' : ''}${esc(w.label || short(w.addr))}</b><span class="muted small">${esc(CHAIN_NAME[w.chain] || w.chain)}</span>${w.changed ? '<span class="tag high">NIEUW</span>' : ''}</div>
      <div class="xrow-sub muted">${w.changed ? `Nieuwe beweging gezien op ${new Date(w.lastChange).toLocaleString(window.CT_LOCALE, { dateStyle: 'short', timeStyle: 'short' })}` : 'Geen nieuwe beweging'} · laatst gecontroleerd ${w.lastCheck ? new Date(w.lastCheck).toLocaleString(window.CT_LOCALE, { dateStyle: 'short', timeStyle: 'short' }) : 'nog niet'}${w.caseName ? ' · ' + esc(w.caseName) : ''}</div>
      <div class="lbtns"><button type="button" class="ghost" data-wopen="${i}">Bekijk</button><button type="button" class="ghost" data-wdel="${i}">Stop met volgen</button></div></div>`).join('')
    || '<p class="muted">Je volgt nog geen adressen. Open een adres en tik op "🔔 Volg dit adres".</p>';
}
function openWatch(i) {
  const l = watch.get();
  const w = l[i];
  if (!w) return;
  w.changed = false;
  watch.set(l);
  // Verse gegevens ophalen: oude antwoorden voor dit adres vergeten.
  for (const k of [...cache.keys()]) if (k.includes(w.addr)) cache.delete(k);
  const n = nodes.get(keyOf(w.chain, w.addr)) || ghosts.get(keyOf(w.chain, w.addr));
  if (n) { n.data = null; n.loadTried = false; }
  $('#watchDlg').close();
  openAddr(w.chain, w.addr);
  if (w.members) {
    // Wallet bijwerken: na het opnieuw laden kan de wallet nieuwe adressen hebben gekregen.
    for (const a of w.members) { const m = nodes.get(keyOf(w.chain, a)) || ghosts.get(keyOf(w.chain, a)); if (m) { m.data = null; m.loadTried = false; } }
    setTimeout(() => {
      invalidateClusters();
      const c = clusterOf(keyOf(w.chain, w.addr));
      if (!c || c.members.length <= w.members.length) return;
      const l2 = watch.get(), e = l2.find(x => x.members && x.addr === w.addr);
      if (!e) return;
      const added = c.members.length - e.members.length;
      e.members = c.members.map(k => k.split(':')[1]).slice(0, 20);
      watch.set(l2);
      setStatus(`De wallet heeft ${added} nieuw(e) adres(sen); de tracker volgt ze nu ook.`);
    }, 8000);
  }
}

// ---------- rondleiding (gebruikt de voorbeeldzaak) ----------
const tour = { on: false };
class TourStop extends Error {}
const tourWait = ms => new Promise((res, rej) => {
  const t0 = Date.now();
  const tick = () => { if (!tour.on) return rej(new TourStop()); if (Date.now() - t0 >= ms) return res(); setTimeout(tick, 100); };
  tick();
});
function tourTop() { for (const id of ['#tourRing', '#tourCap']) { const e = $(id); try { if (e.matches(':popover-open')) e.hidePopover(); e.showPopover(); } catch { /* geen popover-API */ } } }
function tourCaption(text) {
  $('#tourText').textContent = text;
  $('#tourCap').hidden = false;
  tourTop();
  if (tour.voice) speak(text);
}
function tourPoint(el) {
  const ring = $('#tourRing');
  if (!el) { ring.hidden = true; return; }
  el.scrollIntoView({ block: 'center', behavior: 'smooth' });
  setTimeout(() => {
    const r = el.getBoundingClientRect();
    Object.assign(ring.style, { left: (r.left - 6) + 'px', top: (r.top - 6) + 'px', width: (r.width + 12) + 'px', height: (r.height + 12) + 'px' });
    ring.hidden = false;
    tourTop();
  }, 350);
}
const q = s => typeof s === 'string' ? document.querySelector(s) : s;
async function tStep(text, ms, sel) {
  const el = sel ? q(sel) : null;
  if (sel && !el) console.warn('rondleiding: niet gevonden', sel);
  tourCaption(text); tourPoint(el); await tourWait(ms);
}
async function tClick(sel, after = 1500) {
  const el = q(sel);
  if (!el) { console.warn('rondleiding: niet gevonden', sel); return; }
  tourPoint(el);
  await tourWait(900);
  $('#tourRing').classList.add('press');
  el.click();
  await tourWait(250);
  $('#tourRing').classList.remove('press');
  await tourWait(after);
}
async function tType(sel, text) {
  const el = q(sel);
  tourPoint(el);
  el.value = '';
  for (let i = 0; i < text.length; i += 3) { el.value = text.slice(0, i + 3); await tourWait(40); }
  updateChainHint();
}
async function runTour() {
  if (tour.on) return;
  tour.on = true;
  tour.voice = !!$('#tourVoice')?.checked;
  $('#formBox').open = true;
  hideDetail();
  demoMode = false;
  resetGraph();
  render(true);
  setTab('form');
  try {
    await tStep('Welkom bij ChainTrace! In deze rondleiding volgen we samen het geld in een verzonnen oplichtingszaak.', 5000);
    await tStep('Stap 1: plak het walletadres van het slachtoffer. Je mag ook een heel bericht plakken, of met de QR-knop een QR-code uit een foto lezen.', 3500, '#addr');
    await tType('#addr', DEMO.victim);
    await tourWait(1200);
    await tStep('Stap 2: kies van wie het adres is. Hier: van het slachtoffer.', 3500, '.seg');
    $('#pattern').value = 'pig'; applyPatternDefaults(); $('#depth').value = 4;
    await tStep('Stap 3: kies wat er gebeurde. Hier: een nep-beleggingsplatform. Dit mag je ook overslaan.', 4000, '#pattern');
    await tStep('Tik op "Start onderzoek". De app volgt nu automatisch waar het geld heen ging.', 2500, '#btnTrace');
    await tClick('#btnTrace', 600);
    for (let i = 0; i < 60 && $('#btnTrace').disabled; i++) await tourWait(250);
    setTab('graph');
    cy?.fit(undefined, 40);
    await tStep('Het web toont alle adressen en geldstromen. Rood en oranje is verdacht, groen is een exchange, paars een mixer.', 6500, '#cy');
    setTab('form');
    await tStep('De samenvatting vertelt in gewone taal wat er gevonden is.', 5000, '#summary');
    await tStep('"Het geld stap voor stap" laat de route zien: van het slachtoffer, via doorsluisadressen, naar een exchange.', 6500, '#routeList .route-card');
    await tStep('Bij een exchange kan de politie opvragen van wie het account is. Met één tik maak je een brief aan de exchange.', 4500, '#routeList [data-letter]');
    await tClick('#routeList [data-letter]', 800);
    await tStep('De brief is al ingevuld met adressen, transacties en tijden. Vul je naam en aangiftenummer in en kopieer of deel de brief.', 6500, '#lText');
    $('#letterDlg').close();
    await tStep('Tik op een stap om dat adres te bekijken.', 2500, '#routeList .route-steps li');
    await tClick('#routeList .route-steps li', 1500);
    await tStep('Bovenaan staat in gewone taal wat we over dit adres weten.', 5500, '#detailBody .story');
    const help = $('#detailBody .tag.help[data-help=passthrough]') || $('#detailBody .tag.help');
    await tStep('Tik op een label met een vraagteken voor uitleg.', 2500, help);
    await tClick(help, 1000);
    await tourWait(3000);
    $('#helpDlg').close();
    await tStep('"Waar kwam het vandaan?" zoekt wie er nog meer geld naar dit adres stuurde: mogelijk andere slachtoffers.', 4000, '#detailBody [data-act=origins]');
    await tClick('#detailBody [data-act=origins]', 1500);
    await tStep('Tik op een transactie om te zien wie betaalde en wie ontving. Zo klik je door, net als in een blockchain-verkenner.', 4000, '#detailBody [data-tx]');
    await tClick('#detailBody [data-tx]', 1200);
    await tourWait(3000);
    await tStep('Met "Terug" ga je een stap terug.', 2500, '#detailBody [data-nav=back]');
    await tClick('#detailBody [data-nav=back]', 1000);
    await tStep('Met "Volg dit adres" krijg je een melding als er weer geld beweegt. Met de luidspreker laat je de uitleg voorlezen.', 6000, '#detailBody [data-act=watch]');
    closeExplorer();
    await tourWait(600);
    setTab('form');
    await tStep('Echte onderzoeken worden automatisch bewaard onder "Mijn zaken". Daar kun je ook meerdere onderzoeken samen in één web zetten.', 6000, '#caseBar');
    await tStep('Maak tot slot een PDF-rapport met alle adressen en transacties voor je aangifte.', 5000, '#btnPdf');
    await tStep('Klaar! Je kunt deze rondleiding altijd opnieuw starten via "Meer". Succes met je onderzoek.', 5000);
  } catch (e) {
    if (!(e instanceof TourStop)) console.error(e);
  } finally {
    stopTour();
  }
}
function stopTour() {
  tour.on = false;
  for (const id of ['#tourRing', '#tourCap']) { const e = $(id); e.hidden = true; try { e.hidePopover(); } catch { /* */ } }
  stopSpeak();
}

function setupFeatures() {
  // voorbeeldzaak en rondleiding
  $('#btnDemo').addEventListener('click', startDemo);
  $('#btnTourEmpty').addEventListener('click', runTour);
  $('#btnTour').addEventListener('click', runTour);
  $('#btnTourStop').addEventListener('click', stopTour);
  $('#btnDemoStop').addEventListener('click', () => { demoMode = false; resetGraph(); render(true); $('#formBox').open = true; renderFormSummary(); renderOverview(); $('#addr').value = ''; updateChainHint(); setStatus(''); renderDemoBanner(); });
  // keuze van de EVM-keten
  $('#chainPick').addEventListener('click', ev => {
    const b = ev.target.closest('[data-pick]');
    if (!b) return;
    $('#chain').value = b.dataset.pick;
    const e = new Event('submit', { cancelable: true });
    e.chainPicked = true;
    $('#traceForm').dispatchEvent(e);
    $('#chain').value = 'auto';
    $('#chainPick').hidden = true;
  });
  // voorlezen
  document.addEventListener('click', ev => {
    const b = ev.target.closest('[data-speak]');
    if (b) { ev.preventDefault(); ev.stopPropagation(); speakTarget(b.dataset.speak, b); }
  }, true);
  for (const id of ['#speakSummary', '#speakRoute', '#speakHelp']) $(id).hidden = !canSpeak();
  window.ChainTraceSpeechDone = () => { speaking = false; };
  // zaken
  renderCaseBar();
  const dlg = $('#caseDlg');
  const openCases = () => { renderCases(); dlg.showModal(); };
  $('#btnCases').addEventListener('click', openCases);
  $('#btnCases2').addEventListener('click', openCases);
  $('#btnCaseClose').addEventListener('click', () => dlg.close());
  $('#caseList').addEventListener('click', ev => { const b = ev.target.closest('[data-case]'); if (b) { caseSel = b.dataset.case; renderCases(); } });
  $('#caseItems').addEventListener('click', async ev => {
    const o = ev.target.closest('[data-open]'), d = ev.target.closest('[data-del]');
    if (o) { cases.setCurrent(caseSel); renderCaseBar(); dlg.close(); await openCaseItem(caseSel, o.dataset.open); if (isMobile()) setTab('graph'); }
    if (d && confirm('Dit onderzoek uit de zaak verwijderen?')) {
      const l = cases.list(); const c = l.find(x => x.id === caseSel);
      if (c.team) { try { await teamApi('DELETE', `cases/${encodeURIComponent(c.team.id)}/items/${encodeURIComponent(d.dataset.del)}`); } catch (e) { alert(e.message); return; } }
      c.items = c.items.filter(i => i.seedKey !== d.dataset.del);
      cases.save(l); idb.del(`dossier:${caseSel}:${d.dataset.del}`).catch(() => {});
      renderCases(); renderCaseBar();
    }
  });
  $('#caseNew').addEventListener('click', () => {
    const name = prompt('Naam van de nieuwe zaak (bijv. aangiftenummer of naam slachtoffer):', '');
    if (name === null) return;
    caseSel = newCase(name.trim() || undefined).id;
    renderCases();
    setStatus('Nieuwe onderzoeken worden nu in deze zaak bewaard.');
  });
  $('#caseUse').addEventListener('click', () => { cases.setCurrent(caseSel); renderCaseBar(); renderCases(); setStatus('Nieuwe onderzoeken worden nu in deze zaak bewaard.'); });
  $('#caseRename').addEventListener('click', async () => {
    const l = cases.list(); const c = l.find(x => x.id === caseSel); if (!c) return;
    const name = prompt('Nieuwe naam:', c.name);
    if (!name?.trim()) return;
    if (c.team) { try { await teamApi('PATCH', `cases/${encodeURIComponent(c.team.id)}`, { name: name.trim() }); } catch (e) { alert(e.message); return; } }
    c.name = name.trim(); cases.save(l); renderCases(); renderCaseBar();
  });
  $('#caseMerge').addEventListener('click', async () => { const c = caseById(caseSel); if (!c) return; dlg.close(); await mergeCase(c); });
  $('#caseDelete').addEventListener('click', async () => {
    const c = caseById(caseSel); if (!c) return;
    if (!confirm(c.team ? `Teamzaak "${c.name}" voor het hele team verwijderen? Dit kan niet ongedaan worden gemaakt.` : `Zaak "${c.name}" met ${c.items.length} onderzoek(en) verwijderen? Dit kan niet ongedaan worden gemaakt.`)) return;
    if (c.team) { try { await teamApi('DELETE', `cases/${encodeURIComponent(c.team.id)}`); } catch (e) { alert(e.message); return; } }
    for (const i of c.items) idb.del(`dossier:${c.id}:${i.seedKey}`).catch(() => {});
    cases.save(cases.list().filter(x => x.id !== c.id));
    if (cases.currentId() === c.id) cases.setCurrent(null);
    caseSel = null; renderCases(); renderCaseBar();
  });
  // gevolgde adressen
  const wd = $('#watchDlg');
  const openWatches = () => { renderWatches(); wd.showModal(); };
  $('#btnWatch').addEventListener('click', openWatches);
  $('#watchBannerBtn').addEventListener('click', openWatches);
  $('#btnWatchClose').addEventListener('click', () => wd.close());
  $('#btnWatchCheck').addEventListener('click', () => checkWatches(true));
  $('#watchList').addEventListener('click', ev => {
    const o = ev.target.closest('[data-wopen]'), d = ev.target.closest('[data-wdel]');
    if (o) openWatch(+o.dataset.wopen);
    if (d) { const l = watch.get(); l.splice(+d.dataset.wdel, 1); watch.set(l); renderWatches(); }
  });
  renderWatchBanner();
  setTimeout(() => checkWatches(false), 4000);
  setInterval(() => checkWatches(false), 30 * 60 * 1000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) renderWatchBanner(); });
  // vanuit een melding geopend?
  window.ChainTraceOpenWatch = a => { const i = watch.get().findIndex(x => x.addr === a); if (i >= 0) openWatch(i); };
  const w = new URLSearchParams(location.search).get('watch');
  if (w) setTimeout(() => { const i = watch.get().findIndex(x => x.addr === w); if (i >= 0) openWatch(i); }, 500);
}

// ---------- instellingen: eigen sleutels (optioneel) en taal ----------
var SOL_DEFAULT = 'https://solana-rpc.publicnode.com';
const settings = {
  get: () => store.get('chaintrace.settings', {}),
  set: s => { store.set('chaintrace.settings', s); applySettings(); }
};
const tronKey = () => settings.get().tronKey || '';
function applySettings() {
  const s = settings.get();
  API.sol = (s.solRpc || '').trim() || SOL_DEFAULT;
  HOST_GAP['api.trongrid.io'] = s.tronKey ? 120 : 1050;
}
const solLimit = () => API.sol === SOL_DEFAULT ? 20 : 60;
function openSettings() {
  const s = settings.get();
  $('#setSol').value = s.solRpc || '';
  $('#setTron').value = s.tronKey || '';
  $('#setLang').value = store.get('chaintrace.lang', 'nl');
  const cr = clusterRules();
  $('#clInput').checked = cr.input; $('#clChange').checked = cr.change; $('#clDeposit').checked = cr.deposit; $('#clGas').checked = cr.gas;
  $('#settingsDlg').showModal();
}
async function saveSettings() {
  const solRpc = $('#setSol').value.trim(), tron = $('#setTron').value.trim();
  if (solRpc && !/^https:\/\/[^\s]+$/.test(solRpc)) { $('#setMsg').textContent = 'Het Solana-adres moet met https:// beginnen.'; return; }
  settings.set({ solRpc, tronKey: tron, cluster: { input: $('#clInput').checked, change: $('#clChange').checked, deposit: $('#clDeposit').checked, gas: $('#clGas').checked } });
  invalidateClusters();
  if (nodes.size) { render(true); renderSummary(); refreshView(); }
  for (const k of [...cache.keys()]) if (/trongrid|solana|helius|rpc/i.test(k)) cache.delete(k);
  const lang = $('#setLang').value;
  const langChanged = lang !== store.get('chaintrace.lang', 'nl');
  store.set('chaintrace.lang', lang);
  $('#settingsDlg').close();
  if (langChanged) location.reload();
  else setStatus('Instellingen opgeslagen.');
}
async function testSettings() {
  $('#setMsg').textContent = 'Testen…';
  const out = [];
  const sol = $('#setSol').value.trim() || SOL_DEFAULT;
  try {
    const r = await fetch(sol, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(solRpc('getSlot', [])) }).then(x => x.json());
    out.push(r.result ? '✓ Solana werkt' : '✗ Solana: ' + (r.error?.message || 'geen antwoord'));
  } catch (e) { out.push('✗ Solana: ' + e.message); }
  if (window.AndroidBridge?.solRpc && !$('#setSol').value.trim()) {
    try {
      const n = await nativeSolPost(solRpc('getSignaturesForAddress', ['9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM', { limit: 1 }]));
      out.push(n.code === 200 && n.text.includes('signature') ? '✓ Solana volledige geschiedenis werkt' : `✗ Solana volledige geschiedenis: HTTP ${n.code} ${String(n.text).slice(0, 80)}`);
    } catch (e) { out.push('✗ Solana volledige geschiedenis: ' + e.message); }
  }
  const key = $('#setTron').value.trim();
  if (key) {
    try {
      const r = await fetch(`${API.tron}/v1/accounts/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`, { headers: { 'TRON-PRO-API-KEY': key } });
      out.push(r.ok ? '✓ TronGrid-sleutel werkt' : `✗ TronGrid: HTTP ${r.status} (sleutel ongeldig?)`);
    } catch (e) { out.push('✗ TronGrid: ' + e.message); }
  }
  $('#setMsg').textContent = out.join(' · ');
}

// ---------- alleen geld met waarde (spamfilter) ----------
const NATIVE = new Set(['BTC', 'LTC', 'ETH', 'AVAX', 'SOL', 'TRX']);
const hasValue = t => !t.dust && (t.usd > 0 || NATIVE.has(t.asset));
// Als er wél waardevolle overboekingen zijn, laat de rest (tokens zonder koers) weg.
const valuedOrAll = list => { const v = list.filter(hasValue); return v.length ? v : list.filter(t => !t.dust); };

// ---------- wallets / zelfde beheerder: interne regels (geen externe labels nodig) ----------
// input:   Bitcoin/Litecoin-adressen die samen als input in één transactie zitten (zelfde sleutelhouder)
// change:  het wisselgeld-adres van zo'n transactie (zelfde adrestype als de inputs en/of geen rond bedrag)
// deposit: adressen die op hetzelfde klant-stortingsadres bij een exchange storten (zelfde klant)
// gas:     een nieuw adres dat eerst een klein bedrag (gas/startgeld) krijgt en daarna tokens doorstuurt
const MAX_GROUP = 15; // grotere input-groepen: mogelijk CoinJoin of exchange-batch, niet samenvoegen
const RULE_NL = { input: 'samen als input gebruikt', change: 'wisselgeld van dezelfde wallet', deposit: 'stort op hetzelfde stortingsadres', gas: 'kreeg startgeld (gas) van dit adres' };
const clusterRules = () => { const c = settings.get().cluster || {}; return { input: c.input !== false, change: c.change !== false, deposit: c.deposit !== false, gas: c.gas !== false }; };
// Slachtoffers (en mogelijke slachtoffers) nooit samenvoegen met andere adressen.
const victimLike = n => n.seed && current?.role !== 'perp' || n.role === 'victim' || n.hint === 'victim2' || n.upstream || nodeClass(n) === 'victim2';
const smallNative = t => { const usd = t.usd || (NATIVE_USD[t.asset] || 0) * t.value; return usd > 0 && usd < 60; };
function walletClusters() {
  const on = clusterRules();
  const parent = new Map(), why = new Map();
  const find = a => { let r = a; while (parent.get(r) !== r) r = parent.get(r); let x = a; while (parent.get(x) !== r) { const nx = parent.get(x); parent.set(x, r); x = nx; } return r; };
  const isBad = k => { const n = nodes.get(k) || ghosts.get(k); return !!n && isEndpoint(n); };
  const union = (a, b, rule) => {
    if (a === b || isBad(a) || isBad(b)) return;
    for (const k of [a, b]) if (!parent.has(k)) parent.set(k, k);
    if (!why.has(b)) why.set(b, { rule, with: a });
    if (!why.has(a)) why.set(a, { rule, with: b });
    const ra = find(a), rb = find(b);
    if (ra !== rb) parent.set(ra, rb);
  };
  const all = [...nodes.values(), ...ghosts.values()].filter(n => n.data);
  for (const n of all) {
    if (isEndpoint(n)) continue;
    const c = n.chain + ':';
    if (isUtxo(n.chain)) {
      if (on.input) for (const g of n.data.coInputs || []) if (g.length >= 2 && g.length <= MAX_GROUP) for (let i = 1; i < g.length; i++) union(c + g[0], c + g[i], 'input');
      if (on.change) for (const [a, ch] of n.data.changeLinks || []) union(c + a, c + ch, 'change');
    } else if (on.gas && n.data.transfers.length < 500) {
      // Eerste activiteit = klein bedrag in de eigen munt, daarna tokens doorsturen → financier en adres zijn waarschijnlijk dezelfde beheerder.
      const tr = n.data.transfers.filter(t => t.time && !t.dust).sort((a, b) => a.time - b.time);
      const first = tr[0];
      const funder = first && nodes.get(c + first.from);
      if (first && funder && !victimLike(funder) && !victimLike(n) && first.to === n.addr && first.asset === SYM[n.chain] && smallNative(first) && !n.data.cursor &&
          !(funder.data?.txCount > 5000) && tr.some(t => t.from === n.addr && t.asset !== first.asset && t.time >= first.time)) union(c + first.from, n.key, 'gas');
    }
  }
  if (on.deposit) {
    for (const d of all) {
      if (!d.depositOf) continue;
      const senders = [...new Set(d.data.transfers.filter(t => t.to === d.addr && !t.dust && t.from !== d.addr).map(t => d.chain + ':' + t.from))]
        .filter(k => { const m = nodes.get(k) || ghosts.get(k); return !m || !victimLike(m); });
      if (senders.length >= 2 && senders.length <= 10) for (let i = 1; i < senders.length; i++) union(senders[0], senders[i], 'deposit');
    }
  }
  const groups = new Map();
  for (const k of parent.keys()) { const r = find(k); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(k); }
  const byKey = new Map();
  for (const members of groups.values()) {
    if (members.length < 2 || members.length > 80) continue;
    const id = 'w:' + members.slice().sort()[0];
    const utxo = isUtxo(members[0].split(':')[0]);
    const reasons = new Map(members.map(k => [k, why.get(k)]));
    for (const k of members) byKey.set(k, { id, members, utxo, reasons });
  }
  return byKey;
}
let clusterCache = null;
const clusterOf = key => (clusterCache || (clusterCache = walletClusters())).get(key) || null;
const invalidateClusters = () => { clusterCache = null; };
const clusterTitle = c => c.utxo ? `Wallet · ${c.members.length} adressen` : `Zelfde beheerder · ${c.members.length} adressen`;

function clusterHtml(n) {
  const c = clusterOf(n.key);
  if (!c) return '';
  const others = c.members.filter(k => k !== n.key);
  const missing = others.filter(k => !nodes.has(k)).length;
  const watched = isWalletWatched(c);
  return `<div class="wallet-box"><div class="story-h"><b>${c.utxo ? '👛 Zelfde wallet' : '👥 Zelfde beheerder'} (vermoedelijk): ${c.members.length} adressen</b><button type="button" class="tag help" data-help="cluster">?</button></div>
    ${others.slice(0, 12).map(k => { const r = c.reasons.get(k); return `<div class="wb-row">${addrChip(n.chain, k.split(':')[1])}<small class="muted">${esc(RULE_NL[r?.rule] || '')}</small></div>`; }).join('')}
    ${others.length > 12 ? `<p class="hint">… en nog ${others.length - 12}</p>` : ''}
    <div class="wb-actions">
      ${missing ? `<button type="button" class="ghost" data-act="wallet">Hele wallet in het web (${missing} erbij)</button>` : ''}
      <button type="button" class="ghost" data-act="walletfollow">Volg het geld van de hele wallet</button>
      <button type="button" class="ghost ${watched ? 'watching' : ''}" data-act="walletwatch">${watched ? '🔕 Wallet niet meer volgen' : '🔔 Volg deze wallet'}</button>
    </div></div>`;
}
function addWalletToGraph(n) {
  const c = clusterOf(n.key);
  if (!c) return;
  ensureCase(n);
  if (n.ghost) addToGraph(n);
  for (const k of c.members) if (!nodes.has(k)) addToGraph(peekNode(n.chain, k.split(':')[1]));
  invalidateClusters();
  render(true);
  renderSummary();
}
async function followWallet(n) {
  addWalletToGraph(n);
  const c = clusterOf(n.key);
  if (!c) return;
  stopped = false;
  setBusy(true);
  current.opts.maxNodes = Math.max(current.opts.maxNodes, nodes.size + c.members.length * current.opts.fanout);
  for (const k of c.members) {
    if (stopped) break;
    const m = nodes.get(k);
    if (!m) continue;
    m.expanded = false;
    await expand(m, m.depth || 0, 'out');
  }
  setBusy(false);
  render(true);
  renderSummary();
  setStatus(`Geld van ${c.members.length} wallet-adressen gevolgd: ${nodes.size} adressen, ${edges.size} geldstromen.`);
}
// Wallets als groepen in het web (Cytoscape compound nodes).
function syncWalletGroups() {
  invalidateClusters();
  const want = new Map();
  for (const n of nodes.values()) {
    const c = clusterOf(n.key);
    if (!c) continue;
    const inGraph = c.members.filter(k => nodes.has(k));
    if (inGraph.length < 2) continue;
    want.set(n.key, c.id);
    if (!want.has(c.id)) want.set(c.id, tr(clusterTitle(c)));
  }
  for (const [k, v] of want) {
    if (!k.startsWith('w:')) continue;
    const el = cy.getElementById(k);
    if (el.empty()) cy.add({ group: 'nodes', data: { id: k, label: v, wallet: true, color: '#4ea1ff', size: 0 } });
    else if (el.data('label') !== v) el.data('label', v);
  }
  cy.nodes().forEach(el => {
    if (el.data('wallet')) return;
    const p = want.get(el.id()) || null;
    if ((el.data('parent') || null) !== p) el.move({ parent: p });
  });
  cy.nodes('[?wallet]').forEach(el => { if (!want.has(el.id()) || el.children().length < 2) { el.children().move({ parent: null }); el.remove(); } });
}

// ---------- wallet-tracker ----------
const isWalletWatched = c => watch.get().some(w => w.members && c.members.some(k => k === keyOf(w.chain, w.addr)));
async function sigOf(w) {
  if (!w.members) return watchSig(w.chain, w.addr);
  const out = [];
  for (const a of w.members.slice(0, 20)) out.push(await watchSig(w.chain, a).catch(() => ''));
  // Eén mislukt adres zou een valse "nieuwe beweging" geven: dan deze controle overslaan.
  if (out.some(x => !x)) throw new Error('niet alle adressen bereikbaar');
  return out.join(',');
}
async function toggleWalletWatch(n) {
  const c = clusterOf(n.key);
  if (!c) return;
  const l = watch.get();
  const i = l.findIndex(w => w.members && c.members.includes(keyOf(w.chain, w.addr)));
  if (i >= 0) { l.splice(i, 1); watch.set(l); setStatus('Deze wallet wordt niet meer gevolgd.'); return; }
  const members = c.members.map(k => k.split(':')[1]).slice(0, 20);
  const w = { chain: n.chain, addr: n.addr, members, label: `${c.utxo ? 'Wallet' : 'Beheerder'} van ${labelOf(n) || short(n.addr)} (${members.length} adressen)`,
    caseName: caseById(cases.currentId())?.name || '', added: Date.now(), sig: '', lastCheck: Date.now(), changed: false };
  setStatus('Wallet wordt vastgelegd…');
  try { w.sig = await sigOf(w); } catch { /* volgende controle */ }
  l.push(w);
  watch.set(l);
  try { window.AndroidBridge?.watchEnabled?.(); } catch { /* geen melding-rechten */ }
  setStatus(`Deze wallet (${members.length} adressen) wordt nu gevolgd. Je krijgt een melding als er op één van de adressen geld beweegt.`);
}

function walletSummary() {
  invalidateClusters();
  const seen = new Set();
  let wallets = 0, addrs = 0;
  for (const n of nodes.values()) {
    const c = clusterOf(n.key);
    if (!c || seen.has(c.id)) continue;
    const inGraph = c.members.filter(k => nodes.has(k)).length;
    if (inGraph < 2) continue;
    seen.add(c.id); wallets++; addrs += inGraph;
  }
  return { wallets, addrs };
}

// ---------- officiële meldpunten van exchanges (gecontroleerd 18-11-2026) ----------
const EX_CONTACTS = [
  { re: /binance/i, name: 'Binance', how: 'Via het officiële politieportaal (Kodex). Eerst registreren als opsporingsinstantie; spoed: kies "Exigent".',
    links: [['Politieportaal Binance', 'https://app.kodexglobal.com/binance/signup'], ['Uitleg Binance', 'https://www.binance.com/en/support/law-enforcement']] },
  { re: /coinbase/i, name: 'Coinbase', how: 'Via het politieportaal (Kodex): internationaal of VS. Overige vragen: subpoenas@coinbase.com.',
    links: [['Portaal internationaal', 'https://app.kodexglobal.com/coinbase-intl/signup?source=legal-intl'], ['Portaal VS', 'https://app.kodexglobal.com/gov/signup'], ['E-mail', 'mailto:subpoenas@coinbase.com']] },
  { re: /\bokx|okex/i, name: 'OKX', how: 'Via het politieportaal (Kodex). Alleen bij spoed of als Kodex niet lukt: enforcement@okx.com.',
    links: [['Politieportaal OKX', 'https://app.kodexglobal.com/okx/signin'], ['Spoed-e-mail', 'mailto:enforcement@okx.com']] },
  { re: /kucoin/i, name: 'KuCoin', how: 'Via het KuCoin Information Request System. EU-entiteit: lawenforcement@kucoin.eu.',
    links: [['KuCoin verzoeken', 'https://www.kucoin.com/legal/requests'], ['E-mail EU', 'mailto:lawenforcement@kucoin.eu']] },
  { re: /kraken|payward/i, name: 'Kraken', how: 'Via het formulier voor juridische verzoeken (categorie Compliance/Legal).',
    links: [['Formulier Kraken', 'https://support.kraken.com/articles/how-do-i-submit-a-legal-inquiry']] },
  { re: /bybit/i, name: 'Bybit', how: 'Bybit vraagt meestal een aangifte én een bevriezingsbevel van de politie; bij spoed kan het sneller.',
    links: [['Bybit: gestolen geld melden', 'https://www.bybit.com/en/help-center/article/How-to-Report-Stolen-Assets']] },
  { re: /bitvavo/i, name: 'Bitvavo', how: 'Fraudeteam van Bitvavo; officiële verzoeken lopen via politie of FIOD.',
    links: [['E-mail fraudeteam', 'mailto:fraud@bitvavo.com'], ['Uitleg Bitvavo', 'https://support.bitvavo.com/hc/en-us/articles/43600757485201-How-can-I-contact-the-Bitvavo-fraud-team']] }
];
const TETHER_CONTACT = { name: 'Tether (USDT)', how: 'Tether kan USDT op een adres bevriezen na een verzoek van een geverifieerde opsporingsinstantie (niet op adressen van exchanges).',
  links: [['Tether contact', 'https://cs.tether.to'], ['E-mail', 'mailto:support@tether.to']] };
const exContact = n => { const t = [labelOf(n), ...(metaStore[n.key]?.tags || [])].join(' '); return EX_CONTACTS.find(c => c.re.test(t)) || null; };
function contactHtml(c) {
  if (!c) return '';
  return `<div class="contact-box"><b>📮 Officieel meldpunt ${esc(c.name)}</b><p>${esc(c.how)}</p>
    <div class="links">${c.links.map(([t, u]) => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(t)}</a>`).join('')}</div>
    <p class="hint">Gecontroleerd op 18-11-2026. Controleer altijd de actuele pagina van de exchange.</p></div>`;
}

// ---------- back-up van zaken ----------
async function exportCase(c) {
  const dossiers = {};
  for (const i of c.items) { const d = await caseDossier(c, i.seedKey); if (d) dossiers[i.seedKey] = d; }
  const { team: _t, ...plain } = c;
  const data = { tool: 'ChainTrace', kind: 'case', version: 1, exported: new Date().toISOString(), case: plain, dossiers };
  saveFile(`chaintrace-zaak-${c.name.replace(/[^\w-]+/g, '_').slice(0, 40)}-${stamp()}.json`, 'application/json', JSON.stringify(data), false);
}
async function importCaseFile(text) {
  const d = JSON.parse(text);
  if (d.tool !== 'ChainTrace') throw new Error('Geen ChainTrace-bestand');
  if (d.kind === 'case') {
    const c = { ...d.case, team: undefined, id: 'c' + Date.now().toString(36), name: d.case.name + (caseById(d.case.id) ? ' (import)' : ''), items: [] };
    for (const i of d.case.items || []) {
      const dos = d.dossiers?.[i.seedKey];
      if (!dos) continue;
      await idb.set(`dossier:${c.id}:${i.seedKey}`, dos);
      c.items.push(i);
    }
    cases.save([c, ...cases.list()]);
    return `Zaak "${c.name}" ingelezen met ${c.items.length} onderzoek(en).`;
  }
  // Los dossier: toevoegen aan de huidige zaak.
  const seed = d.nodes.find(n => n.seed);
  if (!seed) throw new Error('Dossier zonder startadres');
  const c = caseById(cases.currentId()) || newCase();
  await idb.set(`dossier:${c.id}:${seed.key}`, d);
  const list = cases.list(); const cc = list.find(x => x.id === c.id);
  cc.items = [{ seedKey: seed.key, chain: seed.chain, addr: seed.address, role: d.case?.role || 'victim', pattern: d.case?.pattern || '', title: seed.label || short(seed.address), saved: Date.now(), size: d.nodes.length }, ...cc.items.filter(i => i.seedKey !== seed.key)];
  cases.save(list);
  if (cc.team) teamPushItem(cc, cc.items[0], d);
  return `Dossier toegevoegd aan zaak "${cc.name}".`;
}

const tr = window.tr || (x => x);

function setupV19() {
  applySettings();
  $('#btnSettings').addEventListener('click', openSettings);
  $('#setSave').addEventListener('click', saveSettings);
  $('#setTest').addEventListener('click', testSettings);
  $('#setClose').addEventListener('click', () => $('#settingsDlg').close());
  $('#caseExport').addEventListener('click', () => { const c = caseById(caseSel); if (c) exportCase(c); });
  $('#caseImportFile').addEventListener('change', async ev => {
    const f = ev.target.files[0];
    ev.target.value = '';
    if (!f) return;
    try { setStatus(await importCaseFile(await f.text())); caseSel = null; renderCases(); renderCaseBar(); }
    catch (e) { setStatus('Inlezen mislukt: ' + e.message, true); }
  });
}

// ---------- v2.0: ontbrekende gegevens, stortingsadressen, tijdlijn, verantwoording ----------
const APP_VERSION = '3.0.4';

// Tron-adressen komen bij native TRX als hex (41…): omzetten naar het gewone T…-adres (base58check).
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const tronCache = new Map();
async function tronHexToB58(hex) {
  if (!hex) return null;
  if (tronCache.has(hex)) return tronCache.get(hex);
  const bytes = new Uint8Array(hex.match(/../g).map(h => parseInt(h, 16)));
  const h1 = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  const h2 = new Uint8Array(await crypto.subtle.digest('SHA-256', h1));
  const full = new Uint8Array([...bytes, ...h2.slice(0, 4)]);
  let n = 0n;
  for (const b of full) n = n * 256n + BigInt(b);
  let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of full) { if (b === 0) s = '1' + s; else break; }
  tronCache.set(hex, s);
  return s;
}
async function fetchTronNative(addr, fp) {
  const r = await getData(`${API.tron}/v1/accounts/${addr}/transactions?limit=100&only_confirmed=true${fp ? '&fingerprint=' + encodeURIComponent(fp) : ''}`, false, 3).catch(() => null);
  const transfers = [];
  for (const t of r?.data || []) {
    const c = t.raw_data?.contract?.[0];
    if (c?.type !== 'TransferContract' || t.ret?.[0]?.contractRet !== 'SUCCESS') continue;
    const v = c.parameter.value;
    const from = await tronHexToB58(v.owner_address), to = await tronHexToB58(v.to_address);
    const trx = Number(v.amount || 0) / 1e6;
    if (!(trx > 0)) continue;
    transfers.push({ from, to, value: trx, asset: 'TRX', time: t.block_timestamp / 1000, txid: t.txID, dust: trx < 0.01 });
  }
  return { transfers, fp: r?.meta?.fingerprint || null };
}
function parseInternal(items) {
  const out = [];
  for (const it of items || []) {
    const v = Number(it.value || 0) / 1e18;
    if (!(v > 0) || it.success === false || it.error) continue;
    const f = it.from?.hash?.toLowerCase(), t = it.to?.hash?.toLowerCase();
    if (!f || !t) continue;
    out.push({ from: f, to: t, value: v, asset: 'ETH', time: Date.parse(it.timestamp) / 1000, txid: it.transaction_hash, internal: true });
  }
  return out;
}

// ---------- stortingsadressen bij exchanges ----------
// Een adres dat (vrijwel) al zijn geld doorstuurt naar één exchange-adres is meestal het persoonlijke
// stortingsadres van één klant: precies het adres waarmee de exchange de klant kan identificeren.
function detectDeposits() {
  for (const n of [...nodes.values(), ...ghosts.values()]) {
    if (!n.data || isEndpoint(n) || n.depositChecked === n.data.transfers.length) continue;
    n.depositChecked = n.data.transfers.length;
    const outs = valuedOrAll(n.data.transfers).filter(t => t.from === n.addr && t.to !== n.addr);
    const ins = n.data.transfers.filter(t => t.to === n.addr && t.from !== n.addr && !t.dust);
    if (!outs.length || !ins.length) continue;
    const val = t => t.usd || (NATIVE_USD[t.asset] || 0) * t.value || 1;
    const by = new Map();
    for (const t of outs) by.set(t.to, (by.get(t.to) || 0) + val(t));
    const total = [...by.values()].reduce((a, b) => a + b, 0);
    const [top, v] = [...by.entries()].sort((a, b) => b[1] - a[1])[0];
    if (v / total < 0.8) continue;
    const r = nodes.get(keyOf(n.chain, top)) || peekNode(n.chain, top);
    if (endKind(r) !== 'exchange') continue;
    const name = exName(labelOf(r)) || 'een exchange';
    n.depositOf = r.key;
    addFlag(n, 'deposit', 'high', `Stortingsadres van een klant bij ${name} (${Math.round(100 * v / total)}% doorgestuurd)`);
  }
}

// ---------- tijdlijn ----------
let timelineOnly = false;
function routeEdgeKeys() {
  const s = new Set();
  for (const r of moneyRoutes(20).routes) for (const e of r.steps) s.add(e.key);
  return s;
}
function renderTimeline() {
  const box = $('#timeline');
  if (box.hidden) return;
  const onRoute = routeEdgeKeys();
  const rows = [];
  for (const e of edges.values()) {
    if (!nodes.has(e.source) || !nodes.has(e.target)) continue;
    if (timelineOnly && !onRoute.has(e.key)) continue;
    for (const t of e.txs) rows.push({ ...t, e, route: onRoute.has(e.key) });
  }
  rows.sort((a, b) => (a.time || 0) - (b.time || 0));
  let day = '';
  const html = rows.slice(0, 600).map(r => {
    const s = nodes.get(r.e.source), t = nodes.get(r.e.target);
    const d = fmtDay(r.time);
    const head = d !== day ? `<div class="tl-day">${esc(d)}</div>` : '';
    day = d;
    const time = r.time ? new Date(r.time * 1000).toLocaleTimeString(window.CT_LOCALE, { hour: '2-digit', minute: '2-digit' }) : '';
    return `${head}<div class="tl-row ${r.route ? 'route' : ''}">
      <span class="tl-time">${esc(time)}</span>
      <div class="tl-main">${addrChip(s.chain, s.addr)}<span class="tl-arrow">→</span>${addrChip(t.chain, t.addr)}</div>
      <div class="tl-sub"><b>${fmt(r.value)} ${esc(r.asset)}</b>${eurOf(r) ? ` <span class="muted">≈ ${fmtEur(eurOf(r))}</span>` : ''}${r.via ? ` <span class="tag info">${esc(r.via)}</span>` : ''} <button type="button" class="txlink" data-tx="${esc(r.txid)}" data-chain="${esc(s.chain)}">${esc(short(r.txid))}</button>${r.route ? ' <span class="tag info">route</span>' : ''}</div>
    </div>`;
  }).join('');
  $('#timelineList').innerHTML = html || '<p class="muted">Nog geen geldstromen.</p>';
  $('#timelineCount').textContent = `${rows.length} betaling${rows.length === 1 ? '' : 'en'}${rows.length > 600 ? ' (eerste 600 getoond)' : ''}`;
}
function setGraphView(v) {
  const tl = v === 'time';
  $('#timeline').hidden = !tl;
  $('#cy').style.visibility = tl ? 'hidden' : '';
  document.querySelector('.legend-wrap').hidden = tl;
  for (const [id, name] of [['#btnLayoutWeb', 'web'], ['#btnLayoutFlow', 'flow'], ['#btnLayoutTime', 'time']]) $(id).classList.toggle('active', v === name);
  if (tl) renderTimeline();
}

// ---------- verantwoording: herkomst van gegevens en controleerbare vingerafdruk ----------
const SOURCE_NAME = { btc: 'mempool.space', ltc: 'litecoinspace.org', eth: 'eth.blockscout.com', op: 'explorer.optimism.io', tron: 'api.trongrid.io', avax: 'api.routescan.io', zksync: 'block-explorer-api.mainnet.zksync.io', sol: () => solViaApp() ? 'api.mainnet-beta.solana.com' : new URL(API.sol).host };
const sourceOf = chain => { const s = SOURCE_NAME[chain]; return typeof s === 'function' ? s() : s; };
async function sha256Hex(text) {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function evidenceDossier() {
  const d = buildDossier();
  d.app = { name: 'ChainTrace', version: APP_VERSION };
  d.settings = { ...current?.opts, timeOrder: current?.opts?.timeOrder !== false };
  d.provenance = [...nodes.values()].filter(n => n.data).map(n => ({
    address: n.addr, chain: n.chain, source: n.data.source || sourceOf(n.chain), fetchedAt: n.data.fetchedAt ? new Date(n.data.fetchedAt).toISOString() : null,
    transfersLoaded: n.data.transfers.length, moreHistoryAvailable: !!n.data.cursor
  }));
  return d;
}

function setupV20() {
  $('#btnLayoutTime').addEventListener('click', () => setGraphView('time'));
  $('#btnLayoutWeb').addEventListener('click', () => setGraphView('web'));
  $('#btnLayoutFlow').addEventListener('click', () => setGraphView('flow'));
  $('#tlOnlyRoute').addEventListener('change', ev => { timelineOnly = ev.target.checked; renderTimeline(); });
  $('#timelineList').addEventListener('click', ev => {
    const a = ev.target.closest('[data-addr]'), t = ev.target.closest('[data-tx]');
    const chain = (a || t)?.closest('.tl-row')?.querySelector('[data-chain]')?.dataset.chain || current?.chain;
    if (t) openTx(t.dataset.chain || chain, t.dataset.tx);
    else if (a) openAddr(chain, a.dataset.addr);
  });
}

// ---------- UI: ingeklapt formulier en overzichtstegels ----------
function renderFormSummary() {
  const seed = current && nodes.get(current.seedKey);
  const has = !!(seed && nodes.size);
  $('#formSummaryText').innerHTML = has
    ? `🔎 <b>${esc(labelOf(seed) || short(seed.addr))}</b><span class="fs-meta">${esc(CHAIN_NAME[seed.chain] || '')} · ${esc(current.role === 'perp' ? 'Dader' : 'Slachtoffer')}</span>`
    : '🔎 <b>Nieuw onderzoek</b>';
  $('#formSummaryHint').textContent = has ? 'Wijzigen' : '';
  $('#formBox').classList.toggle('has-case', has);
}
function renderOverview() {
  const box = $('#overview');
  if (!current || !nodes.size) { box.hidden = true; return; }
  const all = [...nodes.values()];
  const sus = all.filter(n => ['perp', 'suspect', 'sanction'].includes(nodeClass(n))).length;
  const ex = all.filter(n => endKind(n) === 'exchange').length;
  const dep = all.filter(n => n.depositOf).length;
  const ws = walletSummary();
  const vic = origins.starts.size;
  const tiles = [
    ['addr', '🕸', nodes.size, 'adressen', ''],
    ['sus', '⚠️', sus, 'verdacht', sus ? 'warn' : ''],
    ['ex', '🏦', ex, 'exchanges', ex ? 'good' : ''],
    ['dep', '📥', dep, 'stortingsadressen', dep ? 'good' : ''],
    ['wallet', '👛', ws.wallets, 'wallets', ''],
    ['vic', '👤', vic, 'mogelijke slachtoffers', '']
  ];
  box.innerHTML = tiles.map(([k, ic, v, l, cls]) => `<button type="button" class="ov-tile ${cls}" data-ov="${k}"><span class="ov-ic">${ic}</span><b>${v}</b><span class="ov-l">${l}</span></button>`).join('');
  box.hidden = false;
}
function onOverview(k) {
  const open = (sel, scroll = true) => { const d = $(sel); if (!d || d.hidden) return; d.open = true; if (scroll) d.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  if (k === 'addr' || k === 'wallet') { setTab('graph'); if (cy) cy.fit(undefined, 40); if (isMobile()) return; }
  if (k === 'sus') open('#findingsBox');
  if (k === 'ex' || k === 'dep') open('#routeBox');
  if (k === 'vic') open('#origins');
  if (k === 'wallet') { const n = [...nodes.values()].find(x => clusterOf(x.key)); if (n) openNode(n); }
}
function setupUI21() {
  $('#overview').addEventListener('click', ev => { const b = ev.target.closest('[data-ov]'); if (b) onOverview(b.dataset.ov); });
  renderFormSummary();
}

// ---------- v2.2: euro-waarde toen, verdeling van het geld (haircut), swaps en bridges ----------

// --- 3. Historische koersen in euro (dagkoers, Binance; stablecoins via EUR/USDT) ---
const EUR_PAIR = { BTC: 'BTCEUR', ETH: 'ETHEUR', WETH: 'ETHEUR', LTC: 'LTCEUR', SOL: 'SOLEUR', wSOL: 'SOLEUR', TRX: 'TRXEUR', AVAX: 'AVAXEUR', WAVAX: 'AVAXEUR' };
const USD_STABLE = /^(USDT|USDC|USDT\.e|USDC\.e|USDt|DAI|BUSD|TUSD|USDP|FDUSD)$/;
const priceMap = new Map(); // pair -> Map(dag -> slotkoers)
const priceLoaded = new Map(); // pair -> [vanDag, totDag]
const dayOf = t => Math.floor(t / 86400);
function priceOn(pair, t) {
  const m = priceMap.get(pair);
  if (!m || !t) return null;
  const d = dayOf(t);
  for (let i = 0; i < 4; i++) { const p = m.get(d - i) ?? m.get(d + i); if (p) return p; }
  return null;
}
function eurOf(t) {
  if (!t || !(t.value > 0) || t.dust) return null;
  const pair = EUR_PAIR[t.asset];
  if (pair) { const p = priceOn(pair, t.time); return p ? t.value * p : null; }
  if (USD_STABLE.test(t.asset) || t.usd) {
    const eurusdt = priceOn('EURUSDT', t.time);
    if (!eurusdt) return null;
    return (USD_STABLE.test(t.asset) ? t.value : t.usd) / eurusdt;
  }
  return null;
}
const fmtEur = v => v == null ? '' : '€' + Math.round(v).toLocaleString(window.CT_LOCALE);
async function loadPair(pair, from, to) {
  const have = priceLoaded.get(pair);
  if (have && have[0] <= dayOf(from) && have[1] >= dayOf(to)) return false;
  const m = priceMap.get(pair) || new Map();
  let start = (dayOf(from) - 2) * 86400000;
  const end = Math.min((dayOf(to) + 2) * 86400000, Date.now());
  while (start < end) {
    const rows = await getData(`https://api.binance.com/api/v3/klines?symbol=${pair}&interval=1d&startTime=${start}&endTime=${end}&limit=1000`, false, 2).catch(() => null);
    if (!Array.isArray(rows) || !rows.length) break;
    for (const r of rows) m.set(Math.floor(r[0] / 86400000), Number(r[4]));
    start = rows[rows.length - 1][0] + 86400000;
    if (rows.length < 1000) break;
  }
  priceMap.set(pair, m);
  priceLoaded.set(pair, [dayOf(from), dayOf(to)]);
  return true;
}
// Laadt (eenmalig) de koersen die nodig zijn voor deze overboekingen; true als er iets nieuws is.
async function ensurePrices(list) {
  const need = new Map();
  for (const t of list) {
    if (!t?.time || t.dust) continue;
    const pair = EUR_PAIR[t.asset] || ((USD_STABLE.test(t.asset) || t.usd) ? 'EURUSDT' : null);
    if (!pair) continue;
    const r = need.get(pair) || [Infinity, 0];
    need.set(pair, [Math.min(r[0], t.time), Math.max(r[1], t.time)]);
  }
  let changed = false;
  for (const [pair, [a, b]] of need) if (await loadPair(pair, a, b).catch(() => false)) changed = true;
  return changed;
}
async function pricesForCase() {
  const list = [];
  for (const n of nodes.values()) for (const t of n.data?.transfers || []) list.push(t);
  for (const e of edges.values()) for (const t of e.txs) list.push(t);
  if (await ensurePrices(list)) { renderTaint(); refreshView(); renderTimeline(); }
}

// --- 2. Swaps en bridges doorvolgen ---
const EVM_ID = { 1: 'eth', 10: 'op', 43114: 'avax', 324: 'zksync' };
const ID_OF = { eth: 1, op: 10, avax: 43114, zksync: 324 };
const DLN_ID = { ...EVM_ID, 7565164: 'sol' };
const LZ_EID = { 30101: 'eth', 30111: 'op', 30106: 'avax', 30165: 'zksync', 30168: 'sol' };
const OTHER_CHAIN = { 42161: 'Arbitrum', 8453: 'Base', 56: 'BNB Chain', 137: 'Polygon', 59144: 'Linea', 534352: 'Scroll', 81457: 'Blast', 100: 'Gnosis', 250: 'Fantom', 30110: 'Arbitrum', 30184: 'Base', 30102: 'BNB Chain', 30109: 'Polygon', 30183: 'Linea' };
// Ontvanger op de doelketen uit de transactie daar: de grootste overboeking naar een niet-contract.
async function recipientFromTx(chain, txid) {
  const r = await fetchTx(chain, txid).catch(() => null);
  const list = (r?.transfers || []).filter(t => t.to && t.value > 0);
  if (!list.length) return null;
  const best = list.sort((a, b) => (eurOf(b) || b.value) - (eurOf(a) || a.value))[0];
  return { addr: best.to, value: best.value, asset: best.asset };
}
async function resolveBridge(chain, txid) {
  // deBridge (DLN)
  const ids = await getData(`https://stats-api.dln.trade/api/Transaction/${txid}/orderIds`, false, 1).catch(() => null);
  const oid = ids?.orderIds?.[0]?.stringValue;
  if (oid) {
    const o = await getData(`https://stats-api.dln.trade/api/Orders/${oid}`, false, 1).catch(() => null);
    const tk = o?.takeOfferWithMetadata;
    const cid = Number(tk?.chainId?.stringValue);
    if (o && tk) {
      const dec = Number(tk.decimals ?? tk.metadata?.decimals ?? 18);
      return { via: 'deBridge', destChain: DLN_ID[cid] || null, destName: CHAIN_NAME[DLN_ID[cid]] || OTHER_CHAIN[cid] || `keten ${cid}`,
        destAddr: o.receiverDst?.stringValue || null, value: Number(tk.amount?.stringValue || 0) / 10 ** dec, asset: tk.metadata?.symbol || tk.symbol || '?',
        destTx: o.fulfilledDstEventMetadata?.transactionHash?.stringValue || null };
    }
  }
  // Across
  if (ID_OF[chain]) {
    const a = await getData(`https://app.across.to/api/deposit/status?originChainId=${ID_OF[chain]}&depositTxHash=${txid}`, false, 1).catch(() => null);
    if (a?.destinationChainId) {
      const dc = EVM_ID[a.destinationChainId];
      const rec = dc && a.fillTx ? await recipientFromTx(dc, a.fillTx) : null;
      return { via: 'Across', destChain: dc || null, destName: CHAIN_NAME[dc] || OTHER_CHAIN[a.destinationChainId] || `keten ${a.destinationChainId}`, destAddr: rec?.addr || null, value: rec?.value, asset: rec?.asset, destTx: a.fillTx || null };
    }
  }
  // LayerZero (o.a. Stargate)
  const lz = await getData(`https://scan.layerzero-api.com/v1/messages/tx/${txid}`, false, 1).catch(() => null);
  const m = lz?.data?.[0];
  if (m?.pathway) {
    const eid = Number(m.pathway.dstEid);
    const dc = LZ_EID[eid];
    const dtx = m.destination?.tx?.txHash || null;
    const rec = dc && dtx ? await recipientFromTx(dc, dtx) : null;
    return { via: 'LayerZero/Stargate', destChain: dc || null, destName: CHAIN_NAME[dc] || OTHER_CHAIN[eid] || `keten ${eid}`, destAddr: rec?.addr || null, value: rec?.value, asset: rec?.asset, destTx: dtx };
  }
  return null;
}
function addXEdge(sk, tk, t, kind) {
  const k = `${sk}>${tk}`;
  let e = edges.get(k);
  if (!e) { e = { key: k, source: sk, target: tk, assets: {}, count: 0, usd: 0, first: Infinity, last: 0, txs: [] }; edges.set(k, e); }
  e[kind] = t.via || true;
  if (e.txs.some(x => x.txid === t.txid && x.asset === t.asset)) return;
  e.assets[t.asset] = (e.assets[t.asset] || 0) + t.value;
  e.count++;
  e.usd += t.usd || 0;
  e.first = Math.min(e.first, t.time);
  e.last = Math.max(e.last, t.time);
  e.txs.push({ txid: t.txid, value: t.value, asset: t.asset, time: t.time, via: t.via, [kind]: true });
}
const SWAP_RE = /swap|router|uniswap|1inch|paraswap|cow ?protocol|0x: exchange|sushi|curve|balancer|kyber|odos|okx dex|lifi|jupiter|raydium/i;
// Na het uitbreiden van een adres: bridges en "wissel-en-stuur" (swap naar een ander adres) doorvolgen.
async function crossFollow(n, depth, next) {
  if (demoMode || !n.data || !(isEvm(n.chain) || n.chain === 'sol')) return;
  const minT = timeOrderOn() && n.minTime ? n.minTime - 600 : 0;
  const outs = n.data.transfers.filter(t => t.from === n.addr && !t.dust && t.time >= minT && hasValue(t));
  const byTx = new Map();
  for (const t of outs) { if (!byTx.has(t.txid)) byTx.set(t.txid, []); byTx.get(t.txid).push(t); }
  const val = list => list.reduce((s, t) => s + (eurOf(t) || t.usd || (NATIVE_USD[t.asset] || 0) * t.value), 0);
  const txs = [...byTx.entries()].sort((a, b) => val(b[1]) - val(a[1]));
  let bridges = 0, swaps = 0;
  for (const [txid, list] of txs) {
    if (stopped) return;
    const t = list[0];
    const r = nodes.get(keyOf(n.chain, t.to)) || peekNode(n.chain, t.to);
    const lab = labelOf(r) || '';
    const isBridge = hasF(r, 'bridge') || BRIDGE_RE.test(lab);
    const backIn = n.data.transfers.some(x => x.txid === txid && x.to === n.addr && x.asset !== t.asset);
    if (isBridge && bridges < 8) {
      bridges++;
      setStatus(`Bridge-overboeking natrekken (${short(txid)})…`);
      const b = await resolveBridge(n.chain, txid).catch(() => null);
      if (!b) continue;
      if (b.destChain && b.destAddr) {
        const dn = getNode(b.destChain, b.destAddr);
        if (dn.depth == null || dn.depth > depth + 1) dn.depth = depth + 1;
        dn.parent = dn.parent || n.key;
        dn.minTime = dn.minTime ? Math.min(dn.minTime, t.time) : t.time;
        addXEdge(n.key, dn.key, { txid, value: b.value || t.value, asset: b.asset || t.asset, time: t.time, via: b.via, usd: t.usd }, 'cross');
        addFlag(dn, 'bridgedin', 'info', `Ontving geld via ${b.via} vanaf ${CHAIN_NAME[n.chain]}`);
        lightAnalyze(dn);
        if (depth + 1 < current.opts.depth && !isEndpoint(dn)) next.push({ n: dn, depth: depth + 1, dir: 'out' });
      } else {
        addFlag(n, 'bridgeout', 'med', `Geld ging via ${b.via} naar ${b.destName}${b.destAddr ? ' (ontvanger ' + short(b.destAddr) + ')' : ''}: daar kan ChainTrace niet verder volgen`);
      }
    } else if (!backIn && !isBridge && swaps < 3 && (isBlockscout(n.chain) || n.chain === 'zksync') && (hasF(r, 'contract') || SWAP_RE.test(lab))) {
      swaps++;
      const tx = await fetchTx(n.chain, txid).catch(() => null);
      const outAsset = t.asset;
      const cand = (tx?.transfers || []).filter(x => x.to && x.to !== n.addr && x.to !== t.to && x.asset !== outAsset && x.value > 0);
      if (!cand.length) continue;
      const best = cand.sort((a, b) => (eurOf(b) || b.value) - (eurOf(a) || a.value))[0];
      const rn = getNode(n.chain, best.to);
      if (isEndpoint(rn) || hasF(rn, 'contract')) continue;
      if (rn.depth == null || rn.depth > depth + 1) rn.depth = depth + 1;
      rn.parent = rn.parent || n.key;
      rn.minTime = rn.minTime ? Math.min(rn.minTime, t.time) : t.time;
      addXEdge(n.key, rn.key, { txid, value: best.value, asset: best.asset, time: t.time, via: lab || 'DEX' }, 'swap');
      lightAnalyze(rn);
      if (depth + 1 < current.opts.depth && !isEndpoint(rn)) next.push({ n: rn, depth: depth + 1, dir: 'out' });
    }
  }
}
// Swaps op het adres zelf (in dezelfde transactie munt X uit en munt Y terug).
function swapsOf(n) {
  if (!n.data) return [];
  const by = new Map();
  for (const t of n.data.transfers) { if (t.dust) continue; if (!by.has(t.txid)) by.set(t.txid, []); by.get(t.txid).push(t); }
  const out = [];
  for (const [txid, l] of by) {
    const o = l.find(t => t.from === n.addr), i = l.find(t => t.to === n.addr && o && t.asset !== o.asset);
    if (o && i) out.push({ txid, from: o, to: i });
  }
  return out;
}

// --- 1. Waar is het geld van het slachtoffer gebleven? (proportionele methode / haircut) ---
function taintAnalysis() {
  if (!current || current.role === 'perp') return null;
  const seed = nodes.get(current.seedKey);
  if (!seed?.data) return null;
  const synthetic = new Set();
  for (const e of edges.values()) if (e.cross || e.swap) for (const t of e.txs) synthetic.add(e.source + '|' + t.txid);
  const ev = new Map();
  const add = t => { const k = `${t.txid}|${t.fk}|${t.tk}|${t.asset}|${t.value}`; if (!ev.has(k)) ev.set(k, t); };
  for (const n of nodes.values()) for (const t of n.data?.transfers || []) {
    if (t.dust || !t.time || t.from === t.to) continue;
    const fk = keyOf(n.chain, t.from), tk = keyOf(n.chain, t.to);
    if (synthetic.has(fk + '|' + t.txid)) continue; // vervangen door de doorgevolgde bridge/swap
    add({ ...t, fk, tk });
  }
  for (const e of edges.values()) if (e.cross || e.swap) for (const t of e.txs) add({ ...t, fk: e.source, tk: e.target });
  const list = [...ev.values()].sort((a, b) => a.time - b.time);
  const S = new Map();
  const st = k => { let s = S.get(k); if (!s) { s = { bal: 0, taint: 0, tIn: 0 }; S.set(k, s); } return s; };
  let total = 0, missing = 0;
  for (const t of list) {
    const v = eurOf(t);
    if (!(v > 0)) { if (t.fk === seed.key && hasValue(t)) missing++; continue; }
    const f = st(t.fk), r = st(t.tk);
    let taint;
    if (t.fk === seed.key) { taint = v; total += v; }
    else {
      if (f.bal < v) f.bal = v; // eerdere (onbekende) tegoeden tellen als niet-besmet
      taint = f.bal > 0 ? Math.min(f.taint, v * f.taint / f.bal) : 0;
      f.taint -= taint; f.bal -= v;
    }
    if (t.tk === seed.key) continue;
    r.bal += v; r.taint += taint; r.tIn += taint;
  }
  if (!(total > 0)) return { total: 0, missing };
  const buckets = { exchange: [], deposit: [], mixer: [], bridge: [], contract: [], held: [], open: [] };
  for (const [k, s] of S) {
    if (k === seed.key || !(s.tIn > 0.5)) continue;
    const n = nodes.get(k) || ghosts.get(k);
    if (!n) { buckets.open.push({ k, eur: s.tIn }); continue; }
    const kind = endKind(n);
    if (n.depositOf && s.taint > 0.5) buckets.deposit.push({ n, eur: s.taint });
    else if (kind === 'exchange') buckets.exchange.push({ n, eur: s.tIn });
    else if (kind === 'mixer' || kind === 'sanction') buckets.mixer.push({ n, eur: s.tIn });
    else if (kind === 'bridge') buckets.bridge.push({ n, eur: s.tIn });
    else if (kind === 'contract') buckets.contract.push({ n, eur: s.tIn });
    else if (!n.data) buckets.open.push({ n, eur: s.tIn });
    else if (s.taint > 0.5) buckets.held.push({ n, eur: s.taint });
  }
  const sum = l => l.reduce((a, x) => a + x.eur, 0);
  const order = [['exchange', 'Bij exchanges', 'good'], ['deposit', 'Op stortingsadressen bij exchanges', 'good'], ['held', 'Staat nog op adressen', 'warn'],
    ['mixer', 'Naar mixers / waarschuwingslijst', 'bad'], ['bridge', 'Via bridges naar elders', 'info'], ['contract', 'In smart contracts / DeFi', 'info'], ['open', 'Nog niet verder gevolgd', 'muted']];
  const rows = order.map(([key, label, cls]) => ({ key, label, cls, eur: sum(buckets[key]), items: buckets[key].sort((a, b) => b.eur - a.eur) })).filter(r => r.eur >= 1);
  return { total, missing, rows };
}
function renderTaint() {
  const box = $('#taintBox');
  const r = taintAnalysis();
  if (!r || !(r.total > 0)) { box.hidden = true; return; }
  box.hidden = false;
  const pct = v => Math.round(100 * v / r.total);
  const bar = r.rows.map(x => `<span class="tb-seg ${x.cls}" style="width:${Math.max(1, 100 * x.eur / r.total)}%" title="${esc(x.label)}"></span>`).join('');
  const nm = x => x.n ? (labelOf(x.n) || short(x.n.addr)) : short(x.k.split(':')[1]);
  $('#taintBody').innerHTML = `<p class="tb-total">Het slachtoffer verstuurde <b>${fmtEur(r.total)}</b> (waarde op de dag zelf).</p>
    <div class="tb-bar">${bar}</div>
    ${r.rows.map(x => `<details class="tb-row ${x.cls}"><summary><i class="tb-dot ${x.cls}"></i><span>${esc(x.label)}</span><b>${fmtEur(x.eur)}</b><small>${pct(x.eur)}%</small></summary>
      ${x.items.slice(0, 8).map(i => `<div class="tb-item">${i.n ? addrChip(i.n.chain, i.n.addr) : esc(nm(i))}<span>${fmtEur(i.eur)}</span></div>`).join('')}</details>`).join('')}
    <p class="hint">Berekend met de proportionele methode (haircut): als geld van het slachtoffer zich mengt met ander geld, gaat bij elke betaling naar verhouding een deel mee. Dit is een schatting op basis van de geladen transacties${r.missing ? `; ${r.missing} betaling(en) zonder bekende koers telden niet mee` : ''}.</p>`;
}
function setupV22() {
  $('#taintBody').addEventListener('click', ev => { const a = ev.target.closest('[data-addr]'); if (a) { const n = [...nodes.values()].find(x => x.addr === a.dataset.addr); if (n) { focusNode(n.key); openNode(n); } } });
}

setup();
// Testhaak voor automatische checks (bijv. via adb/DevTools).
window.ChainTrace = { team, teamApi, teamSync, buildDossier, taintAnalysis, eurOf, ensurePrices, resolveBridge, swapsOf, followWallet, toggleWalletWatch, renderOverview, evidenceDossier, sha256Hex, tronHexToB58, routeEdgeKeys, get cy() { return cy; }, walletSummary, clusterOf, labelOf, idb, importCaseFile, cyWallets: () => cy ? cy.nodes('[?wallet]').length : 0, extract: extractFromText, runTour, stopTour, startDemo, checkWatches, watch, cases, DEMO, openLetter, moneyRoutes, openAddr, openTx, nav, ghosts, runTrace, nodes, edges, detectChain, origins, traceOrigins, composeReport, exportPdf, summaryLines, notes: () => notes };
})();
