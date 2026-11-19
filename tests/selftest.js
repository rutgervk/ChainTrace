// Tijdelijke zelftest voor ChainTrace (niet in git). Start: ChainTraceSelftest.run(['groep', ...])
(() => {
'use strict';
const CT = window.ChainTrace;
const $ = s => document.querySelector(s);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const R = window.__ctResults = { done: false, log: [], errors: [], warnings: [] };
const oe = console.error, ow = console.warn;
console.error = (...a) => { R.errors.push(a.map(String).join(' ').slice(0, 200)); oe(...a); };
console.warn = (...a) => { R.warnings.push(a.map(String).join(' ').slice(0, 200)); ow(...a); };
window.addEventListener('error', e => R.errors.push('window.onerror: ' + e.message));
window.addEventListener('unhandledrejection', e => R.errors.push('unhandled: ' + (e.reason?.message || e.reason)));

const rec = (group, name, ok, detail = '', ms = 0) => R.log.push({ group, name, ok: !!ok, detail: String(detail).slice(0, 220), ms });
async function t(group, name, fn) {
  const t0 = performance.now();
  try {
    const d = await fn();
    const ms = Math.round(performance.now() - t0);
    if (d === true || d === undefined) rec(group, name, true, '', ms);
    else if (d && typeof d === 'object' && 'info' in d) rec(group, name, true, d.info, ms);
    else if (typeof d === 'string' && d.startsWith('skip')) rec(group, name, true, d, ms);
    else rec(group, name, false, d === false ? '' : d, ms);
  }
  catch (e) { rec(group, name, false, 'EXC ' + (e.message || e), Math.round(performance.now() - t0)); }
}
const busy = () => $('#btnTrace').disabled;
async function trace(addr, { depth = 1, fanout = 3, chain = 'auto', role = 'victim', pattern = 'generic', pick = null, timeout = 90000 } = {}) {
  $('#addr').value = addr; $('#depth').value = depth; $('#fanout').value = fanout; $('#chain').value = chain;
  $(role === 'perp' ? '#rolePerp' : '#roleVictim').checked = true;
  $('#pattern').value = pattern;
  $('#traceForm').requestSubmit();
  const t0 = Date.now();
  if (pick) {
    while ($('#chainPick').hidden && Date.now() - t0 < 30000) await sleep(300);
    const b = $(`#chainPick [data-pick=${pick}]`);
    if (!b) throw new Error('keten niet in keuzelijst: ' + $('#chainPick').innerText.replace(/\s+/g, ' '));
    b.click();
  }
  await sleep(500);
  while ((busy() || /Kijken op welke/.test($('#status').textContent)) && Date.now() - t0 < timeout) await sleep(300);
  if (busy()) { $('#btnStop').click(); throw new Error('time-out na ' + timeout / 1000 + ' s'); }
  return [...CT.nodes.values()].find(n => n.seed);
}
const overflow = () => {
  const w = document.documentElement.clientWidth;
  const bad = [...document.querySelectorAll('body *')].filter(e => { const r = e.getBoundingClientRect(); return r.width && r.right > w + 2 && getComputedStyle(e).position !== 'fixed' && !e.closest('#cy, .xtabs, .case-list, dialog:not([open])'); });
  return bad.slice(0, 4).map(e => `${e.tagName}${e.id ? '#' + e.id : ''}.${[...e.classList].join('.')}:${Math.round(e.getBoundingClientRect().right)}`);
};

const groups = {

  async v22() {
    const G = 'v2.2';
    await t(G, 'verdeling van het geld (voorbeeld)', async () => {
      CT.startDemo(); await sleep(600); for (let i = 0; i < 60 && busy(); i++) await sleep(200);
      let ta; for (let i = 0; i < 30; i++) { ta = CT.taintAnalysis(); if (ta?.total > 0) break; await sleep(500); }
      if (!(ta?.total > 0)) return 'geen koersen/verdeling';
      const ex = ta.rows.find(r => r.key === 'exchange')?.eur || 0, mix = ta.rows.find(r => r.key === 'mixer')?.eur || 0;
      const sum = ta.rows.reduce((a, r) => a + r.eur, 0);
      return (ex > mix && Math.abs(sum - ta.total) / ta.total < 0.02 && !document.querySelector('#taintBox').hidden) ? { info: `totaal €${Math.round(ta.total)}, exchange €${Math.round(ex)}, mixer €${Math.round(mix)}` } : `ex=${ex} mix=${mix} som=${sum} totaal=${ta.total}`;
    });
    await t(G, 'euro-waarde in verkenner', async () => {
      CT.openAddr('eth', CT.DEMO.scammer); await sleep(1500);
      const has = /€/.test(document.querySelector('#detailBody').innerText);
      document.querySelector('#detailBody [data-nav=close]')?.click();
      return has || 'geen €-bedragen';
    });
    await t(G, 'bridge natrekken (deBridge → Optimism)', async () => {
      const b = await CT.resolveBridge('eth', '0x7585311f556ccf282008bb8b0a7b2c3b9fd76f0a58445c616ed570f0b426bc64');
      return (b?.destChain === 'op' && b.destAddr) ? { info: `${b.via} → ${b.destName}, ${b.value} ${b.asset}` } : JSON.stringify(b);
    });
    await t(G, 'bridge naar niet-ondersteunde keten (Across → Base)', async () => {
      const b = await CT.resolveBridge('eth', '0xab4d8e9b3be884db3ef97b5c604752bbe89547504569953a60b0e33137e42221');
      return (b && !b.destChain && b.destName === 'Base') || JSON.stringify(b);
    });
  },

  async v21() {
    const G = 'v2.1';
    await t(G, 'voorbeeld: zelfde beheerder (gas + stortingsadres)', async () => {
      CT.startDemo(); await sleep(600); for (let i = 0; i < 60 && busy(); i++) await sleep(200); await sleep(400);
      const g = [...CT.nodes.values()].find(n => n.addr.endsWith('0b'));
      const b = [...CT.nodes.values()].find(n => n.addr.endsWith('05'));
      if (!g) return 'G niet in het web';
      const c = CT.clusterOf(g.key);
      const rules = c ? [...c.reasons.values()].map(r => r?.rule).join(',') : '';
      return (c && c.members.includes(b.key) && !c.utxo) ? { info: `cluster ${c.members.length} adressen, regels: ${rules}` } : `cluster=${!!c} regels=${rules}`;
    });
    await t(G, 'slachtoffer nooit in een cluster', async () => {
      const v = [...CT.nodes.values()].find(n => n.seed);
      return !CT.clusterOf(v.key) || 'slachtoffer zit in cluster';
    });
    await t(G, 'formulier ingeklapt + overzichtstegels', async () => {
      const closed = !document.querySelector('#formBox').open;
      const tiles = document.querySelectorAll('#overview .ov-tile').length;
      const sum = document.querySelector('#formSummaryText').innerText;
      document.querySelector('#overview [data-ov=sus]').click(); await sleep(300);
      const fo = document.querySelector('#findingsBox').open;
      return (closed && tiles === 6 && /0xdec0|Slachtoffer/.test(sum) && fo) || `dicht=${closed} tegels=${tiles} samenvatting=${sum} bevindingen=${fo}`;
    });
    await t(G, 'wallet-vak + wallet volgen', async () => {
      const g = [...CT.nodes.values()].find(n => n.addr.endsWith('0b'));
      CT.openAddr('eth', g.addr); await sleep(400);
      const box = !!document.querySelector('#detailBody .wallet-box');
      const saved = CT.watch.get();
      document.querySelector('#detailBody [data-act=walletwatch]').click();
      for (let i = 0; i < 40 && !CT.watch.get().some(w => w.members); i++) await sleep(250);
      const e = CT.watch.get().find(w => w.members);
      await CT.checkWatches(false);
      const ok = box && e && e.members.length >= 2;
      CT.watch.set(saved);
      return ok ? { info: `wallet met ${e.members.length} adressen gevolgd, sig ${String(e.sig).length} tekens` } : `vak=${box} entry=${JSON.stringify(e)}`;
    });
    await t(G, 'geld van hele wallet volgen', async () => {
      const g = [...CT.nodes.values()].find(n => n.addr.endsWith('0b'));
      const before = CT.nodes.size;
      await CT.followWallet(g);
      return CT.nodes.size >= before ? { info: `adressen ${before}→${CT.nodes.size}` } : 'minder adressen';
    });
    await t(G, 'Bitcoin: wisselgeld-regel', async () => {
      const s = await trace('bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', { fanout: 8 });
      const ch = [...CT.nodes.values()].reduce((a, n) => a + (n.data?.changeLinks?.length || 0), 0);
      const rules = new Set();
      for (const n of CT.nodes.values()) { const c = CT.clusterOf(n.key); if (c) for (const r of c.reasons.values()) if (r) rules.add(r.rule); }
      return { info: `wisselgeld-koppelingen ${ch}, regels in gebruik: ${[...rules].join(',') || 'geen'}` };
    });
  },

  async v20() {
    const G = 'v2.0';
    await t(G, 'stortingsadres herkend (voorbeeld)', async () => {
      CT.startDemo(); await sleep(600); for (let i = 0; i < 60 && busy(); i++) await sleep(200); await sleep(300);
      const c = [...CT.nodes.values()].find(n => n.addr.endsWith('06'));
      const ex = [...CT.nodes.values()].find(n => n.addr.endsWith('07'));
      const lab = CT.labelOf(c) || '';
      CT.openLetter(ex); await sleep(200);
      const txt = document.querySelector('#lText').value; document.querySelector('#letterDlg').close();
      const ok = c?.depositOf === ex?.key && /Stortingsadres bij|Deposit address at/.test(lab) && /very likely|zeer waarschijnlijk/.test(txt) && txt.includes(c.addr);
      return ok || `depositOf=${c?.depositOf} label=${lab}`;
    });
    await t(G, 'tijdlijn', async () => {
      document.querySelector('#btnLayoutTime').click(); await sleep(300);
      const all = document.querySelectorAll('#timelineList .tl-row').length, route = document.querySelectorAll('#timelineList .tl-row.route').length;
      document.querySelector('#tlOnlyRoute').click(); await sleep(150);
      const only = document.querySelectorAll('#timelineList .tl-row').length;
      document.querySelector('#tlOnlyRoute').click();
      document.querySelector('#timelineList [data-tx]').click(); await sleep(400);
      const opened = /Transactie|Transaction/.test(document.querySelector('#detailBody h3')?.textContent || '');
      CT.nav && document.querySelector('#detailBody [data-nav=close]')?.click(); await sleep(300);
      document.querySelector('#btnLayoutWeb').click(); await sleep(200);
      return (all > 0 && route > 0 && only === route && opened && document.querySelector('#timeline').hidden) || `alle=${all} route=${route} alleenRoute=${only} geopend=${opened}`;
    });
    await t(G, 'PDF + dossier met vingerafdruk', async () => {
      await CT.exportPdf();
      const ev = CT.evidenceDossier();
      const h = await CT.sha256Hex(JSON.stringify(ev, null, 2));
      const ok = /dossierbestand|evidence file/.test(document.querySelector('#status').textContent) && ev.provenance.length >= 5 && ev.provenance.every(p => p.fetchedAt && p.source) && h.length === 64;
      return ok ? { info: `bronnen ${ev.provenance.length}, hash ${h.slice(0, 12)}` } : document.querySelector('#status').textContent;
    });
    await t(G, 'Tron: gewone TRX-overboekingen', async () => {
      const s = await trace('TV6MuMXfmLbBqPZvBHdwFsDnQeVfnmiuSi');
      const trx = s.data.transfers.filter(x => x.asset === 'TRX');
      const valid = trx.every(x => CT.detectChain(x.from) === 'tron' && CT.detectChain(x.to) === 'tron');
      return trx.length && valid ? { info: `${trx.length} TRX-overboekingen, cursor ${JSON.stringify(Object.keys(s.data.cursor || {}))}` } : `trx=${trx.length} geldig=${valid}`;
    });
    await t(G, 'Ethereum: interne overboekingen', async () => {
      const s = await trace('0x28C6c06298d514Db089934071355E5743bf21d60', { pick: 'eth' });
      const n = s.data.transfers.filter(x => x.internal).length;
      return n ? { info: `${n} interne overboekingen` } : 'skip: geen interne overboekingen geladen (API traag of geen)';
    });
    await t(G, 'Bitcoin: meer geschiedenis startadres', async () => {
      const s = await trace('bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh');
      const tx = new Set(s.data.transfers.map(x => x.txid)).size;
      return tx >= 60 ? { info: `${tx} transacties` } : `${tx} transacties`;
    });
    await t(G, 'tijdvolgorde aan vs uit', async () => {
      document.querySelector('#timeOrder').checked = false;
      await trace('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', { pick: 'eth', depth: 2 });
      const off = CT.nodes.size;
      document.querySelector('#timeOrder').checked = true;
      await trace('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', { pick: 'eth', depth: 2 });
      const on = CT.nodes.size;
      return on <= off ? { info: `adressen: uit ${off}, aan ${on}` } : `aan (${on}) > uit (${off})`;
    });
  },

  async v19() {
    const G = 'nieuw';
    await t(G, 'wallet-herkenning (BTC)', async () => {
      const s = await trace('bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', { depth: 1, fanout: 8 });
      const groups = s.data.coInputs?.length || 0;
      const ws = CT.walletSummary();
      const compound = document.querySelectorAll ? CT.cyWallets() : 0;
      return (groups > 0) ? { info: `co-input-groepen ${groups}, wallets in web ${ws.wallets} (${ws.addrs} adr), groepen in grafiek ${compound}` } : 'geen co-input-groepen';
    });
    await t(G, 'wallet op adrespagina + hele wallet toevoegen', async () => {
      const k = [...CT.nodes.keys()].find(k => CT.clusterOf(k));
      if (!k) return 'skip: geen wallet in dit web';
      const n = CT.nodes.get(k);
      CT.openAddr(n.chain, n.addr); await sleep(500);
      const box = !!document.querySelector('#detailBody .wallet-box');
      const btn = document.querySelector('#detailBody [data-act=wallet]');
      const before = CT.nodes.size;
      if (btn) { btn.click(); await sleep(800); }
      return box ? { info: `vak zichtbaar, adressen ${before}→${CT.nodes.size}, groepen ${CT.cyWallets()}` } : 'geen wallet-vak';
    });
    await t(G, 'spamfilter (ETH Vitalik)', async () => {
      const s = await trace('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', { pick: 'eth' });
      CT.openAddr('eth', s.addr); await sleep(500);
      const chip = document.querySelector('#detailBody [data-filter=novalue]');
      const shown = document.querySelectorAll('#detailBody .xrow').length;
      chip?.click(); await sleep(100);
      const all = document.querySelectorAll('#detailBody .xrow').length;
      return chip ? { info: `met filter ${shown} rijen, zonder ${all}` } : 'skip: geen tokens zonder koers';
    });
    await t(G, 'meldpunt Binance in brief', async () => {
      await trace('0x28C6c06298d514Db089934071355E5743bf21d60', { pick: 'eth' });
      const ex = [...CT.nodes.values()].find(n => /binance/i.test(CT.labelOf(n) || ''));
      if (!ex) return 'skip: geen Binance-label (alleen in de app met lokale database)';
      CT.openLetter(ex); await sleep(200);
      const ok = /kodexglobal\.com\/binance/.test(document.querySelector('#lContact').innerHTML);
      document.querySelector('#letterDlg').close();
      return ok || document.querySelector('#lContact').innerText.slice(0, 120);
    });
    await t(G, 'instellingen: testen + opslaan', async () => {
      document.querySelector('#btnSettings').click(); await sleep(100);
      document.querySelector('#setTest').click(); await sleep(4000);
      const msg = document.querySelector('#setMsg').textContent;
      document.querySelector('#settingsDlg').close();
      return /✓ Solana/.test(msg) || msg;
    });
    await t(G, 'zaak back-up en terugzetten', async () => {
      const c = CT.cases.list().find(x => x.items.length);
      if (!c) return 'skip: geen zaak met onderzoeken';
      const dossiers = {};
      for (const i of c.items) dossiers[i.seedKey] = await CT.idb.get(`dossier:${c.id}:${i.seedKey}`);
      const before = CT.cases.list().length;
      const msg = await CT.importCaseFile(JSON.stringify({ tool: 'ChainTrace', kind: 'case', case: c, dossiers }));
      const after = CT.cases.list();
      const imp = after[0];
      const d = await CT.idb.get(`dossier:${imp.id}:${imp.items[0].seedKey}`);
      CT.cases.save(after.filter(x => x.id !== imp.id));
      return (after.length === before + 1 && imp.items.length === c.items.length && !!d?.nodes?.length) || msg;
    });
  },
  async basis() {
    const G = 'basis';
    await t(G, 'vereiste elementen', () => {
      const ids = ['#addr', '#btnQr', '#btnTrace', '#routeBox', '#caseBar', '#watchBanner', '#demoBanner', '#caseDlg', '#watchDlg', '#letterDlg', '#helpDlg', '#tourCap', '#tourRing', '#chainPick', '#btnTour', '#btnCases', '#btnWatch', '#btnBig', '#btnGlossary'];
      const miss = ids.filter(i => !$(i));
      return miss.length ? false || 'ontbreekt: ' + miss.join(',') : true;
    });
    await t(G, 'ketenherkenning', () => {
      const cases = { bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh: 'btc', '1BoatSLRHtKNngkdXEeobR76b53LETtpyT': 'btc', '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045': 'eth', TV6MuMXfmLbBqPZvBHdwFsDnQeVfnmiuSi: 'tron',
        ltc1q8myx3nw0lsv6t8zxlupu8x53ndyxlyakjmcjws: 'ltc', LQ3B36Yv2rBTxdgAdYpU2UcEZsaNwXeATk: 'ltc', '9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM': 'sol', 'hallo wereld': null, '0x123': null };
      const bad = Object.entries(cases).filter(([a, c]) => CT.detectChain(a) !== c).map(([a, c]) => `${a.slice(0, 10)}→${CT.detectChain(a)} (verwacht ${c})`);
      return bad.length ? 'fout: ' + bad.join('; ') : true;
    });
    await t(G, 'slim plakken (bericht, URI, tx)', () => {
      const ex = CT.extract;
      const a = ex('Stuur naar bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.1 aub');
      const b = ex('mijn usdt adres TV6MuMXfmLbBqPZvBHdwFsDnQeVfnmiuSi.');
      const c = ex('tx: 0x' + 'ab'.repeat(32));
      const d = ex('geen adres hier, alleen tekst van meer dan tweeëndertig tekens lang zonder spaties');
      const ok = a?.value === 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' && b?.chain === 'tron' && c?.kind === 'tx' && !d;
      return ok || `a=${a?.value} b=${b?.chain} c=${c?.kind} d=${JSON.stringify(d)}`;
    });
    await t(G, 'geen horizontale overloop', () => { const o = overflow(); return o.length ? 'overloop: ' + o.join(' ') : true; });
  },

  async demo() {
    const G = 'voorbeeldzaak';
    await t(G, 'voorbeeld draait', async () => {
      CT.startDemo();
      await sleep(600);
      const t0 = Date.now();
      while (busy() && Date.now() - t0 < 30000) await sleep(200);
      return CT.nodes.size >= 7 || 'adressen: ' + CT.nodes.size;
    });
    await t(G, 'routes: exchange eerst, mixer', () => {
      const r = CT.moneyRoutes();
      const ends = r.routes.map(x => x.end.addr.slice(-2));
      return (r.reached && ends[0] === '07' && ends.includes('08')) || 'eindpunten: ' + ends.join(',');
    });
    await t(G, 'herkomst: inkoop bij exchange', () => CT.origins.cashIn.length >= 2 || 'cashIn=' + CT.origins.cashIn.length);
    await t(G, 'samenvatting', () => $('#summaryList').children.length >= 3 || $('#summaryList').innerText);
    await t(G, 'voorbeeld-banner zichtbaar', () => !$('#demoBanner').hidden);
    await t(G, 'brief: adressen en tx-hashes', async () => {
      const ex = [...CT.nodes.values()].find(n => n.addr.endsWith('07'));
      CT.openLetter(ex); await sleep(200);
      const txt = $('#lText').value; $('#letterDlg').close();
      const first = txt.split(/\r?\n/)[0];
      return (/0xdec0de0+f\b/.test(txt) && txt.includes(ex.addr) && /deposit address/i.test(txt) && /Voorbeeld-Exchange/.test(first)) || 'naam/inhoud fout: ' + first;
    });
    await t(G, 'brief NL', async () => {
      const ex = [...CT.nodes.values()].find(n => n.addr.endsWith('07'));
      CT.openLetter(ex); $('#lLang').value = 'nl'; $('#lLang').dispatchEvent(new Event('change'));
      const txt = $('#lText').value; $('#lLang').value = 'en'; $('#lLang').dispatchEvent(new Event('change')); $('#letterDlg').close();
      return /Geachte/.test(txt) || txt.slice(0, 80);
    });
    await t(G, 'demo wordt niet in Mijn zaken bewaard', async () => {
      await sleep(1800);
      return !CT.cases.list().some(c => c.items.some(i => i.addr.startsWith('0xdec0de'))) || 'demo staat in zaken';
    });
  },

  async verkenner() {
    const G = 'verkenner';
    const V = CT.DEMO.victim, A = CT.DEMO.scammer;
    await t(G, 'adrespagina + tabbladen', async () => {
      CT.openAddr('eth', A); await sleep(300);
      const story = !!$('#detailBody .story');
      $('#detailBody [data-tab=cp]').click(); await sleep(100);
      const cp = $('#detailBody').querySelectorAll('.xrow').length;
      $('#detailBody [data-tab=osint]').click(); await sleep(100);
      const os = !!$('#nodeNote');
      $('#detailBody [data-tab=tx]').click(); await sleep(100);
      const tx = $('#detailBody').querySelectorAll('.xrow').length;
      return (story && cp >= 3 && os && tx >= 5) || `story=${story} cp=${cp} osint=${os} tx=${tx}`;
    });
    await t(G, 'filters in/uit', async () => {
      $('#detailBody [data-filter=in]').click(); await sleep(80);
      const ins = [...$('#detailBody').querySelectorAll('.xrow .dir')].every(d => d.classList.contains('in'));
      $('#detailBody [data-filter=out]').click(); await sleep(80);
      const outs = [...$('#detailBody').querySelectorAll('.xrow .dir')].every(d => d.classList.contains('out'));
      $('#detailBody [data-filter=all]').click();
      return (ins && outs) || `in=${ins} uit=${outs}`;
    });
    await t(G, 'transactie → adres → terug', async () => {
      $('#detailBody [data-tx]').click(); await sleep(400);
      const isTx = /Transactie/.test($('#detailBody h3').textContent);
      $('#detailBody [data-addr]').click(); await sleep(400);
      const depth1 = CT.nav.i;
      if (window.AndroidBridge) window.ChainTraceBack(); else history.back();
      await sleep(400);
      const back = /Transactie/.test($('#detailBody h3').textContent);
      return (isTx && depth1 === 2 && back) || `tx=${isTx} i=${depth1} terug=${back}`;
    });
    await t(G, 'uitleg-popup', async () => {
      CT.openAddr('eth', A); await sleep(300);
      const h = $('#detailBody .tag.help'); h.click(); await sleep(150);
      const ok = $('#helpDlg').open && $('#helpBody h2').textContent.length > 2;
      $('#helpDlg').close(); return ok;
    });
    await t(G, 'woordenlijst', async () => { $('#btnGlossary').click(); await sleep(100); const n = $('#helpBody').querySelectorAll('h3').length; $('#helpDlg').close(); return n >= 15 || 'termen=' + n; });
    await t(G, 'herkomst vindt andere slachtoffers', async () => {
      CT.openAddr('eth', A); await sleep(200);
      $('#detailBody [data-act=origins]').click();
      const t0 = Date.now(); while (busy() && Date.now() - t0 < 15000) await sleep(200);
      await sleep(300);
      const starts = [...CT.origins.starts.values()].map(s => s.addr.slice(-2));
      return (starts.includes('03') && starts.includes('04')) || 'startwallets: ' + starts.join(',');
    });
    await t(G, 'toevoegen aan web (+ web)', async () => {
      const before = CT.nodes.size;
      CT.openAddr('eth', V); await sleep(200);
      $('#detailBody [data-tab=cp]').click(); await sleep(100);
      const add = $('#detailBody [data-add]');
      if (!add) return 'skip: alle tegenpartijen al in web';
      add.click(); await sleep(300);
      return CT.nodes.size > before || `adressen ${before}→${CT.nodes.size}`;
    });
    await t(G, 'sluiten', async () => { $('#detailBody [data-nav=close]')?.click(); await sleep(500); return $('#detail').hidden || 'nog open, i=' + CT.nav.i; });
  },

  async ketens() {
    const G = 'ketens';
    const cases = [
      ['Bitcoin', 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', {}],
      ['Ethereum', '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', { pick: 'eth' }],
      ['Optimism', '0x28C6c06298d514Db089934071355E5743bf21d60', { pick: 'op' }],
      ['Avalanche', '0x28C6c06298d514Db089934071355E5743bf21d60', { pick: 'avax' }],
      ['zkSync', '0x28C6c06298d514Db089934071355E5743bf21d60', { pick: 'zksync' }],
      ['Tron', 'TV6MuMXfmLbBqPZvBHdwFsDnQeVfnmiuSi', {}],
      ['Solana', '9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM', {}],
      ['Litecoin', 'ltc1q8myx3nw0lsv6t8zxlupu8x53ndyxlyakjmcjws', {}]
    ];
    for (const [name, addr, opt] of cases) {
      await t(G, name, async () => {
        const s = await trace(addr, opt);
        if (!s) return 'geen startadres';
        const err = s.flags.find(f => f.code === 'error');
        if (err) return false || err.text;
        const n = s.data?.transfers.length || 0;
        return n > 0 ? { info: `${n} transfers, ${CT.nodes.size} adressen, saldo ${s.data.balance || '?'}` } : `0 transfers (${$('#status').textContent})`;
      });
    }
    await t(G, 'tx-detail per keten', async () => {
      const out = [];
      for (const [chain, txid] of [['btc', '131576aeb4fd09926c85c8539700a8e06d4d3b719c9f66a8bd0d8f90b05032ce']]) {
        CT.openTx(chain, txid); await sleep(3000);
        out.push(chain + ':' + $('#detailBody').querySelectorAll('.xrow').length);
      }
      const sol = [...CT.nodes.values(), ...CT.ghosts.values()].find(n => n.chain === 'sol' && n.data?.transfers.length);
      if (sol) { CT.openTx('sol', sol.data.transfers[0].txid); await sleep(4000); out.push('sol:' + $('#detailBody').querySelectorAll('.xrow').length); }
      $('#detailBody [data-nav=close]')?.click();
      return out.every(x => +x.split(':')[1] > 0) ? { info: out.join(' ') } : out.join(' ');
    });
  },

  async meer() {
    const G = 'meer laden';
    await t(G, 'oudere transacties (BTC)', async () => {
      CT.openAddr('btc', 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh');
      const k = 'btc:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh';
      let n; for (let i = 0; i < 60; i++) { n = CT.nodes.get(k) || CT.ghosts.get(k); if (n?.data) break; await sleep(500); }
      await sleep(300);
      const before = n?.data?.transfers.length || 0;
      let b, guard = 0; while ((b = $('#detailBody [data-more=show]')) && guard++ < 50) { b.click(); await sleep(50); }
      b = $('#detailBody [data-more=fetch]');
      if (!b) return 'geen "oudere laden"-knop (cursor=' + JSON.stringify(n?.data?.cursor) + ')';
      b.click(); await sleep(6000);
      return n.data.transfers.length > before || `${before}→${n.data.transfers.length}`;
    });
  },

  async zaken() {
    const G = 'mijn zaken';
    await t(G, 'autosave na onderzoek', async () => {
      await sleep(2000);
      const c = CT.cases.list().find(x => x.id === CT.cases.currentId());
      return (c && c.items.length >= 1) || 'geen zaak/onderzoek bewaard';
    });
    await t(G, 'openen uit zaak', async () => {
      const c = CT.cases.list().find(x => x.id === CT.cases.currentId());
      $('#btnCases2').click(); await sleep(200);
      const open = $('#caseItems [data-open]');
      open.click(); await sleep(800);
      return (!$('#caseDlg').open && CT.nodes.size > 0) || 'nodes=' + CT.nodes.size;
    });
    await t(G, 'samenvoegen', async () => {
      $('#btnCases2').click(); await sleep(200);
      const dis = $('#caseMerge').disabled;
      if (dis) { $('#caseDlg').close(); return 'skip: minder dan 2 onderzoeken in zaak'; }
      $('#caseMerge').click(); await sleep(1500);
      return /samen in één web/.test($('#status').textContent) || $('#status').textContent;
    });
  },

  async volgen() {
    const G = 'volgen';
    const saved = CT.watch.get();
    await t(G, 'volgen aan/uit op adrespagina', async () => {
      CT.openAddr('btc', 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh'); await sleep(2500);
      const b = $('#detailBody [data-act=watch]'); b.click(); await sleep(3000);
      const on = CT.watch.get().some(w => w.addr === 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' && w.sig);
      $('#detailBody [data-act=watch]').click(); await sleep(300);
      const off = !CT.watch.get().some(w => w.addr === 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh');
      return (on && off) || `aan=${on} uit=${off}`;
    });
    await t(G, 'beweging gedetecteerd + banner', async () => {
      CT.watch.set([{ chain: 'btc', addr: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', label: 'test', sig: 'oud', changed: false }]);
      await CT.checkWatches(true);
      const ok = CT.watch.get()[0].changed && !$('#watchBanner').hidden;
      CT.watch.set(saved);
      return ok;
    });
    $('#detailBody [data-nav=close]')?.click();
  },

  async qr() {
    const G = 'qr';
    await t(G, 'QR uit afbeelding', async () => {
      // QR genereren kan niet zonder bibliotheek: gebruik een ingebakken test-PNG als die er is.
      const r = await fetch('qrtest.png').catch(() => null);
      if (!r?.ok) return 'skip: geen qrtest.png';
      const f = new File([await r.blob()], 'qr.png', { type: 'image/png' });
      const dt = new DataTransfer(); dt.items.add(f);
      $('#qrFile').files = dt.files; $('#qrFile').dispatchEvent(new Event('change'));
      await sleep(1500);
      return $('#addr').value === 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' || $('#addr').value;
    });
  },

  async pdf() {
    const G = 'pdf';
    await t(G, 'PDF-rapport', async () => { await CT.exportPdf(); return /PDF-rapport (en dossierbestand )?opgeslagen|PDF report/.test($('#status').textContent) || $('#status').textContent; });
  },

  async tour() {
    const G = 'rondleiding';
    await t(G, 'volledige rondleiding', async () => {
      const w0 = R.warnings.length;
      await CT.runTour();
      const miss = R.warnings.slice(w0).filter(w => /rondleiding/.test(w));
      return miss.length ? 'niet gevonden: ' + miss.join(' | ') : true;
    });
  },

  async layout() {
    const G = 'layout';
    for (const tab of ['form', 'graph', 'detail']) {
      await t(G, 'overloop tab ' + tab, async () => {
        if (tab === 'detail') { CT.openAddr('eth', CT.DEMO.scammer); await sleep(400); }
        else document.querySelector(`.tabbar [data-go=${tab}]`)?.click();
        await sleep(300);
        const o = overflow();
        return o.length ? o.join(' ') : true;
      });
    }
    await t(G, 'knoppen groot genoeg (telefoon)', () => {
      if (innerWidth > 820) return 'skip: breed scherm';
      const small = [...document.querySelectorAll('button, .seg label')].filter(b => { const r = b.getBoundingClientRect(); return r.width && r.height && r.height < 30 && !b.closest('.legend, #cy, dialog:not([open])') && getComputedStyle(b).visibility !== 'hidden'; });
      return small.length <= 3 ? true : small.length + ' kleine knoppen: ' + small.slice(0, 6).map(b => (b.textContent || b.className).trim().slice(0, 14) + ':' + Math.round(b.getBoundingClientRect().height)).join(', ');
    });
    $('#detailBody [data-nav=close]')?.click();
  }
};

window.ChainTraceSelftest = {
  async run(list) {
    R.done = false; R.log = []; R.started = Date.now();
    for (const g of list) { R.current = g; await groups[g](); }
    R.done = true; R.current = null;
    return R;
  },
  summary() {
    return { done: R.done, current: R.current, fail: R.log.filter(x => !x.ok), pass: R.log.filter(x => x.ok).map(x => `${x.group}/${x.name}${x.detail ? ' [' + x.detail + ']' : ''} ${x.ms}ms`), errors: [...new Set(R.errors)].slice(0, 12), warnings: [...new Set(R.warnings)].slice(0, 8) };
  }
};
})();
