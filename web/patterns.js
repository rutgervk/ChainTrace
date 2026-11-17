// Fraudepatronen: bepalen traceerrichting, diepte en welke heuristieken zwaar wegen.
// dir: welke kant op wordt vanaf het startadres gevolgd per rol.
//   victim -> 'out' volgt het geld van het slachtoffer naar de dader(s)
//   perp   -> 'both' toont andere slachtoffers (in) én de cash-out (out)
window.PATTERNS = {
  pig: {
    name: 'Pig butchering / nep-beleggingsplatform',
    info: 'Slachtoffer stort (vaak USDT op Tron) op een "platform"; geld wordt via doorsluisadressen naar exchanges gebracht.',
    depth: 3, fanout: 6,
    dir: { victim: 'out', perp: 'both' },
    focus: ['exchange', 'passthrough', 'fanin', 'consolidation'],
    steps: [
      'Noteer alle stortingen (datum, bedrag, tx-hash) vanuit het slachtofferadres.',
      'Zoek in het web de eerste exchange/dienst (groen) — daar kan een bevriezings- of informatieverzoek naartoe.',
      'Doe aangifte bij de politie (fraudehelpdesk / politie.nl) en voeg het dossier (JSON + PNG) toe.',
      'USDT? Tether kan adressen bevriezen via een verzoek van opsporingsinstanties — noem de dader-adressen expliciet.',
      'Meld de dader-adressen op chainabuse.com zodat anderen gewaarschuwd worden.'
    ]
  },
  romance: {
    name: 'Romance scam',
    info: 'Vertrouwensrelatie online; slachtoffer koopt crypto en stuurt die door naar "partner".',
    depth: 3, fanout: 5,
    dir: { victim: 'out', perp: 'both' },
    focus: ['exchange', 'passthrough', 'fanin'],
    steps: [
      'Bewaar alle chats, profielen en betaalbewijzen naast dit dossier.',
      'Volg het geld tot de eerste exchange; vermeld die in de aangifte.',
      'Controleer of het dader-adres geld van meerdere slachtoffers ontvangt (fan-in) — dat versterkt de zaak.',
      'Meld profielen bij het platform en de adressen op chainabuse.com.'
    ]
  },
  drainer: {
    name: 'Phishing / wallet drainer',
    info: 'Slachtoffer tekent een kwaadaardige transactie/approval; tokens worden razendsnel weggesluisd.',
    depth: 2, fanout: 6,
    dir: { victim: 'out', perp: 'both' },
    focus: ['scamlist', 'passthrough', 'fanin', 'contract'],
    steps: [
      'Trek direct alle token-approvals in (revoke.cash) en verplaats resterende tegoeden naar een nieuwe wallet.',
      'Controleer welke adressen op de ScamSniffer-lijst staan — vaak de drainer-ontvanger.',
      'Volg de snelle doorstort-adressen naar exchanges/bridges en documenteer de tx-hashes.',
      'Meld de phishingsite en adressen (chainabuse.com, ScamSniffer).'
    ]
  },
  poisoning: {
    name: 'Address poisoning',
    info: 'Dader stuurt nep- of 0-transacties vanaf een adres dat lijkt op een bekend adres; slachtoffer kopieert het verkeerde adres.',
    depth: 2, fanout: 8,
    dir: { victim: 'both', perp: 'both' },
    focus: ['lookalike', 'dust', 'passthrough'],
    steps: [
      'Vergelijk het ontvangende adres teken-voor-teken met het bedoelde adres (begin én eind lijken gelijk).',
      'Lookalike-adressen zijn rood gemarkeerd; volg het geld verder vanaf daar.',
      'Kopieer voortaan adressen uit een adresboek, niet uit transactiegeschiedenis.',
      'Meld het lookalike-adres op chainabuse.com.'
    ]
  },
  ransomware: {
    name: 'Ransomware / afpersing',
    info: 'Losgeld (meestal BTC) wordt via peel chains en mixers witgewassen.',
    depth: 3, fanout: 4,
    dir: { victim: 'out', perp: 'both' },
    focus: ['peel', 'sanction', 'exchange', 'consolidation'],
    steps: [
      'Doe aangifte en meld bij het NCSC; betaal liever niet.',
      'Volg de peel chain: elke hop splitst een klein bedrag af (vaak naar een exchange).',
      'Check de OFAC-sanctiehits — betalingen aan gesanctioneerde adressen hebben juridische gevolgen.',
      'Bewaar de losgeldnota met het betaaladres in het dossier.'
    ]
  },
  ponzi: {
    name: 'Ponzi / rug pull',
    info: 'Veel inleggers (fan-in) naar een verzameladres; opbrengst wordt weggehaald of uitbetaald aan vroege deelnemers.',
    depth: 2, fanout: 8,
    dir: { victim: 'out', perp: 'both' },
    focus: ['fanin', 'fanout', 'exchange', 'contract'],
    steps: [
      'Bepaal het verzameladres (veel inkomende stortingen = fan-in).',
      'Kijk waar het verzamelde geld heen gaat (cash-out naar exchanges of bridges).',
      'Andere inleggers vind je als inkomende pijlen op het verzameladres — zij zijn mogelijk medegedupeerden.'
    ]
  },
  recovery: {
    name: 'Nep-helpdesk / recovery scam',
    info: 'Na een eerdere oplichting belooft een "recovery-bureau" het geld terug te halen tegen betaling vooraf.',
    depth: 2, fanout: 5,
    dir: { victim: 'out', perp: 'both' },
    focus: ['exchange', 'passthrough', 'fanin'],
    steps: [
      'Echte opsporing vraagt nooit vooraf betaling in crypto — stop met betalen.',
      'Check of het "recovery"-adres verbonden is met de oorspronkelijke dader-adressen.',
      'Voeg beide fraudes samen in één aangifte.'
    ]
  },
  generic: {
    name: 'Onbekend / algemeen',
    info: 'Geen probleem: de app zoekt breed en let op alle bekende signalen.',
    depth: 2, fanout: 6,
    dir: { victim: 'out', perp: 'both' },
    focus: [],
    steps: [
      'Bekijk de bevindingen; rode en oranje adressen verdienen extra aandacht.',
      'Klik op een adres en gebruik "Verder traceren" om dieper te gaan.',
      'Exporteer het dossier en voeg het toe aan een aangifte.'
    ]
  }
};
