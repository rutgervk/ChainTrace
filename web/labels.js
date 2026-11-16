// Kleine, handmatig bijgehouden set publiek bekende service-adressen (OSINT).
// Ethereum/Optimism-labels komen live uit Blockscout; deze lijst vult vooral BTC en Tron aan.
// Uitbreiden kan via een pull request, of lokaal via "Label toevoegen" in de app.
window.KNOWN_LABELS = {
  // Bitcoin
  '34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo': { name: 'Binance (cold wallet)', type: 'exchange' },
  '3M219KR5vEneNb47ewrPfWyb5jQ2DjxRP6': { name: 'Binance', type: 'exchange' },
  'bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97': { name: 'Bitfinex (cold wallet)', type: 'exchange' },
  '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa': { name: 'Genesis-adres (Satoshi)', type: 'other' },
  // Tron
  'TV6MuMXfmLbBqPZvBHdwFsDnQeVfnmiuSi': { name: 'Binance (hot wallet)', type: 'exchange' },
  'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t': { name: 'Tether USDT-contract', type: 'contract' }
};
