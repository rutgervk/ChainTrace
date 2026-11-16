# ChainTrace

Open-source blockchain-onderzoek zonder login. Voer een walletadres in, kies **slachtoffer** of **dader** en een **fraudepatroon** — de app bouwt direct een web van geldstromen en markeert verdachte adressen met OSINT en heuristieken.

Eén codebase, twee vormen:
- **Web** — statische site in [`web/`](web/), draait in elke browser.
- **Android** — WebView-schil (`app/`) die exact dezelfde webapp bundelt, met opslaan naar Downloads en een eigen lokale OSINT-database.

Er is geen server: de app praat rechtstreeks met publieke blockchain-API's en bewaart alle OSINT op het apparaat.

## Ketens en databronnen (allemaal gratis, geen API-sleutel)

| Keten | Bron | Wat |
|---|---|---|
| Bitcoin | mempool.space | transacties, saldo, tx-aantal |
| Ethereum | eth.blockscout.com | ETH + ERC-20, publieke labels (bv. "Binance: Hot Wallet"), ENS, scam-vlag |
| Optimism | explorer.optimism.io (Blockscout) | idem |
| Tron | TronGrid | TRC-20 (USDT/USDC), nep-token-detectie |

OSINT-lijsten: OFAC-sanctieadressen ([0xB10C](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses)), [ScamSniffer](https://github.com/scamsniffer/scam-database)-blacklist, een kleine eigen labelset (`web/labels.js`) en eigen labels (lokaal opgeslagen). Per adres zijn er zoeklinks naar Chainabuse, Breadcrumbs, Arkham, Google, X, Reddit, GitHub en Telegram.

## Lokale OSINT-database (Android)

De app houdt een SQLite-database bij (`osint.db`, ca. 200 MB) die via WorkManager **dagelijks** wordt bijgewerkt (eerste keer direct na installatie, alleen met netwerk). Via **Database** in de app zie je per bron de status, kun je zoeken op adres of label en handmatig bijwerken.

| Bron | Inhoud | Records (nov 2026) |
|---|---|---|
| [OFAC (0xB10C)](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses) | sanctieadressen BTC/ETH/TRX/USDT/USDC/LTC/… | ~1.000 |
| [ScamSniffer](https://github.com/scamsniffer/scam-database) | drainers/scams (EVM) | ~2.500 |
| [MyEtherWallet darklist](https://github.com/MyEtherWallet/ethereum-lists) | phishing/scam (EVM) | ~650 |
| [Forta labelled datasets](https://github.com/forta-network/labelled-datasets) | phishing, kwaadaardige contracten + makers | ~7.000 |
| [Etherscan-labels](https://github.com/brianleect/etherscan-labels) | exchanges, protocollen, hacks (EVM) | ~30.000 |
| [Ransomwhere](https://ransomwhe.re) | ransomware-betaaladressen per familie | ~11.000 |
| [GraphSense tagpacks](https://github.com/graphsense/graphsense-tagpacks) | exchanges, mixers, darknet, scams (BTC/ETH/TRX) | ~500.000 |
| Tether USDT-blacklist (Tron, TronGrid) | bevroren adressen, opheffingen verwerkt | ~8.000 |
| Tether USDT-blacklist (Ethereum, Blockscout) | bevroren adressen, opheffingen verwerkt | ~3.000 |

Daarnaast slaat de app na elke trace **eigen waarnemingen** op (adres, rol, classificatie, zaak). Komt een adres later in een andere zaak terug, dan meldt de app "eerder als dader/verdacht gezien". Eigen labels gaan ook de database in.

De webversie heeft geen lokale database en laadt OFAC en ScamSniffer direct bij het traceren.

## Heuristieken
- **Exchange/dienst** (label of zeer hoog tx-volume) → cash-out-punt, trace stopt daar
- **Doorsluisadres** — ≥60% van de inkomende stortingen binnen 1 uur doorgestort
- **Fan-in / fan-out** — ≥10 afzenders/ontvangers (verzameladres, layering)
- **Peel chain** (BTC) — herhaalde 2-output-transacties met ≥80% in één output
- **Address poisoning** — tegenpartijen met hetzelfde begin/eind, nul- of nep-tokentransfers
- **Sanctie / scamlijst / mixer / bridge**

Rol en patroon bepalen de richting: bij een slachtoffer volgt de app het geld vooruit naar de dader(s); bij een dader toont hij ook de inkomende kant (mogelijke andere slachtoffers). Elk patroon heeft eigen diepte, focus en vervolgstappen.

> Heuristieken zijn aanwijzingen, geen bewijs. Gebruik de resultaten als startpunt voor een aangifte of verder onderzoek.

## Draaien

Web (lokaal):
```bash
python -m http.server 8765 --directory web
```
Open daarna http://localhost:8765. De map `web/` kan ook op elke statische host (GitHub Pages, Netlify) worden gezet.

Android:
```bash
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Dossier
"Dossier" exporteert alle adressen, labels, bevindingen en transacties als JSON; "PNG" exporteert het web als afbeelding. Een dossier kan weer worden geïmporteerd.

## Licentie
MIT
