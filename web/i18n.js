// Vertaallaag: Nederlands is de brontaal; in het Engels wordt zichtbare tekst via dit woordenboek vertaald.
// exact: hele tekst (spaties genormaliseerd). patterns: {0},{1}… zijn variabele delen (worden zelf ook vertaald).
(() => {
'use strict';
const LANG = (() => { try { return JSON.parse(localStorage.getItem('chaintrace.lang') || '"nl"'); } catch { return 'nl'; } })();
window.CT_LANG = LANG;
window.CT_LOCALE = LANG === 'en' ? 'en-GB' : 'nl-NL';

const exact = {
  // --- kop, menu, formulier ---
  'Open-source blockchain-onderzoek · geen login · OSINT': 'Open-source blockchain investigation · no login · OSINT',
  'Zoek adres of transactie-hash…': 'Search address or transaction hash…', 'Zoek adres of transactie': 'Search address or transaction',
  'PDF-rapport': 'PDF report', 'Meer': 'More', 'Afbeelding opslaan': 'Save image', 'Dossier opslaan': 'Save file', 'Dossier openen': 'Open file',
  'OSINT-database': 'OSINT database', '▶ Rondleiding': '▶ Guided tour', '📁 Mijn zaken': '📁 My cases', '🔔 Gevolgde adressen': '🔔 Watched addresses',
  'Grote letters': 'Large text', 'Normale letters': 'Normal text', 'Woordenlijst (uitleg)': 'Glossary', '⚙ Instellingen': '⚙ Settings',
  'Bekijk': 'View', '📘 Dit is een': '📘 This is an', 'voorbeeldzaak met verzonnen gegevens': 'example case with made-up data', 'Stop voorbeeld': 'Stop example',
  '📁 Zaak:': '📁 Case:', 'nog geen zaak': 'no case yet', 'Mijn zaken': 'My cases',
  '1. Welk walletadres wil je onderzoeken?': '1. Which wallet address do you want to investigate?', 'Uitleg walletadres': 'What is a wallet address',
  'Plak hier het adres': 'Paste the address here', 'Plak': 'Paste', 'QR-code uit een foto of screenshot lezen': 'Read QR code from a photo or screenshot',
  'Bitcoin, Ethereum, Tron, Solana, Litecoin, Avalanche, Optimism en zkSync worden automatisch herkend. Je mag ook een heel bericht plakken, of een QR-code uit een foto/screenshot lezen.':
    'Bitcoin, Ethereum, Tron, Solana, Litecoin, Avalanche, Optimism and zkSync are recognised automatically. You may also paste a whole message, or read a QR code from a photo/screenshot.',
  '2. Van wie is dit adres?': '2. Whose address is this?', 'Slachtoffer': 'Victim', 'Dader': 'Perpetrator', '3. Wat is er gebeurd?': '3. What happened?', '(mag je overslaan)': '(optional)',
  'Geavanceerde instellingen': 'Advanced settings', 'Keten': 'Chain', 'Automatisch': 'Automatic', 'Aantal stappen volgen': 'Number of hops to follow',
  'Max. tegenpartijen per adres': 'Max. counterparties per address', 'Max. adressen totaal': 'Max. addresses in total', 'Start onderzoek': 'Start investigation', 'Stop': 'Stop',
  'Samenvatting': 'Summary', '🔊 Lees voor': '🔊 Read aloud', 'Maak PDF-rapport': 'Create PDF report', 'Het geld stap voor stap': 'The money step by step',
  'Wat kun je nu doen?': 'What can you do now?', 'Waar kwam het geld vandaan?': 'Where did the money come from?',
  'Startwallets zijn adressen waar het geld begon: mogelijke andere slachtoffers. Bij een exchange kan de politie opvragen wie de klant is.':
    'Start wallets are addresses where the money began: possibly other victims. At an exchange, the police can request who the customer is.',
  'Geld dat van een exchange kwam': 'Money that came from an exchange', 'Startwallets · mogelijke slachtoffers': 'Start wallets · possible victims',
  'Lijst opslaan als CSV (Excel)': 'Save list as CSV (Excel)', 'Opvallende adressen': 'Notable addresses', 'Notities bij deze zaak': 'Notes for this case',
  'Aangiftenummer, contact met exchange, verklaringen, vervolgstappen…': 'Report number, contact with exchange, statements, next steps…',
  'Web': 'Graph', 'Stroom': 'Flow', 'Passend': 'Fit', 'Legenda': 'Legend', 'Mogelijk slachtoffer': 'Possible victim', 'Verdacht': 'Suspicious',
  'Exchange/dienst': 'Exchange/service', 'Sanctie/scam-lijst': 'Sanction/scam list', 'Onbekend': 'Unknown',
  'Volg het geld': 'Follow the money', 'Plak een walletadres': 'Paste a wallet address', '— van het slachtoffer of van de dader.': '— of the victim or of the perpetrator.',
  'Start het onderzoek': 'Start the investigation', '— de app tekent waar het geld heen ging en waar het vandaan kwam.': '— the app draws where the money went and where it came from.',
  'Klik door': 'Click through', '— tik op een adres of transactie en blijf doorklikken, net als in een blockchain-explorer.': '— tap an address or transaction and keep clicking through, just like in a blockchain explorer.',
  'Maak een PDF-rapport': 'Create a PDF report', '— met alle adressen en transacties, voor je aangifte.': '— with all addresses and transactions, for your police report.',
  'Geen account nodig. Je gegevens blijven op dit apparaat.': 'No account needed. Your data stays on this device.',
  '▶ Rondleiding (2 minuten)': '▶ Guided tour (2 minutes)', 'Bekijk een voorbeeldzaak': 'View an example case', 'rondleiding laten voorlezen': 'read the tour aloud',
  'Schermen': 'Screens', 'Onderzoek': 'Investigate', 'Verkenner': 'Explorer',
  'Lokale OSINT-database': 'Local OSINT database', 'Sluiten': 'Close', 'Zoek adres of label (bv. Binance, Lazarus, LockBit)…': 'Search address or label (e.g. Binance, Lazarus, LockBit)…',
  'Bron': 'Source', 'Records': 'Records', 'Status': 'Status', 'Bijgewerkt': 'Updated', 'Nu bijwerken': 'Update now',
  'Afbeelding exporteren': 'Export image', 'Thema': 'Theme', 'Licht (print / rapport)': 'Light (print / report)', 'Donker (scherm)': 'Dark (screen)',
  'Inhoud rapport': 'Report contents', 'Herkomst: exchange-instroom en startwallets': 'Origin: exchange inflow and start wallets', 'Bevindingen': 'Findings', 'Notities': 'Notes',
  'Volledig rapport (PNG)': 'Full report (PNG)', 'Alleen het web (PNG, hoge resolutie)': 'Graph only (PNG, high resolution)',
  'Brief aan exchange': 'Letter to exchange',
  'Stuur deze brief naar de afdeling voor politieverzoeken (law enforcement / compliance) van de exchange. Exchanges reageren meestal alleen op politie of justitie: vul daarom het aangifte- of zaaknummer in. Snel zijn helpt: geld kan binnen uren weg zijn.':
    "Send this letter to the exchange's law enforcement / compliance team. Exchanges usually only respond to police or prosecutors, so fill in the report or case number. Speed matters: money can be gone within hours.",
  'Naam en organisatie': 'Name and organisation', 'E-mail voor reactie': 'Reply e-mail', 'Aangifte- of zaaknummer': 'Report or case number', 'Taal': 'Language',
  'Engels (aanbevolen)': 'English (recommended)', 'Nederlands': 'Dutch', 'Kopieer brief': 'Copy letter', 'Delen (mail, WhatsApp…)': 'Share (mail, WhatsApp…)', 'Zoek het contactadres': 'Find the contact address',
  'Elk onderzoek wordt automatisch bewaard in de huidige zaak, alleen op dit apparaat. Zet meerdere onderzoeken samen in één web om verbanden te zien, zoals dezelfde oplichter bij verschillende slachtoffers.':
    'Every investigation is saved automatically in the current case, only on this device. Put several investigations together in one graph to see connections, such as the same scammer behind different victims.',
  '+ Nieuwe zaak': '+ New case', 'Back-up terugzetten': 'Restore backup', 'Alle onderzoeken samen in één web': 'All investigations together in one graph',
  'Nieuwe onderzoeken hierin bewaren': 'Save new investigations here', 'Naam wijzigen': 'Rename', 'Back-up maken (bestand)': 'Make backup (file)', 'Zaak verwijderen': 'Delete case',
  'Taal / Language': 'Language / Taal', 'Solana-server (optioneel)': 'Solana server (optional)',
  'Leeg = gratis openbare server (20 transacties per adres, traag). Met een eigen gratis sleutel (bijv. van Helius) haalt de app er 60 per keer op.':
    'Empty = free public server (20 transactions per address, slow). With your own free key (e.g. from Helius) the app fetches 60 at a time.',
  'TronGrid-sleutel (optioneel)': 'TronGrid key (optional)', 'bijv. 1a2b3c4d-…': 'e.g. 1a2b3c4d-…',
  'Gratis aan te maken op trongrid.io. Maakt Tron-onderzoek ongeveer 8× sneller.': 'Free to create at trongrid.io. Makes Tron investigations about 8× faster.',
  'Sleutels blijven alleen op dit apparaat.': 'Keys stay on this device only.', 'Testen': 'Test', 'Opslaan': 'Save',
  'De app controleert gevolgde adressen regelmatig (op Android ook als de app dicht is) en geeft een melding als er weer geld beweegt. Dan is het tijd om de exchange of politie te waarschuwen.':
    'The app checks watched addresses regularly (on Android also when the app is closed) and notifies you when money moves again. That is the moment to alert the exchange or the police.',
  'Nu controleren': 'Check now', 'Stop rondleiding': 'Stop tour',
  'Data: mempool.space · Blockscout · TronGrid · OFAC-lijst (0xB10C) · ScamSniffer. Heuristieken zijn aanwijzingen, geen bewijs.':
    'Data: mempool.space · Blockscout · TronGrid · OFAC list (0xB10C) · ScamSniffer. Heuristics are indications, not proof.',
  'Weet ik niet / iets anders': "I don't know / something else",
  // --- verkenner ---
  '‹ Terug': '‹ Back', 'Kopieer': 'Copy', 'Niet in het web': 'Not in graph', 'In gewone taal': 'In plain language', 'Saldo': 'Balance', 'Transacties': 'Transactions',
  'Ontvangen*': 'Received*', 'Verzonden*': 'Sent*', 'Actief (geladen)': 'Active (loaded)', '+ Toevoegen aan web': '+ Add to graph', 'Toon in web': 'Show in graph',
  'Waar ging het geld heen?': 'Where did the money go?', 'Waar kwam het vandaan?': 'Where did it come from?', '🔔 Volg dit adres': '🔔 Watch this address',
  '🔕 Niet meer volgen': '🔕 Stop watching', 'Meer…': 'More…', 'Markeer als dader': 'Mark as perpetrator', 'Markeer als slachtoffer': 'Mark as victim',
  'Dader-markering weghalen': 'Remove perpetrator mark', 'Slachtoffer-markering weghalen': 'Remove victim mark', 'Label toevoegen': 'Add label', 'Verwijder uit web': 'Remove from graph',
  'Tegenpartijen': 'Counterparties', 'OSINT & notitie': 'OSINT & note', 'Alles': 'All', '↓ In': '↓ In', '↑ Uit': '↑ Out', 'Uit': 'Out',
  'Transacties ophalen…': 'Fetching transactions…', 'Transactie ophalen…': 'Fetching transaction…', 'Oudere transacties laden': 'Load older transactions', 'Laden…': 'Loading…',
  'Geen transacties in deze selectie.': 'No transactions in this selection.', 'Geen tegenpartijen gevonden.': 'No counterparties found.',
  '* Op basis van de geladen transacties. Tik op een adres of transactie om erheen te gaan.': '* Based on the loaded transactions. Tap an address or transaction to go there.',
  'spam/nul': 'spam/zero', 'Transactie': 'Transaction', 'Bevestigd': 'Confirmed', 'Onbevestigd': 'Unconfirmed', 'Mislukt': 'Failed', 'Tijd': 'Time', 'Fee': 'Fee', 'Methode': 'Method',
  'Afzender → ontvanger': 'Sender → recipient', 'Overboekingen': 'Transfers', 'Geen waarde-overboekingen.': 'No value transfers.', 'Van (inputs)': 'From (inputs)', 'Naar (outputs)': 'To (outputs)',
  'Hier staan alleen de overboekingen van adressen die de app al geladen heeft. Gebruik de link hieronder voor de volledige transactie.': 'Only transfers of addresses the app has already loaded are shown. Use the link below for the full transaction.',
  'Geldstroom': 'Money flow', 'Van': 'From', 'Naar': 'To', 'Eerste': 'First', 'Laatste': 'Last', 'Aantal': 'Count', 'Deze geldstroom staat niet meer in het web.': 'This money flow is no longer in the graph.',
  'OSINT (automatisch)': 'OSINT (automatic)', 'OFAC-sanctie': 'OFAC sanction', 'nee': 'no', '⚠️ JA': '⚠️ YES', 'niet gevonden': 'not found', '⚠️ op blacklist': '⚠️ on blacklist',
  'lijst niet geladen': 'list not loaded', 'Publieke labels': 'Public labels', 'Contractnaam': 'Contract name', 'Bekend label': 'Known label', 'Hop': 'Hop', 'niet in het web': 'not in graph',
  'OSINT-bronnen': 'OSINT sources', 'Notitie': 'Note', 'Lokale OSINT-database': 'Local OSINT database', 'Geen labels in de lokale database.': 'No labels in the local database.',
  'Bijv. bevestigd door slachtoffer, aangifte nr., contact exchange…': 'E.g. confirmed by victim, report no., contact with exchange…',
  'Geen startwallets gevonden.': 'No start wallets found.', 'Lees voor': 'Read aloud', 'Staat in het web': 'In the graph', 'Toevoegen aan web': 'Add to graph',
  'Geen instroom via exchanges gevonden binnen de zoekdiepte.': 'No inflow via exchanges found within the search depth.',
  'Opnieuw proberen': 'Try again', 'Details ›': 'Details ›', 'Volg het geld': 'Follow the money', 'Tokens zonder koers': 'Tokens without price',
  // rollen
  'Exchange / dienst': 'Exchange / service', 'Sanctie / scamlijst': 'Sanction / scam list',
  // --- route, brief, meldpunten ---
  'Eindigt bij': 'Ends at', 'exchange': 'exchange', 'mixer': 'mixer', 'bridge': 'bridge', 'smart contract': 'smart contract', 'waarschuwingslijst': 'warning list',
  'Zo is het geld gelopen tot waar het uitkwam. Tik op een stap om dat adres te bekijken.': 'This is how the money moved to where it ended up. Tap a step to view that address.',
  'Het geld is in dit onderzoek nog niet bij een exchange aangekomen. Dit zijn de verste adressen. Tik op het laatste adres en kies "Waar ging het geld heen?" om verder te zoeken.':
    'In this investigation the money has not reached an exchange yet. These are the furthest addresses. Tap the last address and choose "Where did the money go?" to search further.',
  'Voor deze exchange is (nog) geen officieel meldpunt bekend: gebruik "Zoek het contactadres".': 'No official reporting channel is known for this exchange (yet): use "Find the contact address".',
  'Gecontroleerd op 18-11-2026. Controleer altijd de actuele pagina van de exchange.': "Checked on 18 Nov 2026. Always check the exchange's current page.",
  'Via het officiële politieportaal (Kodex). Eerst registreren als opsporingsinstantie; spoed: kies "Exigent".': 'Via the official law enforcement portal (Kodex). Register as an agency first; urgent: choose "Exigent".',
  'Via het politieportaal (Kodex): internationaal of VS. Overige vragen: subpoenas@coinbase.com.': 'Via the law enforcement portal (Kodex): international or US. Other questions: subpoenas@coinbase.com.',
  'Via het politieportaal (Kodex). Alleen bij spoed of als Kodex niet lukt: enforcement@okx.com.': 'Via the law enforcement portal (Kodex). Only if urgent or if Kodex fails: enforcement@okx.com.',
  'Via het KuCoin Information Request System. EU-entiteit: lawenforcement@kucoin.eu.': 'Via the KuCoin Information Request System. EU entity: lawenforcement@kucoin.eu.',
  'Via het formulier voor juridische verzoeken (categorie Compliance/Legal).': 'Via the legal inquiry form (category Compliance/Legal).',
  'Bybit vraagt meestal een aangifte én een bevriezingsbevel van de politie; bij spoed kan het sneller.': 'Bybit usually requires a police report and a freezing order; urgent cases can go faster.',
  'Fraudeteam van Bitvavo; officiële verzoeken lopen via politie of FIOD.': "Bitvavo's fraud team; official requests go through the police or FIOD.",
  'Tether kan USDT op een adres bevriezen na een verzoek van een geverifieerde opsporingsinstantie (niet op adressen van exchanges).': 'Tether can freeze USDT on an address after a request from a verified law enforcement agency (not on exchange addresses).',
  'Politieportaal Binance': 'Binance law enforcement portal', 'Uitleg Binance': 'Binance guidelines', 'Portaal internationaal': 'International portal', 'Portaal VS': 'US portal', 'E-mail': 'E-mail',
  'Politieportaal OKX': 'OKX law enforcement portal', 'Spoed-e-mail': 'Urgent e-mail', 'KuCoin verzoeken': 'KuCoin requests', 'E-mail EU': 'E-mail EU', 'Formulier Kraken': 'Kraken form',
  'Bybit: gestolen geld melden': 'Bybit: report stolen assets', 'E-mail fraudeteam': 'Fraud team e-mail', 'Uitleg Bitvavo': 'Bitvavo help', 'Tether contact': 'Tether contact',
  // --- zaken, volgen, instellingen ---
  'Nog geen zaken. Een onderzoek wordt automatisch bewaard zodra het klaar is.': 'No cases yet. An investigation is saved automatically when it finishes.',
  'Deze zaak heeft nog geen onderzoeken. Start een onderzoek: het wordt hier automatisch bewaard.': 'This case has no investigations yet. Start one: it will be saved here automatically.',
  'Openen': 'Open', 'Verwijderen': 'Delete', 'huidige zaak': 'current case', 'Stop met volgen': 'Stop watching', 'NIEUW': 'NEW', 'Geen nieuwe beweging': 'No new movement',
  'Je volgt nog geen adressen. Open een adres en tik op "🔔 Volg dit adres".': 'You are not watching any addresses yet. Open an address and tap "🔔 Watch this address".',
  'Testen…': 'Testing…', 'Het Solana-adres moet met https:// beginnen.': 'The Solana address must start with https://.',
  'Dit adres is actief op meerdere blockchains. Welke wil je onderzoeken?': 'This address is active on several blockchains. Which one do you want to investigate?',
  'Hele wallet in het web zetten': 'Put the whole wallet in the graph',
  // --- statusmeldingen ---
  'Adres uit de tekst gehaald. Tik nog een keer op Start.': 'Address taken from the text. Tap Start again.', 'Afbeelding maken…': 'Creating image…', 'Afbeelding opgeslagen.': 'Image saved.',
  'Dit adres wordt niet herkend. Controleer of je het hele adres hebt geplakt.': 'This address is not recognised. Check that you pasted the whole address.',
  'Dit adres wordt niet meer gevolgd.': 'This address is no longer watched.', 'Dit adres wordt nu gevolgd. Je krijgt een melding als er weer geld beweegt.': 'This address is now watched. You will be notified when money moves again.',
  'Dit is een transactie: tik in de verkenner op het adres dat je wilt onderzoeken.': 'This is a transaction: in the explorer, tap the address you want to investigate.',
  'Dit onderzoek kon niet worden geladen.': 'This investigation could not be loaded.', 'Gekopieerd.': 'Copied.', 'Gestopt.': 'Stopped.', 'Instellingen opgeslagen.': 'Settings saved.',
  'Je volgt nog geen adressen.': 'You are not watching any addresses yet.', 'Kijken op welke blockchain dit adres actief is…': 'Checking which blockchain this address is active on…',
  'Niet herkend als adres of transactie-hash.': 'Not recognised as an address or transaction hash.', 'Nieuwe onderzoeken worden nu in deze zaak bewaard.': 'New investigations are now saved in this case.',
  'OSINT-lijsten laden (OFAC, ScamSniffer)…': 'Loading OSINT lists (OFAC, ScamSniffer)…', 'PDF-rapport maken…': 'Creating PDF report…',
  'Plakken lukt hier niet automatisch. Houd het veld ingedrukt en kies Plakken.': 'Pasting does not work automatically here. Press and hold the field and choose Paste.',
  'QR-code lezen…': 'Reading QR code…', 'Toegevoegd aan het web.': 'Added to the graph.', 'Gecontroleerd: geen nieuwe beweging.': 'Checked: no new movement.',
  'Geen QR-code gevonden. Probeer een scherpere foto, of knip alleen de QR-code uit.': 'No QR code found. Try a sharper photo, or crop just the QR code.',
  'Dit adres past niet bij deze keten.': 'This address does not match this chain.',
  '✓ Dit is een Ethereum-adres': '✓ This is an Ethereum address',
  'Dit lijkt geen geldig Bitcoin-, Ethereum- of Tron-adres. Controleer of je het hele adres hebt gekopieerd.': 'This does not look like a valid Bitcoin, Ethereum or Tron address. Check that you copied the whole address.',
  'Bitcoin, Ethereum en Tron worden automatisch herkend': 'Bitcoin, Ethereum and Tron are recognised automatically',
  'Dit is een transactie, geen adres. Tik op Start: je ziet dan wie betaalde en wie ontving, en tikt het adres aan dat je wilt onderzoeken.': 'This is a transaction, not an address. Tap Start: you will see who paid and who received, then tap the address you want to investigate.',
  'De app volgt waar het geld van het slachtoffer naartoe is gegaan.': "The app follows where the victim's money went.",
  'De app zoekt waar de dader het geld heen stuurde én wie er nog meer geld naartoe stuurde.': 'The app searches where the perpetrator sent the money and who else sent money to them.',
  // --- woordenlijst (HELP) ---
  'Walletadres': 'Wallet address', 'Een soort rekeningnummer voor crypto. Iedereen kan zonder naam zoveel adressen aanmaken als hij wil. Pas bij een exchange is te achterhalen van wie een adres is.':
    'A kind of account number for crypto. Anyone can create as many addresses as they like without a name. Only at an exchange can the owner of an address be identified.',
  'Transactie (tx-hash)': 'Transaction (tx hash)', 'Elke overboeking heeft een unieke code: de transactie-hash. Daarmee kan iedereen, ook de politie of een exchange, precies die overboeking terugvinden. Zet hem altijd in je aangifte.':
    'Every transfer has a unique code: the transaction hash. With it, anyone, including the police or an exchange, can find exactly that transfer. Always include it in your police report.',
  'Stap (hop)': 'Step (hop)', 'Elke keer dat geld naar een volgend adres gaat, is één stap. Hoe meer stappen, hoe minder zeker het is dat het nog hetzelfde geld is.':
    'Each time money moves to a next address is one step. The more steps, the less certain it is that it is still the same money.',
  'Het adres waar het geld van het slachtoffer vandaan kwam (of dat je zelf als slachtoffer hebt gemarkeerd).': "The address the victim's money came from (or that you marked as victim yourself).",
  'Iemand die geld naar de dader stuurde. Dat kan een ander slachtoffer zijn. Het is een aanwijzing, geen zekerheid.': 'Someone who sent money to the perpetrator. That may be another victim. It is an indication, not a certainty.',
  'Een adres dat je als dader hebt gemarkeerd, of dat sterk lijkt op een valstrik-adres.': 'An address you marked as perpetrator, or that strongly resembles a trap address.',
  'Dit adres ontving geld van het slachtoffer, of gedraagt zich verdacht (geld snel doorsturen, van veel mensen ontvangen). Het is een aanwijzing, geen bewijs.':
    'This address received money from the victim, or behaves suspiciously (forwarding money quickly, receiving from many people). It is an indication, not proof.',
  'Over dit adres is (nog) niets bijzonders bekend.': 'Nothing special is known about this address (yet).',
  'Exchange': 'Exchange', 'Een bedrijf waar mensen crypto kopen en verkopen, zoals Binance, Coinbase of Bitvavo. Klanten moeten zich daar met een ID registreren. Daarom kan de politie bij een exchange opvragen van wie een account is, en vragen het geld te bevriezen. Dit is meestal het belangrijkste spoor.':
    'A company where people buy and sell crypto, such as Binance, Coinbase or Bitvavo. Customers must register there with ID. That is why the police can ask an exchange who owns an account and ask it to freeze the money. This is usually the most important lead.',
  'Zeer druk adres': 'Very busy address', 'Dit adres doet zoveel transacties dat het vrijwel zeker van een bedrijf is (vaak een exchange of betaaldienst), niet van één persoon.':
    'This address makes so many transactions that it almost certainly belongs to a company (often an exchange or payment service), not to one person.',
  'Waarschuwingslijst': 'Warning list', 'Dit adres staat op een lijst met verboden of bekende criminele partijen, zoals de sanctielijst van de Amerikaanse overheid (OFAC) of een scamlijst.':
    'This address is on a list of prohibited or known criminal parties, such as the US government sanctions list (OFAC) or a scam list.',
  'Scamlijst': 'Scam list', 'Dit adres is eerder door anderen gemeld als oplichting, phishing of hack.': 'This address was previously reported by others as fraud, phishing or a hack.',
  'Fraude-label': 'Fraud label', 'Een openbare blockchain-verkenner heeft dit adres een label gegeven dat op fraude of een hack wijst.': 'A public blockchain explorer labelled this address as related to fraud or a hack.',
  'Ransomware': 'Ransomware', 'Dit adres is gebruikt om losgeld te ontvangen voor gegijzelde computers.': 'This address was used to receive ransom for hijacked computers.',
  'Bevroren door Tether': 'Frozen by Tether', 'Tether (het bedrijf achter USDT) heeft dit adres geblokkeerd. Het geld kan daar niet meer weg. Tether werkt samen met politie.':
    'Tether (the company behind USDT) has blocked this address. The money can no longer leave it. Tether cooperates with the police.',
  'Darknet': 'Darknet', 'Dit adres hoort bij een verborgen marktplaats op internet waar illegale spullen worden verkocht.': 'This address belongs to a hidden online marketplace where illegal goods are sold.',
  'Mixer': 'Mixer', 'Een dienst die geld van veel mensen door elkaar husselt, zodat je niet meer ziet waar het vandaan komt. Na een mixer is het spoor meestal niet verder te volgen.':
    'A service that shuffles money from many people so you can no longer see where it came from. After a mixer the trail usually cannot be followed further.',
  'Bridge': 'Bridge', 'Een dienst die geld overzet naar een andere blockchain (bijvoorbeeld van Ethereum naar Tron). Het spoor gaat dan verder op die andere blockchain.':
    'A service that moves money to another blockchain (for example from Ethereum to Tron). The trail then continues on that other blockchain.',
  'Smart contract': 'Smart contract', 'Een programma op de blockchain, geen persoon. Bijvoorbeeld een online wisselkantoor (DEX) of een munt. Geld dat erin gaat, komt er vaak elders weer uit.':
    'A program on the blockchain, not a person. For example an online exchange (DEX) or a token. Money that goes in often comes out elsewhere.',
  'Startwallet': 'Start wallet', "Het verste adres waar het geld naar terug te volgen was. Als de dader geld kreeg van zo'n adres, kan dat een ander slachtoffer zijn.":
    'The furthest address the money could be traced back to. If the perpetrator received money from such an address, it may be another victim.',
  'Doorsluisadres': 'Pass-through address', 'Geld komt binnen en gaat binnen een uur weer weg. Oplichters doen dat om het spoor moeilijker te volgen te maken.':
    'Money comes in and leaves again within an hour. Scammers do this to make the trail harder to follow.',
  'Verzameladres': 'Collection address', 'Dit adres ontvangt geld van veel verschillende mensen. Bij oplichting kan dat betekenen dat er meer slachtoffers zijn.':
    'This address receives money from many different people. In a fraud case that may mean there are more victims.',
  'Verspreidadres': 'Distribution address', 'Dit adres stuurt geld naar veel verschillende adressen. Zo wordt het geld opgeknipt om het spoor te verbergen.':
    'This address sends money to many different addresses. The money is split up to hide the trail.',
  'Peel chain': 'Peel chain', 'Steeds een klein deel afsplitsen en de rest doorsturen naar een nieuw adres. Een bekende witwastruc bij Bitcoin.':
    'Repeatedly splitting off a small part and forwarding the rest to a new address. A well-known Bitcoin laundering trick.',
  'Lijkt-op-adres (address poisoning)': 'Look-alike address (address poisoning)',
  'Oplichters maken een adres dat aan het begin en eind hetzelfde is als een adres dat je vaker gebruikt. Wie dan een adres uit de geschiedenis kopieert, stuurt het geld per ongeluk naar de oplichter. Vergelijk daarom altijd het hele adres.':
    'Scammers create an address that starts and ends the same as one you use often. Anyone who copies an address from their history then accidentally sends money to the scammer. Always compare the whole address.',
  'Spam / nul-transacties': 'Spam / zero transactions', 'Overboekingen van 0 of met nepmunten. Vaak bedoeld om een lijkt-op-adres in de geschiedenis van het slachtoffer te zetten.':
    "Transfers of 0 or with fake tokens. Often meant to put a look-alike address in the victim's history.",
  'Eerder gezien': 'Seen before', 'Dit adres kwam al voor in een ander onderzoek op dit apparaat.': 'This address already appeared in another investigation on this device.',
  'Reputatie': 'Reputation', 'De blockchain-verkenner waarschuwt dat dit adres of deze munt niet te vertrouwen is.': 'The blockchain explorer warns that this address or token is not trustworthy.',
  'Zelfde wallet': 'Same wallet',
  'Bij Bitcoin en Litecoin kan één eigenaar veel adressen hebben. Als adressen samen als bron (input) in één transactie worden gebruikt, moet de eigenaar ze allemaal kunnen ondertekenen: ze horen dus vrijwel zeker bij dezelfde wallet. Uitzondering: speciale privacy-transacties (CoinJoin); die voegt de app niet samen.':
    'With Bitcoin and Litecoin one owner can have many addresses. When addresses are used together as sources (inputs) in one transaction, the owner must be able to sign for all of them: so they almost certainly belong to the same wallet. Exception: special privacy transactions (CoinJoin); the app does not merge those.',
  'Komt vaker voor': 'Appears more often', 'Dit adres komt voor in meerdere onderzoeken van dezelfde zaak. Dat is een belangrijk verband: bijvoorbeeld dezelfde oplichter bij verschillende slachtoffers.':
    'This address appears in several investigations of the same case. That is an important connection: for example the same scammer behind different victims.',
  'Woordenlijst': 'Glossary',
  // --- vlaggen ---
  'Publiek label wijst op fraude/hack': 'Public label indicates fraud/hack', 'Bridge — geld gaat naar een andere keten': 'Bridge — money moves to another chain', 'Smart contract': 'Smart contract',
  'Exchange — cash-out-punt, bevriezing/informatieverzoek mogelijk': 'Exchange — cash-out point, freeze/information request possible', 'Mixer / privacy-dienst': 'Mixer / privacy service',
  'OFAC-sanctielijst (lokale DB)': 'OFAC sanctions list (local DB)', 'Op OFAC-sanctielijst': 'On OFAC sanctions list', 'Door Blockscout als scam gemarkeerd': 'Marked as scam by Blockscout', 'Op ScamSniffer-blacklist': 'On ScamSniffer blacklist',
  // --- tour ---
  'Welkom bij ChainTrace! In deze rondleiding volgen we samen het geld in een verzonnen oplichtingszaak.': "Welcome to ChainTrace! In this tour we'll follow the money in a made-up fraud case together.",
  'Stap 1: plak het walletadres van het slachtoffer. Je mag ook een heel bericht plakken, of met de QR-knop een QR-code uit een foto lezen.': "Step 1: paste the victim's wallet address. You may also paste a whole message, or read a QR code from a photo with the QR button.",
  'Stap 2: kies van wie het adres is. Hier: van het slachtoffer.': 'Step 2: choose whose address it is. Here: the victim’s.',
  'Stap 3: kies wat er gebeurde. Hier: een nep-beleggingsplatform. Dit mag je ook overslaan.': 'Step 3: choose what happened. Here: a fake investment platform. You may also skip this.',
  'Tik op "Start onderzoek". De app volgt nu automatisch waar het geld heen ging.': 'Tap "Start investigation". The app now automatically follows where the money went.',
  'Het web toont alle adressen en geldstromen. Rood en oranje is verdacht, groen is een exchange, paars een mixer.': 'The graph shows all addresses and money flows. Red and orange are suspicious, green is an exchange, purple a mixer.',
  'De samenvatting vertelt in gewone taal wat er gevonden is.': 'The summary tells you in plain language what was found.',
  '"Het geld stap voor stap" laat de route zien: van het slachtoffer, via doorsluisadressen, naar een exchange.': '"The money step by step" shows the route: from the victim, via pass-through addresses, to an exchange.',
  'Bij een exchange kan de politie opvragen van wie het account is. Met één tik maak je een brief aan de exchange.': 'At an exchange the police can request who owns the account. With one tap you create a letter to the exchange.',
  'De brief is al ingevuld met adressen, transacties en tijden. Vul je naam en aangiftenummer in en kopieer of deel de brief.': 'The letter is already filled in with addresses, transactions and times. Enter your name and report number and copy or share the letter.',
  'Tik op een stap om dat adres te bekijken.': 'Tap a step to view that address.', 'Bovenaan staat in gewone taal wat we over dit adres weten.': 'At the top you see in plain language what we know about this address.',
  'Tik op een label met een vraagteken voor uitleg.': 'Tap a label with a question mark for an explanation.',
  '"Waar kwam het vandaan?" zoekt wie er nog meer geld naar dit adres stuurde: mogelijk andere slachtoffers.': '"Where did it come from?" looks for who else sent money to this address: possibly other victims.',
  'Tik op een transactie om te zien wie betaalde en wie ontving. Zo klik je door, net als in een blockchain-verkenner.': 'Tap a transaction to see who paid and who received. That way you click through, just like in a blockchain explorer.',
  'Met "Terug" ga je een stap terug.': '"Back" takes you one step back.',
  'Met "Volg dit adres" krijg je een melding als er weer geld beweegt. Met de luidspreker laat je de uitleg voorlezen.': 'With "Watch this address" you get a notification when money moves again. The speaker button reads the explanation aloud.',
  'Echte onderzoeken worden automatisch bewaard onder "Mijn zaken". Daar kun je ook meerdere onderzoeken samen in één web zetten.': 'Real investigations are saved automatically under "My cases". There you can also combine several investigations in one graph.',
  'Maak tot slot een PDF-rapport met alle adressen en transacties voor je aangifte.': 'Finally, create a PDF report with all addresses and transactions for your police report.',
  'Klaar! Je kunt deze rondleiding altijd opnieuw starten via "Meer". Succes met je onderzoek.': 'Done! You can always restart this tour via "More". Good luck with your investigation.',
  // --- plainStory vaste zinnen ---
  'Dit is het adres van het slachtoffer.': 'This is the victim’s address.', 'Dit adres is gemarkeerd als dader.': 'This address is marked as perpetrator.',
  'Dit adres is zó actief dat het vrijwel zeker van een bedrijf is (exchange of betaaldienst). Ook hier kan de politie gegevens opvragen.': 'This address is so active that it almost certainly belongs to a company (exchange or payment service). The police can request data here too.',
  'Dit is een mixer: hier wordt geld onherkenbaar gemaakt. Verder volgen lukt meestal niet.': 'This is a mixer: money is made untraceable here. Following it further usually fails.',
  'Via dit adres is geld naar een andere blockchain gegaan. Het spoor gaat daar verder.': 'Money went to another blockchain via this address. The trail continues there.',
  'Dit is een programma (smart contract), geen persoon.': 'This is a program (smart contract), not a person.',
  'Dit adres lijkt sterk op een ander adres: waarschijnlijk een valstrik (address poisoning).': 'This address strongly resembles another address: probably a trap (address poisoning).',
  'Er zijn geen overboekingen met waarde gevonden.': 'No transfers with value were found.', 'Er is (nog) niets doorgestuurd: het geld staat hier mogelijk nog.': 'Nothing has been forwarded (yet): the money may still be here.',
  'Geld bleef hier meestal korter dan een uur: typisch een doorsluisadres van oplichters.': 'Money usually stayed here less than an hour: typical of a scammer’s pass-through address.',
  'Veel verschillende mensen stuurden geld naar dit adres: mogelijk zijn er meer slachtoffers.': 'Many different people sent money to this address: there may be more victims.',
  'Hier begint het geld voor zover te volgen: mogelijk een ander slachtoffer of de bron van het geld.': 'This is where the money starts, as far as it can be traced: possibly another victim or the source of the money.',
  'Dit adres kwam al voor in een eerder onderzoek op dit apparaat.': 'This address appeared in an earlier investigation on this device.',
  'Dit adres staat nog niet in je web. Tik op "Toevoegen aan web" om het mee te nemen in het rapport.': 'This address is not in your graph yet. Tap "Add to graph" to include it in the report.',
  'Tik op "Waar ging het geld heen?" om verder te zoeken.': 'Tap "Where did the money go?" to search further.',
  'Tether heeft USDT op dit exchange-adres geblokkeerd. Bij een groot exchange-adres zegt dat iets over de exchange, niet per se over jouw zaak.': 'Tether has blocked USDT on this exchange address. For a large exchange address that says something about the exchange, not necessarily about your case.',
  // --- samenvatting ---
  'Er is nog geen exchange gevonden waar het geld uitkomt. Tik op een oranje adres en kies "Waar ging het geld heen?" om dieper te zoeken.': 'No exchange has been found where the money ends up yet. Tap an orange address and choose "Where did the money go?" to search deeper.',
  // --- patronen ---
  'Pig butchering / nep-beleggingsplatform': 'Pig butchering / fake investment platform',
  'Slachtoffer stort (vaak USDT op Tron) op een "platform"; geld wordt via doorsluisadressen naar exchanges gebracht.': 'Victim deposits (often USDT on Tron) to a "platform"; money is moved via pass-through addresses to exchanges.',
  'Noteer alle stortingen (datum, bedrag, tx-hash) vanuit het slachtofferadres.': "Record all deposits (date, amount, tx hash) from the victim's address.",
  'Zoek in het web de eerste exchange/dienst (groen) — daar kan een bevriezings- of informatieverzoek naartoe.': 'Find the first exchange/service (green) in the graph — a freeze or information request can go there.',
  'Doe aangifte bij de politie (fraudehelpdesk / politie.nl) en voeg het dossier (JSON + PNG) toe.': 'Report to the police and attach the file (JSON + PNG).',
  'USDT? Tether kan adressen bevriezen via een verzoek van opsporingsinstanties — noem de dader-adressen expliciet.': 'USDT? Tether can freeze addresses at the request of law enforcement — list the perpetrator addresses explicitly.',
  'Meld de dader-adressen op chainabuse.com zodat anderen gewaarschuwd worden.': 'Report the perpetrator addresses on chainabuse.com so others are warned.',
  'Romance scam': 'Romance scam', 'Vertrouwensrelatie online; slachtoffer koopt crypto en stuurt die door naar "partner".': 'Online trust relationship; victim buys crypto and sends it to the "partner".',
  'Bewaar alle chats, profielen en betaalbewijzen naast dit dossier.': 'Keep all chats, profiles and payment receipts alongside this file.',
  'Volg het geld tot de eerste exchange; vermeld die in de aangifte.': 'Follow the money to the first exchange; mention it in the police report.',
  'Controleer of het dader-adres geld van meerdere slachtoffers ontvangt (fan-in) — dat versterkt de zaak.': 'Check whether the perpetrator address receives money from several victims (fan-in) — that strengthens the case.',
  'Meld profielen bij het platform en de adressen op chainabuse.com.': 'Report the profiles to the platform and the addresses on chainabuse.com.',
  'Phishing / wallet drainer': 'Phishing / wallet drainer', 'Slachtoffer tekent een kwaadaardige transactie/approval; tokens worden razendsnel weggesluisd.': 'Victim signs a malicious transaction/approval; tokens are siphoned off very quickly.',
  'Trek direct alle token-approvals in (revoke.cash) en verplaats resterende tegoeden naar een nieuwe wallet.': 'Revoke all token approvals immediately (revoke.cash) and move remaining funds to a new wallet.',
  'Controleer welke adressen op de ScamSniffer-lijst staan — vaak de drainer-ontvanger.': 'Check which addresses are on the ScamSniffer list — often the drainer recipient.',
  'Volg de snelle doorstort-adressen naar exchanges/bridges en documenteer de tx-hashes.': 'Follow the fast pass-through addresses to exchanges/bridges and document the tx hashes.',
  'Meld de phishingsite en adressen (chainabuse.com, ScamSniffer).': 'Report the phishing site and addresses (chainabuse.com, ScamSniffer).',
  'Address poisoning': 'Address poisoning', 'Dader stuurt nep- of 0-transacties vanaf een adres dat lijkt op een bekend adres; slachtoffer kopieert het verkeerde adres.': 'Perpetrator sends fake or zero transactions from an address resembling a known one; the victim copies the wrong address.',
  'Vergelijk het ontvangende adres teken-voor-teken met het bedoelde adres (begin én eind lijken gelijk).': 'Compare the receiving address character by character with the intended address (start and end look the same).',
  'Lookalike-adressen zijn rood gemarkeerd; volg het geld verder vanaf daar.': 'Look-alike addresses are marked red; follow the money further from there.',
  'Kopieer voortaan adressen uit een adresboek, niet uit transactiegeschiedenis.': 'From now on copy addresses from an address book, not from transaction history.',
  'Meld het lookalike-adres op chainabuse.com.': 'Report the look-alike address on chainabuse.com.',
  'Ransomware / afpersing': 'Ransomware / extortion', 'Losgeld (meestal BTC) wordt via peel chains en mixers witgewassen.': 'Ransom (usually BTC) is laundered via peel chains and mixers.',
  'Doe aangifte en meld bij het NCSC; betaal liever niet.': 'Report to the police and your national cyber security centre; preferably do not pay.',
  'Volg de peel chain: elke hop splitst een klein bedrag af (vaak naar een exchange).': 'Follow the peel chain: each hop splits off a small amount (often to an exchange).',
  'Check de OFAC-sanctiehits — betalingen aan gesanctioneerde adressen hebben juridische gevolgen.': 'Check the OFAC sanction hits — payments to sanctioned addresses have legal consequences.',
  'Bewaar de losgeldnota met het betaaladres in het dossier.': 'Keep the ransom note with the payment address in the file.',
  'Ponzi / rug pull': 'Ponzi / rug pull', 'Veel inleggers (fan-in) naar een verzameladres; opbrengst wordt weggehaald of uitbetaald aan vroege deelnemers.': 'Many depositors (fan-in) to a collection address; proceeds are withdrawn or paid to early participants.',
  'Bepaal het verzameladres (veel inkomende stortingen = fan-in).': 'Identify the collection address (many incoming deposits = fan-in).',
  'Kijk waar het verzamelde geld heen gaat (cash-out naar exchanges of bridges).': 'See where the collected money goes (cash-out to exchanges or bridges).',
  'Andere inleggers vind je als inkomende pijlen op het verzameladres — zij zijn mogelijk medegedupeerden.': 'Other depositors appear as incoming arrows on the collection address — they may be fellow victims.',
  'Nep-helpdesk / recovery scam': 'Fake helpdesk / recovery scam', 'Na een eerdere oplichting belooft een "recovery-bureau" het geld terug te halen tegen betaling vooraf.': 'After an earlier scam, a "recovery agency" promises to retrieve the money for an upfront payment.',
  'Echte opsporing vraagt nooit vooraf betaling in crypto — stop met betalen.': 'Real investigators never ask for upfront payment in crypto — stop paying.',
  'Check of het "recovery"-adres verbonden is met de oorspronkelijke dader-adressen.': 'Check whether the "recovery" address is connected to the original perpetrator addresses.',
  'Voeg beide fraudes samen in één aangifte.': 'Combine both frauds in one police report.',
  'Onbekend / algemeen': 'Unknown / general', 'Geen probleem: de app zoekt breed en let op alle bekende signalen.': 'No problem: the app searches broadly and watches for all known signals.',
  'Bekijk de bevindingen; rode en oranje adressen verdienen extra aandacht.': 'Review the findings; red and orange addresses deserve extra attention.',
  'Klik op een adres en kies "Waar ging het geld heen?" om dieper te gaan.': 'Click an address and choose "Where did the money go?" to go deeper.',
  'Exporteer het dossier en voeg het toe aan een aangifte.': 'Export the file and attach it to a police report.'
};

const patterns = [
  // status
  ['Klaar: {0} adressen, {1} geldstromen. Tik op een adres voor details.', 'Done: {0} addresses, {1} money flows. Tap an address for details.'],
  ['{0} adressen, {1} geldstromen.', '{0} addresses, {1} money flows.'],
  ['Ophalen {0} (hop {1})…', 'Fetching {0} (hop {1})…'],
  ['Herkomst zoeken: hop {0}, {1} startwallets, {2} instroom-tx…', 'Tracing origin: hop {0}, {1} start wallets, {2} inflow tx…'],
  ['Herkomst: {0} startwallets, {1} instroom-transacties.', 'Origin: {0} start wallets, {1} inflow transactions.'],
  ['Dossier geladen: {0} adressen.', 'File loaded: {0} addresses.'],
  ['PDF-rapport opgeslagen ({0} pagina\'s).', 'PDF report saved ({0} pages).'],
  ['Toegevoegd aan het web: {0}', 'Added to the graph: {0}'],
  ['Nieuwe beweging op {0} adres(sen)!', 'New movement on {0} address(es)!'],
  ['{0} onderzoeken samen in één web: {1} adressen, {2} adres(sen) komen in meer dan één onderzoek voor.', '{0} investigations together in one graph: {1} addresses, {2} address(es) appear in more than one investigation.'],
  ['Adres past niet bij {0}.', 'Address does not match {0}.'],
  ['Fout: {0}', 'Error: {0}'], ['Ophalen mislukt: {0}', 'Fetching failed: {0}'], ['Ophalen mislukt. {0}', 'Fetching failed. {0}'], ['Ophalen mislukt: {0}', 'Fetching failed: {0}'],
  ['Inlezen mislukt: {0}', 'Import failed: {0}'], ['Import mislukt: {0}', 'Import failed: {0}'], ['PDF maken mislukt: {0}', 'Creating PDF failed: {0}'], ['Meer laden mislukt: {0}', 'Loading more failed: {0}'],
  ['Geen antwoord van {0}', 'No response from {0}'], ['Rate limit bij {0}', 'Rate limit at {0}'],
  ['QR-code gelezen, maar er staat geen adres in: {0}', 'QR code read, but it contains no address: {0}'],
  ['Zaak "{0}" ingelezen met {1} onderzoek(en).', 'Case "{0}" imported with {1} investigation(s).'], ['Dossier toegevoegd aan zaak "{0}".', 'File added to case "{0}".'],
  ['✓ Dit is een {0}-adres · gekozen keten: {1}', '✓ {0} address recognised · chosen chain: {1}'], ['✓ Dit is een {0}-adres', '✓ {0} address recognised'],
  ['✓ {0}-adres gevonden in de QR-code', '✓ {0} address found in the QR code'], ['✓ {0}-adres gevonden in de tekst', '✓ {0} address found in the text'],
  ['Nieuwe beweging op {0} gevolgd adres', 'New movement on {0} watched address'], ['Nieuwe beweging op {0} gevolgde adressen', 'New movement on {0} watched addresses'],
  ['Nieuwe beweging gezien op {0}', 'New movement seen on {0}'], ['laatst gecontroleerd {0}', 'last checked {0}'], ['nog niet', 'not yet'],
  ['Zaak van {0}', 'Case of {0}'],
  ['{#0} onderzoek', '{0} investigation'], ['{#0} onderzoeken', '{0} investigations'],
  ['{#0} adressen', '{0} addresses'], ['bewaard {0}', 'saved {0}'],
  // verkenner
  ['Tokens zonder koers ({0})', 'Tokens without price ({0})'], ['Spam ({0})', 'Spam ({0})'], ['Toon meer ({0})', 'Show more ({0})'],
  ['· {0} tx · {1}', '· {0} tx · {1}'], ['Brief aan {0}', 'Letter to {0}'], ['✉ Brief aan {0} maken', '✉ Create letter to {0}'], ['✉ Brief aan {0}', '✉ Letter to {0}'],
  ['👛 Zelfde wallet (vermoedelijk): {0} adressen', '👛 Same wallet (probably): {0} addresses'], ['Hele wallet in het web zetten ({0} erbij)', 'Put the whole wallet in the graph ({0} more)'],
  ['… en nog {0}', '… and {0} more'], ['Wallet · {0} adressen', 'Wallet · {0} addresses'],
  ['📮 Officieel meldpunt {0}', '📮 Official reporting channel {0}'],
  ['Eerder gezien in: {0}', 'Seen before in: {0}'],
  // vlaggen
  ['Bridge: {0}', 'Bridge: {0}'], ['{0} nul-/nep-tokentransfer(s) ontvangen (poisoning-kenmerk)', '{0} zero/fake token transfer(s) received (poisoning sign)'],
  ['Exchange: {0} — cash-out-punt', 'Exchange: {0} — cash-out point'], ['Fan-in: {0} verschillende afzenders (verzameladres)', 'Fan-in: {0} different senders (collection address)'],
  ['Fan-out: {0} ontvangers (verspreiding/layering)', 'Fan-out: {0} recipients (distribution/layering)'], ['Door Tether bevroren — {0} (USDT-blacklist)', 'Frozen by Tether — {0} (USDT blacklist)'],
  ['Door Tether bevroren (USDT-blacklist)', 'Frozen by Tether (USDT blacklist)'], ['bevroren sinds {0}', 'frozen since {0}'],
  ['Doorsluisadres: {0}% binnen 1 uur doorgestort', 'Pass-through address: {0}% forwarded within 1 hour'], ['Peel chain-patroon ({0} splitsingen)', 'Peel chain pattern ({0} splits)'],
  ['Reputatie: {0}', 'Reputation: {0}'], ['Eerder als dader/verdacht gezien in zaak {0} ({1})', 'Seen before as perpetrator/suspect in case {0} ({1})'],
  ['Al eerder gezien in {0} andere zaak/zaken', 'Seen before in {0} other case(s)'], ['Zeer actief ({0}) — waarschijnlijk exchange/dienst', 'Very active ({0}) — probably exchange/service'],
  ['veel tx per dag', 'many tx per day'], ['Startwallet: {0} — mogelijk slachtoffer of geldbron', 'Start wallet: {0} — possible victim or source of funds'],
  ['gefinancierd vanuit {0}', 'funded from {0}'], ['maximale zoekdiepte bereikt', 'maximum search depth reached'], ['geen eerdere instroom gevonden', 'no earlier inflow found'],
  ['niet verder te volgen (ophalen mislukt)', 'cannot be followed further (fetching failed)'], ['Komt voor in {0} onderzoeken van deze zaak', 'Appears in {0} investigations of this case'],
  ['Lijkt op {0} (zelfde begin/eind) — waarschijnlijk vergiftigingsadres', 'Resembles {0} (same start/end) — probably a poisoning address'],
  ['Lijkt op {0} (zelfde begin/eind) — vergelijk zorgvuldig', 'Resembles {0} (same start/end) — compare carefully'],
  ['{0} — bron: {1}', '{0} — source: {1}'],
  // verhaal en samenvatting
  ['Dit adres hoort bij {0}. Hier kan de politie opvragen van wie het account is, en vragen het geld te bevriezen. Maak hiervoor de brief aan de exchange.', 'This address belongs to {0}. Here the police can request who owns the account and ask for the money to be frozen. Use the letter to the exchange for this.'],
  ['een exchange', 'an exchange'],
  ['Let op: dit adres staat op een waarschuwingslijst ({0}).', 'Warning: this address is on a warning list ({0}).'],
  ['Het adres ontving {0} van {1} afzender en stuurde {2}', 'The address received {0} from {1} sender and sent {2}'],
  ['Het adres ontving {0} van {1} afzenders en stuurde {2}', 'The address received {0} from {1} senders and sent {2}'],
  ['Het adres ontving niets en stuurde {0}', 'The address received nothing and sent {0}'],
  ['{0} naar {1} ontvanger tussen {2} en {3} (in de laatst geladen transacties).', '{0} to {1} recipient between {2} and {3} (in the most recently loaded transactions).'],
  ['{0} naar {1} ontvangers tussen {2} en {3} (in de laatst geladen transacties).', '{0} to {1} recipients between {2} and {3} (in the most recently loaded transactions).'],
  ['{0} naar {1} ontvanger tussen {2} en {3}.', '{0} to {1} recipient between {2} and {3}.'],
  ['{0} naar {1} ontvangers tussen {2} en {3}.', '{0} to {1} recipients between {2} and {3}.'],
  ['niets door tussen {0} en {1} (in de laatst geladen transacties).', 'nothing on between {0} and {1} (in the most recently loaded transactions).'],
  ['niets door tussen {0} en {1}.', 'nothing on between {0} and {1}.'],
  ['Er staat nu nog {0} op dit adres.', 'There is still {0} on this address.'],
  ['Vanaf het adres van het slachtoffer is het geld gevolgd langs {0} adressen.', "The money was followed from the victim's address along {0} addresses."],
  ['Vanaf het adres van de dader is het geld gevolgd langs {0} adressen.', "The money was followed from the perpetrator's address along {0} addresses."],
  ['Het geld komt uit bij {0} exchange(s) of dienst(en): {1}. Daar kan de politie opvragen wie de rekeninghouder is en om bevriezing vragen.', 'The money ends up at {0} exchange(s) or service(s): {1}. There the police can request who the account holder is and ask for a freeze.'],
  ['{0} adres(sen) staan op een waarschuwingslijst (sanctie, scam, ransomware, mixer of door Tether bevroren).', '{0} address(es) are on a warning list (sanction, scam, ransomware, mixer or frozen by Tether).'],
  ['{0} adres(sen) lijken sterk op een ander adres: mogelijk "address poisoning".', '{0} address(es) strongly resemble another address: possibly "address poisoning".'],
  ['{0} adres(sen) kwamen al voor in een eerder onderzoek op dit apparaat.', '{0} address(es) appeared in an earlier investigation on this device.'],
  ['{0} startwallet(s) gevonden waar geld vandaan kwam: mogelijke andere slachtoffers.', '{0} start wallet(s) found where money came from: possible other victims.'],
  ['{0} startwallet(s) gevonden waar geld vandaan kwam.', '{0} start wallet(s) found where money came from.'],
  ['{0} storting(en) kwamen rechtstreeks van een exchange of dienst ({1}). Transactie-hash en tijdstip staan in het rapport.', '{0} deposit(s) came directly from an exchange or service ({1}). Transaction hash and time are in the report.'],
  ['{0} adressen zijn samengevoegd tot {1} wallet(s): ze werden samen als bron gebruikt, dus vrijwel zeker dezelfde eigenaar.', '{0} addresses were merged into {1} wallet(s): they were used together as sources, so almost certainly the same owner.'],
  ['Gevonden cash-out-punten: {0}.', 'Cash-out points found: {0}.'],
  ['{0} e.a.', '{0} and others'],
  // route
  ['{0} stuurde {1} naar {2}.', '{0} sent {1} to {2}.'], ['{0} t/m {1}', '{0} to {1}'],
  ['Het slachtoffer', 'The victim'], ['het slachtoffer', 'the victim'], ['De dader', 'The perpetrator'], ['de dader', 'the perpetrator'],
  ['Adres {0} (verdacht)', 'Address {0} (suspicious)'], ['adres {0} (verdacht)', 'address {0} (suspicious)'], ['Adres {0}', 'Address {0}'], ['adres {0}', 'address {0}'],
  ['{0} (verdacht)', '{0} (suspicious)'], ['{0} (dader)', '{0} (perpetrator)'], ['{0} (waarschuwingslijst)', '{0} (warning list)'], ['{0} (mogelijk slachtoffer)', '{0} (possible victim)'],
  ['Zo is het geld gelopen tot waar het uitkwam (de {0} grootste van {1} routes). Tik op een stap om dat adres te bekijken.', 'This is how the money moved to where it ended up (the {0} largest of {1} routes). Tap a step to view that address.'],
  ['Eindigt bij {0}', 'Ends at {0}'], ['een {0}', 'a {0}'],
  // keten-keuze
  ['{0} · {1} tx', '{0} · {1} tx'],
  // PDF
  ['ChainTrace onderzoeksrapport', 'ChainTrace investigation report'], ['{0} | {1} | gemaakt op {2}', '{0} | {1} | created on {2}']
];

const PDF_EXTRA = {
  'Zaakgegevens': 'Case details', 'Gegeven': 'Field', 'Waarde': 'Value', 'Onderzocht adres': 'Investigated address', 'Dit adres is van': 'This address belongs to',
  'de (vermoedelijke) dader': 'the (suspected) perpetrator', 'Soort fraude': 'Type of fraud', 'Blockchain': 'Blockchain', 'Onderzoek uitgevoerd': 'Investigation performed', 'Omvang': 'Scope',
  'Geldstromen in beeld': 'Money flows', 'Adres': 'Address', 'Naam / label': 'Name / label', 'Beoordeling': 'Assessment', 'Waarom': 'Why',
  'Ontving geld rechtstreeks van het slachtoffer': 'Received money directly from the victim', 'Geen adressen als verdacht aangemerkt.': 'No addresses marked as suspicious.',
  'Wallets (zelfde eigenaar)': 'Wallets (same owner)', 'Wallet': 'Wallet', 'Adressen': 'Addresses',
  'Deze adressen zijn samen als bron (input) in dezelfde transactie gebruikt en horen daarom vrijwel zeker bij dezelfde eigenaar.': 'These addresses were used together as sources (inputs) in the same transaction and therefore almost certainly belong to the same owner.',
  'Het geld stap voor stap (nog niet bij een exchange)': 'The money step by step (not yet at an exchange)',
  'Notities bij deze zaak': 'Notes for this case', 'Toelichting': 'Explanation', 'Vervolgstappen': 'Next steps',
  'Geen instroom vanuit een exchange gevonden binnen de zoekdiepte.': 'No inflow from an exchange found within the search depth.',
  'Geen stortingen bij een exchange gevonden binnen de zoekdiepte.': 'No deposits at an exchange found within the search depth.', 'Geen transacties gevonden.': 'No transactions found.',
  'Adressen waar het geld begon: zonder eerdere instroom, of rechtstreeks gevuld vanuit een exchange. Bij fraude zijn dit vaak andere slachtoffers.':
    'Addresses where the money began: without earlier inflow, or funded directly from an exchange. In fraud cases these are often other victims.',
  'Alle transacties van het onderzochte adres en van of naar verdachte adressen. Met de transactie-hash kan iedereen de betaling controleren in een block explorer.':
    'All transactions of the investigated address and from or to suspicious addresses. With the transaction hash anyone can verify the payment in a block explorer.',
  'Blauw = slachtoffer, lichtblauw = mogelijk slachtoffer/startwallet, rood = dader, oranje = verdacht, groen = exchange of dienst, paars = waarschuwingslijst, grijs = onbekend. Gestippelde blauwe lijnen tonen waar het geld vandaan kwam.':
    'Blue = victim, light blue = possible victim/start wallet, red = perpetrator, orange = suspicious, green = exchange or service, purple = warning list, grey = unknown. Dashed blue lines show where the money came from.',
  'Hier verlaat het geld de blockchain. Met deze gegevens kan de politie bij de exchange de rekeninghouder opvragen of om bevriezing vragen.':
    'This is where the money leaves the blockchain. With these details the police can request the account holder from the exchange or ask for a freeze.',
  'Dit rapport is automatisch gemaakt met ChainTrace (open source) op basis van openbare blockchaingegevens (mempool.space, Blockscout, TronGrid) en openbare lijsten (OFAC, ScamSniffer, GraphSense, Ransomwhere, Forta, Etherscan-labels, Tether-blacklist). De beoordelingen "verdacht", "mogelijk slachtoffer" en "exchange" zijn aanwijzingen op basis van patronen en labels, geen bewijs. Controleer transacties altijd met de transactie-hash in een block explorer. Per adres zijn alleen de meest recente transacties onderzocht.':
    'This report was generated automatically with ChainTrace (open source) from public blockchain data (mempool.space, Blockscout, TronGrid) and public lists (OFAC, ScamSniffer, GraphSense, Ransomwhere, Forta, Etherscan labels, Tether blacklist). The assessments "suspicious", "possible victim" and "exchange" are indications based on patterns and labels, not proof. Always verify transactions with the transaction hash in a block explorer. Only the most recent transactions per address were examined.',
  'Stap': 'Hop', 'Verstuurd': 'Sent', 'Eerste betaling': 'First payment', 'Tijdstip': 'Time', 'Naar wallet': 'To wallet', 'Bedrag': 'Amount', 'Transactie-hash': 'Transaction hash',
  'Naar (exchange)': 'To (exchange)', 'Exchange / dienst': 'Exchange / service',
  // v2.0
  'Tijdlijn': 'Timeline', 'alleen de geldroute': 'money route only', 'Nog geen geldstromen.': 'No money flows yet.', 'route': 'route',
  'Alleen geld volgen dat ná de storting vertrok': 'Only follow money that left after the deposit',
  'de exchange': 'the exchange', 'Stortingsadres': 'Deposit address',
  'Bij een exchange krijgt elke klant een eigen stortingsadres. Wat daar binnenkomt, zet de exchange door naar een groot verzameladres (hot wallet). Een adres dat bijna al zijn geld naar één exchange doorstuurt, is daarom meestal het stortingsadres van één klant. Met dit adres kan de exchange de klant direct vinden.':
    'At an exchange every customer gets their own deposit address. Whatever arrives there is swept by the exchange to a large collection address (hot wallet). An address that forwards almost all its money to one exchange is therefore usually the deposit address of one customer. With this address the exchange can find the customer directly.',
  'Verantwoording en controle': 'Accountability and verification',
  'Wie het bestand later controleert (bijv. met "sha256sum" of "certutil -hashfile <bestand> SHA256"), moet exact deze code krijgen. Een andere code betekent dat het bestand is gewijzigd.':
    'Anyone verifying the file later (e.g. with "sha256sum" or "certutil -hashfile <file> SHA256") must get exactly this code. A different code means the file has been changed.',
  'Programma': 'Program', 'Rapport gemaakt (UTC)': 'Report created (UTC)', 'Instellingen': 'Settings', 'Tijdvolgorde': 'Time order', 'aan': 'on', 'uit': 'off',
  'Alleen geld gevolgd dat vertrok nadat het op het adres binnenkwam.': 'Only money that left after it arrived at the address was followed.',
  'Uit: alle uitgaande betalingen gevolgd.': 'Off: all outgoing payments followed.',
  'Opgehaald (UTC)': 'Fetched (UTC)', 'Geladen': 'Loaded', 'Volledig?': 'Complete?', 'nee, alleen recentste': 'no, most recent only', 'ja': 'yes', 'voorbeeldgegevens': 'example data'
};
patterns.push(
  ['{#0} adressen, {#1} geldstromen', '{0} addresses, {1} money flows'],
  ['Route {#0}: eindigt bij {1}', 'Route {0}: ends at {1}'], ['van {0} naar {1}', 'from {0} to {1}'],
  ['Verdachte adressen ({#0})', 'Suspicious addresses ({0})'], ['Verdachte transacties ({#0})', 'Suspicious transactions ({0})'],
  ['Geld afkomstig van exchanges - instroom ({#0})', 'Money from exchanges - inflow ({0})'], ['Alle adressen in dit onderzoek ({#0})', 'All addresses in this investigation ({0})'],
  ['Startwallets - mogelijke slachtoffers of geldbronnen ({#0})', 'Start wallets - possible victims or sources of funds ({0})'],
  ['Uitbetaling via exchanges - cash-out ({#0})', 'Payout via exchanges - cash-out ({0})'],
  ['Startadres - {0}', 'Start address - {0}'], ['Pagina {#0} van {#1}', 'Page {0} of {1}'], ['Wallet {#0} ({#1})', 'Wallet {0} ({1})'],
  ['{#0} betaling', '{0} payment'], ['{#0} betalingen', '{0} payments'], ['{#0} betalingen (eerste 600 getoond)', '{0} payments (first 600 shown)'],
  ['Stortingsadres van een klant bij {0} ({#1}% doorgestuurd)', 'Customer deposit address at {0} ({1}% forwarded)'], ['Stortingsadres bij {0}', 'Deposit address at {0}'],
  ['Dit is waarschijnlijk het persoonlijke stortingsadres van één klant bij {0}. Met dit adres kan de exchange de klant direct vinden: zet het in de brief.', 'This is probably the personal deposit address of one customer at {0}. With this address the exchange can find the customer directly: put it in the letter.'],
  ['{#0} stortingsadres(sen) van klanten bij een exchange gevonden: {1}. Dit zijn de sterkste aanknopingspunten voor de brief aan de exchange.', '{0} customer deposit address(es) at an exchange found: {1}. These are the strongest leads for the letter to the exchange.'],
  ['Tijdlijn van de geldroute ({#0})', 'Timeline of the money route ({0})'], ['Bronnen per adres ({#0})', 'Sources per address ({0})'],
  ['Bij dit rapport hoort het dossierbestand "{0}" met alle adressen, geldstromen en instellingen. De SHA-256-vingerafdruk van dat bestand is:', 'This report comes with the file "{0}" containing all addresses, money flows and settings. The SHA-256 fingerprint of that file is:'],
  ['stappen {0}, tegenpartijen {1}, max. adressen {2}, tijdvolgorde {3}', 'hops {0}, counterparties {1}, max. addresses {2}, time order {3}'],
  ['PDF-rapport en dossierbestand opgeslagen ({#0} pagina\'s).', 'PDF report and evidence file saved ({0} pages).'],
  ['- {0}', '- {0}'], ['{#0}. {1}', '{0}. {1}'], ['{#0}. {1}: {2}', '{0}. {1}: {2}']
);
Object.assign(exact, PDF_EXTRA);

// ----- motor -----
const norm = s => s.replace(/\s+/g, ' ').trim();
const ex = new Map(Object.entries(exact).map(([k, v]) => [norm(k), v]));
const esc = s => s.replace(/[.*+?^$()|[\]\\]/g, '\\$&');
// {0} = willekeurige tekst, {#0} = alleen een getal
const pats = patterns.map(([nl, en]) => ({
  re: new RegExp('^' + esc(norm(nl)).replace(/\{(#?)(\d)\}/g, (_, h) => h ? '([\\d.,]+)' : '(.+?)') + '$'),
  en: en.replace(/\{#(\d)\}/g, '{$1}')
}));
const DUTCH = /\b(het|een|van|niet|naar|wordt|zijn|bij|voor|dit|deze|je|uit|geen|nog|hier|tik|waar|adres|adressen|geld|stap|zaak|onderzoek|transacties|slachtoffer|dader|verdacht|ophalen|gevonden|mislukt|bewaard|opgeslagen|toevoegen|verwijder|tegenpartijen|ontvangen|verzonden|eerste|laatste|alleen|zonder|koers|uitleg|kopieer|terug|sluiten)\b/i;
const misses = window.__i18nMiss = new Set();
const cache = new Map();
function trCore(s, depth = 0) {
  const k = norm(s);
  if (!k || depth > 3) return null;
  if (ex.has(k)) return ex.get(k);
  for (const p of pats) {
    const m = k.match(p.re);
    if (m) return p.en.replace(/\{(\d)\}/g, (_, i) => { const g = m[+i + 1]; return trCore(g, depth + 1) ?? g; });
  }
  // Opsomming met " · " of "; ": elk deel apart vertalen.
  for (const sep of [' · ', '; ']) {
    if (!k.includes(sep)) continue;
    const segs = k.split(sep);
    const t = segs.map(x => trCore(x, depth + 1));
    if (t.some(x => x != null)) return segs.map((x, i) => t[i] ?? x).join(sep);
  }
  // Meerdere zinnen: per zin vertalen als alle zinnen bekend zijn.
  const parts = k.split(/(?<=[.!?])\s+(?=[A-Z"“(])/);
  if (parts.length > 1) {
    const t = parts.map(x => trCore(x, depth + 1));
    if (t.every(x => x != null)) return t.join(' ');
  }
  return null;
}
function tr(s) {
  if (LANG !== 'en' || s == null) return s;
  const str = String(s);
  if (cache.has(str)) return cache.get(str);
  const lead = str.match(/^\s*/)[0], trail = str.match(/\s*$/)[0];
  const t = trCore(str);
  const out = t == null ? str : lead + t + trail;
  if (t == null && DUTCH.test(str) && str.length < 400) misses.add(norm(str));
  cache.set(str, out);
  return out;
}
window.tr = tr;
if (LANG !== 'en') return;

document.documentElement.lang = 'en';
const ATTRS = ['placeholder', 'title', 'aria-label'];
const done = new WeakMap();
function fixText(node) {
  const v = node.nodeValue;
  if (!v || !/[A-Za-zÀ-ÿ]/.test(v) || done.get(node) === v) return;
  const t = tr(v);
  done.set(node, t);
  if (t !== v) node.nodeValue = t;
}
function fixEl(el) {
  for (const a of ATTRS) { const v = el.getAttribute?.(a); if (v) { const t = tr(v); if (t !== v) el.setAttribute(a, t); } }
}
function walk(root) {
  if (root.nodeType === 3) { if (!root.parentElement?.closest('script,style,textarea,#cy')) fixText(root); return; }
  if (root.nodeType !== 1 || root.closest?.('script,style,#cy')) return;
  fixEl(root);
  const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
  let n;
  while ((n = w.nextNode())) {
    if (n.nodeType === 1) { if (n.matches('script,style,textarea,#cy')) continue; fixEl(n); }
    else if (!n.parentElement?.closest('script,style,textarea,#cy')) fixText(n);
  }
}
const obs = new MutationObserver(list => {
  for (const m of list) {
    if (m.type === 'characterData') fixText(m.target);
    else if (m.type === 'attributes') fixEl(m.target);
    else m.addedNodes.forEach(walk);
  }
});
document.addEventListener('DOMContentLoaded', () => {
  walk(document.body);
  obs.observe(document.body, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS });
});
// prompt/confirm in het Engels
const P = window.prompt.bind(window), C = window.confirm.bind(window);
window.prompt = (m, d) => P(tr(m), d);
window.confirm = m => C(tr(m));
// Vertalingen van de patronen zelf (keuzelijst, uitleg, stappen) gebeuren via het woordenboek bij weergave.
})();
