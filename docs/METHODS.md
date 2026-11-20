# Methodes van ChainTrace

Dit document beschrijft precies hoe ChainTrace tot zijn uitkomsten komt, zodat iedereen ze kan controleren en de beperkingen kent. Alle regels zitten in `web/app.js`; de namen van de functies staan tussen haakjes.

> Uitkomsten zijn **aanwijzingen, geen bewijs**. Ze zijn bedoeld als startpunt voor een aangifte, een bevriezingsverzoek of verder onderzoek.

## 1. Gegevens

- Per adres haalt de app de **recentste transacties** op via openbare API's (zie README). Standaard ±50 transacties per adres, voor het startadres bij Bitcoin/Litecoin ±100. Met "Oudere transacties laden" haalt de app meer op. Het PDF vermeldt per adres of de geschiedenis volledig is.
- Overboekingen worden genormaliseerd naar: van, naar, bedrag, munt, tijdstip, transactie-hash.
- **Spam** (nul-overboekingen, nepmunten met dezelfde naam als USDT/USDC, absurde bedragen) wordt gemarkeerd en standaard verborgen. Tokens zonder bekende koers worden in de verkenner standaard weggelaten (aan te zetten).
- Bitcoin/Litecoin: bij een uitgaande transactie telt elke output (behalve terug naar een eigen input-adres) als overboeking; bij een inkomende transactie wordt het ontvangen bedrag gelijk verdeeld over de afzenders.
- Ethereum/Optimism/Avalanche: gewone overboekingen, ERC-20-tokens én **interne overboekingen** (ETH via een contract).
- Tron: TRC-20-tokens (USDT/USDC) én gewone TRX-overboekingen.

## 2. Het geld volgen (`expand`)

- Vanaf het startadres volgt de app per stap de tegenpartijen met het hoogste bedrag (instelbaar aantal per adres en aantal stappen).
- **Tijdsvolgorde** (standaard aan): van een adres wordt alleen geld gevolgd dat vertrok **na** het moment dat het geld van de vorige stap binnenkwam (10 minuten speling voor bloktijden). Bij herkomst (terugzoeken) omgekeerd: alleen geld dat binnenkwam vóór het doorsturen.
- Het volgen stopt bij **eindpunten**: exchanges (label of zeer hoog transactievolume), mixers, bridges, smart contracts en adressen op een sanctielijst.

## 3. Herkenning van adressen

| Kenmerk | Regel |
|---|---|
| Exchange | openbaar label (Blockscout, lokale database, eigen labels) of ≥ 5.000 transacties / zeer veel transacties per dag. Bridges en decentrale exchanges (DEX) tellen niet als exchange. |
| Doorsluisadres | ≥ 60% van de inkomende stortingen binnen 1 uur doorgestuurd |
| Verzameladres / verspreidadres | ≥ 10 verschillende afzenders / ontvangers |
| Peel chain (Bitcoin) | herhaaldelijk 2 outputs waarvan één ≥ 80% van het totaal |
| Lijkt-op-adres (address poisoning) | tegenpartijen met hetzelfde begin én eind; extra verdacht bij nul- of nepmunt-overboekingen |
| **Stortingsadres** (`detectDeposits`) | adres dat ≥ 80% van zijn (waardevolle) uitgaande geld naar één exchange-adres stuurt → vermoedelijk het persoonlijke klant-stortingsadres bij die exchange |

## 4. Wallets en beheerders samenvoegen (`walletClusters`)

Vier regels, elk uit te zetten onder *Instellingen*:

1. **Samen als input** (Bitcoin/Litecoin): adressen die samen als input in één transactie zitten, horen bij dezelfde sleutelhouder. Groepen van meer dan 15 inputs worden genegeerd (mogelijk CoinJoin of een exchange-batch).
2. **Wisselgeld** (Bitcoin/Litecoin): bij een transactie met precies 2 nieuwe outputs is het wisselgeld het output-adres van hetzelfde adrestype als de inputs en/of het niet-ronde bedrag. Spreken de twee signalen elkaar tegen, dan wordt niets samengevoegd.
3. **Zelfde stortingsadres**: 2 tot 10 adressen die op hetzelfde klant-stortingsadres bij een exchange storten, horen vermoedelijk bij dezelfde klant.
4. **Startgeld voor transactiekosten** (Ethereum, Tron, Solana e.a.): een adres waarvan de eerste activiteit een klein bedrag (< ±€60) in de eigen munt is van een adres dat al in het onderzoek zit, en dat daarna tokens doorstuurt, hoort vermoedelijk bij dezelfde beheerder (typisch wegwerpadres).

**Nooit samengevoegd**: slachtoffers en mogelijke slachtoffers, exchanges en andere eindpunten, en groepen groter dan 80 adressen. Bij elk adres toont de app welke regel de koppeling maakte.

## 5. Bridges en swaps (`crossFollow`, `resolveBridge`)

- Gaat geld naar een **bridge**, dan vraagt de app de openbare status-API van deBridge, Across of LayerZero op met de transactie-hash. Is de doelketen ondersteund, dan loopt het web daar verder bij de ontvanger; anders vermeldt de app de doelketen en ontvanger.
- Gaat geld naar een **DEX/router** zonder dat er in dezelfde transactie iets terugkomt, dan zoekt de app in die transactie de overboeking in een andere munt naar een ander adres ("wissel en stuur door") en volgt die.
- Maximaal 8 bridge-transacties en 3 swaps per adres worden nagetrokken.

## 6. Waar is het geld gebleven? (`taintAnalysis`)

**Proportionele methode (haircut)**, in tijdsvolgorde:

1. Alle overboekingen tussen de geladen adressen worden op tijd gesorteerd en omgerekend naar **euro op de dag van betaling** (`eurOf`: dagkoersen van Binance; stablecoins via de EUR/USDT-koers).
2. Elke uitgaande betaling van het slachtoffer is volledig "geld van het slachtoffer".
3. Elk ander adres houdt een saldo en een besmet deel bij. Bij een uitgaande betaling gaat naar verhouding (besmet deel ÷ saldo) een deel van het slachtoffergeld mee. Geld dat het adres al had vóór de geladen geschiedenis telt als niet-besmet (conservatief).
4. Bridge- en swap-koppelingen vervangen de oorspronkelijke overboeking naar het bridge- of DEX-contract.
5. Uitkomst per bestemming: exchanges, stortingsadressen, nog op adressen, mixers/waarschuwingslijst, bridges, smart contracts, nog niet gevolgd.

Beperkingen: betalingen zonder bekende koers tellen niet mee (de app meldt hoeveel). Het is een schatting op basis van de geladen transacties; met meer geschiedenis of diepere stappen kan de verdeling veranderen.

## 7. Rapport en controle

- Het PDF bevat alle gebruikte instellingen, de bron en het ophaalmoment per adres, en de SHA-256-vingerafdruk van het bijbehorende dossierbestand (`chaintrace-dossier-….json`). Wie dat bestand later controleert (`sha256sum` of `certutil -hashfile <bestand> SHA256`), moet exact dezelfde code krijgen.
- Elke transactie staat met volledige hash in het rapport en is te controleren in een openbare block explorer.

## 8. Wat ChainTrace níet doet

- Geen eigen labeldatabase van niet-openbare bronnen; onbekende adressen blijven onbekend.
- Geen volledige indexering van de blockchain: wallets worden alleen samengevoegd binnen de geladen gegevens.
- Geen ondersteuning voor privacy-munten (bijv. Monero) en geen "demixing" na mixers.
- Ketens buiten de 8 ondersteunde (bijv. Arbitrum, Base, BNB Chain, Polygon) worden herkend als bestemming van een bridge, maar niet verder gevolgd.

## 9. Samenwerken via de teamserver (optioneel)

- Een ☁ teamzaak wordt na elke wijziging (±1,5 s) als dossier naar de teamserver gestuurd. Alleen-kijken-leden slaan niets op in de teamzaak; hun eigen onderzoeken gaan naar een eigen zaak op het apparaat.
- **Gelijktijdig bewerken**: de app stuurt mee op welke versie de wijziging is gebaseerd. Heeft iemand anders intussen opgeslagen, dan weigert de server (409); de app haalt die versie op en voegt hem samen met de eigen versie: alle adressen, kenmerken en geldstromen van beide blijven bestaan. De notitie bij de zaak en eigen labels van de laatste opslag blijven staan; gebruik voor overleg de opmerkingen bij de zaak.
- Elke ±20 seconden kijkt de app of er iets is gewijzigd. Is het geopende onderzoek door een ander bijgewerkt, dan verschijnt een melding met de knop om de nieuwe versie te openen.
- Het activiteitenlog legt vast wie wanneer een onderzoek toevoegde, bijwerkte of verwijderde, leden en deellinks beheerde en opmerkingen plaatste. Het SHA-256-dossier voor het PDF-rapport wordt zoals altijd op het eigen apparaat gemaakt.
