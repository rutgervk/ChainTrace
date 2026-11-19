# ChainTrace zelftest

`selftest.js` test de app in een echte browser of in de Android-app (WebView), met echte blockchain-API's.

## Draaien in de browser
1. Kopieer `tests/selftest.js` tijdelijk naar `web/` (en eventueel een `qrtest.png` met een QR-code van
   `bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.01`).
2. Start een webserver in `web/` (bijv. `python -m http.server 8765`) en open de app.
3. In de console:
   ```js
   await new Promise(r => { const s = document.createElement('script'); s.src = 'selftest.js'; s.onload = r; document.head.appendChild(s); });
   ChainTraceSelftest.run(['basis','demo','verkenner','qr','pdf','ketens','meer','zaken','volgen','layout','v19','v20','v21','v22']);
   // na afloop:
   ChainTraceSelftest.summary();
   ```

## Draaien op een Android-toestel
Zelfde script via WebView DevTools (`adb forward tcp:9333 localabstract:webview_devtools_remote_<pid>`).

## Let op
- Verwijder `web/selftest.js` en `web/qrtest.png` weer vóór het bouwen van de APK (anders komen ze in de app).
- De tests bewaren onderzoeken in "Mijn zaken" en maken PDF's: ruim die daarna op.
