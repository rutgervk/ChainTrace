package nl.chaintrace.app

import android.annotation.SuppressLint
import android.content.ContentValues
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.speech.tts.TextToSpeech
import android.speech.tts.UtteranceProgressListener
import java.util.Locale
import android.os.Environment
import android.provider.MediaStore
import android.util.Base64
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.webkit.WebViewAssetLoader
import nl.chaintrace.app.osint.OsintDb
import nl.chaintrace.app.osint.OsintSyncWorker
import java.io.File

/**
 * Dunne schil rond de webapp in /web: die wordt via WebViewAssetLoader geserveerd op
 * https://appassets.androidplatform.net zodat fetch() naar de publieke API's met CORS werkt.
 */
class MainActivity : ComponentActivity() {

    private lateinit var webView: WebView
    private var fileCallback: ValueCallback<Array<Uri>>? = null

    private var tts: TextToSpeech? = null
    private var ttsReady = false
    private val askNotify = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    private val pickFile = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        fileCallback?.onReceiveValue(uri?.let { arrayOf(it) } ?: emptyArray())
        fileCallback = null
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val assetLoader = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()

        webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            settings.setSupportMultipleWindows(false)
            addJavascriptInterface(Bridge(), "AndroidBridge")
            webViewClient = object : WebViewClient() {
                override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? =
                    assetLoader.shouldInterceptRequest(request.url)

                // Externe OSINT-links openen in de browser, niet in de app.
                override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                    if (request.url.host == APP_HOST) return false
                    runCatching { startActivity(Intent(Intent.ACTION_VIEW, request.url)) }
                    return true
                }
            }
            webChromeClient = object : WebChromeClient() {
                override fun onShowFileChooser(
                    view: WebView, callback: ValueCallback<Array<Uri>>, params: FileChooserParams
                ): Boolean {
                    fileCallback?.onReceiveValue(null)
                    fileCallback = callback
                    pickFile.launch(if (params.acceptTypes.any { it.startsWith("image/") }) "image/*" else "*/*")
                    return true
                }

                override fun onConsoleMessage(msg: android.webkit.ConsoleMessage): Boolean {
                    Log.d(TAG, "${msg.messageLevel()}: ${msg.message()} (${msg.sourceId()}:${msg.lineNumber()})")
                    return true
                }
            }
        }
        setContentView(webView)
        WebView.setWebContentsDebuggingEnabled(true)

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                // Eerst de webapp laten sluiten wat open staat (venster, verkenner, tab); anders de app sluiten.
                webView.evaluateJavascript("window.ChainTraceBack ? ChainTraceBack() : false") { handled ->
                    if (handled != "true") { if (webView.canGoBack()) webView.goBack() else finish() }
                }
            }
        })

        // De eerste periodieke run start direct; daarna elke 24 uur.
        OsintSyncWorker.scheduleDaily(this)
        if (WatchStore.get(this).length > 2) WatchWorker.schedule(this)

        val watch = intent?.getStringExtra(EXTRA_WATCH)
        if (savedInstanceState != null && watch == null) webView.restoreState(savedInstanceState)
        else webView.loadUrl("https://$APP_HOST/assets/index.html" + (watch?.let { "?watch=" + Uri.encode(it) } ?: ""))
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val watch = intent.getStringExtra(EXTRA_WATCH) ?: return
        webView.evaluateJavascript("window.ChainTraceOpenWatch && window.ChainTraceOpenWatch(${org.json.JSONObject.quote(watch)})", null)
    }

    override fun onDestroy() {
        tts?.shutdown()
        super.onDestroy()
    }

    /** Voorlezen in het Nederlands; lange teksten in stukjes (TTS heeft een maximum per stuk). */
    private var ttsLang = "nl"

    private fun speakText(text: String, lang: String = "nl") {
        val go = {
            val t = tts!!
            t.stop()
            if (lang != ttsLang) { ttsLang = lang; t.language = if (lang == "en") Locale.UK else Locale("nl", "NL") }
            val max = TextToSpeech.getMaxSpeechInputLength() - 100
            val parts = text.split(Regex("(?<=[.!?])\\s+")).flatMap { it.chunked(max) }.filter { it.isNotBlank() }
            parts.forEachIndexed { i, p ->
                t.speak(p, if (i == 0) TextToSpeech.QUEUE_FLUSH else TextToSpeech.QUEUE_ADD, null, if (i == parts.lastIndex) "last" else "p$i")
            }
        }
        if (tts != null && ttsReady) { go(); return }
        tts = TextToSpeech(this) { status ->
            ttsReady = status == TextToSpeech.SUCCESS
            if (!ttsReady) return@TextToSpeech
            ttsLang = lang
            tts?.language = if (lang == "en") Locale.UK else Locale("nl", "NL")
            tts?.setOnUtteranceProgressListener(object : UtteranceProgressListener() {
                override fun onStart(id: String?) {}
                override fun onError(id: String?) { done() }
                override fun onDone(id: String?) { if (id == "last") done() }
                private fun done() = runOnUiThread { webView.evaluateJavascript("window.ChainTraceSpeechDone && window.ChainTraceSpeechDone()", null) }
            })
            runOnUiThread { go() }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        webView.saveState(outState)
    }

    private inner class Bridge {
        /** Tekst van het klembord, voor de Plak-knop (navigator.clipboard werkt niet in een WebView). */
        @JavascriptInterface
        fun readClipboard(): String = runCatching {
            val cm = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
            cm.primaryClip?.getItemAt(0)?.coerceToText(this@MainActivity)?.toString() ?: ""
        }.getOrDefault("")

        @JavascriptInterface
        fun speak(text: String) = runOnUiThread { speakText(text) }

        @JavascriptInterface
        fun speakLang(text: String, lang: String) = runOnUiThread { speakText(text, lang) }

        @JavascriptInterface
        fun stopSpeaking() = runOnUiThread { tts?.stop() }

        @JavascriptInterface
        fun getWatchlist(): String = WatchStore.get(this@MainActivity)

        @JavascriptInterface
        fun saveWatchlist(json: String) {
            WatchStore.set(this@MainActivity, json)
            if (json.length > 2) WatchWorker.schedule(this@MainActivity)
        }

        /** Eerste keer volgen: toestemming voor meldingen vragen en de controle plannen. */
        @JavascriptInterface
        fun watchEnabled() = runOnUiThread {
            WatchWorker.ensureChannel(this@MainActivity)
            if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                askNotify.launch(android.Manifest.permission.POST_NOTIFICATIONS)
            }
            WatchWorker.schedule(this@MainActivity)
        }

        @JavascriptInterface
        fun watchCheckNow() = WatchWorker.runNow(this@MainActivity)

        @JavascriptInterface
        fun writeClipboard(text: String) {
            runOnUiThread {
                val cm = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
                cm.setPrimaryClip(android.content.ClipData.newPlainText("ChainTrace", text))
            }
        }

        /** Tekst delen via e-mail, WhatsApp e.d. (bv. de brief aan een exchange). */
        @JavascriptInterface
        fun shareText(subject: String, text: String) {
            runOnUiThread {
                val send = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_SUBJECT, subject)
                    putExtra(Intent.EXTRA_TEXT, text)
                }
                runCatching { startActivity(Intent.createChooser(send, "Delen via")) }
            }
        }

        private val db get() = OsintDb.get(this@MainActivity)

        /** Labels uit de lokale OSINT-database + eigen eerdere waarnemingen (andere zaken). */
        @JavascriptInterface
        fun osintLookup(address: String, currentCase: String?): String =
            runCatching { db.lookup(address, currentCase).toString() }.getOrElse { "{\"labels\":[],\"observations\":[]}" }

        @JavascriptInterface
        fun osintSearch(query: String): String = runCatching { db.search(query).toString() }.getOrElse { "[]" }

        @JavascriptInterface
        fun osintStats(): String = db.stats(getDatabasePath("osint.db").length()).toString()

        @JavascriptInterface
        fun osintSyncNow() = OsintSyncWorker.runNow(this@MainActivity)

        @JavascriptInterface
        fun recordObservations(json: String) {
            runCatching { db.recordObservations(json) }.onFailure { Log.e(TAG, "recordObservations", it) }
        }

        @JavascriptInterface
        fun saveUserLabel(chain: String, address: String, label: String) {
            runCatching { db.setUserLabel(chain, address, label) }.onFailure { Log.e(TAG, "saveUserLabel", it) }
        }

        /** Bestand (bv. het PDF-rapport) delen via het Android-deelmenu: mail, WhatsApp, Drive… */
        @JavascriptInterface
        fun shareFile(name: String, mime: String, base64: String) {
            runCatching {
                val dir = File(cacheDir, "share").apply { mkdirs() }
                val f = File(dir, name.replace(Regex("[^A-Za-z0-9._-]"), "_"))
                f.writeBytes(Base64.decode(base64, Base64.DEFAULT))
                val uri = androidx.core.content.FileProvider.getUriForFile(this@MainActivity, "$packageName.files", f)
                val send = Intent(Intent.ACTION_SEND).apply {
                    type = mime
                    putExtra(Intent.EXTRA_STREAM, uri)
                    // ClipData zorgt dat de leesrechten ook naar het deelmenu zelf (voorbeeld) en de gekozen app gaan.
                    clipData = android.content.ClipData.newRawUri(f.name, uri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                val chooser = Intent.createChooser(send, "Delen via").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                runOnUiThread { startActivity(chooser) }
            }.onFailure { Log.e(TAG, "shareFile", it) }
        }

        @JavascriptInterface
        fun saveFile(name: String, mime: String, base64: String) {
            val safeName = name.replace(Regex("[^A-Za-z0-9._-]"), "_")
            val result = runCatching { writeDownload(safeName, mime, Base64.decode(base64, Base64.DEFAULT)) }
            runOnUiThread {
                val text = result.fold({ "Opgeslagen in Downloads: $safeName" }, { "Opslaan mislukt: ${it.message}" })
                Toast.makeText(this@MainActivity, text, Toast.LENGTH_LONG).show()
            }
            result.exceptionOrNull()?.let { Log.e(TAG, "saveFile", it) }
        }
    }

    private fun writeDownload(name: String, mime: String, bytes: ByteArray) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, mime)
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/ChainTrace")
            }
            val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: error("Geen toegang tot Downloads")
            contentResolver.openOutputStream(uri)!!.use { it.write(bytes) }
        } else {
            val dir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: filesDir
            File(dir, name).writeBytes(bytes)
        }
    }

    companion object {
        const val EXTRA_WATCH = "watch"
        private const val TAG = "ChainTrace"
        private const val APP_HOST = "appassets.androidplatform.net"
    }
}
