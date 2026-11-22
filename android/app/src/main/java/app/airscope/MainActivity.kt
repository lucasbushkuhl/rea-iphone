package app.airscope

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Color
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.net.Uri
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.os.VibrationEffect
import android.os.Vibrator
import android.provider.MediaStore
import android.provider.Settings
import android.view.WindowManager
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.webkit.WebViewAssetLoader
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Airscope for Android. The interface is the same web app as the iPhone
 * version, bundled in the APK and served from a private https origin. This
 * native core does what only an app can: a continuous Bluetooth LE scan with
 * hardware addresses, Wi-Fi network scans, and location. It only listens; it
 * never connects to, pairs with, or transmits to another device.
 */
class MainActivity : Activity() {

    private lateinit var web: WebView
    private val main = Handler(Looper.getMainLooper())

    private var scanning = false
    private var bleScanner: BluetoothLeScanner? = null
    private var wifiReceiverRegistered = false
    private var locationOn = false
    private var pendingStart = false

    // Event batching: the latest advertisement per Bluetooth device, plus
    // other events in order, flushed to the page a few times per second.
    private val pendingBle = LinkedHashMap<String, JSONObject>()
    private val pendingOther = ArrayList<JSONObject>()
    private var flushScheduled = false

    // ------------------------------------------------------------ lifecycle

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = Color.parseColor("#070b10")
        window.navigationBarColor = Color.parseColor("#0d141c")

        val assets = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()

        web = WebView(this)
        web.setBackgroundColor(Color.parseColor("#070b10"))
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = false
        web.settings.allowContentAccess = false
        web.settings.mediaPlaybackRequiresUserGesture = false
        web.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? =
                assets.shouldInterceptRequest(request.url)

            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                if (request.url.host == APP_HOST) return false
                // Map links and anything else external open in the browser.
                try {
                    startActivity(Intent(Intent.ACTION_VIEW, request.url))
                } catch (e: Exception) {
                    toast("No app can open that link.")
                }
                return true
            }
        }
        web.addJavascriptInterface(Bridge(), "AirscopeNative")
        setContentView(web)
        web.loadUrl("https://$APP_HOST/assets/airscope/index.html")
    }

    override fun onDestroy() {
        stopScan()
        web.destroy()
        super.onDestroy()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (web.canGoBack()) web.goBack() else super.onBackPressed()
    }

    // ------------------------------------------------------------ bridge

    /** Called from the page's JavaScript (on a background thread). */
    inner class Bridge {
        @JavascriptInterface
        fun start() = main.post { requestStart() }.let { }

        @JavascriptInterface
        fun stop() = main.post { stopScan() }.let { }

        @JavascriptInterface
        fun vibrate(ms: Int) = main.post { buzz(ms.toLong().coerceIn(10, 2000)) }.let { }

        @JavascriptInterface
        fun copy(text: String) = main.post {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("Airscope", text))
        }.let { }

        @JavascriptInterface
        fun saveFile(name: String, mime: String, text: String) = main.post { save(name, mime, text) }.let { }

        @JavascriptInterface
        fun openSettings() = main.post { openAppSettings() }.let { }

        @JavascriptInterface
        fun info(): String = JSONObject()
            .put("sdk", Build.VERSION.SDK_INT)
            .put("model", "${Build.MANUFACTURER} ${Build.MODEL}")
            .toString()
    }

    // ------------------------------------------------------------ permissions

    private fun missingPermissions(): Array<String> {
        val wanted = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
        )
        if (Build.VERSION.SDK_INT >= 31) {
            wanted += Manifest.permission.BLUETOOTH_SCAN
            wanted += Manifest.permission.BLUETOOTH_CONNECT
        }
        if (Build.VERSION.SDK_INT >= 33) wanted += Manifest.permission.NEARBY_WIFI_DEVICES
        return wanted.filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }.toTypedArray()
    }

    private fun requestStart() {
        val missing = missingPermissions()
        if (missing.isNotEmpty()) {
            pendingStart = true
            requestPermissions(missing, REQUEST_PERMISSIONS)
        } else {
            startScan()
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQUEST_PERMISSIONS || !pendingStart) return
        pendingStart = false
        val stillMissing = missingPermissions()
        val canBle = Build.VERSION.SDK_INT >= 31 && Manifest.permission.BLUETOOTH_SCAN !in stillMissing ||
            Build.VERSION.SDK_INT < 31 && Manifest.permission.ACCESS_FINE_LOCATION !in stillMissing
        val canWifi = Manifest.permission.ACCESS_FINE_LOCATION !in stillMissing
        if (!canBle && !canWifi) {
            sendState(
                message = "Airscope needs Nearby devices and Location permission to scan.",
                warnings = listOf("Permissions were denied. Open Settings › Apps › Airscope › Permissions, allow Nearby devices and Location, then tap Start scan."),
            )
            return
        }
        startScan()
    }

    private fun openAppSettings() {
        startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null)))
    }

    // ------------------------------------------------------------ scanning

    @SuppressLint("MissingPermission")
    private fun startScan() {
        if (scanning) return
        val warnings = mutableListOf<String>()
        val missing = missingPermissions()

        if (!locationServicesOn()) {
            warnings += "Location is turned off. Android needs it on for Wi-Fi and Bluetooth scans. Turn it on in Quick Settings."
        }

        // Bluetooth
        var bleOk = false
        val adapter = (getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
        if (adapter == null) {
            warnings += "This phone has no Bluetooth."
        } else if (!adapter.isEnabled) {
            warnings += "Bluetooth is off. Turn it on, then stop and start the scan."
            if (Build.VERSION.SDK_INT < 31 || Manifest.permission.BLUETOOTH_CONNECT !in missing) {
                try {
                    startActivity(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
                } catch (_: Exception) { }
            }
        } else if ((Build.VERSION.SDK_INT >= 31 && Manifest.permission.BLUETOOTH_SCAN in missing) ||
            (Build.VERSION.SDK_INT < 31 && Manifest.permission.ACCESS_FINE_LOCATION in missing)
        ) {
            warnings += "Bluetooth permission was denied, so only Wi-Fi is scanned."
        } else {
            try {
                val settings = ScanSettings.Builder()
                    .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                    .setReportDelay(0)
                    .apply {
                        // Extended advertising (Bluetooth 5) carries long-range Remote ID.
                        if (adapter.isLeExtendedAdvertisingSupported) {
                            setLegacy(false)
                            setPhy(ScanSettings.PHY_LE_ALL_SUPPORTED)
                        }
                    }
                    .build()
                bleScanner = adapter.bluetoothLeScanner
                bleScanner?.startScan(null, settings, bleCallback)
                bleOk = bleScanner != null
            } catch (e: Exception) {
                warnings += "Bluetooth scan couldn't start: ${e.message}"
            }
        }

        // Wi-Fi
        var wifiOk = false
        if (Manifest.permission.ACCESS_FINE_LOCATION in missing) {
            warnings += "Location permission was denied, so Wi-Fi networks can't be listed."
        } else {
            val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            if (!wifi.isWifiEnabled && !wifiScanAlwaysAvailable(wifi)) {
                warnings += "Wi-Fi is off. Turn it on to list Wi-Fi networks (you don't need to connect to one)."
            }
            val filter = IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)
            if (Build.VERSION.SDK_INT >= 33) registerReceiver(wifiReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            else registerReceiver(wifiReceiver, filter)
            wifiReceiverRegistered = true
            wifiOk = true
            sendWifiResults() // whatever the phone already has
            main.post(wifiLoop)
        }

        // Location
        if (Manifest.permission.ACCESS_FINE_LOCATION !in missing || Manifest.permission.ACCESS_COARSE_LOCATION !in missing) {
            startLocation()
        }

        scanning = bleOk || wifiOk
        if (scanning) window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        sendState(message = if (scanning) null else "Scanning couldn't start.", warnings = warnings, bluetooth = bleOk, wifi = wifiOk)
    }

    @SuppressLint("MissingPermission")
    private fun stopScan() {
        main.removeCallbacks(wifiLoop)
        try { bleScanner?.stopScan(bleCallback) } catch (_: Exception) { }
        bleScanner = null
        if (wifiReceiverRegistered) {
            try { unregisterReceiver(wifiReceiver) } catch (_: Exception) { }
            wifiReceiverRegistered = false
        }
        stopLocation()
        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val was = scanning
        scanning = false
        if (was) sendState(bluetooth = false, wifi = false)
    }

    private fun locationServicesOn(): Boolean {
        val lm = getSystemService(Context.LOCATION_SERVICE) as LocationManager
        return if (Build.VERSION.SDK_INT >= 28) lm.isLocationEnabled
        else lm.isProviderEnabled(LocationManager.GPS_PROVIDER) || lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
    }

    @Suppress("DEPRECATION")
    private fun wifiScanAlwaysAvailable(wifi: WifiManager): Boolean = try {
        wifi.isScanAlwaysAvailable
    } catch (_: Exception) { false }

    // ------------------------------------------------------------ Bluetooth

    private val bleCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) = onBle(result)
        override fun onBatchScanResults(results: MutableList<ScanResult>) = results.forEach { onBle(it) }
        override fun onScanFailed(errorCode: Int) {
            val why = when (errorCode) {
                SCAN_FAILED_ALREADY_STARTED -> "already running"
                SCAN_FAILED_APPLICATION_REGISTRATION_FAILED -> "Android refused to register the scan; try turning Bluetooth off and on"
                SCAN_FAILED_FEATURE_UNSUPPORTED -> "not supported on this phone"
                else -> "error $errorCode"
            }
            sendState(message = "Bluetooth scan stopped: $why.", bluetooth = false)
        }
    }

    @SuppressLint("MissingPermission")
    private fun onBle(r: ScanResult) {
        val rec = r.scanRecord
        val o = JSONObject()
        o.put("type", "ble")
        o.put("id", r.device.address)
        o.put("mac", r.device.address)
        o.put("rssi", r.rssi)
        if (r.txPower != ScanResult.TX_POWER_NOT_PRESENT) o.put("txPower", r.txPower)
        rec?.deviceName?.let { if (it.isNotBlank()) o.put("name", it) }
        val md = JSONObject()
        rec?.manufacturerSpecificData?.let { sa ->
            for (i in 0 until sa.size()) md.put(sa.keyAt(i).toString(), hex(sa.valueAt(i)))
        }
        o.put("manufacturerData", md)
        val sd = JSONObject()
        rec?.serviceData?.forEach { (uuid, bytes) -> sd.put(uuid.uuid.toString(), hex(bytes)) }
        o.put("serviceData", sd)
        val uuids = JSONArray()
        rec?.serviceUuids?.forEach { uuids.put(it.uuid.toString()) }
        o.put("uuids", uuids)
        o.put("connectable", r.isConnectable)
        synchronized(pendingBle) {
            pendingBle[r.device.address] = o
        }
        scheduleFlush()
    }

    // ------------------------------------------------------------ Wi-Fi

    private val wifiReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) = sendWifiResults()
    }

    /** Android allows about 4 scans per 2 minutes, so ask every 30 seconds. */
    private val wifiLoop = object : Runnable {
        override fun run() {
            if (!scanning && !wifiReceiverRegistered) return
            val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            @Suppress("DEPRECATION")
            val started = try { wifi.startScan() } catch (_: Exception) { false }
            if (!started) sendWifiResults() // throttled: send the latest cached results
            main.postDelayed(this, 30_000)
        }
    }

    @SuppressLint("MissingPermission")
    private fun sendWifiResults() {
        val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val results = try { wifi.scanResults } catch (e: SecurityException) {
            sendState(message = "Wi-Fi results need Location permission.")
            return
        }
        val list = JSONArray()
        for (s in results) {
            val n = JSONObject()
            n.put("bssid", s.BSSID)
            @Suppress("DEPRECATION")
            n.put("ssid", s.SSID ?: "")
            n.put("rssi", s.level)
            n.put("frequency", s.frequency)
            n.put("capabilities", s.capabilities ?: "")
            val ies = JSONArray()
            if (Build.VERSION.SDK_INT >= 30) {
                for (ie in s.informationElements) {
                    if (ie.id == 221) { // vendor specific: may carry Remote ID
                        val buf = ie.bytes.duplicate()
                        val bytes = ByteArray(buf.remaining())
                        buf.get(bytes)
                        ies.put(hex(bytes))
                    }
                }
            }
            n.put("vendorIes", ies)
            list.put(n)
        }
        queue(JSONObject().put("type", "wifi").put("networks", list))
    }

    // ------------------------------------------------------------ location

    private val locationListener = object : LocationListener {
        override fun onLocationChanged(location: Location) {
            queue(
                JSONObject().put("type", "location")
                    .put("latitude", location.latitude)
                    .put("longitude", location.longitude)
                    .put("accuracy", location.accuracy.toDouble()),
            )
        }

        override fun onProviderEnabled(provider: String) {}
        override fun onProviderDisabled(provider: String) {}

        @Deprecated("Deprecated in Java")
        override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) {}
    }

    @SuppressLint("MissingPermission")
    private fun startLocation() {
        if (locationOn) return
        val lm = getSystemService(Context.LOCATION_SERVICE) as LocationManager
        for (p in listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER)) {
            try {
                if (lm.isProviderEnabled(p)) {
                    lm.requestLocationUpdates(p, 5000L, 5f, locationListener, Looper.getMainLooper())
                    locationOn = true
                }
            } catch (_: Exception) { }
        }
    }

    private fun stopLocation() {
        if (!locationOn) return
        try {
            (getSystemService(Context.LOCATION_SERVICE) as LocationManager).removeUpdates(locationListener)
        } catch (_: Exception) { }
        locationOn = false
    }

    // ------------------------------------------------------------ events to the page

    private fun sendState(message: String? = null, warnings: List<String>? = null, bluetooth: Boolean? = null, wifi: Boolean? = null) {
        val o = JSONObject().put("type", "state").put("scanning", scanning)
        if (message != null) o.put("message", message)
        if (warnings != null) o.put("warnings", JSONArray(warnings))
        if (bluetooth != null) o.put("bluetooth", bluetooth)
        if (wifi != null) o.put("wifi", wifi)
        queue(o)
    }

    private fun queue(o: JSONObject) {
        synchronized(pendingBle) { pendingOther.add(o) }
        scheduleFlush()
    }

    private fun scheduleFlush() {
        synchronized(pendingBle) {
            if (flushScheduled) return
            flushScheduled = true
        }
        main.postDelayed({ flush() }, 300)
    }

    private fun flush() {
        val batch = JSONArray()
        synchronized(pendingBle) {
            for (o in pendingOther) batch.put(o)
            for (o in pendingBle.values) batch.put(o)
            pendingOther.clear()
            pendingBle.clear()
            flushScheduled = false
        }
        if (batch.length() == 0) return
        web.evaluateJavascript("window.__airscopeEvents && window.__airscopeEvents($batch)", null)
    }

    // ------------------------------------------------------------ helpers

    private fun save(name: String, mime: String, text: String) {
        val safeName = name.replace(Regex("[^A-Za-z0-9._-]"), "_")
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, safeName)
                    put(MediaStore.Downloads.MIME_TYPE, mime)
                }
                val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: throw IllegalStateException("couldn't create the file")
                contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray()) }
                toast("Saved to Downloads: $safeName")
            } else {
                val dir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: filesDir
                val file = File(dir, safeName)
                file.writeText(text)
                // Older Android: offer to send the data anywhere as well.
                startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_SUBJECT, safeName)
                    putExtra(Intent.EXTRA_TEXT, text)
                }, "Send $safeName"))
            }
        } catch (e: Exception) {
            toast("Couldn't save: ${e.message}")
        }
    }

    @Suppress("DEPRECATION")
    private fun buzz(ms: Long) {
        val v = getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator ?: return
        try {
            v.vibrate(VibrationEffect.createOneShot(ms, VibrationEffect.DEFAULT_AMPLITUDE))
        } catch (_: Exception) { }
    }

    private fun toast(text: String) = Toast.makeText(this, text, Toast.LENGTH_LONG).show()

    private fun hex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) sb.append(HEX[(b.toInt() shr 4) and 0xf]).append(HEX[b.toInt() and 0xf])
        return sb.toString()
    }

    companion object {
        private const val APP_HOST = "appassets.androidplatform.net"
        private const val REQUEST_PERMISSIONS = 7
        private val HEX = "0123456789abcdef".toCharArray()
    }
}
