package com.example.ztemanager.network

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.ConnectionSpec
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.FormBody
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.TlsVersion
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider
import java.net.InetAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

enum class LogType { SYS, OK, ERR, WARN, ACT }

enum class SpeedPreset(
    val title: String,
    val subtitle: String,
    val standard: String,
    val bandWidth: String,
    val dataRate: String,
    val txPower: String
) {
    ECO("Eco", "~1-2 Mbps (Save Quota)", "b", "20MHz", "2M", "40%"),
    LOW("Low", "~4-5 Mbps (802.11b)", "b", "20MHz", "11M", "60%"),
    MEDIUM("Medium", "~12-15 Mbps (802.11g)", "g", "20MHz", "24M", "80%"),
    MAX("Max", "Full Line Speed (b/g/n)", "b,g,n", "40MHz", "Auto", "100%")
}

data class DslStats(
    val status: String = "Unknown",
    val downRateKbps: String = "--",
    val upRateKbps: String = "--",
    val maxDownKbps: String = "--",
    val maxUpKbps: String = "--",
    val downSnrDb: String = "--",
    val upSnrDb: String = "--",
    val downAttnDb: String = "--",
    val upAttnDb: String = "--",
    val rawRows: List<String> = emptyList()
)

data class ConnectedDevice(
    val hostName: String,
    val ipAddress: String,
    val macAddress: String,
    val leaseTime: String
)

data class BlockedRule(
    val index: Int,
    val name: String,
    val macAddress: String
)

data class WifiConfig(
    val ssid: String = "",
    val hidden: Boolean = false,
    val password: String = "",
    val standard: String = "b,g,n",
    val bandWidth: String = "20MHz",
    val txPower: String = "100%",
    val rawBasicKeys: Map<String, String> = emptyMap()
)

class ZteRouterClient(
    private val context: Context,
    private val onLog: (String, LogType) -> Unit
) {
    private val cookieStore = mutableMapOf<String, MutableList<Cookie>>()
    private var baseUrl: String = "https://192.168.1.1"
    private var targetHost: String = "192.168.1.1"

    private val bcJsseProvider: BouncyCastleJsseProvider by lazy {
        try {
            Security.setProperty("jdk.tls.disabledAlgorithms", "")
            Security.setProperty("jdk.certpath.disabledAlgorithms", "")
        } catch (_: Exception) {
        }
        BouncyCastleJsseProvider(BouncyCastleProvider())
    }

    private val compactLegacySuites = listOf(
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
    )

    private class BcTls10SocketFactory(
        private val delegate: SSLSocketFactory,
        private val suites: List<String>
    ) : SSLSocketFactory() {

        override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

        override fun createSocket(): Socket = patch(delegate.createSocket())
        override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket =
            patch(delegate.createSocket(s, host, port, autoClose))
        override fun createSocket(host: String, port: Int): Socket =
            patch(delegate.createSocket(host, port))
        override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
            patch(delegate.createSocket(host, port, localHost, localPort))
        override fun createSocket(host: InetAddress, port: Int): Socket =
            patch(delegate.createSocket(host, port))
        override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket =
            patch(delegate.createSocket(address, port, localAddress, localPort))

        private fun patch(socket: Socket): Socket {
            if (socket is SSLSocket) {
                socket.enabledProtocols = arrayOf("TLSv1")
                val supported = socket.supportedCipherSuites.toSet()
                val matched = suites.filter { it in supported }
                if (matched.isNotEmpty()) {
                    socket.enabledCipherSuites = matched.toTypedArray()
                }
            }
            return socket
        }
    }

    private fun buildClient(): OkHttpClient {
        @SuppressLint("CustomX509TrustManager")
        val trustManager = object : X509TrustManager {
            @SuppressLint("TrustAllX509TrustManager")
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            @SuppressLint("TrustAllX509TrustManager")
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

        val sslContext = SSLContext.getInstance("TLS", bcJsseProvider).apply {
            init(null, arrayOf(trustManager), SecureRandom())
        }

        val tlsSpec = ConnectionSpec.Builder(ConnectionSpec.COMPATIBLE_TLS)
            .tlsVersions(TlsVersion.TLS_1_0)
            .allEnabledCipherSuites()
            .build()

        val builder = OkHttpClient.Builder()
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(12, TimeUnit.SECONDS)
            .protocols(listOf(Protocol.HTTP_1_1))
            .connectionSpecs(listOf(tlsSpec, ConnectionSpec.CLEARTEXT))
            .sslSocketFactory(
                BcTls10SocketFactory(sslContext.socketFactory, compactLegacySuites),
                trustManager
            )
            .hostnameVerifier { hostname, _ ->
                hostname == targetHost ||
                    hostname.startsWith("192.168.") ||
                    hostname.startsWith("10.")
            }
            .cookieJar(object : CookieJar {
                override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
                    val list = cookieStore.getOrPut(url.host) { mutableListOf() }
                    cookies.forEach { c ->
                        list.removeAll { it.name == c.name }
                        list.add(c)
                    }
                }

                override fun loadForRequest(url: HttpUrl): List<Cookie> {
                    val saved = cookieStore[url.host]?.toMutableList() ?: mutableListOf()
                    if (saved.none { it.name == "_TESTCOOKIESUPPORT" }) {
                        saved.add(
                            Cookie.Builder()
                                .name("_TESTCOOKIESUPPORT")
                                .value("1")
                                .domain(url.host)
                                .build()
                        )
                    }
                    return saved
                }
            })

        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val wifiNet = cm.allNetworks.firstOrNull { net ->
                cm.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
            }
            if (wifiNet != null) builder.socketFactory(wifiNet.socketFactory)
        } catch (_: Exception) {
        }

        return builder.build()
    }

    private var client: OkHttpClient = buildClient()

    fun clearSession() {
        cookieStore.clear()
        onLog("SESSION TERMINATED", LogType.WARN)
    }

    // ===================== 1. AUTHENTICATION =====================
    suspend fun login(ip: String, username: String, password: String): Boolean =
        withContext(Dispatchers.IO) {
            try {
                val cleanHost = ip.trim()
                    .removePrefix("http://")
                    .removePrefix("https://")
                    .trimEnd('/')
                    .substringBefore("/")
                targetHost = cleanHost.substringBefore(":")
                baseUrl = "https://$cleanHost"
                cookieStore.clear()
                client = buildClient()

                onLog("CONNECT -> $baseUrl (BC TLS 1.0)", LogType.SYS)
                val initHtml = try {
                    client.newCall(Request.Builder().url("$baseUrl/").get().build())
                        .execute().use { it.body?.string() ?: "" }
                } catch (_: Exception) {
                    baseUrl = "http://$cleanHost"
                    onLog("FALLBACK -> $baseUrl", LogType.WARN)
                    client.newCall(Request.Builder().url("$baseUrl/").get().build())
                        .execute().use { it.body?.string() ?: "" }
                }

                if (initHtml.isEmpty()) {
                    onLog("EMPTY ROUTER RESPONSE", LogType.ERR)
                    return@withContext false
                }

                val loginToken = Regex("""Frm_Logintoken["']\)\.value\s*=\s*["'](\d+)["']""")
                    .find(initHtml)?.groupValues?.get(1)
                    ?: Regex("""name=["']Frm_Logintoken["'][^>]*value=["'](\d+)["']""")
                        .find(initHtml)?.groupValues?.get(1)
                    ?: ""

                val form = FormBody.Builder()
                    .add("action", "login")
                    .add("Username", username)
                    .add("Password", password)
                    .add("Frm_Logintoken", loginToken)
                    .add("frashnum", "")
                    .build()

                val respHtml = client.newCall(
                    Request.Builder().url("$baseUrl/").post(form).build()
                ).execute().use { it.body?.string() ?: "" }

                val ok = respHtml.isNotEmpty() &&
                    !respHtml.contains("Frm_Logintoken") &&
                    !respHtml.contains("Password is wrong", ignoreCase = true)

                onLog(
                    if (ok) "AUTH SUCCESS (TOKEN=$loginToken)" else "AUTH REJECTED - CHECK CREDENTIALS",
                    if (ok) LogType.OK else LogType.ERR
                )
                ok
            } catch (e: Exception) {
                onLog("LOGIN ERR: ${e.message}", LogType.ERR)
                false
            }
        }

    // ===================== 2. DSL TELEMETRY (HTML TABLE + JS PARSER) =====================
    suspend fun getDslStats(): DslStats = withContext(Dispatchers.IO) {
        try {
            onLog("FETCH -> status_dsl_info_t.gch", LogType.SYS)
            val html = fetchPage("status_dsl_info_t.gch")
            val rows = parseHtmlTableRows(html)
            val jsMap = parseTransferMeaning(html)
            val rowDebug = rows.map { it.joinToString(" | ") }

            var status = jsMap["LinkStatus"] ?: jsMap["ModulationType"] ?: "Unknown"
            var downRate = jsMap["DownstreamCurrRate"] ?: "--"
            var upRate = jsMap["UpstreamCurrRate"] ?: "--"
            var maxDown = jsMap["DownstreamMaxRate"] ?: "--"
            var maxUp = jsMap["UpstreamMaxRate"] ?: "--"
            var downSnr = formatDb(jsMap["DownstreamNoiseMargin"])
            var upSnr = formatDb(jsMap["UpstreamNoiseMargin"])
            var downAttn = formatDb(jsMap["DownstreamAttenuation"])
            var upAttn = formatDb(jsMap["UpstreamAttenuation"])

            for (cells in rows) {
                if (cells.size < 2) continue
                val label = cells[0].lowercase(Locale.US)
                val v1 = cells[1]
                val v2 = cells.getOrNull(2) ?: ""

                when {
                    label.contains("line status") || label.contains("dsl status") || label == "status" -> {
                        if (v1.isNotBlank()) status = v1
                    }
                    label.contains("modulation") && status == "Unknown" -> {
                        if (v1.isNotBlank()) status = v1
                    }
                    (label.contains("current rate") || label.contains("actual rate") || label.contains("actual data rate")) -> {
                        if (cells.size >= 3) {
                            downRate = cleanNum(v1)
                            upRate = cleanNum(v2)
                        } else if (label.contains("down")) {
                            downRate = cleanNum(v1)
                        } else if (label.contains("up")) {
                            upRate = cleanNum(v1)
                        }
                    }
                    (label.contains("max rate") || label.contains("attainable")) -> {
                        if (cells.size >= 3) {
                            maxDown = cleanNum(v1)
                            maxUp = cleanNum(v2)
                        } else if (label.contains("down")) {
                            maxDown = cleanNum(v1)
                        } else if (label.contains("up")) {
                            maxUp = cleanNum(v1)
                        }
                    }
                    (label.contains("noise margin") || label.contains("snr")) -> {
                        if (cells.size >= 3) {
                            downSnr = formatDb(v1)
                            upSnr = formatDb(v2)
                        } else if (label.contains("down")) {
                            downSnr = formatDb(v1)
                        } else if (label.contains("up")) {
                            upSnr = formatDb(v1)
                        }
                    }
                    label.contains("attenuation") -> {
                        if (cells.size >= 3) {
                            downAttn = formatDb(v1)
                            upAttn = formatDb(v2)
                        } else if (label.contains("down")) {
                            downAttn = formatDb(v1)
                        } else if (label.contains("up")) {
                            upAttn = formatDb(v1)
                        }
                    }
                }
            }

            onLog("DSL PARSED: ${rows.size} TABLE ROWS (DOWN=$downRate, UP=$upRate)", LogType.OK)
            DslStats(
                status = status,
                downRateKbps = downRate,
                upRateKbps = upRate,
                maxDownKbps = maxDown,
                maxUpKbps = maxUp,
                downSnrDb = downSnr,
                upSnrDb = upSnr,
                downAttnDb = downAttn,
                upAttnDb = upAttn,
                rawRows = rowDebug
            )
        } catch (e: Exception) {
            onLog("DSL ERR: ${e.message}", LogType.ERR)
            DslStats()
        }
    }

    // ===================== 3. CONNECTED DEVICES & KICK / BLOCK / UNBLOCK =====================
    suspend fun getConnectedDevices(): List<ConnectedDevice> = withContext(Dispatchers.IO) {
        try {
            onLog("SCAN -> net_dhcp_dynamic_t.gch", LogType.SYS)
            val map = parseTransferMeaning(fetchPage("net_dhcp_dynamic_t.gch"))

            val indices = map.keys
                .mapNotNull {
                    Regex("""^(?:MACAddr|IPAddr)(\d+)$""").find(it)?.groupValues?.get(1)?.toIntOrNull()
                }
                .distinct()
                .sorted()

            val devices = indices.mapNotNull { i ->
                val mac = map["MACAddr$i"].orEmpty().uppercase(Locale.US)
                val ip = map["IPAddr$i"].orEmpty()
                if (mac.isBlank() && ip.isBlank()) return@mapNotNull null
                val rawName = map["HostName$i"].orEmpty().trim()
                val name = if (rawName.isBlank() || rawName == "*" || rawName == "null") "Device ($ip)" else rawName
                ConnectedDevice(
                    hostName = name,
                    ipAddress = ip.ifBlank { "--" },
                    macAddress = mac.ifBlank { "--" },
                    leaseTime = formatLease(map["ExpiredTime$i"])
                )
            }
            onLog("FOUND ${devices.size} DHCP CLIENTS", LogType.OK)
            devices
        } catch (e: Exception) {
            onLog("DHCP ERR: ${e.message}", LogType.ERR)
            emptyList()
        }
    }

    suspend fun getBlockedRules(): List<BlockedRule> = withContext(Dispatchers.IO) {
        try {
            val map = parseTransferMeaning(fetchPage("sec_macfilter_t.gch"))
            val indices = map.keys
                .mapNotNull {
                    Regex("""^SrcMacAddr(\d+)$""").find(it)?.groupValues?.get(1)?.toIntOrNull()
                }
                .distinct()
                .sorted()

            indices.mapNotNull { i ->
                val mac = map["SrcMacAddr$i"].orEmpty().uppercase(Locale.US)
                if (mac.isBlank()) return@mapNotNull null
                BlockedRule(
                    index = i,
                    name = map["Name$i"].orEmpty().ifBlank { "Rule #$i" },
                    macAddress = mac
                )
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    suspend fun blockMacAddress(mac: String, alias: String): Boolean = withContext(Dispatchers.IO) {
        try {
            onLog("BLOCK MAC -> $mac", LogType.ACT)
            val html = fetchPage("sec_macfilter_t.gch")
            val token = extractSessionToken(html) ?: run {
                onLog("MISSING _SESSION_TOKEN", LogType.ERR)
                return@withContext false
            }

            val cleanAlias = alias.replace(Regex("""[^a-zA-Z0-9_-]"""), "").take(14).ifBlank { "Blocked" }
            val overrides = linkedMapOf(
                "IF_ACTION" to "new",
                "IF_ERRORSTR" to "SUCC",
                "IF_ERRORPARAM" to "SUCC",
                "IF_ERRORTYPE" to "-1",
                "Enable" to "1",
                "Name" to cleanAlias,
                "SrcMacAddr" to mac.uppercase(Locale.US),
                "DstMacAddr" to "",
                "_SESSION_TOKEN" to token
            )
            val ok = postForm("sec_macfilter_t.gch", overrides)
            onLog(if (ok) "MAC BLOCKED: $mac" else "MAC BLOCK FAILED", if (ok) LogType.OK else LogType.ERR)
            ok
        } catch (e: Exception) {
            onLog("BLOCK ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    suspend fun unblockRule(index: Int): Boolean = withContext(Dispatchers.IO) {
        try {
            onLog("UNBLOCK RULE #$index", LogType.ACT)
            val html = fetchPage("sec_macfilter_t.gch")
            val token = extractSessionToken(html) ?: return@withContext false

            val overrides = linkedMapOf(
                "IF_ACTION" to "delete",
                "IF_INDEX" to index.toString(),
                "IF_ERRORSTR" to "SUCC",
                "IF_ERRORPARAM" to "SUCC",
                "IF_ERRORTYPE" to "-1",
                "_SESSION_TOKEN" to token
            )
            val ok = postForm("sec_macfilter_t.gch", overrides)
            onLog(if (ok) "RULE #$index REMOVED" else "UNBLOCK FAILED", if (ok) LogType.OK else LogType.ERR)
            ok
        } catch (e: Exception) {
            onLog("UNBLOCK ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    // طرد مؤقت: يقطع اتصال الجهاز 8 ثوانٍ ثم يزيل القاعدة تلقائياً دون حظر دائم
    suspend fun kickDevice(mac: String): Boolean = withContext(Dispatchers.IO) {
        try {
            onLog("KICK START -> $mac (TEMP 8s DROP)", LogType.WARN)
            val added = blockMacAddress(mac, "KickTemp")
            if (!added) return@withContext false

            delay(8000)

            val rules = getBlockedRules()
            val target = rules.lastOrNull {
                it.macAddress.equals(mac, ignoreCase = true) || it.name == "KickTemp"
            }
            return@withContext if (target != null) {
                val removed = unblockRule(target.index)
                onLog(
                    if (removed) "KICK COMPLETE -> DEVICE DROPPED & NOT BANNED" else "TEMP RULE CLEANUP FAILED",
                    if (removed) LogType.OK else LogType.ERR
                )
                removed
            } else {
                onLog("KICK DONE (NO TEMP RULE REMAINING)", LogType.OK)
                true
            }
        } catch (e: Exception) {
            onLog("KICK ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    // ===================== 4. WI-FI PASSWORD, SSID & SPEED CONTROL =====================
    suspend fun getWifiConfig(): WifiConfig = withContext(Dispatchers.IO) {
        try {
            onLog("FETCH -> WLAN SSID / SEC / BASIC", LogType.SYS)
            val ssidMap = parseTransferMeaning(fetchPage("net_wlan_ssid_t.gch"))
            val secMap = parseTransferMeaning(fetchPage("net_wlan_sec_t.gch"))
            val basicMap = parseTransferMeaning(fetchPage("net_wlan_basic_t.gch"))

            val cfg = WifiConfig(
                ssid = ssidMap["ESSID"] ?: ssidMap["ESSID0"] ?: "",
                hidden = (ssidMap["ESSIDHideEnable"] ?: ssidMap["ESSIDHideEnable0"]) == "1",
                password = secMap["KeyPassphrase"] ?: secMap["PreSharedKey"] ?: "",
                standard = basicMap["Standard"] ?: "b,g,n",
                bandWidth = basicMap["BandWidth"] ?: basicMap["ChannelWidth"] ?: "20MHz",
                txPower = basicMap["TxPower"] ?: "100%",
                rawBasicKeys = basicMap
            )
            onLog("WLAN LOADED: SSID=${cfg.ssid}, MODE=${cfg.standard}, BW=${cfg.bandWidth}, TX=${cfg.txPower}", LogType.OK)
            cfg
        } catch (e: Exception) {
            onLog("WLAN FETCH ERR: ${e.message}", LogType.ERR)
            WifiConfig()
        }
    }

    suspend fun updateWifiPassword(newPassword: String): Boolean = withContext(Dispatchers.IO) {
        if (newPassword.length !in 8..63) {
            onLog("PASSWORD MUST BE 8-63 CHARACTERS", LogType.ERR)
            return@withContext false
        }
        try {
            onLog("UPDATING WI-FI PASSWORD -> net_wlan_sec_t.gch", LogType.ACT)
            val html = fetchPage("net_wlan_sec_t.gch")
            val token = extractSessionToken(html) ?: run {
                onLog("MISSING _SESSION_TOKEN ON WLAN SEC", LogType.ERR)
                return@withContext false
            }

            val fields = extractFormFields(html)
            fields["IF_ACTION"] = "apply"
            fields["IF_ERRORSTR"] = "SUCC"
            fields["IF_ERRORPARAM"] = "SUCC"
            fields["IF_ERRORTYPE"] = "-1"
            fields["KeyPassphrase"] = newPassword
            if (fields.containsKey("PreSharedKey")) fields["PreSharedKey"] = newPassword
            fields["_SESSION_TOKEN"] = token

            val ok = postForm("net_wlan_sec_t.gch", fields)
            onLog(if (ok) "WI-FI PASSWORD UPDATED" else "PASSWORD UPDATE FAILED", if (ok) LogType.OK else LogType.ERR)
            ok
        } catch (e: Exception) {
            onLog("WIFI PASS ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    suspend fun updateWifiSsid(newSsid: String, hideSsid: Boolean): Boolean = withContext(Dispatchers.IO) {
        if (newSsid.isBlank()) {
            onLog("SSID CANNOT BE EMPTY", LogType.ERR)
            return@withContext false
        }
        try {
            onLog("UPDATING SSID ($newSsid, HIDE=$hideSsid) -> net_wlan_ssid_t.gch", LogType.ACT)
            val html = fetchPage("net_wlan_ssid_t.gch")
            val token = extractSessionToken(html) ?: run {
                onLog("MISSING _SESSION_TOKEN ON WLAN SSID", LogType.ERR)
                return@withContext false
            }

            val fields = extractFormFields(html)
            fields["IF_ACTION"] = "apply"
            fields["IF_ERRORSTR"] = "SUCC"
            fields["IF_ERRORPARAM"] = "SUCC"
            fields["IF_ERRORTYPE"] = "-1"
            fields["ESSID"] = newSsid.trim()
            fields["ESSIDHideEnable"] = if (hideSsid) "1" else "0"
            fields["_SESSION_TOKEN"] = token

            val ok = postForm("net_wlan_ssid_t.gch", fields)
            onLog(if (ok) "SSID SETTINGS SAVED" else "SSID UPDATE FAILED", if (ok) LogType.OK else LogType.ERR)
            ok
        } catch (e: Exception) {
            onLog("SSID ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    suspend fun applySpeedPreset(preset: SpeedPreset, customTxPower: String? = null): Boolean =
        withContext(Dispatchers.IO) {
            try {
                val tx = customTxPower ?: preset.txPower
                onLog("SPEED PRESET [${preset.title}] -> MODE=${preset.standard}, BW=${preset.bandWidth}, TX=$tx", LogType.ACT)
                val html = fetchPage("net_wlan_basic_t.gch")
                val token = extractSessionToken(html) ?: run {
                    onLog("MISSING _SESSION_TOKEN ON WLAN BASIC", LogType.ERR)
                    return@withContext false
                }

                val fields = extractFormFields(html)
                fields["IF_ACTION"] = "apply"
                fields["IF_ERRORSTR"] = "SUCC"
                fields["IF_ERRORPARAM"] = "SUCC"
                fields["IF_ERRORTYPE"] = "-1"
                fields["Standard"] = preset.standard
                if (fields.containsKey("BandWidth")) fields["BandWidth"] = preset.bandWidth
                if (fields.containsKey("ChannelWidth")) fields["ChannelWidth"] = preset.bandWidth
                if (fields.containsKey("TxPower")) fields["TxPower"] = tx
                if (fields.containsKey("DataRate")) fields["DataRate"] = preset.dataRate
                if (fields.containsKey("BasicDataRates")) fields["BasicDataRates"] = preset.dataRate
                fields["_SESSION_TOKEN"] = token

                val ok = postForm("net_wlan_basic_t.gch", fields)
                onLog(
                    if (ok) "SPEED PROFILE APPLIED (${preset.title})" else "SPEED PROFILE FAILED",
                    if (ok) LogType.OK else LogType.ERR
                )
                ok
            } catch (e: Exception) {
                onLog("SPEED ERR: ${e.message}", LogType.ERR)
                false
            }
        }

    // ===================== 5. REBOOT =====================
    suspend fun rebootRouter(): Boolean = withContext(Dispatchers.IO) {
        try {
            onLog("REBOOT -> manager_dev_conf_t.gch", LogType.WARN)
            val html = fetchPage("manager_dev_conf_t.gch")
            val token = extractSessionToken(html) ?: run {
                onLog("MISSING _SESSION_TOKEN ON REBOOT", LogType.ERR)
                return@withContext false
            }

            val fields = linkedMapOf(
                "IF_ACTION" to "devrestart",
                "IF_ERRORSTR" to "SUCC",
                "IF_ERRORPARAM" to "SUCC",
                "IF_ERRORTYPE" to "-1",
                "flag" to "1",
                "_SESSION_TOKEN" to token
            )
            val ok = postForm("manager_dev_conf_t.gch", fields)
            onLog(if (ok) "REBOOT TRANSMITTED" else "REBOOT FAILED", if (ok) LogType.OK else LogType.ERR)
            ok
        } catch (e: Exception) {
            onLog("REBOOT ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    // ===================== INTERNAL HELPERS =====================
    private fun fetchPage(nextPage: String): String {
        val req = Request.Builder()
            .url("$baseUrl/getpage.gch?pid=1002&nextpage=$nextPage")
            .get()
            .build()
        return client.newCall(req).execute().use { it.body?.string() ?: "" }
    }

    private fun postForm(nextPage: String, fields: Map<String, String>): Boolean {
        val form = FormBody.Builder().apply {
            fields.forEach { (k, v) -> add(k, v) }
        }.build()

        val req = Request.Builder()
            .url("$baseUrl/getpage.gch?pid=1002&nextpage=$nextPage")
            .post(form)
            .build()

        return client.newCall(req).execute().use { resp ->
            val body = resp.body?.string() ?: ""
            if (!resp.isSuccessful || body.contains("Frm_Logintoken")) return@use false
            val err = parseTransferMeaning(body)["IF_ERRORSTR"]
            err == null || err.equals("SUCC", ignoreCase = true) || err.isBlank()
        }
    }

    private fun extractFormFields(html: String): LinkedHashMap<String, String> {
        val fields = LinkedHashMap<String, String>()
        val inputTagRegex = Regex("""(?is)<input\b[^>]*>""")
        val nameRegex = Regex("""(?i)\bname\s*=\s*["']([^"']+)["']""")
        val valueRegex = Regex("""(?i)\bvalue\s*=\s*["']([^"']*)["']""")

        inputTagRegex.findAll(html).forEach { tag ->
            val t = tag.value
            val name = nameRegex.find(t)?.groupValues?.get(1) ?: return@forEach
            val value = valueRegex.find(t)?.groupValues?.get(1) ?: ""
            fields[name] = unescapeZte(value)
        }

        // تعبئة قيم الحقول الفعلية من Transfer_meaning
        parseTransferMeaning(html).forEach { (k, v) ->
            if (fields.containsKey(k)) fields[k] = v
        }
        return fields
    }

    private fun parseHtmlTableRows(html: String): List<List<String>> {
        val clean = html
            .replace(Regex("""(?is)<script[^>]*>.*?</script>"""), "")
            .replace(Regex("""(?is)<style[^>]*>.*?</style>"""), "")

        val rows = mutableListOf<List<String>>()
        val trRegex = Regex("""(?is)<tr[^>]*>(.*?)</tr>""")
        val cellRegex = Regex("""(?is)<t[dh][^>]*>(.*?)</t[dh]>""")

        trRegex.findAll(clean).forEach { trMatch ->
            val cells = cellRegex.findAll(trMatch.groupValues[1])
                .map { cellMatch ->
                    unescapeZte(cellMatch.groupValues[1].replace(Regex("""<[^>]+>"""), " "))
                        .replace(Regex("""\s+"""), " ")
                        .trim()
                }
                .filter { it.isNotEmpty() }
                .toList()
            if (cells.size >= 2) rows.add(cells)
        }
        return rows
    }

    private fun parseTransferMeaning(html: String): Map<String, String> {
        val result = mutableMapOf<String, String>()
        val pattern = Regex("""Transfer_meaning\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]*)['"]\s*\)""")
        pattern.findAll(html).forEach { m ->
            result[unescapeZte(m.groupValues[1])] = unescapeZte(m.groupValues[2])
        }
        return result
    }

    private fun extractSessionToken(html: String): String? {
        val patterns = listOf(
            Regex("""_SESSION_TOKEN\s*=\s*["']([^"']+)["']"""),
            Regex("""session_token\s*=\s*["']([^"']+)["']"""),
            Regex("""name=["']_SESSION_TOKEN["'][^>]*value=["']([^"']+)["']""")
        )
        for (p in patterns) {
            p.find(html)?.groupValues?.get(1)?.let { return it }
        }
        return null
    }

    private fun unescapeZte(raw: String): String {
        var out = raw
        out = Regex("""\\x([0-9a-fA-F]{2})""").replace(out) { it.groupValues[1].toInt(16).toChar().toString() }
        out = Regex("""\\u([0-9a-fA-F]{4})""").replace(out) { it.groupValues[1].toInt(16).toChar().toString() }
        out = out
            .replace("\\'", "'")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&nbsp;", " ")
        out = Regex("""&#(\d+);""").replace(out) { m ->
            m.groupValues[1].toIntOrNull()?.toChar()?.toString() ?: m.value
        }
        return out.trim()
    }

    private fun cleanNum(raw: String): String {
        val v = raw.trim()
        if (v.isEmpty()) return "--"
        return v.replace(Regex("""\s*kbps$""", RegexOption.IGNORE_CASE), "")
    }

    private fun formatDb(raw: String?): String {
        val v = raw?.trim().orEmpty()
        if (v.isEmpty()) return "--"
        if (v.contains("dB", ignoreCase = true)) return v
        if (v.contains(".")) return "$v dB"
        val num = v.toDoubleOrNull() ?: return v
        return String.format(Locale.US, "%.1f dB", num / 10.0)
    }

    private fun formatLease(raw: String?): String {
        val sec = raw?.toLongOrNull() ?: return raw?.ifBlank { "--" } ?: "--"
        val h = sec / 3600
        val m = (sec % 3600) / 60
        return if (h > 0) "${h}h ${m}m" else "${m}m"
    }
}