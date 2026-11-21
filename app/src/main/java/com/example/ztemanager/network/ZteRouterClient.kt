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

    // بيانات الجلسة لإعادة الدخول التلقائي عند انتهاء المهلة أو رفض صفحة
    private var savedIp: String = ""
    private var savedUser: String = ""
    private var savedPass: String = ""
    private var isRelogging: Boolean = false

    // الصفحات المكتشفة فعلياً من قائمة الراوتر
    private val discoveredPages = linkedSetOf<String>()
    private var wlanBasicPage: String? = null
    private var wlanSsidPage: String? = null
    private var wlanSecPage: String? = null
    private var macFilterPage: String? = null

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
        savedPass = ""
        discoveredPages.clear()
        wlanBasicPage = null
        wlanSsidPage = null
        wlanSecPage = null
        macFilterPage = null
        onLog("SESSION TERMINATED", LogType.WARN)
    }

    // ===================== 1. AUTHENTICATION & AUTO RE-LOGIN =====================
    suspend fun login(ip: String, username: String, password: String): Boolean =
        withContext(Dispatchers.IO) {
            savedIp = ip
            savedUser = username
            savedPass = password
            discoveredPages.clear()
            wlanBasicPage = null
            wlanSsidPage = null
            wlanSecPage = null
            macFilterPage = null
            performLogin(silent = false)
        }

    private fun performLogin(silent: Boolean): Boolean {
        return try {
            val cleanHost = savedIp.trim()
                .removePrefix("http://")
                .removePrefix("https://")
                .trimEnd('/')
                .substringBefore("/")
            targetHost = cleanHost.substringBefore(":")
            baseUrl = "https://$cleanHost"
            cookieStore.clear()
            client = buildClient()

            if (!silent) onLog("CONNECT -> $baseUrl (BC TLS 1.0)", LogType.SYS)
            val initHtml = try {
                client.newCall(Request.Builder().url("$baseUrl/").get().build())
                    .execute().use { it.body?.string() ?: "" }
            } catch (_: Exception) {
                baseUrl = "http://$cleanHost"
                if (!silent) onLog("FALLBACK -> $baseUrl", LogType.WARN)
                client.newCall(Request.Builder().url("$baseUrl/").get().build())
                    .execute().use { it.body?.string() ?: "" }
            }

            if (initHtml.isEmpty()) {
                if (!silent) onLog("EMPTY ROUTER RESPONSE", LogType.ERR)
                return false
            }

            val loginToken = Regex("""Frm_Logintoken["']\)\.value\s*=\s*["'](\d+)["']""")
                .find(initHtml)?.groupValues?.get(1)
                ?: Regex("""name=["']Frm_Logintoken["'][^>]*value=["'](\d+)["']""")
                    .find(initHtml)?.groupValues?.get(1)
                ?: ""

            val form = FormBody.Builder()
                .add("action", "login")
                .add("Username", savedUser)
                .add("Password", savedPass)
                .add("Frm_Logintoken", loginToken)
                .add("frashnum", "")
                .build()

            val respHtml = client.newCall(
                Request.Builder().url("$baseUrl/").post(form).build()
            ).execute().use { it.body?.string() ?: "" }

            val ok = respHtml.isNotEmpty() &&
                !respHtml.contains("Frm_Logintoken") &&
                !respHtml.contains("Password is wrong", ignoreCase = true)

            if (ok) {
                collectMenuPages(respHtml)
                if (!silent) onLog("AUTH SUCCESS (TOKEN=$loginToken)", LogType.OK)
            } else {
                if (!silent) onLog("AUTH REJECTED - CHECK CREDENTIALS", LogType.ERR)
            }
            ok
        } catch (e: Exception) {
            if (!silent) onLog("LOGIN ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    // ===================== 2. DSL TELEMETRY (UP/DOWN + INLINE SCRIPT PARSER) =====================
    suspend fun getDslStats(): DslStats = withContext(Dispatchers.IO) {
        try {
            onLog("FETCH -> status_dsl_info_t.gch", LogType.SYS)
            val html = fetchPage("status_dsl_info_t.gch")
            if (html.isBlank()) return@withContext DslStats()

            val rows = parseHtmlTableRows(html)
            val jsMap = parseTransferMeaning(html)
            val rowDebug = mutableListOf<String>()
            rows.forEach { rowDebug.add(it.joinToString(" | ")) }

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
                val upFirst = label.contains("up") && label.contains("down") &&
                    label.indexOf("up") < label.indexOf("down")

                when {
                    label.contains("link status") || label.contains("line status") || label == "status" -> {
                        if (v1.isNotBlank()) status = v1
                    }
                    label.contains("modulation") && status == "Unknown" -> {
                        if (v1.isNotBlank()) status = v1
                    }
                    label.contains("actual rate") || label.contains("current rate") || label.contains("actual data rate") -> {
                        val pair = extractNumberPair(v1)
                        when {
                            pair != null -> {
                                upRate = if (upFirst) pair.first else pair.second
                                downRate = if (upFirst) pair.second else pair.first
                            }
                            cells.size >= 3 -> {
                                upRate = if (upFirst) cleanNum(v1) else cleanNum(v2)
                                downRate = if (upFirst) cleanNum(v2) else cleanNum(v1)
                            }
                        }
                    }
                    label.contains("attainable") || label.contains("max rate") -> {
                        val pair = extractNumberPair(v1)
                        when {
                            pair != null -> {
                                maxUp = if (upFirst) pair.first else pair.second
                                maxDown = if (upFirst) pair.second else pair.first
                            }
                            cells.size >= 3 -> {
                                maxUp = if (upFirst) cleanNum(v1) else cleanNum(v2)
                                maxDown = if (upFirst) cleanNum(v2) else cleanNum(v1)
                            }
                        }
                    }
                    label.contains("noise margin") || label.contains("snr") -> {
                        val pair = extractNumberPair(v1)
                        if (pair != null) {
                            upSnr = formatDb(if (upFirst) pair.first else pair.second)
                            downSnr = formatDb(if (upFirst) pair.second else pair.first)
                        } else if (cells.size >= 3) {
                            upSnr = formatDb(if (upFirst) v1 else v2)
                            downSnr = formatDb(if (upFirst) v2 else v1)
                        }
                    }
                    label.contains("attenuation") -> {
                        val pair = extractNumberPair(v1)
                        if (pair != null) {
                            upAttn = formatDb(if (upFirst) pair.first else pair.second)
                            downAttn = formatDb(if (upFirst) pair.second else pair.first)
                        } else if (cells.size >= 3) {
                            upAttn = formatDb(if (upFirst) v1 else v2)
                            downAttn = formatDb(if (upFirst) v2 else v1)
                        }
                    }
                }
            }

            // إذا لم تُقرأ قيم SNR أو Attenuation من الجدول، نبحث في أكواد الجافاسكربت للصفحة
            if (downSnr == "--" || downAttn == "--") {
                val jsSnrUp = extractJsVar(html, "UpNoiseMargin", "UpstreamNoiseMargin", "Up_NoiseMargin", "snr_up", "UpSnr")
                val jsSnrDown = extractJsVar(html, "DownNoiseMargin", "DownstreamNoiseMargin", "Down_NoiseMargin", "snr_down", "DownSnr")
                val jsAttnUp = extractJsVar(html, "UpAttenuation", "UpstreamAttenuation", "Up_Attenuation", "attn_up")
                val jsAttnDown = extractJsVar(html, "DownAttenuation", "DownstreamAttenuation", "Down_Attenuation", "attn_down")
                if (upSnr == "--" && jsSnrUp != null) upSnr = formatDb(jsSnrUp)
                if (downSnr == "--" && jsSnrDown != null) downSnr = formatDb(jsSnrDown)
                if (upAttn == "--" && jsAttnUp != null) upAttn = formatDb(jsAttnUp)
                if (downAttn == "--" && jsAttnDown != null) downAttn = formatDb(jsAttnDown)
            }

            // إضافة سطر تشخيصي مختصر عند الحاجة لمعرفة طريقة كتابة SNR في HTML
            if (downSnr == "--") {
                Regex("""(?is)<tr[^>]*>.*?Noise Margin.*?</tr>""")
                    .find(html)?.value
                    ?.replace(Regex("""\s+"""), " ")
                    ?.take(220)
                    ?.let { rowDebug.add("RAW SNR HTML: $it") }
            }

            onLog("DSL OK -> DOWN=$downRate, UP=$upRate, SNR=$downSnr/$upSnr", LogType.OK)
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
            val html = fetchPage("net_dhcp_dynamic_t.gch")
            val map = parseTransferMeaning(html)

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
            val resolved = resolveMacFilterPage() ?: return@withContext emptyList()
            val map = parseTransferMeaning(resolved.second)
            val indices = map.keys
                .mapNotNull {
                    Regex("""^(?:SrcMacAddr|MACAddress|MacAddr)(\d+)$""").find(it)?.groupValues?.get(1)?.toIntOrNull()
                }
                .distinct()
                .sorted()

            indices.mapNotNull { i ->
                val mac = (map["SrcMacAddr$i"] ?: map["MACAddress$i"] ?: map["MacAddr$i"])
                    .orEmpty().uppercase(Locale.US)
                if (mac.isBlank()) return@mapNotNull null
                BlockedRule(
                    index = i,
                    name = (map["Name$i"] ?: map["Description$i"]).orEmpty().ifBlank { "Rule #$i" },
                    macAddress = mac
                )
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    suspend fun blockMacAddress(mac: String, alias: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val resolved = resolveMacFilterPage() ?: run {
                onLog("MAC FILTER PAGE NOT FOUND ON THIS FIRMWARE", LogType.ERR)
                return@withContext false
            }
            val (page, html) = resolved
            onLog("BLOCK MAC ($mac) -> $page", LogType.ACT)

            val cleanAlias = alias.replace(Regex("""[^a-zA-Z0-9_-]"""), "").take(14).ifBlank { "Blocked" }
            val fields = extractFormFields(html)
            fields["IF_ACTION"] = "new"
            fields["IF_ERRORSTR"] = "SUCC"
            fields["IF_ERRORPARAM"] = "SUCC"
            fields["IF_ERRORTYPE"] = "-1"
            fields["Enable"] = "1"
            if (fields.containsKey("Name") || page.contains("macfilter", ignoreCase = true)) {
                fields["Name"] = cleanAlias
            }
            when {
                fields.containsKey("MACAddress") -> fields["MACAddress"] = mac.uppercase(Locale.US)
                fields.containsKey("MacAddr") -> fields["MacAddr"] = mac.uppercase(Locale.US)
                else -> {
                    fields["SrcMacAddr"] = mac.uppercase(Locale.US)
                    fields["DstMacAddr"] = ""
                }
            }
            extractSessionToken(html)?.let { fields["_SESSION_TOKEN"] = it }

            val ok = postForm(page, fields)
            onLog(if (ok) "MAC BLOCKED: $mac" else "MAC BLOCK FAILED", if (ok) LogType.OK else LogType.ERR)
            ok
        } catch (e: Exception) {
            onLog("BLOCK ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    suspend fun unblockRule(index: Int): Boolean = withContext(Dispatchers.IO) {
        try {
            val resolved = resolveMacFilterPage() ?: return@withContext false
            val (page, html) = resolved
            onLog("UNBLOCK RULE #$index -> $page", LogType.ACT)

            val fields = linkedMapOf(
                "IF_ACTION" to "delete",
                "IF_INDEX" to index.toString(),
                "IF_ERRORSTR" to "SUCC",
                "IF_ERRORPARAM" to "SUCC",
                "IF_ERRORTYPE" to "-1"
            )
            extractSessionToken(html)?.let { fields["_SESSION_TOKEN"] = it }

            val ok = postForm(page, fields)
            onLog(if (ok) "RULE #$index REMOVED" else "UNBLOCK FAILED", if (ok) LogType.OK else LogType.ERR)
            ok
        } catch (e: Exception) {
            onLog("UNBLOCK ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    suspend fun kickDevice(mac: String): Boolean = withContext(Dispatchers.IO) {
        try {
            onLog("KICK START -> $mac (TEMP 8s DROP)", LogType.WARN)
            if (!blockMacAddress(mac, "KickTemp")) return@withContext false

            delay(8000)

            val rules = getBlockedRules()
            val target = rules.lastOrNull {
                it.macAddress.equals(mac, ignoreCase = true) || it.name == "KickTemp"
            }
            return@withContext if (target != null) {
                val removed = unblockRule(target.index)
                onLog(
                    if (removed) "KICK COMPLETE -> DROPPED & NOT BANNED" else "CLEANUP FAILED",
                    if (removed) LogType.OK else LogType.ERR
                )
                removed
            } else {
                onLog("KICK DONE", LogType.OK)
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
            ensureMenuDiscovered()
            onLog("FETCH -> WLAN CONFIG", LogType.SYS)

            val ssidRes = resolveWlanSsidPage()
            val secRes = resolveWlanSecPage()
            val basicRes = resolveWlanBasicPage()

            val ssidMap = ssidRes?.second?.let { parseTransferMeaning(it) } ?: emptyMap()
            val secMap = secRes?.second?.let { parseTransferMeaning(it) } ?: emptyMap()
            val basicMap = basicRes?.second?.let { parseTransferMeaning(it) } ?: emptyMap()

            val debugMap = linkedMapOf<String, String>()
            debugMap["_SSID_PAGE"] = ssidRes?.first ?: "NOT_FOUND"
            debugMap["_SEC_PAGE"] = secRes?.first ?: "NOT_FOUND"
            debugMap["_BASIC_PAGE"] = basicRes?.first ?: "NOT_FOUND"
            debugMap["_MAC_PAGE"] = macFilterPage ?: "PENDING"
            val wlanDiscovered = discoveredPages.filter {
                it.contains("wlan", ignoreCase = true) ||
                    it.contains("mac", ignoreCase = true) ||
                    it.contains("acl", ignoreCase = true)
            }
            if (wlanDiscovered.isNotEmpty()) {
                debugMap["_MENU_PAGES"] = wlanDiscovered.joinToString(", ")
            }
            basicMap.forEach { (k, v) -> debugMap[k] = v }

            val cfg = WifiConfig(
                ssid = ssidMap["ESSID"] ?: ssidMap["ESSID0"] ?: basicMap["ESSID"] ?: "",
                hidden = (ssidMap["ESSIDHideEnable"] ?: ssidMap["ESSIDHideEnable0"]) == "1",
                password = secMap["KeyPassphrase"] ?: secMap["PreSharedKey"] ?: secMap["KeyPassphrase0"] ?: "",
                standard = basicMap["Standard"] ?: "b,g,n",
                bandWidth = basicMap["BandWidth"] ?: basicMap["ChannelWidth"] ?: "20MHz",
                txPower = basicMap["TxPower"] ?: "100%",
                rawBasicKeys = debugMap
            )
            onLog(
                "WLAN -> SSID=${cfg.ssid.ifBlank { "--" }}, MODE=${cfg.standard}, BW=${cfg.bandWidth}, TX=${cfg.txPower}",
                LogType.OK
            )
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
            val resolved = resolveWlanSecPage() ?: run {
                onLog("WLAN SECURITY PAGE NOT FOUND", LogType.ERR)
                return@withContext false
            }
            val (page, html) = resolved
            onLog("UPDATING PASSWORD -> $page", LogType.ACT)

            val fields = extractFormFields(html)
            fields["IF_ACTION"] = "apply"
            fields["IF_ERRORSTR"] = "SUCC"
            fields["IF_ERRORPARAM"] = "SUCC"
            fields["IF_ERRORTYPE"] = "-1"
            fields["KeyPassphrase"] = newPassword
            if (fields.containsKey("PreSharedKey")) fields["PreSharedKey"] = newPassword
            extractSessionToken(html)?.let { fields["_SESSION_TOKEN"] = it }

            val ok = postForm(page, fields)
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
            val resolved = resolveWlanSsidPage() ?: run {
                onLog("WLAN SSID PAGE NOT FOUND", LogType.ERR)
                return@withContext false
            }
            val (page, html) = resolved
            onLog("UPDATING SSID ($newSsid, HIDE=$hideSsid) -> $page", LogType.ACT)

            val fields = extractFormFields(html)
            fields["IF_ACTION"] = "apply"
            fields["IF_ERRORSTR"] = "SUCC"
            fields["IF_ERRORPARAM"] = "SUCC"
            fields["IF_ERRORTYPE"] = "-1"
            fields["ESSID"] = newSsid.trim()
            fields["ESSIDHideEnable"] = if (hideSsid) "1" else "0"
            extractSessionToken(html)?.let { fields["_SESSION_TOKEN"] = it }

            val ok = postForm(page, fields)
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
                val resolved = resolveWlanBasicPage() ?: run {
                    onLog("WLAN BASIC PAGE NOT FOUND (TAP WLAN KEYS)", LogType.ERR)
                    return@withContext false
                }
                val (page, html) = resolved
                val tx = customTxPower ?: preset.txPower
                onLog("SPEED [${preset.title}] -> $page (MODE=${preset.standard}, BW=${preset.bandWidth}, TX=$tx)", LogType.ACT)

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
                extractSessionToken(html)?.let { fields["_SESSION_TOKEN"] = it }

                val ok = postForm(page, fields)
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
            val page = discoveredPages.firstOrNull {
                it.contains("dev_conf", ignoreCase = true) || it.contains("restart", ignoreCase = true)
            } ?: "manager_dev_conf_t.gch"
            onLog("REBOOT -> $page", LogType.WARN)
            val html = fetchPage(page)
            if (html.isBlank()) {
                onLog("REBOOT PAGE UNAVAILABLE", LogType.ERR)
                return@withContext false
            }

            val fields = linkedMapOf(
                "IF_ACTION" to "devrestart",
                "IF_ERRORSTR" to "SUCC",
                "IF_ERRORPARAM" to "SUCC",
                "IF_ERRORTYPE" to "-1",
                "flag" to "1"
            )
            extractSessionToken(html)?.let { fields["_SESSION_TOKEN"] = it }

            val ok = postForm(page, fields)
            onLog(if (ok) "REBOOT TRANSMITTED" else "REBOOT FAILED", if (ok) LogType.OK else LogType.ERR)
            ok
        } catch (e: Exception) {
            onLog("REBOOT ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    // ===================== MENU & PAGE RESOLUTION =====================
    private fun ensureMenuDiscovered() {
        if (discoveredPages.any { it.contains("wlan", ignoreCase = true) && it.startsWith("net_", ignoreCase = true) }) {
            return
        }
        // قراءة القائمة الجانبية من صفحات نعلم يقيناً أنها موجودة في H108N V2.5
        listOf("status_wlan_info_t.gch", "IPv46_net_wan_conf_t.gch", "sec_firewall_conf_t.gch").forEach { seed ->
            val html = fetchPage(seed)
            if (html.isNotBlank()) collectMenuPages(html)
        }
    }

    private fun resolveWlanBasicPage(): Pair<String, String>? {
        val candidates = buildList {
            wlanBasicPage?.let { add(it) }
            addAll(discoveredPages.filter {
                it.contains("wlan", ignoreCase = true) &&
                    (it.contains("basic", ignoreCase = true) || it.contains("conf", ignoreCase = true))
            })
            addAll(listOf("net_wlan_conf1_t.gch", "net_wlan_basic_t.gch", "net_wlan_basic_11n_t.gch"))
        }.distinct()

        for (page in candidates) {
            val html = fetchPage(page)
            if (html.isNotBlank() && (html.contains("Standard") || html.contains("TxPower") || html.contains("Channel"))) {
                wlanBasicPage = page
                return page to html
            }
        }
        return null
    }

    private fun resolveWlanSsidPage(): Pair<String, String>? {
        val candidates = buildList {
            wlanSsidPage?.let { add(it) }
            addAll(discoveredPages.filter {
                it.contains("wlan", ignoreCase = true) && it.contains("ssid", ignoreCase = true)
            })
            addAll(listOf("net_wlan_multi_ssid_t.gch", "net_wlan_ssid_t.gch", "net_wlan_conf1_t.gch"))
        }.distinct()

        for (page in candidates) {
            val html = fetchPage(page)
            if (html.isNotBlank() && (html.contains("ESSID") || html.contains("SSID"))) {
                wlanSsidPage = page
                return page to html
            }
        }
        return null
    }

    private fun resolveWlanSecPage(): Pair<String, String>? {
        val candidates = buildList {
            wlanSecPage?.let { add(it) }
            addAll(discoveredPages.filter {
                it.contains("wlan", ignoreCase = true) && it.contains("sec", ignoreCase = true)
            })
            addAll(listOf("net_wlan_sec_t.gch", "net_wlan_security_t.gch", "net_wlan_sec_11n_t.gch"))
        }.distinct()

        for (page in candidates) {
            val html = fetchPage(page)
            if (html.isNotBlank() && (html.contains("KeyPassphrase") || html.contains("PreSharedKey") || html.contains("BeaconType"))) {
                wlanSecPage = page
                return page to html
            }
        }
        return null
    }

    private fun resolveMacFilterPage(): Pair<String, String>? {
        ensureMenuDiscovered()
        val candidates = buildList {
            macFilterPage?.let { add(it) }
            addAll(discoveredPages.filter {
                it.contains("macfilter", ignoreCase = true) ||
                    it.contains("mac_filter", ignoreCase = true) ||
                    it.contains("acl", ignoreCase = true)
            })
            addAll(listOf("net_wlan_acl_t.gch", "sec_macfilter_t.gch", "sec_mac_filter_t.gch"))
        }.distinct()

        for (page in candidates) {
            val html = fetchPage(page)
            if (html.isNotBlank() && (html.contains("MacAddr", ignoreCase = true) || html.contains("MACAddress", ignoreCase = true) || html.contains("ACL", ignoreCase = true))) {
                macFilterPage = page
                return page to html
            }
        }
        return null
    }

    private fun collectMenuPages(html: String) {
        val ignored = setOf("getpage.gch", "template.gch", "start.gch", "login.gch", "index.gch", "top.gch")
        Regex("""([a-zA-Z0-9_]+\.gch)""").findAll(html).forEach { m ->
            val p = m.groupValues[1]
            if (p.lowercase(Locale.US) !in ignored) discoveredPages.add(p)
        }
    }

    // ===================== SESSION-GUARDED HTTP HELPERS =====================
    private fun fetchPage(nextPage: String, allowRelogin: Boolean = true): String {
        val body = rawGetPage(nextPage)
        if (!isSessionInvalid(body)) {
            collectMenuPages(body)
            return body
        }

        if (allowRelogin && !isRelogging && savedPass.isNotEmpty()) {
            isRelogging = true
            try {
                onLog("SESSION RESET ON $nextPage -> AUTO RE-LOGIN", LogType.WARN)
                if (performLogin(silent = true)) {
                    val retry = rawGetPage(nextPage)
                    if (!isSessionInvalid(retry)) {
                        collectMenuPages(retry)
                        return retry
                    }
                    // الصفحة غير مدعومة في هذا الراوتر وأسقطت الجلسة، نعيد الجلسة للطلبات التالية
                    onLog("PAGE NOT SUPPORTED: $nextPage (RESTORING SESSION)", LogType.WARN)
                    performLogin(silent = true)
                }
            } finally {
                isRelogging = false
            }
        }
        return ""
    }

    private fun rawGetPage(nextPage: String): String {
        return try {
            val req = Request.Builder()
                .url("$baseUrl/getpage.gch?pid=1002&nextpage=$nextPage")
                .header("Referer", "$baseUrl/template.gch")
                .get()
                .build()
            client.newCall(req).execute().use { it.body?.string() ?: "" }
        } catch (_: Exception) {
            ""
        }
    }

    private fun postForm(nextPage: String, fields: Map<String, String>): Boolean {
        val form = FormBody.Builder().apply {
            fields.forEach { (k, v) -> add(k, v) }
        }.build()

        val req = Request.Builder()
            .url("$baseUrl/getpage.gch?pid=1002&nextpage=$nextPage")
            .header("Referer", "$baseUrl/getpage.gch?pid=1002&nextpage=$nextPage")
            .post(form)
            .build()

        return client.newCall(req).execute().use { resp ->
            val body = resp.body?.string() ?: ""
            if (!resp.isSuccessful || isSessionInvalid(body)) {
                if (savedPass.isNotEmpty() && !isRelogging) {
                    isRelogging = true
                    try { performLogin(silent = true) } finally { isRelogging = false }
                }
                return@use false
            }
            val err = parseTransferMeaning(body)["IF_ERRORSTR"]
            err == null || err.equals("SUCC", ignoreCase = true) || err.isBlank()
        }
    }

    private fun isSessionInvalid(html: String): Boolean {
        if (html.isBlank()) return true
        if (html.contains("Frm_Logintoken") || html.contains("Frm_Username")) return true
        if (html.length < 1500 && (
                html.contains("top.location", ignoreCase = true) ||
                    html.contains("Session timeout", ignoreCase = true)
                )
        ) return true
        return false
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

        parseTransferMeaning(html).forEach { (k, v) ->
            if (fields.containsKey(k)) fields[k] = v
        }
        return fields
    }

    // ===================== HTML & SCRIPT PARSERS =====================
    private fun parseHtmlTableRows(html: String): List<List<String>> {
        val noStyle = html.replace(Regex("""(?is)<style[^>]*>.*?</style>"""), "")
        val rows = mutableListOf<List<String>>()
        val trRegex = Regex("""(?is)<tr[^>]*>(.*?)</tr>""")
        val cellRegex = Regex("""(?is)<t[dh][^>]*>(.*?)</t[dh]>""")

        trRegex.findAll(noStyle).forEach { trMatch ->
            val cells = cellRegex.findAll(trMatch.groupValues[1])
                .map { cellMatch -> parseCellKeepingInlineScripts(cellMatch.groupValues[1]) }
                .filter { it.isNotEmpty() }
                .toList()
            if (cells.size >= 2) rows.add(cells)
        }
        return rows
    }

    private fun parseCellKeepingInlineScripts(cellHtml: String): String {
        val resolved = Regex("""(?is)<script[^>]*>(.*?)</script>""").replace(cellHtml) { match ->
            val script = match.groupValues[1]
            // استخراج عمليات القسمة على 10 مثل parseInt("124")/10 أو 124/10
            val divMatch = Regex("""['"]?(-?\d+(?:\.\d+)?)['"]?\s*\)\s*/\s*10|(-?\d+(?:\.\d+)?)\s*/\s*10""").find(script)
            if (divMatch != null) {
                val rawNum = (divMatch.groupValues[1].ifEmpty { divMatch.groupValues[2] }).toDoubleOrNull()
                if (rawNum != null) return@replace String.format(Locale.US, "%.1f", rawNum / 10.0)
            }
            // استخراج النصوص المكتوبة عبر document.write("...")
            val writeMatch = Regex("""document\.write\(\s*['"]([^'"]+)['"]\s*\)""").find(script)
            if (writeMatch != null) return@replace writeMatch.groupValues[1]
            ""
        }
        return unescapeZte(resolved.replace(Regex("""<[^>]+>"""), " "))
            .replace(Regex("""\s+"""), " ")
            .trim()
    }

    private fun extractNumberPair(text: String): Pair<String, String>? {
        val m = Regex("""(-?\d+(?:\.\d+)?)\s*/\s*(-?\d+(?:\.\d+)?)""").find(text) ?: return null
        return m.groupValues[1] to m.groupValues[2]
    }

    private fun extractJsVar(html: String, vararg names: String): String? {
        for (name in names) {
            val r = Regex("""(?i)\b$name\b\s*=\s*['"]?(-?\d+(?:\.\d+)?)['"]?""")
            r.find(html)?.groupValues?.get(1)?.let { return it }
        }
        return null
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
            Regex("""name=["']_SESSION_TOKEN["'][^>]*value=["']([^"']+)["']"""),
            Regex("""Transfer_meaning\(\s*['"]_SESSION_TOKEN['"]\s*,\s*['"]([^'"]+)['"]\s*\)""")
        )
        for (p in patterns) {
            p.find(html)?.groupValues?.get(1)?.let { if (it.isNotBlank()) return it }
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
        return if (num > 50.0) String.format(Locale.US, "%.1f dB", num / 10.0) else "$v dB"
    }

    private fun formatLease(raw: String?): String {
        val sec = raw?.toLongOrNull() ?: return raw?.ifBlank { "--" } ?: "--"
        val h = sec / 3600
        val m = (sec % 3600) / 60
        return if (h > 0) "${h}h ${m}m" else "${m}m"
    }
}