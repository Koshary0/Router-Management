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
    companion object {
        // المسارات الفعلية المستخرجة من قائمة ZXHN H108N V2.5
        private const val PAGE_DSL = "status_dsl_info_t.gch"
        private const val PAGE_DHCP = "net_dhcp_dynamic_t.gch"
        private const val PAGE_WLAN_BASIC = "net_11n_conf_t.gch"
        private const val PAGE_WLAN_SSID = "net_wlan_essid_t.gch"
        private const val PAGE_WLAN_SEC = "net_wlan_secrity_t.gch"
        private const val PAGE_WLAN_MAC_FILTER = "net_wlan_MacFilter_t.gch"
        private const val PAGE_WLAN_ASSOC = "net_wlan_assoc_t.gch"
        private const val PAGE_REBOOT = "manager_dev_conf_t.gch"
    }

    private val cookieStore = mutableMapOf<String, MutableList<Cookie>>()
    private var baseUrl: String = "https://192.168.1.1"
    private var targetHost: String = "192.168.1.1"

    private var savedIp: String = ""
    private var savedUser: String = ""
    private var savedPass: String = ""
    private var isRelogging: Boolean = false

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
        onLog("SESSION TERMINATED", LogType.WARN)
    }

    // ===================== 1. AUTHENTICATION & AUTO RE-LOGIN =====================
    suspend fun login(ip: String, username: String, password: String): Boolean =
        withContext(Dispatchers.IO) {
            savedIp = ip
            savedUser = username
            savedPass = password
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

            if (!silent) {
                onLog(
                    if (ok) "AUTH SUCCESS (TOKEN=$loginToken)" else "AUTH REJECTED - CHECK CREDENTIALS",
                    if (ok) LogType.OK else LogType.ERR
                )
            }
            ok
        } catch (e: Exception) {
            if (!silent) onLog("LOGIN ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    // ===================== 2. DSL TELEMETRY (TABLE + HIDDEN INPUTS / 10) =====================
    suspend fun getDslStats(): DslStats = withContext(Dispatchers.IO) {
        try {
            onLog("FETCH -> $PAGE_DSL", LogType.SYS)
            val html = fetchPage(PAGE_DSL)
            if (html.isBlank()) return@withContext DslStats()

            val rows = parseHtmlTableRows(html)
            val hiddenInputs = extractFormFields(html)

            var status = "Unknown"
            var downRate = "--"
            var upRate = "--"
            var maxDown = "--"
            var maxUp = "--"

            // قراءة قيم SNR والتوهين من الحقول المخفية وقسمتها على 10 مثل pageGetValues() في الراوتر
            val upSnr = formatTenthsDb(hiddenInputs["Upstream_noise_margin"])
            val downSnr = formatTenthsDb(hiddenInputs["Downstream_noise_margin"])
            val upAttn = formatTenthsDb(hiddenInputs["Upstream_attenuation"])
            val downAttn = formatTenthsDb(hiddenInputs["Downstream_attenuation"])

            for (cells in rows) {
                if (cells.size < 2) continue
                val label = cells[0].lowercase(Locale.US)
                val v1 = cells[1]
                when {
                    label.contains("link status") -> status = v1
                    label.contains("actual rate") -> {
                        extractNumberPair(v1)?.let { (up, down) ->
                            upRate = up
                            downRate = down
                        }
                    }
                    label.contains("attainable rate") -> {
                        extractNumberPair(v1)?.let { (up, down) ->
                            maxUp = up
                            maxDown = down
                        }
                    }
                }
            }

            val debugRows = buildList {
                rows.forEach { add(it.joinToString(" | ")) }
                add("SNR (Down/Up): $downSnr / $upSnr")
                add("ATTN (Down/Up): $downAttn / $upAttn")
                hiddenInputs["Downstream_power"]?.let { p ->
                    add("POWER (Down/Up): ${formatTenthsUnit(p, "dBm")} / ${formatTenthsUnit(hiddenInputs["Upstream_power"], "dBm")}")
                }
            }

            onLog("DSL OK -> DOWN=$downRate, UP=$upRate, SNR=$downSnr/$upSnr, ATTN=$downAttn", LogType.OK)
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
                rawRows = debugRows
            )
        } catch (e: Exception) {
            onLog("DSL ERR: ${e.message}", LogType.ERR)
            DslStats()
        }
    }

    // ===================== 3. CONNECTED DEVICES & KICK / BLOCK / UNBLOCK =====================
    suspend fun getConnectedDevices(): List<ConnectedDevice> = withContext(Dispatchers.IO) {
        try {
            onLog("SCAN -> $PAGE_DHCP", LogType.SYS)
            var html = fetchPage(PAGE_DHCP)
            var map = parseTransferMeaning(html)

            // إذا لم تظهر علامة IF_INSTNUM، نعيد تسجيل الدخول مرة واحدة تلقائياً
            if (!map.containsKey("IF_INSTNUM") && savedPass.isNotEmpty()) {
                onLog("STALE DHCP RESPONSE -> RE-LOGIN & RETRY", LogType.WARN)
                if (performLogin(silent = true)) {
                    html = rawGetPage(PAGE_DHCP)
                    map = parseTransferMeaning(html)
                }
            }

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
            val html = fetchPage(PAGE_WLAN_MAC_FILTER)
            if (html.isBlank()) return@withContext emptyList()
            val map = parseTransferMeaning(html)
            val indices = map.keys
                .mapNotNull {
                    Regex("""^(?:MACAddress|SrcMacAddr|MacAddr)(\d+)$""").find(it)?.groupValues?.get(1)?.toIntOrNull()
                }
                .distinct()
                .sorted()

            indices.mapNotNull { i ->
                val mac = (map["MACAddress$i"] ?: map["SrcMacAddr$i"] ?: map["MacAddr$i"])
                    .orEmpty().uppercase(Locale.US)
                if (mac.isBlank()) return@mapNotNull null
                BlockedRule(
                    index = i,
                    name = (map["Name$i"] ?: map["Description$i"] ?: map["SSIDName$i"]).orEmpty().ifBlank { "ACL #$i" },
                    macAddress = mac
                )
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    suspend fun blockMacAddress(mac: String, alias: String): Boolean = withContext(Dispatchers.IO) {
        try {
            onLog("BLOCK MAC ($mac) -> $PAGE_WLAN_MAC_FILTER", LogType.ACT)
            val html = fetchPage(PAGE_WLAN_MAC_FILTER)
            val token = extractSessionToken(html)
            if (html.isBlank() || token == null) {
                onLog("CANNOT LOAD $PAGE_WLAN_MAC_FILTER OR TOKEN", LogType.ERR)
                return@withContext false
            }

            // أولاً: تفعيل وضع الحظر (Discard / Block) إذا كان ACL Policy متاحاً ومعطلاً
            val initFields = extractFormFields(html)
            val policyKey = listOf("ACLPolicy", "Policy", "Mode").firstOrNull { initFields.containsKey(it) }
            if (policyKey != null && initFields[policyKey] != "Discard" && initFields[policyKey] != "2") {
                val policyForm = LinkedHashMap(initFields)
                policyForm["IF_ACTION"] = "apply"
                policyForm["IF_ERRORSTR"] = "SUCC"
                policyForm["IF_ERRORPARAM"] = "SUCC"
                policyForm["IF_ERRORTYPE"] = "-1"
                policyForm[policyKey] = if (html.contains("Discard")) "Discard" else "2"
                policyForm["_SESSION_TOKEN"] = token
                postForm(PAGE_WLAN_MAC_FILTER, policyForm)
            }

            // جلب توكن جديد لإضافة عنوان الـ MAC
            val freshHtml = fetchPage(PAGE_WLAN_MAC_FILTER)
            val freshToken = extractSessionToken(freshHtml) ?: token
            val fields = extractFormFields(freshHtml)
            val cleanAlias = alias.replace(Regex("""[^a-zA-Z0-9_-]"""), "").take(14).ifBlank { "Blocked" }

            fields["IF_ACTION"] = "new"
            fields["IF_ERRORSTR"] = "SUCC"
            fields["IF_ERRORPARAM"] = "SUCC"
            fields["IF_ERRORTYPE"] = "-1"
            if (fields.containsKey("Enable")) fields["Enable"] = "1"
            if (fields.containsKey("Name")) fields["Name"] = cleanAlias
            when {
                fields.containsKey("MACAddress") -> fields["MACAddress"] = mac.uppercase(Locale.US)
                fields.containsKey("MacAddr") -> fields["MacAddr"] = mac.uppercase(Locale.US)
                else -> {
                    fields["SrcMacAddr"] = mac.uppercase(Locale.US)
                    if (fields.containsKey("DstMacAddr")) fields["DstMacAddr"] = ""
                }
            }
            fields["_SESSION_TOKEN"] = freshToken

            val ok = postForm(PAGE_WLAN_MAC_FILTER, fields)
            onLog(if (ok) "MAC BLOCKED: $mac" else "MAC BLOCK FAILED", if (ok) LogType.OK else LogType.ERR)
            ok
        } catch (e: Exception) {
            onLog("BLOCK ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    suspend fun unblockRule(index: Int): Boolean = withContext(Dispatchers.IO) {
        try {
            onLog("UNBLOCK RULE #$index -> $PAGE_WLAN_MAC_FILTER", LogType.ACT)
            val html = fetchPage(PAGE_WLAN_MAC_FILTER)
            val token = extractSessionToken(html) ?: return@withContext false

            val fields = extractFormFields(html)
            fields["IF_ACTION"] = "delete"
            fields["IF_INDEX"] = index.toString()
            fields["IF_ERRORSTR"] = "SUCC"
            fields["IF_ERRORPARAM"] = "SUCC"
            fields["IF_ERRORTYPE"] = "-1"
            fields["_SESSION_TOKEN"] = token

            val ok = postForm(PAGE_WLAN_MAC_FILTER, fields)
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
            onLog("FETCH -> $PAGE_WLAN_SSID / $PAGE_WLAN_SEC / $PAGE_WLAN_BASIC", LogType.SYS)
            val ssidMap = parseTransferMeaning(fetchPage(PAGE_WLAN_SSID))
            val secMap = parseTransferMeaning(fetchPage(PAGE_WLAN_SEC))
            val basicMap = parseTransferMeaning(fetchPage(PAGE_WLAN_BASIC))

            val debugMap = linkedMapOf<String, String>()
            basicMap.forEach { (k, v) -> debugMap["BASIC.$k"] = v }
            ssidMap.entries.take(15).forEach { (k, v) -> debugMap["SSID.$k"] = v }
            secMap.entries.filterNot { it.key.contains("Key", ignoreCase = true) || it.key.contains("Pass", ignoreCase = true) }
                .take(15).forEach { (k, v) -> debugMap["SEC.$k"] = v }

            val cfg = WifiConfig(
                ssid = ssidMap["ESSID0"] ?: ssidMap["ESSID"] ?: "",
                hidden = (ssidMap["ESSIDHideEnable0"] ?: ssidMap["ESSIDHideEnable"]) == "1",
                password = secMap["KeyPassphrase0"] ?: secMap["KeyPassphrase"] ?: secMap["PreSharedKey0"] ?: secMap["PreSharedKey"] ?: "",
                standard = basicMap["Standard"] ?: basicMap["Mode"] ?: "b,g,n",
                bandWidth = basicMap["BandWidth"] ?: basicMap["ChannelWidth"] ?: "20MHz",
                txPower = basicMap["TxPower"] ?: "100%",
                rawBasicKeys = debugMap
            )
            onLog(
                "WLAN OK -> SSID=${cfg.ssid.ifBlank { "--" }}, MODE=${cfg.standard}, BW=${cfg.bandWidth}, TX=${cfg.txPower}",
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
            onLog("UPDATE PASSWORD -> $PAGE_WLAN_SEC", LogType.ACT)
            val html = fetchPage(PAGE_WLAN_SEC)
            val token = extractSessionToken(html) ?: run {
                onLog("MISSING TOKEN ON $PAGE_WLAN_SEC", LogType.ERR)
                return@withContext false
            }

            val fields = extractFormFields(html)
            fields["IF_ACTION"] = "apply"
            fields["IF_ERRORSTR"] = "SUCC"
            fields["IF_ERRORPARAM"] = "SUCC"
            fields["IF_ERRORTYPE"] = "-1"
            if (fields.containsKey("KeyPassphrase")) fields["KeyPassphrase"] = newPassword
            if (fields.containsKey("KeyPassphrase0")) fields["KeyPassphrase0"] = newPassword
            if (fields.containsKey("PreSharedKey")) fields["PreSharedKey"] = newPassword
            if (!fields.containsKey("KeyPassphrase") && !fields.containsKey("KeyPassphrase0")) {
                fields["KeyPassphrase"] = newPassword
            }
            fields["_SESSION_TOKEN"] = token

            val ok = postForm(PAGE_WLAN_SEC, fields)
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
            onLog("UPDATE SSID ($newSsid, HIDE=$hideSsid) -> $PAGE_WLAN_SSID", LogType.ACT)
            val html = fetchPage(PAGE_WLAN_SSID)
            val token = extractSessionToken(html) ?: run {
                onLog("MISSING TOKEN ON $PAGE_WLAN_SSID", LogType.ERR)
                return@withContext false
            }

            val fields = extractFormFields(html)
            fields["IF_ACTION"] = "apply"
            fields["IF_ERRORSTR"] = "SUCC"
            fields["IF_ERRORPARAM"] = "SUCC"
            fields["IF_ERRORTYPE"] = "-1"
            if (fields.containsKey("ESSID")) fields["ESSID"] = newSsid.trim()
            if (fields.containsKey("ESSID0")) fields["ESSID0"] = newSsid.trim()
            if (fields.containsKey("ESSIDHideEnable")) fields["ESSIDHideEnable"] = if (hideSsid) "1" else "0"
            if (fields.containsKey("ESSIDHideEnable0")) fields["ESSIDHideEnable0"] = if (hideSsid) "1" else "0"
            fields["_SESSION_TOKEN"] = token

            val ok = postForm(PAGE_WLAN_SSID, fields)
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
                onLog("SPEED [${preset.title}] -> $PAGE_WLAN_BASIC (MODE=${preset.standard}, BW=${preset.bandWidth}, TX=$tx)", LogType.ACT)
                val html = fetchPage(PAGE_WLAN_BASIC)
                val token = extractSessionToken(html) ?: run {
                    onLog("MISSING TOKEN ON $PAGE_WLAN_BASIC", LogType.ERR)
                    return@withContext false
                }

                val fields = extractFormFields(html)
                fields["IF_ACTION"] = "apply"
                fields["IF_ERRORSTR"] = "SUCC"
                fields["IF_ERRORPARAM"] = "SUCC"
                fields["IF_ERRORTYPE"] = "-1"
                if (fields.containsKey("Standard")) fields["Standard"] = preset.standard
                if (fields.containsKey("BandWidth")) fields["BandWidth"] = preset.bandWidth
                if (fields.containsKey("ChannelWidth")) fields["ChannelWidth"] = preset.bandWidth
                if (fields.containsKey("TxPower")) fields["TxPower"] = tx
                if (fields.containsKey("DataRate")) fields["DataRate"] = preset.dataRate
                if (fields.containsKey("BasicDataRates")) fields["BasicDataRates"] = preset.dataRate
                fields["_SESSION_TOKEN"] = token

                val ok = postForm(PAGE_WLAN_BASIC, fields)
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
            onLog("REBOOT -> $PAGE_REBOOT", LogType.WARN)
            val html = fetchPage(PAGE_REBOOT)
            val token = extractSessionToken(html) ?: run {
                onLog("MISSING TOKEN ON $PAGE_REBOOT", LogType.ERR)
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
            val ok = postForm(PAGE_REBOOT, fields)
            onLog(if (ok) "REBOOT TRANSMITTED" else "REBOOT FAILED", if (ok) LogType.OK else LogType.ERR)
            ok
        } catch (e: Exception) {
            onLog("REBOOT ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    // ===================== 6. COMPACT FORMS EXPORTER (NO CSS BOILERPLATE) =====================
    suspend fun exportRouterHtmlDump(): String = withContext(Dispatchers.IO) {
        if (savedPass.isEmpty()) {
            onLog("EXPORT: CONNECT TO ROUTER FIRST", LogType.WARN)
            return@withContext ""
        }

        val sb = StringBuilder()

        fun sanitize(text: String): String {
            var s = text
            val sensitive = listOf("KeyPassphrase", "PreSharedKey", "Password", "UserName", "Username", "WPAPSK")
            for (k in sensitive) {
                s = Regex(
                    """(Transfer_meaning\(\s*['"]$k\d*['"]\s*,\s*['"])([^'"]*)(['"]\s*\))""",
                    RegexOption.IGNORE_CASE
                ).replace(s, "$1***REDACTED***$3")
            }
            return s
        }

        fun extractBodyDiv(html: String): String {
            val start = html.indexOf("<div id=\"div1\">")
            val end = html.indexOf("<div class=\"bottom_div\"")
            return if (start != -1 && end > start) {
                html.substring(start, end)
            } else {
                html.replace(Regex("""(?is)<style[^>]*>.*?</style>"""), "").take(4000)
            }
        }

        val pages = listOf(
            PAGE_WLAN_BASIC,
            PAGE_WLAN_SSID,
            PAGE_WLAN_SEC,
            PAGE_WLAN_MAC_FILTER,
            PAGE_WLAN_ASSOC,
            PAGE_REBOOT
        )
        try {
            for (p in pages) {
                onLog("EXPORT COMPACT -> $p", LogType.SYS)
                val html = fetchPage(p)
                sb.append("\n==================== $p (full=${html.length}) ====================\n")
                sb.append(sanitize(extractBodyDiv(html)))
                sb.append("\n")
            }
            onLog("COMPACT EXPORT READY (${sb.length / 1024} KB)", LogType.OK)
            sb.toString()
        } catch (e: Exception) {
            onLog("EXPORT ERR: ${e.message}", LogType.ERR)
            ""
        }
    }

    // ===================== SESSION-GUARDED HTTP HELPERS =====================
    private fun fetchPage(nextPage: String, allowRelogin: Boolean = true): String {
        val body = rawGetPage(nextPage)
        if (!isSessionInvalid(body)) return body

        if (allowRelogin && !isRelogging && savedPass.isNotEmpty()) {
            isRelogging = true
            try {
                onLog("SESSION EXPIRED ON $nextPage -> AUTO RE-LOGIN", LogType.WARN)
                if (performLogin(silent = true)) {
                    val retry = rawGetPage(nextPage)
                    if (!isSessionInvalid(retry)) return retry
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
        if (html.contains("Frm_Logintoken") || html.contains("Frm_Username") || html.contains("Frm_Password")) return true
        // كل صفحة مصادق عليها في H108N V2.5 تحتوي على session_token
        if (!html.contains("session_token")) return true
        return false
    }

    private fun extractFormFields(html: String): LinkedHashMap<String, String> {
        val fields = LinkedHashMap<String, String>()
        val inputTagRegex = Regex("""(?is)<input\b[^>]*>""")
        val nameRegex = Regex("""(?i)\bname\s*=\s*["']?([^"'\s>]+)["']?""")
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

    private fun extractNumberPair(text: String): Pair<String, String>? {
        val m = Regex("""(-?\d+(?:\.\d+)?)\s*/\s*(-?\d+(?:\.\d+)?)""").find(text) ?: return null
        return m.groupValues[1] to m.groupValues[2]
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
            Regex("""session_token\s*=\s*["']([^"']+)["']"""),
            Regex("""_SESSION_TOKEN\s*=\s*["']([^"']+)["']"""),
            Regex("""name=["']_SESSION_TOKEN["'][^>]*value=["']([^"']+)["']""")
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

    private fun formatTenthsDb(raw: String?): String = formatTenthsUnit(raw, "dB")

    private fun formatTenthsUnit(raw: String?, unit: String): String {
        val num = raw?.trim()?.toDoubleOrNull() ?: return "--"
        return String.format(Locale.US, "%.1f %s", num / 10.0, unit)
    }

    private fun formatLease(raw: String?): String {
        val sec = raw?.toLongOrNull() ?: return raw?.ifBlank { "--" } ?: "--"
        val h = sec / 3600
        val m = (sec % 3600) / 60
        return if (h > 0) "${h}h ${m}m" else "${m}m"
    }
}