package com.example.ztemanager.network

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import kotlinx.coroutines.Dispatchers
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
import java.security.MessageDigest
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

private enum class TlsMode(
    val label: String,
    val okHttpVersions: Array<TlsVersion>,
    val socketProtocols: Set<String>,
    val compactLegacySuites: Boolean = false
) {
    TLS10_COMPACT(
        "BC TLS 1.0 (Compact Legacy)",
        arrayOf(TlsVersion.TLS_1_0),
        setOf("TLSv1"),
        compactLegacySuites = true
    ),
    TLS10_ALL(
        "BC TLS 1.0 (All Ciphers)",
        arrayOf(TlsVersion.TLS_1_0),
        setOf("TLSv1"),
        compactLegacySuites = false
    ),
    TLS_MULTI(
        "BC TLS 1.0 / 1.1 / 1.2",
        arrayOf(TlsVersion.TLS_1_2, TlsVersion.TLS_1_1, TlsVersion.TLS_1_0),
        setOf("TLSv1.2", "TLSv1.1", "TLSv1"),
        compactLegacySuites = false
    )
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
    val uptime: String = "--",
    val rawMap: Map<String, String> = emptyMap()
)

data class ConnectedDevice(
    val hostName: String,
    val ipAddress: String,
    val macAddress: String,
    val leaseTime: String
)

class ZteRouterClient(
    private val context: Context,
    private val onLog: (String, LogType) -> Unit
) {
    private val cookieStore = mutableMapOf<String, MutableList<Cookie>>()
    private var baseUrl: String = "http://192.168.1.1"
    private var targetHost: String = "192.168.1.1"

    private var discoveredPages: List<String> = emptyList()
    private var lastDslPage: String = "none"
    private var lastDslPreview: String = ""
    private var lastDhcpSample: Map<String, String> = emptyMap()

    private val bcJsseProvider: BouncyCastleJsseProvider by lazy {
        try {
            Security.setProperty("jdk.tls.disabledAlgorithms", "")
            Security.setProperty("jdk.certpath.disabledAlgorithms", "")
        } catch (_: Exception) {
        }
        BouncyCastleJsseProvider(BouncyCastleProvider())
    }

    private val legacyClassicSuites = listOf(
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
    )

    private class BcTlsSocketFactory(
        private val delegate: SSLSocketFactory,
        private val allowedProtocols: Set<String>,
        private val preferredSuites: List<String>?
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
                val enabled = socket.supportedProtocols.filter { it in allowedProtocols }.toTypedArray()
                if (enabled.isNotEmpty()) {
                    socket.enabledProtocols = enabled
                }

                val supported = socket.supportedCipherSuites.toSet()
                val chosen = if (preferredSuites != null) {
                    val matched = preferredSuites.filter { it in supported }
                    if (matched.isNotEmpty()) matched.toTypedArray() else null
                } else {
                    null
                }

                socket.enabledCipherSuites = chosen ?: socket.supportedCipherSuites
                    .filterNot { it.contains("SCSV") || it.contains("NULL") || it.contains("anon") }
                    .toTypedArray()
            }
            return socket
        }
    }

    private fun buildClient(mode: TlsMode, followRedirects: Boolean = true): OkHttpClient {
        @SuppressLint("CustomX509TrustManager")
        val localTrustManager = object : X509TrustManager {
            @SuppressLint("TrustAllX509TrustManager")
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            @SuppressLint("TrustAllX509TrustManager")
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

        val sslContext = SSLContext.getInstance("TLS", bcJsseProvider).apply {
            init(null, arrayOf(localTrustManager), SecureRandom())
        }

        val tlsSpec = ConnectionSpec.Builder(ConnectionSpec.COMPATIBLE_TLS)
            .tlsVersions(*mode.okHttpVersions)
            .allEnabledCipherSuites()
            .build()

        val builder = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(12, TimeUnit.SECONDS)
            .protocols(listOf(Protocol.HTTP_1_1))
            .followRedirects(followRedirects)
            .followSslRedirects(followRedirects)
            .connectionSpecs(listOf(tlsSpec, ConnectionSpec.CLEARTEXT))
            .sslSocketFactory(
                BcTlsSocketFactory(
                    delegate = sslContext.socketFactory,
                    allowedProtocols = mode.socketProtocols,
                    preferredSuites = if (mode.compactLegacySuites) legacyClassicSuites else null
                ),
                localTrustManager
            )
            .hostnameVerifier { hostname, _ ->
                hostname == targetHost ||
                    hostname.startsWith("192.168.") ||
                    hostname.startsWith("10.")
            }
            .cookieJar(object : CookieJar {
                override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
                    val list = cookieStore.getOrPut(url.host) { mutableListOf() }
                    cookies.forEach { newCookie ->
                        list.removeAll { it.name == newCookie.name }
                        list.add(newCookie)
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
            val wifiNetwork = cm.allNetworks.firstOrNull { net ->
                cm.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
            }
            if (wifiNetwork != null) {
                builder.socketFactory(wifiNetwork.socketFactory)
            }
        } catch (_: Exception) {
        }

        return builder.build()
    }

    private var client: OkHttpClient = buildClient(TlsMode.TLS10_COMPACT)

    fun setRouterIp(ip: String) {
        val trimmed = ip.trim().trimEnd('/')
        val hasHttps = trimmed.startsWith("https://", ignoreCase = true)
        val cleanHost = trimmed
            .removePrefix("http://")
            .removePrefix("https://")
            .substringBefore("/")
        targetHost = cleanHost.substringBefore(":")
        baseUrl = if (hasHttps) "https://$cleanHost" else "http://$cleanHost"
    }

    fun clearSession() {
        cookieStore.clear()
        discoveredPages = emptyList()
        lastDslPage = "none"
        lastDslPreview = ""
        lastDhcpSample = emptyMap()
        onLog("SESSION CLEARED BY USER", LogType.WARN)
    }

    suspend fun login(ip: String, username: String, password: String): Boolean =
        withContext(Dispatchers.IO) {
            try {
                setRouterIp(ip)
                cookieStore.clear()
                discoveredPages = emptyList()

                var initHtml = ""
                var needsHttpsProbe = baseUrl.startsWith("https://")

                if (!needsHttpsProbe) {
                    onLog("PROBE -> GET $baseUrl/ (NO-REDIRECT)", LogType.SYS)
                    val probeClient = buildClient(TlsMode.TLS10_COMPACT, followRedirects = false)
                    val probeReq = Request.Builder().url("$baseUrl/").get().build()
                    probeClient.newCall(probeReq).execute().use { resp ->
                        val location = resp.header("Location")
                        onLog(
                            "HTTP ${resp.code}${if (location != null) " -> Location: $location" else ""}",
                            LogType.ACT
                        )
                        if (resp.code in 300..399 && location != null) {
                            if (location.startsWith("https://", ignoreCase = true)) {
                                needsHttpsProbe = true
                                val cleanTarget = location.removePrefix("https://").substringBefore("/")
                                baseUrl = "https://$cleanTarget"
                                targetHost = cleanTarget.substringBefore(":")
                            } else {
                                client = buildClient(TlsMode.TLS10_COMPACT, followRedirects = true)
                                initHtml = client.newCall(Request.Builder().url("$baseUrl/").get().build())
                                    .execute().use { it.body?.string() ?: "" }
                            }
                        } else {
                            client = buildClient(TlsMode.TLS10_COMPACT, followRedirects = true)
                            initHtml = resp.body?.string() ?: ""
                        }
                    }
                }

                if (needsHttpsProbe) {
                    var lastErr: String? = null
                    for (mode in TlsMode.entries) {
                        try {
                            onLog("TRY HTTPS (${mode.label}) -> $baseUrl/", LogType.ACT)
                            val candidate = buildClient(mode, followRedirects = true)
                            val html = candidate.newCall(Request.Builder().url("$baseUrl/").get().build())
                                .execute().use { it.body?.string() ?: "" }
                            if (html.isNotEmpty()) {
                                client = candidate
                                initHtml = html
                                onLog("HTTPS CONNECTED USING: ${mode.label}", LogType.OK)
                                break
                            }
                        } catch (e: Exception) {
                            lastErr = e.message
                            onLog("MODE FAILED (${mode.label}): ${e.message}", LogType.WARN)
                        }
                    }

                    if (initHtml.isEmpty()) {
                        onLog("ALL BCTLS MODES FAILED: $lastErr", LogType.ERR)
                        return@withContext false
                    }
                }

                if (initHtml.isEmpty()) {
                    onLog("EMPTY RESPONSE FROM ROUTER", LogType.ERR)
                    return@withContext false
                }

                val loginToken = Regex("""Frm_Logintoken["']\)\.value\s*=\s*["'](\d+)["']""")
                    .find(initHtml)?.groupValues?.get(1)
                    ?: Regex("""name=["']Frm_Logintoken["'][^>]*value=["'](\d+)["']""")
                        .find(initHtml)?.groupValues?.get(1)
                    ?: ""

                onLog(
                    "EXTRACTED LOGIN TOKEN: ${if (loginToken.isEmpty()) "NONE" else loginToken}",
                    LogType.SYS
                )

                val usesSha256 = initHtml.contains("sha256", ignoreCase = true)
                val randomNum = if (usesSha256) (10000000..99999999).random().toString() else ""
                val finalPassword = if (usesSha256) {
                    onLog("FIRMWARE MODE: SHA-256 + SALT ($randomNum)", LogType.ACT)
                    sha256(password + randomNum)
                } else {
                    onLog("FIRMWARE MODE: STANDARD ZTE FORM", LogType.ACT)
                    password
                }

                val form = FormBody.Builder()
                    .add("action", "login")
                    .add("Username", username)
                    .add("Password", finalPassword)
                    .add("Frm_Logintoken", loginToken)
                    .add("frashnum", randomNum)
                    .build()

                val loginReq = Request.Builder()
                    .url("$baseUrl/")
                    .post(form)
                    .build()

                val responseHtml = client.newCall(loginReq).execute().use { it.body?.string() ?: "" }
                val success = responseHtml.isNotEmpty() &&
                    !responseHtml.contains("Frm_Logintoken") &&
                    !responseHtml.contains("Password is wrong", ignoreCase = true)

                if (success) {
                    onLog("AUTH SUCCESS -> SESSION ESTABLISHED", LogType.OK)
                    discoverPagesFromHtml(responseHtml)
                    try {
                        val tplHtml = fetchRawPath("/template.gch")
                        discoverPagesFromHtml(tplHtml)
                        onLog("DISCOVERED ${discoveredPages.size} ROUTER .gch PAGES", LogType.SYS)
                    } catch (_: Exception) {
                    }
                } else {
                    onLog("AUTH REJECTED -> CHECK CREDENTIALS OR FIRMWARE", LogType.ERR)
                }
                success
            } catch (e: Exception) {
                onLog("NETWORK ERROR: ${e.message}", LogType.ERR)
                false
            }
        }

    suspend fun getDslStats(): DslStats = withContext(Dispatchers.IO) {
        try {
            val discoveredDsl = discoveredPages.filter {
                it.contains("dsl", ignoreCase = true) ||
                    (it.contains("status", ignoreCase = true) && it.contains("wan", ignoreCase = true))
            }
            val fallbackDsl = listOf(
                "status_wan_dsl_t.gch",
                "status_dsl_t.gch",
                "status_adsl_t.gch",
                "status_dsl_info_t.gch",
                "status_net_dsl_t.gch",
                "status_wan_adsl_t.gch",
                "status_wan_if_t.gch"
            )
            val candidates = (discoveredDsl + fallbackDsl).distinct()

            var bestMap: Map<String, String> = emptyMap()
            var matchedPage = "none"

            for (page in candidates) {
                onLog("TRYING DSL PAGE -> $page", LogType.SYS)
                val html = fetchPage(page)
                if (html.isBlank()) continue

                val map = parseTransferMeaning(html)
                val hasDslData = map.keys.any { k ->
                    k.contains("Rate", ignoreCase = true) ||
                        k.contains("Noise", ignoreCase = true) ||
                        k.contains("Snr", ignoreCase = true) ||
                        k.contains("Atten", ignoreCase = true) ||
                        k.contains("Modulation", ignoreCase = true) ||
                        k.contains("LinkStatus", ignoreCase = true)
                }

                if (hasDslData) {
                    bestMap = map
                    matchedPage = page
                    onLog("MATCHED DSL PAGE: $page (${map.size} keys)", LogType.OK)
                    break
                } else if (map.size > bestMap.size) {
                    bestMap = map
                    matchedPage = page
                } else if (lastDslPreview.isEmpty() && html.length > 40) {
                    lastDslPreview = html
                        .replace(Regex("""\s+"""), " ")
                        .take(280)
                }
            }

            lastDslPage = matchedPage
            if (bestMap.isEmpty()) {
                onLog("NO DSL KEYS FOUND ACROSS ${candidates.size} PAGES -> TAP DUMP KEYS", LogType.WARN)
                return@withContext DslStats()
            }

            DslStats(
                status = findKey(bestMap, "LinkStatus", "Status", "AdslStatus", "LineStatus", "ModulationType") ?: "Connected",
                downRateKbps = formatRateNumber(
                    findKey(bestMap, "DownstreamCurrRate", "DownCurrRate", "ActDataRateDown", "CurrentDownRate", "DownstreamRate", "DownRate")
                ),
                upRateKbps = formatRateNumber(
                    findKey(bestMap, "UpstreamCurrRate", "UpCurrRate", "ActDataRateUp", "CurrentUpRate", "UpstreamRate", "UpRate")
                ),
                maxDownKbps = formatRateNumber(
                    findKey(bestMap, "DownstreamMaxRate", "DownMaxRate", "MaxDownRate", "AttainableDownRate")
                ),
                maxUpKbps = formatRateNumber(
                    findKey(bestMap, "UpstreamMaxRate", "UpMaxRate", "MaxUpRate", "AttainableUpRate")
                ),
                downSnrDb = formatDb(
                    findKey(bestMap, "DownstreamNoiseMargin", "DownNoiseMargin", "SnrDown", "NoiseMarginDown")
                ),
                upSnrDb = formatDb(
                    findKey(bestMap, "UpstreamNoiseMargin", "UpNoiseMargin", "SnrUp", "NoiseMarginUp")
                ),
                downAttnDb = formatDb(
                    findKey(bestMap, "DownstreamAttenuation", "DownAttenuation", "AttnDown", "LineAttenuationDown")
                ),
                upAttnDb = formatDb(
                    findKey(bestMap, "UpstreamAttenuation", "UpAttenuation", "AttnUp", "LineAttenuationUp")
                ),
                uptime = findKey(bestMap, "UpTime", "ShowtimeStart", "LinkUpTime") ?: "--",
                rawMap = bestMap
            )
        } catch (e: Exception) {
            onLog("DSL FETCH FAILED: ${e.message}", LogType.ERR)
            DslStats()
        }
    }

    suspend fun getConnectedDevices(): List<ConnectedDevice> = withContext(Dispatchers.IO) {
        try {
            val dhcpPage = discoveredPages.firstOrNull {
                it.contains("dhcp_dynamic", ignoreCase = true)
            } ?: "net_dhcp_dynamic_t.gch"

            onLog("SCANNING DHCP -> $dhcpPage", LogType.SYS)
            val html = fetchPage(dhcpPage)
            val map = parseTransferMeaning(html)
            lastDhcpSample = map.entries.take(12).associate { it.key to it.value }

            val indices = map.keys
                .mapNotNull {
                    Regex("""^(?:MACAddr|IPAddr)(\d+)$""").find(it)?.groupValues?.get(1)?.toIntOrNull()
                }
                .distinct()
                .sorted()

            val devices = indices.mapNotNull { idx ->
                val mac = map["MACAddr$idx"].orEmpty().uppercase(Locale.US)
                val ip = map["IPAddr$idx"].orEmpty()
                if (mac.isBlank() && ip.isBlank()) return@mapNotNull null

                val rawName = map["HostName$idx"].orEmpty().trim()
                val cleanName = if (rawName.isBlank() || rawName == "*" || rawName == "null") {
                    "Device ($ip)"
                } else {
                    rawName
                }

                ConnectedDevice(
                    hostName = cleanName,
                    ipAddress = ip.ifBlank { "--" },
                    macAddress = mac.ifBlank { "--" },
                    leaseTime = formatLease(map["ExpiredTime$idx"])
                )
            }
            onLog("FOUND ${devices.size} ACTIVE DHCP CLIENTS (DECODED)", LogType.OK)
            devices
        } catch (e: Exception) {
            onLog("DEVICE SCAN FAILED: ${e.message}", LogType.ERR)
            emptyList()
        }
    }

    suspend fun blockMacAddress(mac: String, alias: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val macPage = discoveredPages.firstOrNull {
                it.contains("macfilter", ignoreCase = true) || it.contains("mac_filter", ignoreCase = true)
            } ?: "sec_macfilter_t.gch"

            onLog("BLOCKING MAC ($mac) -> $macPage", LogType.ACT)
            val pageHtml = fetchPage(macPage)
            val token = extractSessionToken(pageHtml)
            if (token == null) {
                onLog("MISSING _SESSION_TOKEN ON $macPage", LogType.ERR)
                return@withContext false
            }

            val cleanAlias = alias.replace(Regex("""[^a-zA-Z0-9_-]"""), "").take(15).ifBlank { "Blocked" }
            val form = FormBody.Builder()
                .add("IF_ACTION", "new")
                .add("IF_ERRORSTR", "SUCC")
                .add("IF_ERRORPARAM", "SUCC")
                .add("IF_ERRORTYPE", "-1")
                .add("Enable", "1")
                .add("Name", cleanAlias)
                .add("SrcMacAddr", mac)
                .add("DstMacAddr", "")
                .add("_SESSION_TOKEN", token)
                .build()

            val req = Request.Builder()
                .url("$baseUrl/getpage.gch?pid=1002&nextpage=$macPage")
                .post(form)
                .build()

            val ok = client.newCall(req).execute().use { it.isSuccessful }
            onLog(
                if (ok) "MAC RULE SENT SUCCESSFULLY" else "MAC RULE FAILED",
                if (ok) LogType.OK else LogType.ERR
            )
            ok
        } catch (e: Exception) {
            onLog("MAC BLOCK ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    suspend fun rebootRouter(): Boolean = withContext(Dispatchers.IO) {
        try {
            val rebootPage = discoveredPages.firstOrNull {
                it.contains("dev_conf", ignoreCase = true) || it.contains("restart", ignoreCase = true)
            } ?: "manager_dev_conf_t.gch"

            onLog("REQUESTING REBOOT -> $rebootPage", LogType.WARN)
            val pageHtml = fetchPage(rebootPage)
            val token = extractSessionToken(pageHtml)
            if (token == null) {
                onLog("FAILED TO EXTRACT _SESSION_TOKEN ON $rebootPage", LogType.ERR)
                return@withContext false
            }

            val form = FormBody.Builder()
                .add("IF_ACTION", "devrestart")
                .add("IF_ERRORSTR", "SUCC")
                .add("IF_ERRORPARAM", "SUCC")
                .add("IF_ERRORTYPE", "-1")
                .add("flag", "1")
                .add("_SESSION_TOKEN", token)
                .build()

            val req = Request.Builder()
                .url("$baseUrl/getpage.gch?pid=1002&nextpage=$rebootPage")
                .post(form)
                .build()

            val ok = client.newCall(req).execute().use { it.isSuccessful }
            onLog(
                if (ok) "REBOOT COMMAND TRANSMITTED" else "REBOOT REJECTED",
                if (ok) LogType.OK else LogType.ERR
            )
            ok
        } catch (e: Exception) {
            onLog("REBOOT ERR: ${e.message}", LogType.ERR)
            false
        }
    }

    fun getDiagnosticLines(dslRawMap: Map<String, String>): List<Pair<String, LogType>> {
        val out = mutableListOf<Pair<String, LogType>>()
        out.add("--- DIAGNOSTICS (DSL PAGE: $lastDslPage) ---" to LogType.ACT)

        if (discoveredPages.isNotEmpty()) {
            out.add("DISCOVERED PAGES (${discoveredPages.size}):" to LogType.OK)
            discoveredPages.chunked(3).forEach { chunk ->
                out.add("  " + chunk.joinToString(" | ") to LogType.SYS)
            }
        } else {
            out.add("NO MENU PAGES DISCOVERED YET" to LogType.WARN)
        }

        if (dslRawMap.isNotEmpty()) {
            out.add("DSL KEYS (${dslRawMap.size}):" to LogType.OK)
            dslRawMap.entries.take(35).forEach { (k, v) ->
                out.add("  $k = $v" to LogType.SYS)
            }
        } else if (lastDslPreview.isNotEmpty()) {
            out.add("DSL HTML PREVIEW: $lastDslPreview" to LogType.WARN)
        }

        if (lastDhcpSample.isNotEmpty()) {
            out.add("DHCP SAMPLE:" to LogType.OK)
            lastDhcpSample.forEach { (k, v) ->
                out.add("  $k = $v" to LogType.SYS)
            }
        }
        return out
    }

    private fun discoverPagesFromHtml(html: String) {
        val ignored = setOf("getpage.gch", "template.gch", "start.gch", "login.gch", "index.gch")
        val found = Regex("""([a-zA-Z0-9_]+\.gch)""").findAll(html)
            .map { it.groupValues[1] }
            .filterNot { it.lowercase(Locale.US) in ignored }
            .distinct()
            .toList()
        if (found.isNotEmpty()) {
            discoveredPages = (discoveredPages + found).distinct()
        }
    }

    private fun fetchRawPath(path: String): String {
        val req = Request.Builder().url("$baseUrl$path").get().build()
        return client.newCall(req).execute().use { it.body?.string() ?: "" }
    }

    private fun fetchPage(nextPage: String): String {
        val req = Request.Builder()
            .url("$baseUrl/getpage.gch?pid=1002&nextpage=$nextPage")
            .get()
            .build()
        return client.newCall(req).execute().use { it.body?.string() ?: "" }
    }

    private fun parseTransferMeaning(html: String): Map<String, String> {
        val result = mutableMapOf<String, String>()
        val pattern = Regex("""Transfer_meaning\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]*)['"]\s*\)""")
        pattern.findAll(html).forEach { match ->
            val key = unescapeZteValue(match.groupValues[1])
            val value = unescapeZteValue(match.groupValues[2])
            result[key] = value
        }
        return result
    }

    // فك ترميز نصوص ZTE مثل \x2d (-) و \x3a (:) و \x20 (مسافة)
    private fun unescapeZteValue(raw: String): String {
        var out = raw
        out = Regex("""\\x([0-9a-fA-F]{2})""").replace(out) { m ->
            m.groupValues[1].toInt(16).toChar().toString()
        }
        out = Regex("""\\u([0-9a-fA-F]{4})""").replace(out) { m ->
            m.groupValues[1].toInt(16).toChar().toString()
        }
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

    private fun findKey(map: Map<String, String>, vararg candidates: String): String? {
        for (c in candidates) {
            map[c]?.takeIf { it.isNotBlank() }?.let { return it }
            map["${c}0"]?.takeIf { it.isNotBlank() }?.let { return it }
            map.entries.firstOrNull { it.key.equals(c, ignoreCase = true) && it.value.isNotBlank() }
                ?.let { return it.value }
            map.entries.firstOrNull { it.key.equals("${c}0", ignoreCase = true) && it.value.isNotBlank() }
                ?.let { return it.value }
        }
        return null
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

    private fun formatRateNumber(raw: String?): String {
        val v = raw?.trim().orEmpty()
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

    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
}