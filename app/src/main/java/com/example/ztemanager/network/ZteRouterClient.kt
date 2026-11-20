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
import java.net.InetAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
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
    val socketProtocols: Set<String>
) {
    NO_TLS13(
        "TLS 1.2 / 1.1 / 1.0 (No TLS 1.3)",
        arrayOf(TlsVersion.TLS_1_2, TlsVersion.TLS_1_1, TlsVersion.TLS_1_0),
        setOf("TLSv1.2", "TLSv1.1", "TLSv1")
    ),
    TLS10_ONLY(
        "TLS 1.0 Only",
        arrayOf(TlsVersion.TLS_1_0),
        setOf("TLSv1")
    ),
    SSLV3_AND_TLS10(
        "SSLv3 + TLS 1.0",
        arrayOf(TlsVersion.TLS_1_0, TlsVersion.SSL_3_0),
        setOf("TLSv1", "SSLv3")
    )
}

data class DslStats(
    val status: String = "غير معروف",
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

    private class LegacyTlsSocketFactory(
        private val delegate: SSLSocketFactory,
        private val allowedProtocols: Set<String>
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
                val suites = socket.supportedCipherSuites
                    .filterNot { it == "TLS_FALLBACK_SCSV" }
                    .toTypedArray()
                if (suites.isNotEmpty()) {
                    socket.enabledCipherSuites = suites
                }
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

        val sslContext = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(localTrustManager), SecureRandom())
        }

        val tlsSpec = ConnectionSpec.Builder(ConnectionSpec.COMPATIBLE_TLS)
            .tlsVersions(*mode.okHttpVersions)
            .allEnabledCipherSuites()
            .build()

        val builder = OkHttpClient.Builder()
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .protocols(listOf(Protocol.HTTP_1_1))
            .followRedirects(followRedirects)
            .followSslRedirects(followRedirects)
            .connectionSpecs(listOf(tlsSpec, ConnectionSpec.CLEARTEXT))
            .sslSocketFactory(
                LegacyTlsSocketFactory(sslContext.socketFactory, mode.socketProtocols),
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

    private var client: OkHttpClient = buildClient(TlsMode.NO_TLS13)

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
        onLog("SESSION CLEARED BY USER", LogType.WARN)
    }

    suspend fun login(ip: String, username: String, password: String): Boolean =
        withContext(Dispatchers.IO) {
            try {
                setRouterIp(ip)
                cookieStore.clear()

                var initHtml = ""
                var needsHttpsProbe = baseUrl.startsWith("https://")

                // 1. فحص الاتصال الأولي بدون تحويل تلقائي لمعرفة رد الراوتر الحقيقي
                if (!needsHttpsProbe) {
                    onLog("PROBE -> GET $baseUrl/ (NO-REDIRECT)", LogType.SYS)
                    val probeClient = buildClient(TlsMode.NO_TLS13, followRedirects = false)
                    val probeReq = Request.Builder().url("$baseUrl/").get().build()
                    probeClient.newCall(probeReq).execute().use { resp ->
                        val location = resp.header("Location")
                        onLog("HTTP ${resp.code}${if (location != null) " -> Location: $location" else ""}", LogType.ACT)
                        if (resp.code in 300..399 && location != null) {
                            if (location.startsWith("https://", ignoreCase = true)) {
                                needsHttpsProbe = true
                                val cleanTarget = location.removePrefix("https://").substringBefore("/")
                                baseUrl = "https://$cleanTarget"
                                targetHost = cleanTarget.substringBefore(":")
                            } else {
                                client = buildClient(TlsMode.NO_TLS13, followRedirects = true)
                                initHtml = client.newCall(Request.Builder().url("$baseUrl/").get().build())
                                    .execute().use { it.body?.string() ?: "" }
                            }
                        } else {
                            client = buildClient(TlsMode.NO_TLS13, followRedirects = true)
                            initHtml = resp.body?.string() ?: ""
                        }
                    }
                }

                // 2. إذا فرض الراوتر HTTPS، نجرب أوضاع TLS القديمة بالتدريج
                if (needsHttpsProbe) {
                    val supported = try {
                        SSLContext.getDefault().supportedSSLParameters.protocols.joinToString(", ")
                    } catch (_: Exception) {
                        "unknown"
                    }
                    onLog("PHONE TLS SUPPORT: [$supported]", LogType.SYS)

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
                        onLog("ALL TLS MODES FAILED -> ROUTER LIKELY USES SSLv3 OR BLOCKED CIPHER ($lastErr)", LogType.ERR)
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
            onLog("FETCHING -> status_dsl_info_t.gch", LogType.SYS)
            val html = fetchPage("status_dsl_info_t.gch")
            val map = parseTransferMeaning(html)
            onLog("PARSED ${map.size} DSL TELEMETRY KEYS", LogType.OK)

            DslStats(
                status = map["LinkStatus"] ?: map["ModulationType"] ?: "Connected",
                downRateKbps = map["DownstreamCurrRate"] ?: "--",
                upRateKbps = map["UpstreamCurrRate"] ?: "--",
                maxDownKbps = map["DownstreamMaxRate"] ?: "--",
                maxUpKbps = map["UpstreamMaxRate"] ?: "--",
                downSnrDb = formatTenths(map["DownstreamNoiseMargin"]),
                upSnrDb = formatTenths(map["UpstreamNoiseMargin"]),
                downAttnDb = formatTenths(map["DownstreamAttenuation"]),
                upAttnDb = formatTenths(map["UpstreamAttenuation"]),
                uptime = map["UpTime"] ?: "--",
                rawMap = map
            )
        } catch (e: Exception) {
            onLog("DSL FETCH FAILED: ${e.message}", LogType.ERR)
            DslStats()
        }
    }

    suspend fun getConnectedDevices(): List<ConnectedDevice> = withContext(Dispatchers.IO) {
        try {
            onLog("SCANNING DHCP -> net_dhcp_dynamic_t.gch", LogType.SYS)
            val html = fetchPage("net_dhcp_dynamic_t.gch")
            val map = parseTransferMeaning(html)

            val indices = map.keys
                .mapNotNull {
                    Regex("""^(?:MACAddr|IPAddr)(\d+)$""").find(it)?.groupValues?.get(1)?.toIntOrNull()
                }
                .distinct()
                .sorted()

            val devices = indices.mapNotNull { idx ->
                val mac = map["MACAddr$idx"].orEmpty()
                val ip = map["IPAddr$idx"].orEmpty()
                if (mac.isBlank() && ip.isBlank()) return@mapNotNull null
                ConnectedDevice(
                    hostName = map["HostName$idx"]?.ifBlank { "جهاز غير مسمى" } ?: "جهاز غير مسمى",
                    ipAddress = ip.ifBlank { "--" },
                    macAddress = mac.ifBlank { "--" },
                    leaseTime = map["ExpiredTime$idx"]?.let { "${it}s" } ?: "--"
                )
            }
            onLog("FOUND ${devices.size} ACTIVE DHCP CLIENTS", LogType.OK)
            devices
        } catch (e: Exception) {
            onLog("DEVICE SCAN FAILED: ${e.message}", LogType.ERR)
            emptyList()
        }
    }

    suspend fun blockMacAddress(mac: String, alias: String): Boolean = withContext(Dispatchers.IO) {
        try {
            onLog("BLOCKING MAC ($mac) -> sec_macfilter_t.gch", LogType.ACT)
            val pageHtml = fetchPage("sec_macfilter_t.gch")
            val token = extractSessionToken(pageHtml)
            if (token == null) {
                onLog("MISSING _SESSION_TOKEN ON MAC FILTER PAGE", LogType.ERR)
                return@withContext false
            }

            val form = FormBody.Builder()
                .add("IF_ACTION", "new")
                .add("IF_ERRORSTR", "SUCC")
                .add("IF_ERRORPARAM", "SUCC")
                .add("IF_ERRORTYPE", "-1")
                .add("Enable", "1")
                .add("Name", alias.take(15).ifBlank { "Blocked" })
                .add("SrcMacAddr", mac)
                .add("DstMacAddr", "")
                .add("_SESSION_TOKEN", token)
                .build()

            val req = Request.Builder()
                .url("$baseUrl/getpage.gch?pid=1002&nextpage=sec_macfilter_t.gch")
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
            onLog("REQUESTING REBOOT -> manager_dev_conf_t.gch", LogType.WARN)
            val pageHtml = fetchPage("manager_dev_conf_t.gch")
            val token = extractSessionToken(pageHtml)
            if (token == null) {
                onLog("FAILED TO EXTRACT _SESSION_TOKEN", LogType.ERR)
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
                .url("$baseUrl/getpage.gch?pid=1002&nextpage=manager_dev_conf_t.gch")
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
            result[match.groupValues[1]] = match.groupValues[2]
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

    private fun formatTenths(raw: String?): String {
        val num = raw?.toDoubleOrNull() ?: return "--"
        return String.format(Locale.US, "%.1f dB", num / 10.0)
    }

    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
}