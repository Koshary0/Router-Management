package com.example.ztemanager

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.core.view.WindowCompat
import com.example.ztemanager.network.*
import com.example.ztemanager.ui.theme.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class TerminalEntry(val time: String, val text: String, val type: LogType)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = BgBase.toArgb()
        window.navigationBarColor = BgBase.toArgb()
        WindowCompat.getInsetsController(window, window.decorView).isAppearanceLightStatusBars = false

        setContent {
            ZteStudioTheme {
                RouterStudioApp()
            }
        }
    }
}

@Composable
fun RouterStudioApp() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val prefs = remember { context.getSharedPreferences("zte_router_prefs", Context.MODE_PRIVATE) }

    var activeTab by remember { mutableIntStateOf(4) } // Setup tab initially
    var isConnected by remember { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(false) }
    var loaderMessage by remember { mutableStateOf("Connecting...") }

    var routerIp by remember { mutableStateOf(prefs.getString("ip", "192.168.1.1") ?: "192.168.1.1") }
    var username by remember { mutableStateOf(prefs.getString("user", "admin") ?: "admin") }
    var password by remember { mutableStateOf(prefs.getString("pass", "") ?: "") }

    var dslStats by remember { mutableStateOf(DslStats()) }
    var devices by remember { mutableStateOf<List<ConnectedDevice>>(emptyList()) }
    var blockedRules by remember { mutableStateOf<List<BlockedRule>>(emptyList()) }
    var wifiConfig by remember { mutableStateOf(WifiConfig()) }

    var selectedDevice by remember { mutableStateOf<ConnectedDevice?>(null) }
    var showRebootConfirm by remember { mutableStateOf(false) }
    var sessionSeconds by remember { mutableLongStateOf(0L) }
    val terminalLogs = remember { mutableStateListOf<TerminalEntry>() }

    fun addLog(msg: String, type: LogType) {
        val time = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        terminalLogs.add(TerminalEntry(time, msg, type))
    }

    val routerClient = remember {
        ZteRouterClient(context) { msg, type ->
            scope.launch { addLog(msg, type) }
        }
    }

    LaunchedEffect(isConnected) {
        if (isConnected) {
            sessionSeconds = 0L
            while (isConnected) {
                delay(1000)
                sessionSeconds++
            }
        }
    }

    fun formatSessionTime(sec: Long): String =
        String.format(Locale.US, "%02d:%02d:%02d", sec / 3600, (sec % 3600) / 60, sec % 60)

    fun runTask(msg: String, block: suspend () -> Unit) {
        scope.launch {
            isLoading = true
            loaderMessage = msg
            block()
            isLoading = false
        }
    }

    fun connectAndSync() = runTask("Authenticating with ZXHN H108N V2.5...") {
        prefs.edit()
            .putString("ip", routerIp)
            .putString("user", username)
            .putString("pass", password)
            .apply()

        val ok = routerClient.login(routerIp, username, password)
        if (ok) {
            isConnected = true
            loaderMessage = "Syncing DSL, Wi-Fi & Devices..."
            dslStats = routerClient.getDslStats()
            devices = routerClient.getConnectedDevices()
            blockedRules = routerClient.getBlockedRules()
            wifiConfig = routerClient.getWifiConfig()
            activeTab = 0
        } else {
            isConnected = false
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(BgBase)
            .systemBarsPadding()
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 14.dp)
        ) {
            when (activeTab) {
                0 -> RouterTab(
                    isConnected = isConnected,
                    routerIp = routerIp,
                    uptimeBadge = formatSessionTime(sessionSeconds),
                    stats = dslStats,
                    onRefresh = {
                        runTask("Refreshing DSL Telemetry...") {
                            dslStats = routerClient.getDslStats()
                        }
                    }
                )
                1 -> WifiControlTab(
                    isConnected = isConnected,
                    wifiConfig = wifiConfig,
                    onRefresh = {
                        runTask("Loading Wi-Fi Settings...") {
                            wifiConfig = routerClient.getWifiConfig()
                        }
                    },
                    onSavePassword = { newPass ->
                        runTask("Updating Wi-Fi Password...") {
                            if (routerClient.updateWifiPassword(newPass)) {
                                wifiConfig = wifiConfig.copy(password = newPass)
                            }
                        }
                    },
                    onSaveSsid = { newSsid, hide ->
                        runTask("Saving SSID Settings...") {
                            if (routerClient.updateWifiSsid(newSsid, hide)) {
                                wifiConfig = wifiConfig.copy(ssid = newSsid, hidden = hide)
                            }
                        }
                    },
                    onApplySpeed = { preset, txPower ->
                        runTask("Applying ${preset.title} Speed Profile...") {
                            if (routerClient.applySpeedPreset(preset, txPower)) {
                                wifiConfig = wifiConfig.copy(
                                    standard = preset.standard,
                                    bandWidth = preset.bandWidth,
                                    txPower = txPower
                                )
                            }
                        }
                    }
                )
                2 -> DevicesTab(
                    isConnected = isConnected,
                    devices = devices,
                    blockedRules = blockedRules,
                    onRefresh = {
                        runTask("Scanning Devices & MAC Filter...") {
                            devices = routerClient.getConnectedDevices()
                            blockedRules = routerClient.getBlockedRules()
                        }
                    },
                    onSelectDevice = { selectedDevice = it },
                    onUnblock = { rule ->
                        runTask("Unblocking ${rule.macAddress}...") {
                            if (routerClient.unblockRule(rule.index)) {
                                blockedRules = routerClient.getBlockedRules()
                            }
                        }
                    }
                )
                3 -> LogsTab(
                    logs = terminalLogs,
                    onClear = { terminalLogs.clear() },
                    onInspectDsl = {
                        if (dslStats.rawRows.isEmpty()) {
                            addLog("NO DSL ROWS CACHED - CONNECT FIRST", LogType.WARN)
                        } else {
                            addLog("--- DSL TABLE ROWS (${dslStats.rawRows.size}) ---", LogType.ACT)
                            dslStats.rawRows.forEach { addLog(it, LogType.SYS) }
                        }
                    },
                    onInspectWlan = {
                        if (wifiConfig.rawBasicKeys.isEmpty()) {
                            addLog("NO WLAN KEYS CACHED - CONNECT FIRST", LogType.WARN)
                        } else {
                            addLog("--- WLAN BASIC KEYS (${wifiConfig.rawBasicKeys.size}) ---", LogType.ACT)
                            wifiConfig.rawBasicKeys.forEach { (k, v) -> addLog("$k = $v", LogType.SYS) }
                        }
                    }
                )
                4 -> SetupTab(
                    routerIp = routerIp,
                    onIpChange = { routerIp = it },
                    username = username,
                    onUserChange = { username = it },
                    password = password,
                    onPassChange = { password = it },
                    isConnected = isConnected,
                    onConnect = { connectAndSync() },
                    onDisconnect = {
                        routerClient.clearSession()
                        isConnected = false
                        devices = emptyList()
                        blockedRules = emptyList()
                        dslStats = DslStats()
                        wifiConfig = WifiConfig()
                    },
                    onRebootRequest = { showRebootConfirm = true }
                )
            }
        }

        FloatingBottomNav(
            activeTab = activeTab,
            onTabSelected = { activeTab = it },
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(bottom = 16.dp)
                .fillMaxWidth(0.94f)
        )

        if (isLoading) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(BgBase.copy(alpha = 0.94f))
                    .clickable(enabled = false) {},
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(
                        color = Accent,
                        trackColor = Surface2,
                        strokeWidth = 4.dp,
                        modifier = Modifier.size(44.dp)
                    )
                    Spacer(Modifier.height(14.dp))
                    Text(loaderMessage, color = TextMuted, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }

    selectedDevice?.let { dev ->
        DeviceActionModal(
            device = dev,
            onDismiss = { selectedDevice = null },
            onKick = {
                selectedDevice = null
                runTask("Kicking ${dev.hostName} (8s temp drop)...") {
                    routerClient.kickDevice(dev.macAddress)
                    blockedRules = routerClient.getBlockedRules()
                }
            },
            onBlock = {
                selectedDevice = null
                runTask("Blocking ${dev.macAddress}...") {
                    if (routerClient.blockMacAddress(dev.macAddress, dev.hostName)) {
                        blockedRules = routerClient.getBlockedRules()
                    }
                }
            }
        )
    }

    if (showRebootConfirm) {
        Dialog(onDismissRequest = { showRebootConfirm = false }) {
            StudioCard(cornerRadius = 24.dp) {
                Text("Reboot Router", color = TextMain, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(8.dp))
                Text(
                    "Connection will drop for ~60 seconds while the router restarts.",
                    color = TextMuted,
                    fontSize = 13.sp,
                    lineHeight = 20.sp
                )
                Spacer(Modifier.height(18.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StudioButton("Cancel", Surface2, Modifier.weight(1f)) { showRebootConfirm = false }
                    StudioButton("Reboot", StatusDnd, Modifier.weight(1f)) {
                        showRebootConfirm = false
                        runTask("Transmitting reboot command...") {
                            if (routerClient.rebootRouter()) isConnected = false
                        }
                    }
                }
            }
        }
    }
}

// ======================= TAB 0: ROUTER & DSL =======================
@Composable
fun RouterTab(
    isConnected: Boolean,
    routerIp: String,
    uptimeBadge: String,
    stats: DslStats,
    onRefresh: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(bottom = 100.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(18.dp))
                .background(Brush.verticalGradient(listOf(Surface2, Surface1)))
                .border(1.dp, BorderColor, RoundedCornerShape(18.dp))
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 24.dp, horizontal = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Box(contentAlignment = Alignment.BottomEnd) {
                    Box(
                        modifier = Modifier
                            .size(86.dp)
                            .clip(CircleShape)
                            .background(BgBase)
                            .border(4.dp, Surface1, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            Icons.Rounded.Home,
                            null,
                            tint = if (isConnected) Accent else TextMuted,
                            modifier = Modifier.size(40.dp)
                        )
                    }
                    Box(
                        modifier = Modifier
                            .size(22.dp)
                            .clip(CircleShape)
                            .background(if (isConnected) StatusOnline else StatusOffline)
                            .border(4.dp, Surface1, CircleShape)
                    )
                }

                Spacer(Modifier.height(12.dp))
                Text(
                    if (isConnected) "ZXHN H108N V2.5" else "Disconnected",
                    color = TextMain,
                    fontSize = 21.sp,
                    fontWeight = FontWeight.ExtraBold
                )
                Spacer(Modifier.height(5.dp))
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(20.dp))
                        .background(BgBase)
                        .padding(horizontal = 12.dp, vertical = 4.dp)
                ) {
                    Text("GW: $routerIp", color = TextMuted, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                }

                if (isConnected) {
                    Spacer(Modifier.height(10.dp))
                    Row(
                        modifier = Modifier
                            .clip(RoundedCornerShape(20.dp))
                            .background(StatusOnline.copy(alpha = 0.15f))
                            .padding(horizontal = 12.dp, vertical = 5.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Icon(Icons.Rounded.CheckCircle, null, tint = StatusOnline, modifier = Modifier.size(14.dp))
                        Text(uptimeBadge, color = StatusOnline, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
            if (!isConnected) OverlayBlocker("Connect in Setup tab first")
        }

        Box(modifier = Modifier.fillMaxWidth()) {
            StudioCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("DSL Line Telemetry", color = TextMain, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                    Text(
                        stats.status,
                        color = if (isConnected) StatusOnline else TextMuted,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                Spacer(Modifier.height(14.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatCell("DOWNSTREAM", "${stats.downRateKbps} Kbps", Accent, Modifier.weight(1f))
                    StatCell("UPSTREAM", "${stats.upRateKbps} Kbps", StatusOnline, Modifier.weight(1f))
                }
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatCell("DOWN SNR", stats.downSnrDb, StatusIdle, Modifier.weight(1f))
                    StatCell("UP SNR", stats.upSnrDb, StatusIdle, Modifier.weight(1f))
                }
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StatCell("MAX DOWN RATE", "${stats.maxDownKbps} Kbps", TextMain, Modifier.weight(1f))
                    StatCell("DOWN ATTN", stats.downAttnDb, TextMuted, Modifier.weight(1f))
                }

                Spacer(Modifier.height(16.dp))
                StudioButton("Refresh Telemetry", Accent, onClick = onRefresh)
            }
            if (!isConnected) OverlayBlocker("Requires Connection")
        }
    }
}

@Composable
fun StatCell(label: String, value: String, valueColor: Color, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(BgBase)
            .border(1.dp, BorderColor, RoundedCornerShape(12.dp))
            .padding(12.dp)
    ) {
        Text(label, color = TextMuted, fontSize = 10.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(4.dp))
        Text(value, color = valueColor, fontSize = 14.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
    }
}

// ======================= TAB 1: WI-FI & SPEED CONTROL =======================
@Composable
fun WifiControlTab(
    isConnected: Boolean,
    wifiConfig: WifiConfig,
    onRefresh: () -> Unit,
    onSavePassword: (String) -> Unit,
    onSaveSsid: (String, Boolean) -> Unit,
    onApplySpeed: (SpeedPreset, String) -> Unit
) {
    var ssidInput by remember(wifiConfig.ssid) { mutableStateOf(wifiConfig.ssid) }
    var hideSsid by remember(wifiConfig.hidden) { mutableStateOf(wifiConfig.hidden) }
    var passInput by remember(wifiConfig.password) { mutableStateOf(wifiConfig.password) }
    var showPass by remember { mutableStateOf(false) }

    val txOptions = listOf("20%", "40%", "60%", "80%", "100%")
    var selectedTx by remember(wifiConfig.txPower) {
        mutableStateOf(if (wifiConfig.txPower in txOptions) wifiConfig.txPower else "100%")
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(bottom = 100.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // بطاقة تحديد سرعة الإنترنت (تقليل / تزويد)
        Box(modifier = Modifier.fillMaxWidth()) {
            StudioCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("Wi-Fi Speed Control", color = TextMain, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                        Text(
                            "Mode: ${wifiConfig.standard} • ${wifiConfig.bandWidth} • TX ${wifiConfig.txPower}",
                            color = TextMuted,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                    IconButton(
                        onClick = onRefresh,
                        modifier = Modifier
                            .size(38.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(Surface2)
                    ) {
                        Icon(Icons.Rounded.Refresh, null, tint = Accent, modifier = Modifier.size(18.dp))
                    }
                }

                Spacer(Modifier.height(14.dp))
                val presets = SpeedPreset.entries
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    presets.chunked(2).forEach { pair ->
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            pair.forEach { preset ->
                                val isActive = wifiConfig.standard == preset.standard &&
                                    (preset != SpeedPreset.ECO || wifiConfig.txPower == "40%")
                                Column(
                                    modifier = Modifier
                                        .weight(1f)
                                        .clip(RoundedCornerShape(12.dp))
                                        .background(if (isActive) Accent.copy(alpha = 0.2f) else BgBase)
                                        .border(
                                            1.dp,
                                            if (isActive) Accent else BorderColor,
                                            RoundedCornerShape(12.dp)
                                        )
                                        .clickable {
                                            selectedTx = preset.txPower
                                            onApplySpeed(preset, preset.txPower)
                                        }
                                        .padding(12.dp)
                                ) {
                                    Text(
                                        preset.title,
                                        color = if (isActive) Accent else TextMain,
                                        fontSize = 14.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Text(preset.subtitle, color = TextMuted, fontSize = 10.sp)
                                }
                            }
                        }
                    }
                }

                Spacer(Modifier.height(14.dp))
                StudioInputLabel("SIGNAL / TX POWER")
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    txOptions.forEach { level ->
                        val active = selectedTx == level
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(10.dp))
                                .background(if (active) Accent else BgBase)
                                .border(1.dp, if (active) Accent else BorderColor, RoundedCornerShape(10.dp))
                                .clickable {
                                    selectedTx = level
                                    val currentPreset = SpeedPreset.entries.firstOrNull {
                                        it.standard == wifiConfig.standard
                                    } ?: SpeedPreset.MAX
                                    onApplySpeed(currentPreset, level)
                                }
                                .padding(vertical = 8.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                level,
                                color = if (active) Color.White else TextMuted,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }
            if (!isConnected) OverlayBlocker("Requires Connection")
        }

        // بطاقة تغيير كلمة سر الواي فاي
        Box(modifier = Modifier.fillMaxWidth()) {
            StudioCard {
                Text("Wi-Fi Security (Password)", color = TextMain, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(12.dp))
                StudioInputLabel("WPA2 PASSPHRASE (8-63 CHARS)")
                StudioTextField(
                    value = passInput,
                    onValueChange = { passInput = it },
                    placeholder = "Enter new Wi-Fi password",
                    isPassword = !showPass
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 6.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Show password", color = TextMuted, fontSize = 12.sp)
                    Switch(
                        checked = showPass,
                        onCheckedChange = { showPass = it },
                        colors = SwitchDefaults.colors(checkedTrackColor = Accent)
                    )
                }
                Spacer(Modifier.height(6.dp))
                StudioButton("Update Wi-Fi Password", Accent) { onSavePassword(passInput) }
            }
            if (!isConnected) OverlayBlocker("Requires Connection")
        }

        // بطاقة اسم الشبكة وإخفائها
        Box(modifier = Modifier.fillMaxWidth()) {
            StudioCard {
                Text("Network Name (SSID)", color = TextMain, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(12.dp))
                StudioInputLabel("SSID NAME")
                StudioTextField(ssidInput, { ssidInput = it }, "Wi-Fi Name")
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 6.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Hide SSID Broadcast", color = TextMuted, fontSize = 12.sp)
                    Switch(
                        checked = hideSsid,
                        onCheckedChange = { hideSsid = it },
                        colors = SwitchDefaults.colors(checkedTrackColor = Accent)
                    )
                }
                Spacer(Modifier.height(6.dp))
                StudioButton("Save SSID Settings", Surface2) { onSaveSsid(ssidInput, hideSsid) }
            }
            if (!isConnected) OverlayBlocker("Requires Connection")
        }
    }
}

// ======================= TAB 2: DEVICES & BLOCKED MACS =======================
@Composable
fun DevicesTab(
    isConnected: Boolean,
    devices: List<ConnectedDevice>,
    blockedRules: List<BlockedRule>,
    onRefresh: () -> Unit,
    onSelectDevice: (ConnectedDevice) -> Unit,
    onUnblock: (BlockedRule) -> Unit
) {
    var showBlocked by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(bottom = 100.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        StudioCard {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text("Network Clients", color = TextMain, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                    Text(
                        "${devices.size} Active  •  ${blockedRules.size} Blocked",
                        color = TextMuted,
                        fontSize = 12.sp
                    )
                }
                IconButton(
                    onClick = onRefresh,
                    enabled = isConnected,
                    modifier = Modifier
                        .clip(RoundedCornerShape(12.dp))
                        .background(Surface2)
                        .border(1.dp, BorderColor, RoundedCornerShape(12.dp))
                ) {
                    Icon(Icons.Rounded.Refresh, null, tint = if (isConnected) Accent else TextMuted)
                }
            }

            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StudioButton(
                    text = "Active (${devices.size})",
                    bgColor = if (!showBlocked) Accent else Surface2,
                    modifier = Modifier.weight(1f)
                ) { showBlocked = false }
                StudioButton(
                    text = "Blocked (${blockedRules.size})",
                    bgColor = if (showBlocked) StatusDnd else Surface2,
                    modifier = Modifier.weight(1f)
                ) { showBlocked = true }
            }
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .clip(RoundedCornerShape(18.dp))
                .background(Surface1)
                .border(1.dp, BorderColor, RoundedCornerShape(18.dp))
        ) {
            if (!showBlocked) {
                if (devices.isEmpty()) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text(
                            if (isConnected) "No active devices. Tap Refresh." else "Connect to scan devices.",
                            color = TextMuted,
                            fontSize = 13.sp
                        )
                    }
                } else {
                    LazyColumn(Modifier.fillMaxSize()) {
                        items(devices) { dev ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { onSelectDevice(dev) }
                                    .padding(horizontal = 16.dp, vertical = 14.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(40.dp)
                                        .clip(CircleShape)
                                        .background(Surface2),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(Icons.Rounded.Phone, null, tint = Accent, modifier = Modifier.size(20.dp))
                                }
                                Column(Modifier.weight(1f)) {
                                    Text(dev.hostName, color = TextMain, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                                    Text(
                                        "${dev.ipAddress}  •  ${dev.macAddress}",
                                        color = TextMuted,
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace
                                    )
                                }
                                Icon(Icons.Rounded.MoreVert, null, tint = TextMuted, modifier = Modifier.size(18.dp))
                            }
                            HorizontalDivider(color = BorderColor)
                        }
                    }
                }
            } else {
                if (blockedRules.isEmpty()) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text("No blocked MAC addresses.", color = TextMuted, fontSize = 13.sp)
                    }
                } else {
                    LazyColumn(Modifier.fillMaxSize()) {
                        items(blockedRules) { rule ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text(rule.name, color = TextMain, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                                    Text(
                                        rule.macAddress,
                                        color = StatusDnd,
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace
                                    )
                                }
                                IconButton(
                                    onClick = { onUnblock(rule) },
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(10.dp))
                                        .background(Surface2)
                                ) {
                                    Icon(Icons.Rounded.Delete, "Unblock", tint = StatusOnline, modifier = Modifier.size(18.dp))
                                }
                            }
                            HorizontalDivider(color = BorderColor)
                        }
                    }
                }
            }
        }
    }
}

// ======================= TAB 3: TERMINAL LOGS =======================
@Composable
fun LogsTab(
    logs: List<TerminalEntry>,
    onClear: () -> Unit,
    onInspectDsl: () -> Unit,
    onInspectWlan: () -> Unit
) {
    val listState = rememberLazyListState()
    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) listState.animateScrollToItem(logs.size - 1)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(bottom = 100.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StudioButton("DSL Rows", Surface2, Modifier.weight(1f), onClick = onInspectDsl)
            StudioButton("WLAN Keys", Surface2, Modifier.weight(1f), onClick = onInspectWlan)
            StudioButton("Clear", Surface2, Modifier.weight(0.7f), onClick = onClear)
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .clip(RoundedCornerShape(16.dp))
                .background(TerminalBg)
                .border(1.dp, TerminalBorder, RoundedCornerShape(16.dp))
                .padding(14.dp)
        ) {
            if (logs.isEmpty()) {
                Text(
                    "[READY] Standby for router API commands...",
                    color = TermTime,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp
                )
            } else {
                LazyColumn(state = listState, verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    items(logs) { entry ->
                        val msgColor = when (entry.type) {
                            LogType.SYS -> TermSys
                            LogType.OK -> TermOk
                            LogType.ERR -> TermErr
                            LogType.WARN -> TermWarn
                            LogType.ACT -> TermAct
                        }
                        Row {
                            Text("[${entry.time}] ", color = TermTime, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                            Text(
                                entry.text,
                                color = msgColor,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                fontWeight = if (entry.type == LogType.ERR) FontWeight.Bold else FontWeight.Normal
                            )
                        }
                    }
                }
            }
        }
    }
}

// ======================= TAB 4: SETUP =======================
@Composable
fun SetupTab(
    routerIp: String,
    onIpChange: (String) -> Unit,
    username: String,
    onUserChange: (String) -> Unit,
    password: String,
    onPassChange: (String) -> Unit,
    isConnected: Boolean,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onRebootRequest: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(bottom = 100.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        StudioCard {
            Text("Router Connection", color = TextMain, fontSize = 16.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(14.dp))

            StudioInputLabel("GATEWAY IP")
            StudioTextField(routerIp, onIpChange, "192.168.1.1")
            Spacer(Modifier.height(12.dp))

            StudioInputLabel("USERNAME")
            StudioTextField(username, onUserChange, "admin")
            Spacer(Modifier.height(12.dp))

            StudioInputLabel("PASSWORD")
            StudioTextField(password, onPassChange, "Router admin password", isPassword = true)
            Spacer(Modifier.height(16.dp))

            if (!isConnected) {
                StudioButton("Connect Router", Accent, onClick = onConnect)
            } else {
                StudioButton("Terminate Session", StatusDnd, onClick = onDisconnect)
            }
        }

        StudioCard {
            Text("System Status", color = TextMain, fontSize = 16.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(10.dp))
            Text(
                text = "• Status: ${if (isConnected) "Online & Authenticated" else "Offline"}\n" +
                    "• Model: ZXHN H108N V2.5\n" +
                    "• Transport: BouncyCastle TLS 1.0 Compact\n" +
                    "• Wi-Fi Binding: Enabled",
                color = TextMuted,
                fontSize = 12.sp,
                lineHeight = 22.sp
            )

            if (isConnected) {
                Spacer(Modifier.height(16.dp))
                OutlinedButton(
                    onClick = onRebootRequest,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, StatusDnd),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = StatusDnd)
                ) {
                    Icon(Icons.Rounded.Warning, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Reboot Router", fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

// ======================= DEVICE MODAL (KICK vs BLOCK) =======================
@Composable
fun DeviceActionModal(
    device: ConnectedDevice,
    onDismiss: () -> Unit,
    onKick: () -> Unit,
    onBlock: () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        StudioCard(cornerRadius = 24.dp) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Box(
                    modifier = Modifier
                        .size(70.dp)
                        .clip(CircleShape)
                        .background(BgBase)
                        .border(3.dp, Accent, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Rounded.Phone, null, tint = Accent, modifier = Modifier.size(32.dp))
                }
                Spacer(Modifier.height(10.dp))
                Text(device.hostName, color = TextMain, fontSize = 19.sp, fontWeight = FontWeight.Bold)
                Text(device.macAddress, color = TextMuted, fontSize = 12.sp, fontFamily = FontFamily.Monospace)

                Spacer(Modifier.height(14.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(BgBase)
                        .border(1.dp, BorderColor, RoundedCornerShape(12.dp))
                        .padding(14.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text("IP ADDRESS", color = TextMuted, fontSize = 10.sp)
                        Text(device.ipAddress, color = TextMain, fontSize = 13.sp, fontFamily = FontFamily.Monospace)
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        Text("LEASE TIME", color = TextMuted, fontSize = 10.sp)
                        Text(device.leaseTime, color = StatusOnline, fontSize = 13.sp, fontFamily = FontFamily.Monospace)
                    }
                }

                Spacer(Modifier.height(16.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StudioButton("Kick (8s)", StatusIdle, Modifier.weight(1f), onClick = onKick)
                    StudioButton("Block MAC", StatusDnd, Modifier.weight(1f), onClick = onBlock)
                }
                Spacer(Modifier.height(8.dp))
                StudioButton("Close", Surface2, onClick = onDismiss)
            }
        }
    }
}

// ======================= SHARED STUDIO UI COMPONENTS =======================
@Composable
fun FloatingBottomNav(
    activeTab: Int,
    onTabSelected: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    val items = listOf(
        Pair("Router", Icons.Rounded.Home),
        Pair("Wi-Fi", Icons.Rounded.Lock),
        Pair("Devices", Icons.Rounded.Phone),
        Pair("Logs", Icons.Rounded.Build),
        Pair("Setup", Icons.Rounded.Settings)
    )

    Row(
        modifier = modifier
            .shadow(20.dp, RoundedCornerShape(24.dp))
            .clip(RoundedCornerShape(24.dp))
            .background(Surface1.copy(alpha = 0.92f))
            .border(1.dp, BorderColor, RoundedCornerShape(24.dp))
            .padding(vertical = 10.dp, horizontal = 6.dp),
        horizontalArrangement = Arrangement.SpaceAround,
        verticalAlignment = Alignment.CenterVertically
    ) {
        items.forEachIndexed { index, (label, icon) ->
            val selected = activeTab == index
            Column(
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(14.dp))
                    .clickable { onTabSelected(index) }
                    .padding(vertical = 4.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(3.dp)
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = label,
                    tint = if (selected) Accent else TextMuted,
                    modifier = Modifier
                        .size(21.dp)
                        .offset(y = if (selected) (-2).dp else 0.dp)
                )
                Text(
                    text = label,
                    color = if (selected) TextMain else TextMuted,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }
}

@Composable
fun StudioCard(
    cornerRadius: Dp = 18.dp,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(cornerRadius))
            .background(Surface1)
            .border(1.dp, BorderColor, RoundedCornerShape(cornerRadius))
            .padding(18.dp),
        content = content
    )
}

@Composable
fun OverlayBlocker(text: String) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .clip(RoundedCornerShape(18.dp))
            .background(BgBase.copy(alpha = 0.78f))
            .clickable(enabled = false) {},
        contentAlignment = Alignment.Center
    ) {
        Text(text, color = TextMain, fontWeight = FontWeight.Bold, fontSize = 14.sp, textAlign = TextAlign.Center)
    }
}

@Composable
fun StudioInputLabel(text: String) {
    Text(
        text = text,
        color = TextMuted,
        fontSize = 11.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = 0.5.sp,
        modifier = Modifier.padding(bottom = 6.dp)
    )
}

@Composable
fun StudioTextField(
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String,
    isPassword: Boolean = false
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        placeholder = { Text(placeholder, color = TextMuted.copy(alpha = 0.6f), fontSize = 13.sp) },
        singleLine = true,
        visualTransformation = if (isPassword) PasswordVisualTransformation() else VisualTransformation.None,
        shape = RoundedCornerShape(12.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Accent,
            unfocusedBorderColor = Surface2,
            focusedContainerColor = BgBase,
            unfocusedContainerColor = BgBase,
            focusedTextColor = TextMain,
            unfocusedTextColor = TextMain,
            cursorColor = Accent
        ),
        modifier = Modifier.fillMaxWidth()
    )
}

@Composable
fun StudioButton(
    text: String,
    bgColor: Color,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Button(
        onClick = onClick,
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.buttonColors(containerColor = bgColor, contentColor = Color.White),
        modifier = modifier
            .fillMaxWidth()
            .height(46.dp)
    ) {
        Text(text, fontWeight = FontWeight.Bold, fontSize = 13.sp)
    }
}