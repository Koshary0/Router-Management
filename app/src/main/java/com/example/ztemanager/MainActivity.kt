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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.core.view.WindowCompat
import com.example.ztemanager.network.ConnectedDevice
import com.example.ztemanager.network.DslStats
import com.example.ztemanager.network.LogType
import com.example.ztemanager.network.ZteRouterClient
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

    var activeTab by remember { mutableIntStateOf(3) }
    var isConnected by remember { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(false) }
    var loaderMessage by remember { mutableStateOf("Connecting to Gateway...") }

    var routerIp by remember { mutableStateOf(prefs.getString("ip", "192.168.1.1") ?: "192.168.1.1") }
    var username by remember { mutableStateOf(prefs.getString("user", "admin") ?: "admin") }
    var password by remember { mutableStateOf(prefs.getString("pass", "") ?: "") }

    var dslStats by remember { mutableStateOf(DslStats()) }
    var devices by remember { mutableStateOf<List<ConnectedDevice>>(emptyList()) }
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

    fun formatSessionTime(sec: Long): String {
        val h = sec / 3600
        val m = (sec % 3600) / 60
        val s = sec % 60
        return String.format(Locale.US, "%02d:%02d:%02d", h, m, s)
    }

    fun connectAndSync() {
        scope.launch {
            prefs.edit()
                .putString("ip", routerIp)
                .putString("user", username)
                .putString("pass", password)
                .apply()

            isLoading = true
            loaderMessage = "Authenticating with ZXHN H108N V2.5..."
            val ok = routerClient.login(routerIp, username, password)
            if (ok) {
                isConnected = true
                loaderMessage = "Syncing DSL Telemetry & DHCP..."
                dslStats = routerClient.getDslStats()
                devices = routerClient.getConnectedDevices()
                activeTab = 0
            } else {
                isConnected = false
            }
            isLoading = false
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
                .padding(horizontal = 18.dp, vertical = 14.dp)
        ) {
            when (activeTab) {
                0 -> RouterStatusTab(
                    isConnected = isConnected,
                    routerIp = routerIp,
                    uptimeBadge = formatSessionTime(sessionSeconds),
                    stats = dslStats,
                    onRefresh = {
                        scope.launch {
                            isLoading = true
                            loaderMessage = "Refreshing DSL telemetry..."
                            dslStats = routerClient.getDslStats()
                            isLoading = false
                        }
                    }
                )
                1 -> DevicesTab(
                    isConnected = isConnected,
                    devices = devices,
                    onRefresh = {
                        scope.launch {
                            isLoading = true
                            loaderMessage = "Scanning connected devices..."
                            devices = routerClient.getConnectedDevices()
                            isLoading = false
                        }
                    },
                    onSelectDevice = { selectedDevice = it }
                )
                2 -> TerminalTab(
                    logs = terminalLogs,
                    onClear = { terminalLogs.clear() },
                    onDumpKeys = {
                        if (dslStats.rawMap.isEmpty()) {
                            addLog("NO CACHED KEYS YET - CONNECT FIRST", LogType.WARN)
                        } else {
                            addLog("--- RAW DSL KEYS (${dslStats.rawMap.size}) ---", LogType.ACT)
                            dslStats.rawMap.entries.take(30).forEach { (k, v) ->
                                addLog("$k = $v", LogType.SYS)
                            }
                        }
                    }
                )
                3 -> SettingsTab(
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
                        dslStats = DslStats()
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
                .padding(bottom = 18.dp)
                .fillMaxWidth(0.92f)
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
                    Text(
                        text = loaderMessage,
                        color = TextMuted,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
        }
    }

    selectedDevice?.let { dev ->
        DeviceActionModal(
            device = dev,
            onDismiss = { selectedDevice = null },
            onBlock = {
                scope.launch {
                    selectedDevice = null
                    isLoading = true
                    loaderMessage = "Sending MAC filter block rule..."
                    routerClient.blockMacAddress(dev.macAddress, dev.hostName)
                    isLoading = false
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
                    "Internet connection will drop for about 1 minute while the router restarts.",
                    color = TextMuted,
                    fontSize = 13.sp,
                    lineHeight = 20.sp
                )
                Spacer(Modifier.height(18.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    StudioButton(
                        text = "Cancel",
                        bgColor = Surface2,
                        modifier = Modifier.weight(1f),
                        onClick = { showRebootConfirm = false }
                    )
                    StudioButton(
                        text = "Reboot Now",
                        bgColor = StatusDnd,
                        modifier = Modifier.weight(1f),
                        onClick = {
                            showRebootConfirm = false
                            scope.launch {
                                isLoading = true
                                loaderMessage = "Transmitting reboot command..."
                                val ok = routerClient.rebootRouter()
                                if (ok) isConnected = false
                                isLoading = false
                            }
                        }
                    )
                }
            }
        }
    }
}

// ======================= Tab 1: Router Status =======================
@Composable
fun RouterStatusTab(
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
            .padding(bottom = 105.dp),
        verticalArrangement = Arrangement.spacedBy(15.dp)
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
                    .padding(vertical = 26.dp, horizontal = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Box(contentAlignment = Alignment.BottomEnd) {
                    Box(
                        modifier = Modifier
                            .size(92.dp)
                            .clip(CircleShape)
                            .background(BgBase)
                            .border(4.dp, Surface1, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Home,
                            contentDescription = null,
                            tint = if (isConnected) Accent else TextMuted,
                            modifier = Modifier.size(44.dp)
                        )
                    }
                    Box(
                        modifier = Modifier
                            .size(24.dp)
                            .clip(CircleShape)
                            .background(if (isConnected) StatusOnline else StatusOffline)
                            .border(4.dp, Surface1, CircleShape)
                    )
                }

                Spacer(Modifier.height(14.dp))
                Text(
                    text = if (isConnected) "ZXHN H108N V2.5" else "Disconnected",
                    color = TextMain,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.ExtraBold
                )
                Spacer(Modifier.height(6.dp))
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(20.dp))
                        .background(BgBase)
                        .padding(horizontal = 14.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = "GW: $routerIp",
                        color = TextMuted,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }

                if (isConnected) {
                    Spacer(Modifier.height(10.dp))
                    Row(
                        modifier = Modifier
                            .clip(RoundedCornerShape(20.dp))
                            .background(StatusOnline.copy(alpha = 0.15f))
                            .padding(horizontal = 14.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Icon(Icons.Rounded.CheckCircle, null, tint = StatusOnline, modifier = Modifier.size(14.dp))
                        Text(uptimeBadge, color = StatusOnline, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }

            if (!isConnected) {
                OverlayBlocker("Connect to router first")
            }
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
                        text = stats.status,
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
                    StatCell("DOWN ATTENUATION", stats.downAttnDb, TextMuted, Modifier.weight(1f))
                }

                Spacer(Modifier.height(16.dp))
                StudioButton(text = "Refresh Telemetry", bgColor = Accent, onClick = onRefresh)
            }

            if (!isConnected) {
                OverlayBlocker("Requires Connection")
            }
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

// ======================= Tab 2: Connected Devices =======================
@Composable
fun DevicesTab(
    isConnected: Boolean,
    devices: List<ConnectedDevice>,
    onRefresh: () -> Unit,
    onSelectDevice: (ConnectedDevice) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(bottom = 105.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        StudioCard {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text("Connected Devices (DHCP)", color = TextMain, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                    Text("Active clients: ${devices.size}", color = TextMuted, fontSize = 12.sp)
                }
                IconButton(
                    onClick = onRefresh,
                    enabled = isConnected,
                    modifier = Modifier
                        .clip(RoundedCornerShape(12.dp))
                        .background(Surface2)
                        .border(1.dp, BorderColor, RoundedCornerShape(12.dp))
                ) {
                    Icon(Icons.Rounded.Refresh, contentDescription = "Refresh", tint = if (isConnected) Accent else TextMuted)
                }
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
            if (devices.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        text = if (isConnected) "No devices found. Tap Refresh." else "Connect to router to scan devices.",
                        color = TextMuted,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            } else {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(devices) { device ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onSelectDevice(device) }
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
                            Column(modifier = Modifier.weight(1f)) {
                                Text(device.hostName, color = TextMain, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                                Text(
                                    text = "${device.ipAddress}  •  ${device.macAddress}",
                                    color = TextMuted,
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                            Icon(Icons.Rounded.MoreVert, null, tint = TextMuted, modifier = Modifier.size(18.dp))
                        }
                        HorizontalDivider(color = BorderColor, thickness = 1.dp)
                    }
                }
            }
        }
    }
}

// ======================= Tab 3: Terminal =======================
@Composable
fun TerminalTab(
    logs: List<TerminalEntry>,
    onClear: () -> Unit,
    onDumpKeys: () -> Unit
) {
    val listState = rememberLazyListState()

    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) listState.animateScrollToItem(logs.size - 1)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(bottom = 105.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            StudioButton(
                text = "Dump DSL Keys",
                bgColor = Surface2,
                modifier = Modifier.weight(1f),
                onClick = onDumpKeys
            )
            StudioButton(
                text = "Clear Log",
                bgColor = Surface2,
                modifier = Modifier.weight(0.6f),
                onClick = onClear
            )
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
                    text = "[READY] Standby for router API commands...",
                    color = TermTime,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp
                )
            } else {
                LazyColumn(
                    state = listState,
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    items(logs) { entry ->
                        val msgColor = when (entry.type) {
                            LogType.SYS -> TermSys
                            LogType.OK -> TermOk
                            LogType.ERR -> TermErr
                            LogType.WARN -> TermWarn
                            LogType.ACT -> TermAct
                        }
                        Row {
                            Text(
                                text = "[${entry.time}] ",
                                color = TermTime,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp
                            )
                            Text(
                                text = entry.text,
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

// ======================= Tab 4: Settings =======================
@Composable
fun SettingsTab(
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
            .padding(bottom = 105.dp),
        verticalArrangement = Arrangement.spacedBy(15.dp)
    ) {
        StudioCard {
            Text("Router Management", color = TextMain, fontSize = 16.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(14.dp))

            StudioInputLabel("GATEWAY IP")
            StudioTextField(value = routerIp, onValueChange = onIpChange, placeholder = "192.168.1.1")

            Spacer(Modifier.height(12.dp))
            StudioInputLabel("USERNAME")
            StudioTextField(value = username, onValueChange = onUserChange, placeholder = "admin")

            Spacer(Modifier.height(12.dp))
            StudioInputLabel("PASSWORD")
            StudioTextField(
                value = password,
                onValueChange = onPassChange,
                placeholder = "Router admin password",
                isPassword = true
            )

            Spacer(Modifier.height(16.dp))
            if (!isConnected) {
                StudioButton(text = "Connect Selected", bgColor = Accent, onClick = onConnect)
            } else {
                StudioButton(text = "Terminate Session", bgColor = StatusDnd, onClick = onDisconnect)
            }
        }

        StudioCard {
            Text("System Status", color = TextMain, fontSize = 16.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(10.dp))
            Text(
                text = "• Connection: ${if (isConnected) "Online & Connected" else "Offline"}\n" +
                        "• Target Model: ZXHN H108N V2.5\n" +
                        "• TLS Engine: BouncyCastle TLS 1.0 Native\n" +
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

// ======================= Device Action Modal =======================
@Composable
fun DeviceActionModal(
    device: ConnectedDevice,
    onDismiss: () -> Unit,
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
                        .size(74.dp)
                        .clip(CircleShape)
                        .background(BgBase)
                        .border(3.dp, Accent, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Rounded.Phone, null, tint = Accent, modifier = Modifier.size(34.dp))
                }
                Spacer(Modifier.height(10.dp))
                Text(device.hostName, color = TextMain, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                Text(
                    device.macAddress,
                    color = TextMuted,
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace
                )

                Spacer(Modifier.height(16.dp))
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
                StudioButton(text = "Block MAC Address", bgColor = StatusDnd, onClick = onBlock)
                Spacer(Modifier.height(8.dp))
                StudioButton(text = "Close", bgColor = Surface2, onClick = onDismiss)
            }
        }
    }
}

// ======================= Shared Studio Components =======================
@Composable
fun FloatingBottomNav(
    activeTab: Int,
    onTabSelected: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    val items = listOf(
        Pair("Router", Icons.Rounded.Home),
        Pair("Devices", Icons.Rounded.Phone),
        Pair("Terminal", Icons.Rounded.Build),
        Pair("Settings", Icons.Rounded.Settings)
    )

    Row(
        modifier = modifier
            .shadow(20.dp, RoundedCornerShape(24.dp))
            .clip(RoundedCornerShape(24.dp))
            .background(Surface1.copy(alpha = 0.92f))
            .border(1.dp, BorderColor, RoundedCornerShape(24.dp))
            .padding(vertical = 10.dp, horizontal = 8.dp),
        horizontalArrangement = Arrangement.SpaceAround,
        verticalAlignment = Alignment.CenterVertically
    ) {
        items.forEachIndexed { index, (label, icon) ->
            val selected = activeTab == index
            NavItem(
                label = label,
                icon = icon,
                selected = selected,
                modifier = Modifier.weight(1f),
                onClick = { onTabSelected(index) }
            )
        }
    }
}

@Composable
fun NavItem(
    label: String,
    icon: ImageVector,
    selected: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(14.dp))
            .clickable(onClick = onClick)
            .padding(vertical = 4.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(3.dp)
    ) {
        Icon(
            imageVector = icon,
            contentDescription = label,
            tint = if (selected) Accent else TextMuted,
            modifier = Modifier
                .size(22.dp)
                .offset(y = if (selected) (-2).dp else 0.dp)
        )
        Text(
            text = label,
            color = if (selected) TextMain else TextMuted,
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
fun StudioCard(
    cornerRadius: androidx.compose.ui.unit.Dp = 18.dp,
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
            .height(48.dp)
    ) {
        Text(text, fontWeight = FontWeight.Bold, fontSize = 14.sp)
    }
}