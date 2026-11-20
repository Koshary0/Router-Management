package com.example.ztemanager.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// الألوان الأساسية مطابقة لمتغيرات CSS في التصميم المرفق
val BgBase = Color(0xFF090A0F)
val Surface1 = Color(0xFF13151F)
val Surface2 = Color(0xFF1E2130)
val Accent = Color(0xFF5865F2)
val AccentHover = Color(0xFF4752C4)
val TextMain = Color(0xFFF2F3F5)
val TextMuted = Color(0xFF949BA4)
val BorderColor = Color(0x14FFFFFF) // rgba(255,255,255,0.08)

// ألوان الحالات
val StatusOnline = Color(0xFF23A559)
val StatusIdle = Color(0xFFF0B232)
val StatusDnd = Color(0xFFF23F43)
val StatusOffline = Color(0xFF80848E)

// ألوان الطرفية (Terminal)
val TerminalBg = Color(0xFF050505)
val TerminalBorder = Color(0xFF1A1A1A)
val TermTime = Color(0xFF5C6370)
val TermSys = Color(0xFF61AFEF)
val TermOk = Color(0xFF98C379)
val TermErr = Color(0xFFE06C75)
val TermWarn = Color(0xFFD19A66)
val TermAct = Color(0xFFC678DD)

private val StudioDarkColors = darkColorScheme(
    primary = Accent,
    onPrimary = Color.White,
    secondary = Surface2,
    onSecondary = TextMain,
    background = BgBase,
    onBackground = TextMain,
    surface = Surface1,
    onSurface = TextMain,
    error = StatusDnd,
    outline = BorderColor
)

@Composable
fun ZteStudioTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = StudioDarkColors,
        content = content
    )
}