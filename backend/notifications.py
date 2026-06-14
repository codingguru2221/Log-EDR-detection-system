import ctypes
import logging
import platform
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("trinetra.notifications")

# Severity-based cooldowns (seconds)
SEVERITY_COOLDOWNS = {
    "critical": 15,
    "high": 30,
    "medium": 60,
    "low": 120,
}

SEVERITY_COLORS = {
    "critical": "#FF4444",
    "high": "#FF8800",
    "medium": "#FFD700",
    "low": "#4488FF",
}

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "WARNING",
    "low": "INFO",
}

# PowerShell script: WPF styled popup with auto-close
_PS_WPF_POPUP = r'''
param(
    [string]$Title = "Trinetra Sentinel",
    [string]$Message = "Alert",
    [string]$Color = "#FF4444",
    [string]$Label = "CRITICAL",
    [int]$Duration = 6
)

Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase
Add-Type -AssemblyName System.Windows.Forms

$hexStyles = [System.Globalization.NumberStyles]::HexNumber
$r = [byte]::Parse($Color.Substring(1,2), $hexStyles)
$g = [byte]::Parse($Color.Substring(3,2), $hexStyles)
$b = [byte]::Parse($Color.Substring(5,2), $hexStyles)
$accentColor = [Windows.Media.Color]::FromRgb($r, $g, $b)
$accentBrush = [Windows.Media.SolidColorBrush]::new($accentColor)

# Determine icon based on severity
$iconChar = "!"
$iconFontSize = 16
if ($Label -eq "CRITICAL") { $iconChar = [char]0x26D4; $iconFontSize = 18 }
elseif ($Label -eq "HIGH") { $iconChar = [char]0x26A0; $iconFontSize = 18 }
elseif ($Label -eq "WARNING") { $iconChar = [char]0x26A1; $iconFontSize = 16 }
else { $iconChar = [char]0x2139; $iconFontSize = 16 }

$win = New-Object Windows.Window
$win.WindowStyle = 'None'
$win.AllowsTransparency = $true
$win.Background = [Windows.Media.Brushes]::Transparent
$win.Topmost = $true
$win.ShowInTaskbar = $false
$win.Width = 420
$win.Height = 160
$win.ResizeMode = 'NoResize'
$win.Opacity = 0
$win.WindowStartupLocation = 'Manual'

$workArea = [Windows.SystemParameters]::WorkArea
$win.Top = $workArea.Height - 180
$slideStart = $workArea.Width + 30
$slideEnd = $workArea.Width - 440
$win.Left = $slideStart

# Drop shadow
$shadow = New-Object Windows.Media.Effects.DropShadowEffect
$shadow.Color = [Windows.Media.Colors]::Black
$shadow.Opacity = 0.55
$shadow.BlurRadius = 28
$shadow.ShadowDepth = 5
$shadow.Direction = 270

# Outer grid for layering
$outerGrid = New-Object Windows.Controls.Grid

# Main card
$border = New-Object Windows.Controls.Border
$border.CornerRadius = [Windows.CornerRadius]::new(14)
$border.Background = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x1A, 0x1A, 0x2E))
$border.BorderBrush = $accentBrush
$border.BorderThickness = [Windows.Thickness]::new(1.5)
$border.Padding = [Windows.Thickness]::new(18, 18, 14, 14)
$border.Effect = $shadow

# Accent bar at top
$accentBar = New-Object Windows.Controls.Border
$accentBar.CornerRadius = [Windows.CornerRadius]::new(14, 14, 0, 0)
$accentBar.Height = 4
$accentBar.Background = $accentBrush
$accentBar.VerticalAlignment = 'Top'
$accentBar.HorizontalAlignment = 'Stretch'
$accentBar.IsHitTestVisible = $false

$stack = New-Object Windows.Controls.StackPanel

# Header row
$headerRow = New-Object Windows.Controls.Grid
$headerRow.Height = 24

$headerLeft = New-Object Windows.Controls.StackPanel
$headerLeft.Orientation = 'Horizontal'
$headerLeft.VerticalAlignment = 'Center'
$headerLeft.HorizontalAlignment = 'Left'

$headerIcon = New-Object Windows.Controls.TextBlock
$headerIcon.Text = $iconChar
$headerIcon.Foreground = $accentBrush
$headerIcon.FontSize = $iconFontSize
$headerIcon.FontWeight = [Windows.FontWeights]::Bold
$headerIcon.VerticalAlignment = 'Center'
$headerIcon.Margin = [Windows.Thickness]::new(0, 0, 8, 0)
$headerLeft.Children.Add($headerIcon) | Out-Null

$headerLabel = New-Object Windows.Controls.TextBlock
$headerLabel.Text = "TRINETRA SENTINEL — $Label"
$headerLabel.Foreground = $accentBrush
$headerLabel.FontSize = 11
$headerLabel.FontWeight = [Windows.FontWeights]::Bold
$headerLabel.VerticalAlignment = 'Center'
$headerLeft.Children.Add($headerLabel) | Out-Null

# Close button
$closeBtn = New-Object Windows.Controls.Button
$closeBtn.Content = [char]0x2715
$closeBtn.Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x88, 0x88, 0x99))
$closeBtn.Background = [Windows.Media.Brushes]::Transparent
$closeBtn.BorderThickness = [Windows.Thickness]::new(0)
$closeBtn.Width = 24
$closeBtn.Height = 24
$closeBtn.HorizontalAlignment = 'Right'
$closeBtn.VerticalAlignment = 'Center'
$closeBtn.Cursor = [Windows.Input.Cursors]::Hand
$closeBtn.FontSize = 13
$closeBtn.Padding = [Windows.Thickness]::new(0)
$closeBtn.Add_Click({ $win.Close(); $script:autoTimer.Stop() })
$closeBtn.Add_MouseEnter({ $closeBtn.Foreground = [Windows.Media.Brushes]::White })
$closeBtn.Add_MouseLeave({ $closeBtn.Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x88, 0x88, 0x99)) })

$headerRow.Children.Add($headerLeft) | Out-Null
$headerRow.Children.Add($closeBtn) | Out-Null

$stack.Children.Add($headerRow) | Out-Null

# Title
$titleBlock = New-Object Windows.Controls.TextBlock
$titleBlock.Text = $Title
$titleBlock.Foreground = [Windows.Media.Brushes]::White
$titleBlock.FontSize = 15
$titleBlock.FontWeight = [Windows.FontWeights]::SemiBold
$titleBlock.Margin = [Windows.Thickness]::new(0, 8, 0, 0)
$titleBlock.TextTrimming = 'CharacterEllipsis'
$stack.Children.Add($titleBlock) | Out-Null

# Body
$bodyBlock = New-Object Windows.Controls.TextBlock
$bodyBlock.Text = $Message
$bodyBlock.Foreground = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xAA, 0xAA, 0xBB))
$bodyBlock.FontSize = 12
$bodyBlock.TextWrapping = 'Wrap'
$bodyBlock.Margin = [Windows.Thickness]::new(0, 4, 0, 0)
$bodyBlock.MaxHeight = 54
$stack.Children.Add($bodyBlock) | Out-Null

# Animated progress bar
$progressTrack = New-Object Windows.Controls.Border
$progressTrack.Height = 3
$progressTrack.CornerRadius = [Windows.CornerRadius]::new(2)
$progressTrack.Background = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x2A, 0x2A, 0x40))
$progressTrack.Margin = [Windows.Thickness]::new(0, 10, 4, 0)

$progressFill = New-Object Windows.Controls.Border
$progressFill.CornerRadius = [Windows.CornerRadius]::new(2)
$progressFill.Background = $accentBrush
$progressFill.HorizontalAlignment = 'Left'
$progressFill.Width = 384

$progressTrack.Child = $progressFill
$stack.Children.Add($progressTrack) | Out-Null

$border.Child = $stack
$outerGrid.Children.Add($border) | Out-Null
$outerGrid.Children.Add($accentBar) | Out-Null
$win.Content = $outerGrid

# Animations
$fadeIn = New-Object Windows.Media.Animation.DoubleAnimation
$fadeIn.From = 0
$fadeIn.To = 1
$fadeIn.Duration = [Windows.Duration]::new([TimeSpan]::FromMilliseconds(250))
$fadeIn.EasingFunction = New-Object Windows.Media.Animation.QuadraticEase
$fadeIn.EasingFunction.EasingMode = 'EaseOut'

$slideIn = New-Object Windows.Media.Animation.DoubleAnimation
$slideIn.From = $slideStart
$slideIn.To = $slideEnd
$slideIn.Duration = [Windows.Duration]::new([TimeSpan]::FromMilliseconds(400))
$slideIn.EasingFunction = New-Object Windows.Media.Animation.QuadraticEase
$slideIn.EasingFunction.EasingMode = 'EaseOut'

$progressAnim = New-Object Windows.Media.Animation.DoubleAnimation
$progressAnim.From = 384
$progressAnim.To = 0
$progressAnim.Duration = [Windows.Duration]::new([TimeSpan]::FromSeconds($Duration))
$progressAnim.EasingFunction = New-Object Windows.Media.Animation.QuadraticEase
$progressAnim.EasingFunction.EasingMode = 'Linear'

$script:autoTimer = New-Object Windows.Threading.DispatcherTimer
$script:autoTimer.Interval = [TimeSpan]::FromSeconds($Duration)

$script:autoTimer.Add_Tick({
    # Fade out before close
    $fadeOut = New-Object Windows.Media.Animation.DoubleAnimation
    $fadeOut.From = 1
    $fadeOut.To = 0
    $fadeOut.Duration = [Windows.Duration]::new([TimeSpan]::FromMilliseconds(200))
    $fadeOut.EasingFunction = New-Object Windows.Media.Animation.QuadraticEase
    $fadeOut.EasingFunction.EasingMode = 'EaseIn'
    $fadeOut.Completed = { $win.Close() }
    $win.BeginAnimation([Windows.Window]::OpacityProperty, $fadeOut)
    $script:autoTimer.Stop()
})

$win.Add_Loaded({
    $win.BeginAnimation([Windows.Window]::OpacityProperty, $fadeIn)
    $win.BeginAnimation([Windows.Window]::LeftProperty, $slideIn)
    $progressFill.BeginAnimation([Windows.FrameworkElement]::WidthProperty, $progressAnim)
    $script:autoTimer.Start()
})

$win.ShowDialog() | Out-Null
'''

# PowerShell script: WinForms NotifyIcon balloon tip (fallback)
_PS_BALLOON_TIP = r'''
param(
    [string]$Title = "Trinetra Sentinel",
    [string]$Message = "Alert",
    [string]$Label = "CRITICAL",
    [int]$Duration = 5
)

Add-Type -AssemblyName System.Windows.Forms

$icon = [System.Drawing.SystemIcons]::Warning
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = $icon
$notify.Visible = $true
$notify.BalloonTipTitle = "TRINETRA SENTINEL - $Label"
$notify.BalloonTipText = "$Title`n$Message"
$notify.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
$notify.ShowBalloonTip($Duration * 1000)

Start-Sleep -Seconds ($Duration + 2)
$notify.Dispose()
'''


class NotificationHandler:
    def __init__(self):
        self.notification_log = Path(__file__).resolve().parent.parent / "notifications.log"
        self._setup_logging()
        self.last_notifications: dict[str, float] = {}
        self._ps_script_path: Path | None = None
        self._balloon_script_path: Path | None = None
        self._wpf_works: bool | None = None  # None = untested

    def _setup_logging(self):
        handler = logging.FileHandler(self.notification_log, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s"
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    def _ensure_wpf_script(self) -> Path:
        """Write the WPF popup script to .cache/ directory."""
        if self._ps_script_path is None or not self._ps_script_path.exists():
            cache_dir = Path(__file__).resolve().parent.parent / ".cache"
            cache_dir.mkdir(exist_ok=True)
            path = cache_dir / "trinetra_popup.ps1"
            path.write_text(_PS_WPF_POPUP, encoding="utf-8")
            self._ps_script_path = path
        return self._ps_script_path

    def _ensure_balloon_script(self) -> Path:
        """Write the balloon tip script to .cache/ directory."""
        if self._balloon_script_path is None or not self._balloon_script_path.exists():
            cache_dir = Path(__file__).resolve().parent.parent / ".cache"
            cache_dir.mkdir(exist_ok=True)
            path = cache_dir / "trinetra_balloon.ps1"
            path.write_text(_PS_BALLOON_TIP, encoding="utf-8")
            self._balloon_script_path = path
        return self._balloon_script_path

    def notify(self, event: dict):
        severity = event.get("severity", "low")
        event_type = event.get("event_type", "unknown")
        title = event.get("title", "Security Alert")
        summary = event.get("summary", "")

        # Cooldown check per severity
        cooldown = SEVERITY_COOLDOWNS.get(severity, 60)
        key = f"{event_type}:{title}"
        now = time.monotonic()
        if now - self.last_notifications.get(key, 0) < cooldown:
            return
        self.last_notifications[key] = now

        # Log to file
        self._log_notification(event)

        # Show OS notification
        self._show_notification(severity, title, summary)

    def _log_notification(self, event: dict):
        severity = event.get("severity", "low").upper()
        title = event.get("title", "Unknown")
        logger.info(f"[{severity}] {title} | {event.get('summary', '')[:120]}")

    def _show_notification(self, severity: str, title: str, message: str):
        """Show notification on a background thread (non-blocking)."""
        try:
            threading.Thread(
                target=self._dispatch_notification,
                args=(severity, title, message),
                daemon=True,
            ).start()
        except Exception as e:
            logger.error(f"Failed to dispatch notification: {e}")

    def _dispatch_notification(self, severity: str, title: str, message: str):
        if platform.system() != "Windows":
            logger.info(f"[{severity.upper()}] {title}: {message[:80]}")
            return

        # Play system sound for critical/high alerts
        if severity in ("critical", "high"):
            self._play_alert_sound(severity)

        # Try WPF popup first
        if self._wpf_works is not False:
            success = self._show_wpf_popup(severity, title, message)
            if success:
                self._wpf_works = True
                return

        # Fallback: WinForms balloon tip
        self._wpf_works = False
        self._show_balloon_tip(severity, title, message)

    def _show_wpf_popup(self, severity: str, title: str, message: str) -> bool:
        """Show a WPF popup window. Returns True on success."""
        try:
            color = SEVERITY_COLORS.get(severity, "#4488FF")
            label = SEVERITY_LABEL.get(severity, "ALERT")
            duration = 8 if severity == "critical" else 6

            ps_path = self._ensure_wpf_script()

            proc = subprocess.Popen(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-File", str(ps_path),
                    "-Title", title,
                    "-Message", message[:200],
                    "-Color", color,
                    "-Label", label,
                    "-Duration", str(duration),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait briefly to check for immediate errors
            try:
                stdout, stderr = proc.communicate(timeout=2)
                if proc.returncode != 0:
                    err_msg = stderr.decode("utf-8", errors="replace")[:200]
                    logger.warning(f"WPF popup failed (rc={proc.returncode}): {err_msg}")
                    return False
            except subprocess.TimeoutExpired:
                # Good — process is still running (popup is displayed)
                pass

            logger.info(f"WPF popup sent: [{severity.upper()}] {title}")
            return True

        except Exception as e:
            logger.debug(f"WPF popup error: {type(e).__name__}: {e}")
            return False

    def _show_balloon_tip(self, severity: str, title: str, message: str):
        """Fallback: WinForms NotifyIcon balloon tip notification."""
        try:
            label = SEVERITY_LABEL.get(severity, "ALERT")
            duration = 8 if severity == "critical" else 6

            ps_path = self._ensure_balloon_script()

            subprocess.Popen(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-File", str(ps_path),
                    "-Title", title,
                    "-Message", message[:200],
                    "-Label", label,
                    "-Duration", str(duration),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info(f"Balloon tip sent: [{severity.upper()}] {title}")

        except Exception as e:
            logger.error(f"Balloon tip failed: {type(e).__name__}: {e}")

    @staticmethod
    def _play_alert_sound(severity: str):
        """Play a system alert sound using Windows API (non-blocking)."""
        try:
            if severity == "critical":
                ctypes.windll.user32.MessageBeep(0x00000010)  # MB_ICONHAND
            elif severity == "high":
                ctypes.windll.user32.MessageBeep(0x00000030)  # MB_ICONEXCLAMATION
            else:
                ctypes.windll.user32.MessageBeep(0x00000040)  # MB_ICONINFORMATION
        except Exception:
            pass


_notification_handler: NotificationHandler | None = None


def get_notification_handler() -> NotificationHandler:
    global _notification_handler
    if _notification_handler is None:
        _notification_handler = NotificationHandler()
    return _notification_handler


def notify(event: dict):
    """Send a notification for a security event."""
    get_notification_handler().notify(event)


def notify_critical(title: str, message: str):
    """Send a critical notification."""
    get_notification_handler().notify({
        "severity": "critical",
        "title": title,
        "summary": message,
        "event_type": "manual_critical",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


def notify_high(title: str, message: str):
    """Send a high-severity notification."""
    get_notification_handler().notify({
        "severity": "high",
        "title": title,
        "summary": message,
        "event_type": "manual_high",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
