
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
