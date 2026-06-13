
param(
    [string]$Title = "Trinetra Sentinel",
    [string]$Message = "Alert",
    [string]$Color = "#FF4444",
    [string]$Label = "CRITICAL",
    [int]$Duration = 6
)

Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase

$hexStyles = [System.Globalization.NumberStyles]::HexNumber
$r = [byte]::Parse($Color.Substring(1,2), $hexStyles)
$g = [byte]::Parse($Color.Substring(3,2), $hexStyles)
$b = [byte]::Parse($Color.Substring(5,2), $hexStyles)
$accentColor = [Windows.Media.Color]::FromRgb($r, $g, $b)
$accentBrush = [Windows.Media.SolidColorBrush]::new($accentColor)

$win = New-Object Windows.Window
$win.WindowStyle = 'None'
$win.AllowsTransparency = $true
$win.Background = [Windows.Media.Brushes]::Transparent
$win.Topmost = $true
$win.ShowInTaskbar = $false
$win.Width = 400
$win.Height = 140
$win.ResizeMode = 'NoResize'

$workArea = [Windows.SystemParameters]::WorkArea
$win.Left = $workArea.Width - 420
$win.Top = $workArea.Height - 160

$border = New-Object Windows.Controls.Border
$border.CornerRadius = [Windows.CornerRadius]::new(10)
$border.Background = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x1A, 0x1A, 0x2E))
$border.BorderBrush = $accentBrush
$border.BorderThickness = [Windows.Thickness]::new(2)
$border.Padding = [Windows.Thickness]::new(16, 12, 16, 12)

$stack = New-Object Windows.Controls.StackPanel

# Header row
$headerRow = New-Object Windows.Controls.StackPanel
$headerRow.Orientation = 'Horizontal'

$dot = New-Object Windows.Shapes.Ellipse
$dot.Width = 10
$dot.Height = 10
$dot.Fill = $accentBrush
$dot.Margin = [Windows.Thickness]::new(0, 0, 8, 0)
$dot.VerticalAlignment = 'Center'
$headerRow.Children.Add($dot) | Out-Null

$headerLabel = New-Object Windows.Controls.TextBlock
$headerLabel.Text = "TRINETRA SENTINEL - $Label"
$headerLabel.Foreground = $accentBrush
$headerLabel.FontSize = 11
$headerLabel.FontWeight = [Windows.FontWeights]::Bold
$headerLabel.VerticalAlignment = 'Center'
$headerRow.Children.Add($headerLabel) | Out-Null

$stack.Children.Add($headerRow) | Out-Null

# Title
$titleBlock = New-Object Windows.Controls.TextBlock
$titleBlock.Text = $Title
$titleBlock.Foreground = [Windows.Media.Brushes]::White
$titleBlock.FontSize = 14
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
$bodyBlock.MaxHeight = 60
$stack.Children.Add($bodyBlock) | Out-Null

$border.Child = $stack
$win.Content = $border

# Auto-close timer
$script:autoTimer = New-Object Windows.Threading.DispatcherTimer
$script:autoTimer.Interval = [TimeSpan]::FromSeconds($Duration)
$script:autoTimer.Add_Tick({
    $win.Close()
    $script:autoTimer.Stop()
})

$win.Add_Loaded({
    $script:autoTimer.Start()
})

$win.ShowDialog() | Out-Null
