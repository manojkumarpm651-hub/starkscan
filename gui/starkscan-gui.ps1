<#
.SYNOPSIS
    Windows desktop front end for starkscan.

.DESCRIPTION
    This GUI does no scanning of its own. It collects options, runs the
    starkscan executable, and renders the JSON report it produces.

    That separation is deliberate: the scanning engine is a separate, tested
    process, so nothing in this file can change how a scan behaves or what it
    is allowed to read. The confinement guarantee still belongs entirely to the
    engine. If this GUI is deleted, the tool is unaffected.

    Uses only Windows Forms from the .NET Framework that ships with Windows -
    no modules to install, no network access, no elevation.

.NOTES
    Launch via starkscan-gui.cmd, which supplies the -STA apartment state that
    Windows Forms requires.
#>
[CmdletBinding()]
param(
    # Pre-populate the target list, so the GUI can be launched straight at a
    # folder from a shortcut or a "scan with starkscan" context-menu entry.
    [string[]]$Target,
    [string]$ExePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# --- palette ----------------------------------------------------------------
# Blues carry structure (header, grid, links); greens carry action (the Scan
# button, success states). Severity keeps its conventional red/amber scale:
# recolouring a CRITICAL finding to fit a theme would make the report lie.

function RGB([int]$r, [int]$g, [int]$b) { [System.Drawing.Color]::FromArgb($r, $g, $b) }

$script:Pal = @{
    Navy        = RGB 11  60  73    # header band
    NavyLight   = RGB 24  86 104
    Blue        = RGB 18 113 140    # structural accent
    BlueSoft    = RGB 227 240 244
    Green       = RGB 20 160 133    # primary action
    GreenHover  = RGB 23 184 150
    GreenDark   = RGB 15 128 106
    Page        = RGB 238 244 246   # window background
    Card        = RGB 255 255 255
    Border      = RGB 211 225 230
    Text        = RGB 23  38  43
    Muted       = RGB 92 123 134
    White       = RGB 255 255 255
    RowAlt      = RGB 248 251 252
    SelBack     = RGB 214 237 233
}

$script:SevColors = @{
    "CRITICAL" = @{ Fore = (RGB 140 33 24);  Back = (RGB 251 230 227) }
    "HIGH"     = @{ Fore = (RGB 150 79  10); Back = (RGB 252 238 221) }
    "MEDIUM"   = @{ Fore = (RGB 133 103 0);  Back = (RGB 251 245 220) }
    "LOW"      = @{ Fore = (RGB 18 113 140); Back = (RGB 227 240 244) }
    "INFO"     = @{ Fore = (RGB 92 123 134); Back = (RGB 238 244 246) }
}

function Get-SevStyle([string]$sev) {
    if ($script:SevColors.ContainsKey($sev)) { return $script:SevColors[$sev] }
    return @{ Fore = $script:Pal.Muted; Back = $script:Pal.Page }
}

function New-Font([single]$size, [string]$style = "Regular") {
    New-Object System.Drawing.Font("Segoe UI", $size, [System.Drawing.FontStyle]::$style)
}

# --- locate the engine -------------------------------------------------------

function Find-Engine {
    param([string]$Explicit)

    if ($Explicit -and (Test-Path -LiteralPath $Explicit)) { return (Resolve-Path -LiteralPath $Explicit).Path }

    $here = Split-Path -Parent $PSCommandPath
    $candidates = @(
        (Join-Path $here "starkscan.exe")
        (Join-Path $here "..\starkscan.exe")
        (Join-Path $here "..\dist\starkscan-windows-amd64.exe")
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return (Resolve-Path -LiteralPath $c).Path }
    }
    $onPath = Get-Command "starkscan.exe" -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    return $null
}

$script:Engine = Find-Engine -Explicit $ExePath
if (-not $script:Engine) {
    [System.Windows.Forms.MessageBox]::Show(
        "Could not find starkscan.exe.`n`nBuild it with build.ps1, or place the executable next to this script.",
        "starkscan", "OK", "Error") | Out-Null
    return
}

# --- argument quoting -------------------------------------------------------

# ProcessStartInfo.ArgumentList does not exist in .NET Framework, which is what
# Windows PowerShell 5.1 runs on, so the command line has to be built as a
# string. Getting that wrong is how a path like "Project Stark" turns into two
# arguments. This implements the exact quoting CommandLineToArgvW expects, so
# spaces, quotes, and trailing backslashes all survive intact.
function ConvertTo-ArgumentString {
    param([string[]]$Arguments)

    $parts = @()
    foreach ($a in $Arguments) {
        if ($a.Length -gt 0 -and $a -notmatch '[\s"]') {
            $parts += $a
            continue
        }
        $bs = [char]0x5C  # backslash, named so the escaping stays readable
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('"')
        $i = 0
        while ($i -lt $a.Length) {
            $backslashes = 0
            while ($i -lt $a.Length -and $a[$i] -eq $bs) { $backslashes++; $i++ }
            if ($i -ge $a.Length) {
                # Trailing backslashes must be doubled so they do not escape
                # the closing quote.
                [void]$sb.Append([string]$bs * ($backslashes * 2))
                break
            } elseif ($a[$i] -eq '"') {
                # An embedded quote needs its own escape, plus doubling of any
                # backslashes that immediately precede it.
                [void]$sb.Append([string]$bs * ($backslashes * 2 + 1))
                [void]$sb.Append('"')
                $i++
            } else {
                [void]$sb.Append([string]$bs * $backslashes)
                [void]$sb.Append($a[$i])
                $i++
            }
        }
        [void]$sb.Append('"')
        $parts += $sb.ToString()
    }
    return ($parts -join ' ')
}

# --- safe property access ---------------------------------------------------

# Under Set-StrictMode, reading .Name off an EMPTY property collection throws
# "The property 'Name' cannot be found on this object". That is exactly what a
# clean report produces: no findings means counts_by_severity is {}, so the
# summary code used to crash on the one outcome a user most wants to see.
#
# Indexing the collection by name returns $null when the property is absent,
# which is safe whether the object has many properties or none.
function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Test-Prop {
    param($Object, [string]$Name)
    $v = Get-Prop $Object $Name
    if ($null -eq $v) { return $false }
    # Checked by type rather than with "-ne ''": comparing an array against a
    # string filters it element by element, which builds a throwaway copy of
    # every finding just to answer a yes/no question.
    if ($v -is [string]) { return $v.Length -gt 0 }
    if ($v -is [array])  { return $v.Count -gt 0 }
    return $true
}

$script:Findings = @()
$script:LastReport = $null
$script:Proc = $null

# --- control factories -------------------------------------------------------

function New-Card {
    param([int]$X, [int]$Y, [int]$W, [int]$H, [string]$Anchor = "Top, Left")
    $p = New-Object System.Windows.Forms.Panel
    $p.Location = New-Object System.Drawing.Point($X, $Y)
    $p.Size = New-Object System.Drawing.Size($W, $H)
    $p.BackColor = $script:Pal.Card
    $p.Anchor = $Anchor
    $p.Padding = New-Object System.Windows.Forms.Padding(1)
    # A single hairline border reads cleaner than the sunken 3D frame.
    $p.Add_Paint({
        param($sender, $e)
        $pen = New-Object System.Drawing.Pen($script:Pal.Border, 1)
        $e.Graphics.DrawRectangle($pen, 0, 0, $sender.Width - 1, $sender.Height - 1)
        $pen.Dispose()
    })
    return $p
}

function New-CardTitle {
    param([string]$Text, [int]$X, [int]$Y)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text.ToUpper()
    $l.Location = New-Object System.Drawing.Point($X, $Y)
    $l.AutoSize = $true
    $l.Font = New-Font 8 "Bold"
    $l.ForeColor = $script:Pal.Blue
    return $l
}

function New-FlatButton {
    param(
        [string]$Text, [int]$X, [int]$Y, [int]$W, [int]$H,
        [string]$Kind = "secondary",   # primary | secondary | ghost
        [string]$Anchor = "Top, Left"
    )
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Location = New-Object System.Drawing.Point($X, $Y)
    $b.Size = New-Object System.Drawing.Size($W, $H)
    $b.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $b.Cursor = [System.Windows.Forms.Cursors]::Hand
    $b.Anchor = $Anchor
    $b.Font = New-Font 9

    switch ($Kind) {
        "primary" {
            $b.BackColor = $script:Pal.Green
            $b.ForeColor = $script:Pal.White
            $b.Font = New-Font 10 "Bold"
            $b.FlatAppearance.BorderSize = 0
            $b.Tag = @{ Idle = $script:Pal.Green; Hover = $script:Pal.GreenHover; Fore = $script:Pal.White }
        }
        "ghost" {
            $b.BackColor = $script:Pal.Card
            $b.ForeColor = $script:Pal.Blue
            $b.FlatAppearance.BorderSize = 1
            $b.FlatAppearance.BorderColor = $script:Pal.Border
            $b.Tag = @{ Idle = $script:Pal.Card; Hover = $script:Pal.BlueSoft; Fore = $script:Pal.Blue }
        }
        default {
            $b.BackColor = $script:Pal.BlueSoft
            $b.ForeColor = $script:Pal.Navy
            $b.FlatAppearance.BorderSize = 0
            $b.Tag = @{ Idle = $script:Pal.BlueSoft; Hover = (RGB 210 231 238); Fore = $script:Pal.Navy }
        }
    }

    $b.Add_MouseEnter({ if ($this.Enabled) { $this.BackColor = $this.Tag.Hover } })
    $b.Add_MouseLeave({ if ($this.Enabled) { $this.BackColor = $this.Tag.Idle } })
    $b.Add_EnabledChanged({
        if ($this.Enabled) {
            $this.BackColor = $this.Tag.Idle
            # The foreground has to be restored too. Muting it on disable and
            # not putting it back leaves the label unreadable once re-enabled.
            $this.ForeColor = $this.Tag.Fore
            $this.Cursor = [System.Windows.Forms.Cursors]::Hand
        } else {
            $this.BackColor = $script:Pal.Page
            $this.ForeColor = $script:Pal.Muted
            $this.Cursor = [System.Windows.Forms.Cursors]::Default
        }
    })
    return $b
}

# --- form --------------------------------------------------------------------

$form = New-Object System.Windows.Forms.Form
$form.Text = "starkscan"
$form.Size = New-Object System.Drawing.Size(1080, 760)
$form.MinimumSize = New-Object System.Drawing.Size(760, 520)
$form.StartPosition = "CenterScreen"
$form.Font = New-Font 9
$form.BackColor = $script:Pal.Page
$form.ForeColor = $script:Pal.Text

# Windows Forms scales the layout by the display DPI, so on a scaled or small
# display the designed size can exceed the screen. Clamping happens on Shown,
# after scaling has been applied, and re-centres whatever size survives.
$form.Add_Shown({
    $wa = [System.Windows.Forms.Screen]::FromControl($form).WorkingArea
    $w = [Math]::Min($form.Width, $wa.Width - 40)
    $h = [Math]::Min($form.Height, $wa.Height - 40)
    $form.Size = New-Object System.Drawing.Size($w, $h)
    $form.Location = New-Object System.Drawing.Point(
        [int]($wa.X + ($wa.Width - $w) / 2),
        [int]($wa.Y + ($wa.Height - $h) / 2))
    $form.Activate()
    if ($env:STARKSCAN_GUI_DIAG) {
        @(
            "form   : $($form.Left),$($form.Top) $($form.Width)x$($form.Height)"
            "work   : $($wa.X),$($wa.Y) $($wa.Width)x$($wa.Height)"
            "fits   : $(($form.Left -ge $wa.X) -and ($form.Left + $form.Width -le $wa.X + $wa.Width))"
        ) | Set-Content -LiteralPath $env:STARKSCAN_GUI_DIAG -Encoding utf8
    }
})

# ---- header band ------------------------------------------------------------

$header = New-Object System.Windows.Forms.Panel
$header.Location = New-Object System.Drawing.Point(0, 0)
$header.Size = New-Object System.Drawing.Size(1080, 74)
$header.Anchor = "Top, Left, Right"
$header.Add_Paint({
    param($sender, $e)
    $rect = New-Object System.Drawing.Rectangle(0, 0, $sender.Width, $sender.Height)
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $rect, $script:Pal.Navy, $script:Pal.NavyLight, 0.0)
    $e.Graphics.FillRectangle($brush, $rect)
    $brush.Dispose()
    # A green rule along the bottom ties the header to the action colour.
    $pen = New-Object System.Drawing.Pen($script:Pal.Green, 3)
    $e.Graphics.DrawLine($pen, 0, $sender.Height - 2, $sender.Width, $sender.Height - 2)
    $pen.Dispose()
})
$form.Controls.Add($header)

$title = New-Object System.Windows.Forms.Label
$title.Text = "starkscan"
$title.Location = New-Object System.Drawing.Point(22, 11)
$title.AutoSize = $true
$title.Font = New-Font 16 "Bold"
$title.ForeColor = $script:Pal.White
$title.BackColor = [System.Drawing.Color]::Transparent
$header.Controls.Add($title)

$subtitle = New-Object System.Windows.Forms.Label
$subtitle.Text = "Reads only the folders and files you select"
$subtitle.Location = New-Object System.Drawing.Point(25, 45)
$subtitle.AutoSize = $true
$subtitle.Font = New-Font 8.5
$subtitle.ForeColor = RGB 158 200 212
$subtitle.BackColor = [System.Drawing.Color]::Transparent
$header.Controls.Add($subtitle)

# ---- targets card -----------------------------------------------------------

$cardTargets = New-Card 16 90 630 150 "Top, Left, Right"
$form.Controls.Add($cardTargets)
$cardTargets.Controls.Add((New-CardTitle "Scan targets" 16 14))

$lstTargets = New-Object System.Windows.Forms.ListBox
$lstTargets.Location = New-Object System.Drawing.Point(16, 38)
$lstTargets.Size = New-Object System.Drawing.Size(460, 96)
$lstTargets.Anchor = "Top, Left, Right, Bottom"
$lstTargets.BorderStyle = "FixedSingle"
$lstTargets.Font = New-Font 9
$lstTargets.ForeColor = $script:Pal.Text
$lstTargets.HorizontalScrollbar = $true
$cardTargets.Controls.Add($lstTargets)

$btnAddFolder = New-FlatButton "Add folder"  488 38 126 28 "secondary" "Top, Right"
$btnAddFile   = New-FlatButton "Add file"    488 71 126 28 "secondary" "Top, Right"
$btnRemove    = New-FlatButton "Remove"      488 104 126 28 "ghost"    "Top, Right"
$cardTargets.Controls.AddRange(@($btnAddFolder, $btnAddFile, $btnRemove))

# ---- options card -----------------------------------------------------------

$cardOptions = New-Card 658 90 406 150 "Top, Right"
$form.Controls.Add($cardOptions)
$cardOptions.Controls.Add((New-CardTitle "Checks" 16 14))

$chkSecrets  = New-Object System.Windows.Forms.CheckBox
$chkMalware  = New-Object System.Windows.Forms.CheckBox
$chkTraits   = New-Object System.Windows.Forms.CheckBox
$chkExposure = New-Object System.Windows.Forms.CheckBox

$checkBoxes = @(
    @{ Ctl = $chkSecrets;  Text = "Secrets";  Id = "secrets";  X = 16;  Y = 36 },
    @{ Ctl = $chkMalware;  Text = "Malware";  Id = "malware";  X = 112; Y = 36 },
    @{ Ctl = $chkTraits;   Text = "Traits";   Id = "traits";   X = 208; Y = 36 },
    @{ Ctl = $chkExposure; Text = "Exposure"; Id = "exposure"; X = 296; Y = 36 }
)
foreach ($c in $checkBoxes) {
    $c.Ctl.Text = $c.Text
    $c.Ctl.Checked = $true
    $c.Ctl.Location = New-Object System.Drawing.Point($c.X, $c.Y)
    $c.Ctl.Size = New-Object System.Drawing.Size(92, 24)
    $c.Ctl.Tag = $c.Id
    $c.Ctl.ForeColor = $script:Pal.Text
    $c.Ctl.Cursor = [System.Windows.Forms.Cursors]::Hand
    $cardOptions.Controls.Add($c.Ctl)
}

$cardOptions.Controls.Add((New-CardTitle "Options" 16 70))

$lblSev = New-Object System.Windows.Forms.Label
$lblSev.Text = "Min severity"
$lblSev.Location = New-Object System.Drawing.Point(16, 96)
$lblSev.Size = New-Object System.Drawing.Size(74, 20)
$lblSev.ForeColor = $script:Pal.Muted
$cardOptions.Controls.Add($lblSev)

$cmbSeverity = New-Object System.Windows.Forms.ComboBox
$cmbSeverity.DropDownStyle = "DropDownList"
$cmbSeverity.Location = New-Object System.Drawing.Point(94, 93)
$cmbSeverity.Size = New-Object System.Drawing.Size(96, 24)
$cmbSeverity.FlatStyle = "Flat"
[void]$cmbSeverity.Items.AddRange(@("info", "low", "medium", "high", "critical"))
$cmbSeverity.SelectedItem = "low"
$cardOptions.Controls.Add($cmbSeverity)

$lblSize = New-Object System.Windows.Forms.Label
$lblSize.Text = "Max file MB"
$lblSize.Location = New-Object System.Drawing.Point(206, 96)
$lblSize.Size = New-Object System.Drawing.Size(74, 20)
$lblSize.ForeColor = $script:Pal.Muted
$cardOptions.Controls.Add($lblSize)

$numSize = New-Object System.Windows.Forms.NumericUpDown
$numSize.Location = New-Object System.Drawing.Point(284, 93)
$numSize.Size = New-Object System.Drawing.Size(70, 24)
$numSize.Minimum = 1
$numSize.Maximum = 4096
$numSize.Value = 32
$numSize.BorderStyle = "FixedSingle"
$cardOptions.Controls.Add($numSize)

$lblExclude = New-Object System.Windows.Forms.Label
$lblExclude.Text = "Exclude"
$lblExclude.Location = New-Object System.Drawing.Point(16, 124)
$lblExclude.Size = New-Object System.Drawing.Size(74, 20)
$lblExclude.ForeColor = $script:Pal.Muted
$cardOptions.Controls.Add($lblExclude)

$txtExclude = New-Object System.Windows.Forms.TextBox
$txtExclude.Location = New-Object System.Drawing.Point(94, 121)
$txtExclude.Size = New-Object System.Drawing.Size(260, 22)
$txtExclude.BorderStyle = "FixedSingle"
$cardOptions.Controls.Add($txtExclude)

$tip = New-Object System.Windows.Forms.ToolTip
$tip.SetToolTip($txtExclude, "Comma-separated globs or folder names, e.g. node_modules,*.iso`nNothing is excluded by default - skipping dependency folders is how a malicious package goes unnoticed.")

# ---- action bar -------------------------------------------------------------

$btnScan   = New-FlatButton "Scan"   16 254 130 38 "primary"
$btnCancel = New-FlatButton "Cancel" 154 254 96 38 "ghost"
$btnCancel.Enabled = $false
$form.Controls.AddRange(@($btnScan, $btnCancel))

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Location = New-Object System.Drawing.Point(264, 265)
$lblStatus.Size = New-Object System.Drawing.Size(520, 20)
$lblStatus.Anchor = "Top, Left, Right"
$lblStatus.ForeColor = $script:Pal.Muted
$lblStatus.Text = "Add a folder or file, then press Scan."
$form.Controls.Add($lblStatus)

$btnExportJson = New-FlatButton "Export JSON" 812 254 120 38 "ghost" "Top, Right"
$btnExportText = New-FlatButton "Export text" 940 254 120 38 "ghost" "Top, Right"
$btnExportJson.Enabled = $false
$btnExportText.Enabled = $false
$form.Controls.AddRange(@($btnExportJson, $btnExportText))

# ---- results ----------------------------------------------------------------

$cardResults = New-Card 16 306 1048 414 "Top, Bottom, Left, Right"
$form.Controls.Add($cardResults)

$split = New-Object System.Windows.Forms.SplitContainer
$split.Location = New-Object System.Drawing.Point(1, 1)
$split.Size = New-Object System.Drawing.Size(1046, 412)
$split.Anchor = "Top, Bottom, Left, Right"
$split.Orientation = "Horizontal"
$split.SplitterWidth = 6
$split.BackColor = $script:Pal.Border
$cardResults.Controls.Add($split)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = "Fill"
$grid.ReadOnly = $true
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $false
$grid.SelectionMode = "FullRowSelect"
$grid.MultiSelect = $false
$grid.RowHeadersVisible = $false
$grid.AutoSizeColumnsMode = "Fill"
$grid.BackgroundColor = $script:Pal.Card
$grid.BorderStyle = "None"
$grid.CellBorderStyle = "SingleHorizontal"
$grid.GridColor = RGB 234 241 244
$grid.EnableHeadersVisualStyles = $false
$grid.ColumnHeadersHeight = 34
$grid.ColumnHeadersBorderStyle = "None"
$grid.RowTemplate.Height = 28

$grid.ColumnHeadersDefaultCellStyle.BackColor = $script:Pal.Navy
$grid.ColumnHeadersDefaultCellStyle.ForeColor = $script:Pal.White
$grid.ColumnHeadersDefaultCellStyle.Font = New-Font 9 "Bold"
$grid.ColumnHeadersDefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
$grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $script:Pal.Navy

$grid.DefaultCellStyle.BackColor = $script:Pal.Card
$grid.DefaultCellStyle.ForeColor = $script:Pal.Text
$grid.DefaultCellStyle.SelectionBackColor = $script:Pal.SelBack
$grid.DefaultCellStyle.SelectionForeColor = $script:Pal.Text
$grid.DefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
$grid.AlternatingRowsDefaultCellStyle.BackColor = $script:Pal.RowAlt
$split.Panel1.Controls.Add($grid)

foreach ($col in @(
    @{ Name = "Severity"; Header = "SEVERITY"; Fill = 11 },
    @{ Name = "Rule";     Header = "RULE";     Fill = 9  },
    @{ Name = "Title";    Header = "FINDING";  Fill = 38 },
    @{ Name = "Path";     Header = "PATH";     Fill = 36 },
    @{ Name = "Line";     Header = "LINE";     Fill = 6  })) {
    $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $c.Name = $col.Name
    $c.HeaderText = $col.Header
    $c.FillWeight = $col.Fill
    # Rows arrive already ordered most-severe-first. Sorting the Severity
    # column alphabetically would scramble that into a meaningless order, so
    # that one column stays fixed while the rest sort freely.
    if ($col.Name -eq "Severity") {
        $c.SortMode = [System.Windows.Forms.DataGridViewColumnSortMode]::NotSortable
    }
    [void]$grid.Columns.Add($c)
}

$detail = New-Object System.Windows.Forms.Panel
$detail.Dock = "Fill"
$detail.BackColor = $script:Pal.Card
$detail.Padding = New-Object System.Windows.Forms.Padding(12, 10, 12, 10)
$split.Panel2.Controls.Add($detail)

$txtDetail = New-Object System.Windows.Forms.TextBox
$txtDetail.Dock = "Fill"
$txtDetail.Multiline = $true
$txtDetail.ReadOnly = $true
$txtDetail.BorderStyle = "None"
$txtDetail.BackColor = $script:Pal.Card
$txtDetail.ForeColor = $script:Pal.Text
$txtDetail.ScrollBars = "Vertical"
$txtDetail.Font = New-Object System.Drawing.Font("Consolas", 9.5)
$txtDetail.Text = "Select a finding to see its detail."
$detail.Controls.Add($txtDetail)

# --- behaviour ---------------------------------------------------------------

$btnAddFolder.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = "Choose a folder to scan"
    if ($dlg.ShowDialog() -eq "OK") {
        if (-not $lstTargets.Items.Contains($dlg.SelectedPath)) {
            [void]$lstTargets.Items.Add($dlg.SelectedPath)
        }
    }
})

$btnAddFile.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = "Choose one or more files to scan"
    $dlg.Multiselect = $true
    $dlg.Filter = "All files (*.*)|*.*"
    if ($dlg.ShowDialog() -eq "OK") {
        foreach ($f in $dlg.FileNames) {
            if (-not $lstTargets.Items.Contains($f)) { [void]$lstTargets.Items.Add($f) }
        }
    }
})

$btnRemove.Add_Click({
    if ($lstTargets.SelectedIndex -ge 0) { $lstTargets.Items.RemoveAt($lstTargets.SelectedIndex) }
})

$grid.Add_SelectionChanged({
    if ($grid.SelectedRows.Count -eq 0) { return }
    $idx = $grid.SelectedRows[0].Index
    if ($idx -lt 0 -or $idx -ge $script:Findings.Count) { return }
    $f = $script:Findings[$idx]

    $lines = @()
    $lines += "$($f.severity)   $($f.rule_id)   [$($f.check) check]"
    $lines += ("-" * 72)
    $lines += $f.title
    $lines += ""
    $loc = $f.path
    if (Test-Prop $f 'line') { $loc = "$loc : line $($f.line)" }
    $lines += "Location:  $loc"
    if (Test-Prop $f 'evidence') {
        $lines += "Evidence:  $($f.evidence)"
    }
    if (Test-Prop $f 'detail') {
        $lines += ""
        $lines += $f.detail
    }
    $txtDetail.Lines = $lines
})

$btnCancel.Add_Click({
    if ($script:Proc -and -not $script:Proc.HasExited) {
        try { $script:Proc.Kill() } catch { }
        $lblStatus.Text = "Scan cancelled."
    }
})

$btnScan.Add_Click({
    if ($lstTargets.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Add at least one folder or file to scan.", "starkscan", "OK", "Information") | Out-Null
        return
    }

    $selected = @()
    foreach ($c in $checkBoxes) { if ($c.Ctl.Checked) { $selected += $c.Ctl.Tag } }
    if ($selected.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Select at least one check to run.", "starkscan", "OK", "Information") | Out-Null
        return
    }

    $grid.Rows.Clear()
    $script:Findings = @()
    $script:LastReport = $null
    $txtDetail.Text = ""
    $btnScan.Enabled = $false
    $btnCancel.Enabled = $true
    $btnExportJson.Enabled = $false
    $btnExportText.Enabled = $false
    $lblStatus.ForeColor = $script:Pal.Blue
    $lblStatus.Text = "Scanning..."
    $form.Cursor = [System.Windows.Forms.Cursors]::AppStarting

    # The report goes to a temp file rather than a redirected pipe. A pipe
    # would deadlock the moment a large report filled the OS buffer while this
    # thread was waiting for the process to exit.
    $tmp = [System.IO.Path]::GetTempFileName()

    try {
        # Arguments are quoted with the CommandLineToArgvW rules, so a path
        # containing spaces or quotes reaches the engine as one argument.
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $script:Engine
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardError = $true

        $argv = @(
            "-format", "json",
            "-out", $tmp,
            "-min-severity", [string]$cmbSeverity.SelectedItem,
            "-max-file-size", [string]([int]$numSize.Value * 1MB),
            "-checks", ($selected -join ","),
            "-fail-on", "none",
            "-quiet"
        )
        if ($txtExclude.Text.Trim()) { $argv += @("-exclude", $txtExclude.Text.Trim()) }
        foreach ($t in $lstTargets.Items) { $argv += [string]$t }
        $psi.Arguments = ConvertTo-ArgumentString $argv

        $script:Proc = [System.Diagnostics.Process]::Start($psi)

        # Keep the window responsive (and the Cancel button live) while the
        # engine runs, instead of blocking the UI thread on WaitForExit.
        while (-not $script:Proc.HasExited) {
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Milliseconds 40
        }
        $stderr = $script:Proc.StandardError.ReadToEnd()
        $exit = $script:Proc.ExitCode

        if ($exit -eq 2) {
            $msg = if ($stderr) { $stderr.Trim() } else { "The scan could not be completed." }
            [System.Windows.Forms.MessageBox]::Show($msg, "starkscan", "OK", "Error") | Out-Null
            $lblStatus.ForeColor = $script:Pal.Muted
            $lblStatus.Text = "Scan failed."
            return
        }

        if (-not (Test-Path -LiteralPath $tmp)) {
            $lblStatus.Text = "Scan produced no report."
            return
        }

        $raw = Get-Content -LiteralPath $tmp -Raw -Encoding utf8
        if (-not $raw) { $lblStatus.Text = "Scan produced an empty report."; return }
        $report = $raw | ConvertFrom-Json
        $script:LastReport = $report

        $script:Findings = @()
        if (Test-Prop $report 'findings') {
            $script:Findings = @($report.findings)
        }

        $grid.SuspendLayout()
        foreach ($f in $script:Findings) {
            $lineText = ""
            if (Test-Prop $f 'line') { $lineText = [string]$f.line }
            $i = $grid.Rows.Add(@($f.severity, $f.rule_id, $f.title, $f.path, $lineText))
            # Only the severity cell is tinted. Colouring the whole row makes a
            # long report hard to read; a single strong chip keeps it scannable.
            $style = Get-SevStyle $f.severity
            $cell = $grid.Rows[$i].Cells["Severity"]
            $cell.Style.BackColor = $style.Back
            $cell.Style.ForeColor = $style.Fore
            $cell.Style.Font = New-Font 8.5 "Bold"
            $cell.Style.SelectionBackColor = $style.Back
            $cell.Style.SelectionForeColor = $style.Fore
        }
        $grid.ResumeLayout()

        $s = $report.stats
        $counts = @()
        foreach ($sev in @("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) {
            $n = Get-Prop $report.counts_by_severity $sev
            if ($null -ne $n) { $counts += "$n $sev" }
        }
        if ($counts.Count) {
            $lblStatus.ForeColor = $script:Pal.Text
            $summary = $counts -join ", "
        } else {
            $lblStatus.ForeColor = $script:Pal.GreenDark
            $summary = "no findings"
        }
        $lblStatus.Text = "$($s.files_scanned) files in $($report.duration_ms) ms   |   $summary"

        if ($s.paths_blocked_out_of_scope -gt 0) {
            $lblStatus.Text += "   |   $($s.paths_blocked_out_of_scope) link(s) out of scope refused"
        }

        $btnExportJson.Enabled = $script:Findings.Count -gt 0
        $btnExportText.Enabled = $script:Findings.Count -gt 0
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("$_", "starkscan", "OK", "Error") | Out-Null
        $lblStatus.ForeColor = $script:Pal.Muted
        $lblStatus.Text = "Scan failed."
    }
    finally {
        # The report can contain redacted secret fragments and full paths, so
        # the temp copy does not outlive the scan.
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        $script:Proc = $null
        $btnScan.Enabled = $true
        $btnCancel.Enabled = $false
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

$btnExportJson.Add_Click({
    if (-not $script:LastReport) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = "JSON report (*.json)|*.json"
    $dlg.FileName = "starkscan-report.json"
    if ($dlg.ShowDialog() -eq "OK") {
        $script:LastReport | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $dlg.FileName -Encoding utf8
        $lblStatus.Text = "Saved $($dlg.FileName)"
    }
})

$btnExportText.Add_Click({
    if (-not $script:Findings -or $script:Findings.Count -eq 0) { return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = "Text report (*.txt)|*.txt"
    $dlg.FileName = "starkscan-report.txt"
    if ($dlg.ShowDialog() -eq "OK") {
        $out = foreach ($f in $script:Findings) {
            $loc = $f.path
            if (Test-Prop $f 'line') { $loc = "${loc}:$($f.line)" }
            "[{0}] {1}  {2}`r`n    {3}`r`n" -f $f.severity, $f.rule_id, $f.title, $loc
        }
        $out | Set-Content -LiteralPath $dlg.FileName -Encoding utf8
        $lblStatus.Text = "Saved $($dlg.FileName)"
    }
})

$form.Add_FormClosing({
    if ($script:Proc -and -not $script:Proc.HasExited) {
        try { $script:Proc.Kill() } catch { }
    }
})

# Enter triggers Scan; Esc closes. Both are what a keyboard user expects.
$form.AcceptButton = $btnScan
$form.CancelButton = $null

foreach ($t in $Target) {
    if ([string]::IsNullOrWhiteSpace($t)) { continue }
    $resolved = $t
    try { $resolved = (Resolve-Path -LiteralPath $t -ErrorAction Stop).Path } catch { }
    if (-not $lstTargets.Items.Contains($resolved)) { [void]$lstTargets.Items.Add($resolved) }
}
if ($lstTargets.Items.Count -gt 0) {
    $lblStatus.Text = "$($lstTargets.Items.Count) target(s) loaded. Press Scan."
}

[void]$form.ShowDialog()
$form.Dispose()
