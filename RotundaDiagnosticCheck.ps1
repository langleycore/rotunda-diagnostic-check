# Rotunda laptop check. IDS / FDRS / FJDS / VCI Manager / VMS.
# Read only. Double-click Rotunda Diagnostic Check.exe.
# Days = how far back to read the logs. NoPause skips the Enter prompt.

#Requires -Version 5.1
param(
    [int]$Days = 14,
    [switch]$NoPause,
    [string]$ReportFolder
)

$ErrorActionPreference = 'Continue'

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Specs = New-Object System.Collections.Generic.List[string]
$script:FirewallStatus = New-Object System.Collections.Generic.List[string]
$script:NetworkStatus = New-Object System.Collections.Generic.List[string]
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

function Add-Finding {
    param($Level, $Section, $Text, $Fix)
    if (-not $Fix) { $Fix = '' }
    $script:Findings.Add([pscustomobject]@{
        Level = $Level
        Section = $Section
        Text = $Text
        Fix = $Fix
    }) | Out-Null
}

function Add-Spec {
    param([string]$Text)
    $script:Specs.Add($Text) | Out-Null
}

function Get-UninstallEntries {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $rows = @()
    foreach ($p in $paths) {
        $rows += Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }
    }
    return $rows
}

function Test-Tcp {
    param(
        [string]$Target,
        [int]$Port,
        [int]$TimeoutMs = 5000
    )
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($Target, $Port, $null, $null)
        $done = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $done) {
            return $false
        }
        $client.EndConnect($iar) | Out-Null
        return $true
    }
    catch {
        return $false
    }
    finally {
        if ($client) { $client.Close() }
    }
}

function Get-CmErrorText {
    param([int]$Code)
    # codes we actually see on a VCM
    $map = @{
        1  = 'Device is not configured correctly.'
        10 = 'Device cannot start. Usually a driver problem.'
        14 = 'Needs a restart before it will work.'
        18 = 'Drivers need to be reinstalled.'
        22 = 'Device is disabled in Device Manager.'
        28 = 'No driver installed.'
        31 = 'Device is not working properly.'
        32 = 'A driver service for this device is missing or disabled.'
        37 = 'Windows could not initialize the driver.'
        39 = 'Driver is missing or damaged.'
        43 = 'Windows stopped the device because the device reported a problem.'
        47 = 'Device was ejected / prepared for removal.'
        48 = 'Driver was blocked. On these laptops that is usually Core isolation (Memory integrity).'
        52 = 'Driver signature was rejected. Same story as a Code 52 in Device Manager, often Memory integrity or a blocked Ford USB driver.'
    }
    if ($map.ContainsKey($Code)) { return $map[$Code] }
    return "Device Manager error code $Code."
}

function Get-J2534 {
    $roots = @(
        @{ Path = 'HKLM:\SOFTWARE\PassThruSupport.04.04';            Bits = '64-bit' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\PassThruSupport.04.04'; Bits = '32-bit' }
    )
    $list = @()
    foreach ($root in $roots) {
        if (-not (Test-Path $root.Path)) { continue }
        foreach ($vendor in (Get-ChildItem $root.Path -ErrorAction SilentlyContinue)) {
            $kids = @(Get-ChildItem $vendor.PSPath -ErrorAction SilentlyContinue)
            if ($kids.Count -eq 0) {
                $props = Get-ItemProperty $vendor.PSPath -ErrorAction SilentlyContinue
                $list += [pscustomobject]@{
                    Bits   = $root.Bits
                    Vendor = $vendor.PSChildName
                    Device = $vendor.PSChildName
                    Name   = [string]$props.Name
                    Dll    = [string]$props.FunctionLibrary
                }
                continue
            }
            foreach ($dev in $kids) {
                $props = Get-ItemProperty $dev.PSPath -ErrorAction SilentlyContinue
                $list += [pscustomobject]@{
                    Bits   = $root.Bits
                    Vendor = $vendor.PSChildName
                    Device = $dev.PSChildName
                    Name   = [string]$props.Name
                    Dll    = [string]$props.FunctionLibrary
                }
            }
        }
    }
    return $list
}

function Get-MatchingEvents {
    param(
        [string]$LogName,
        [datetime]$Start,
        [string]$Pattern,
        [int]$Max = 400
    )
    $hits = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $LogName
            StartTime = $Start
            Level     = 2, 3
        } -MaxEvents $Max -ErrorAction Stop
    }
    catch {
        return $hits
    }
    foreach ($ev in $events) {
        $msg = $ev.Message
        if (-not $msg) { continue }
        if ($msg -notmatch $Pattern) { continue }
        $hits += [pscustomobject]@{
            Time    = $ev.TimeCreated
            Id      = $ev.Id
            Provider = $ev.ProviderName
            Message = (($msg -replace '\s+', ' ').Trim())
        }
    }
    return $hits
}

function Get-SecurityBlocks {
    param(
        [datetime]$Start,
        [string]$Pattern
    )
    # 5152 packet blocked, 5157 connection blocked, 5031 app blocked.
    # These only exist if Windows was already writing them.
    $hits = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 5031, 5152, 5157
            StartTime = $Start
        } -MaxEvents 300 -ErrorAction Stop
    }
    catch {
        return $hits
    }
    foreach ($ev in $events) {
        $msg = $ev.Message
        if (-not $msg) { continue }
        if ($msg -notmatch $Pattern) { continue }
        $hits += [pscustomobject]@{
            Time     = $ev.TimeCreated
            Id       = $ev.Id
            Provider = 'Security'
            Message  = (($msg -replace '\s+', ' ').Trim())
        }
    }
    return $hits
}

function Get-ResultFolder {
    if ($ReportFolder) { return $ReportFolder.TrimEnd('\') }
    if ($env:ROTUNDA_DIR) { return $env:ROTUNDA_DIR.TrimEnd('\') }
    if ($PSScriptRoot) { return $PSScriptRoot }
    $desk = [Environment]::GetFolderPath('Desktop')
    if ($desk) { return $desk }
    return $env:TEMP
}

function Get-OsCheck {
    Write-Host 'Checking Windows version...'
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $os = Get-CimInstance Win32_OperatingSystem
    $build = [int]$cv.CurrentBuild
    $edition = [string]$cv.EditionID
    $verLabel = $cv.DisplayVersion
    if (-not $verLabel) { $verLabel = $cv.ReleaseId }
    $ubr = $cv.UBR
    $arch = $os.OSArchitecture
    $caption = $os.Caption

    $buildText = "$caption, $arch"
    if ($verLabel) { $buildText += ", $verLabel" }
    $buildText += " (build $build.$ubr)"
    Add-Spec $buildText

    $isHome = $edition -match '^(Core|CoreN|CoreSingleLanguage|CoreCountrySpecific)$'
    $proLike = $edition -match 'Professional|Enterprise|Education|ServerRdsh|IoTEnterprise|CloudEdition'
    $isServer = $os.ProductType -ne 1
    $isWin11 = $build -ge 22000
    $isWin10 = ($build -ge 10240 -and $build -lt 22000)

    if ($arch -notmatch '64') {
        Add-Finding Problem 'Windows' 'This Windows is not 64-bit. IDS and FDRS are 64-bit installs. A 32-bit laptop will not run them.' 'Use a 64-bit Windows install.'
    }

    if ($isServer) {
        Add-Finding Problem 'Windows' 'This is Windows Server. The Ford diagnostic software is written for a shop laptop, not a server.' 'Install it on Windows 10 Pro or Windows 11 Pro on the bay PC.'
    }
    elseif ($isHome) {
        $which = 'Windows 10'
        if ($isWin11) { $which = 'Windows 11' }
        Add-Finding Problem 'Windows' "$which Home is on this PC. Ford's published requirement is Windows 10 Professional, 64-bit. Home is missing components the installer and the VCM driver expect, and Ford support stops when they hear Home." 'Put Windows 10 Pro or Windows 11 Pro on the laptop that runs IDS and FDRS.'
    }
    elseif ($isWin11) {
        $edNote = $edition
        if (-not $edNote) { $edNote = 'this edition' }
        Add-Finding Ok 'Windows' "Windows 11 ($edNote), 64-bit."
    }
    elseif ($isWin10 -and $proLike) {
        Add-Finding Ok 'Windows' "Windows 10, 64-bit, edition $edition. That matches the operating system Ford publishes for IDS and FDRS."
        if ($build -lt 19041) {
            Add-Finding Check 'Windows' "This Windows 10 build ($build) is old. Current VCI drivers and FDRS installers are built against newer Windows 10. Bring it to 22H2 before fighting the Ford installer." 'Update Windows 10 to 22H2, reboot, then install VCI Software and the diagnostic programs.'
        }
    }
    elseif ($build -lt 10240) {
        Add-Finding Problem 'Windows' "This is older than Windows 10 ($caption). Current IDS, FDRS, and VCI Manager are not built for it. Ford also says an in-place upgrade of an old Windows onto Windows 10 is not a supported base. They want a clean Windows 10 Pro install." 'Clean-install Windows 10 Pro 64-bit. Do not upgrade this Windows in place and then load IDS on top.'
    }
    else {
        Add-Finding Check 'Windows' "Windows edition is '$edition' ($caption). Ford's sheet calls out Windows 10 Professional specifically. If this is Pro under a different edition name, you are fine. If it is a locked-down or education image, the installer may be blocked by policy." 'Confirm this is a normal Pro or Enterprise image, not Windows in S mode.'
    }

    if (Test-Path "$env:SystemRoot\Windows.old") {
        Add-Finding Check 'Windows' 'Windows.old is still on the disk, so this PC was upgraded in place. Ford''s IDS requirement page says upgrading an older Windows to Windows 10 is not supported. Strange install failures after an upgrade are what that note is about.' 'If IDS or the VCM driver keeps failing on this image, the fix Ford recognizes is a clean Windows 10 Pro install, not another repair of the upgrade.'
    }

    try {
        $we = (Get-WindowsEdition -Online -ErrorAction Stop).Edition
        if ($we -match 'Cloud' -or $caption -match '\bS\b' -or $edition -match 'Cloud') {
            Add-Finding Problem 'Windows' "Windows is in S mode ($we). S mode will not allow the Ford installers or the VCM driver to install." 'Switch out of S mode before installing. That switch is one-way.'
        }
    }
    catch { }
}

function Get-HardwareCheck {
    Write-Host 'Checking processor, memory, disk, and USB...'
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $cs = Get-CimInstance Win32_ComputerSystem
    $name = ([string]$cpu.Name).Trim()
    $cores = $cpu.NumberOfCores
    $mhz = [int]$cpu.MaxClockSpeed
    $ramGb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    $model = ('{0} {1}' -f $cs.Manufacturer, $cs.Model).Trim()

    Add-Spec "PC: $model"
    Add-Spec ("CPU: {0} ({1} cores, reported base {2} MHz)" -f $name, $cores, $mhz)
    Add-Spec "Memory: $ramGb GB"

    $vm = $false
    if ($cs.Model -match 'Virtual|VMware|VirtualBox|KVM|HVM' -or $cs.Manufacturer -match 'VMware|innotek|QEMU|Xen|Parallels') {
        $vm = $true
    }
    if ($cs.Manufacturer -eq 'Microsoft Corporation' -and $cs.Model -match 'Virtual') {
        $vm = $true
    }
    if ($vm) {
        Add-Finding Problem 'This PC' 'This Windows is a virtual machine. The VCM / VCMM / VCM3 USB driver does not survive USB passthrough. The installer may finish and the interface will still never stay connected.' 'Install IDS, FDRS, and VCI Manager on the Windows that is installed directly on the laptop, not in a VM.'
    }

    if ($cpu.Architecture -eq 12) {
        Add-Finding Problem 'This PC' 'This is an ARM processor. Ford''s diagnostic software and the VCM drivers are regular Intel/AMD programs. They will not run here.' 'Use an Intel or AMD 64-bit laptop.'
    }

    $lowCpu = $name -match 'Celeron|Pentium|Atom|Athlon Silver|Sempron'
    $i3 = $name -match '\bi3\b' -or $name -match 'Core\(TM\) i3' -or $name -match 'Core i3'
    $goodIntel = $name -match 'i5|i7|i9|Xeon|Core Ultra'
    $goodAmd = $name -match 'Ryzen [5-9]'
    $gen = $null
    if ($name -match '(?:i[3579]|Ryzen)-(\d{4,5})') {
        $digits = $Matches[1]
        if ($digits.Length -ge 5) { $gen = [int]$digits.Substring(0, 2) }
        else { $gen = [int]$digits.Substring(0, 1) }
    }
    elseif ($name -match '(\d+)(?:st|nd|rd|th) Gen') {
        $gen = [int]$Matches[1]
    }

    if ($lowCpu) {
        Add-Finding Problem 'This PC' "Processor is $name. Ford asks for an Intel Core i5 or i7 around 2.4 GHz. A Celeron, Pentium, or Atom will install slowly and then time out while programming a module. It gets blamed on the car." 'Use a laptop with a Core i5 / i7 or a Ryzen 5 / 7.'
    }
    elseif ($i3) {
        Add-Finding Check 'This PC' "Processor is $name. That is below the i5/i7 Ford lists. IDS may limp along. FDRS module downloads are where this CPU falls behind." 'An i5 or better is the spec. An i3 is a "try it" not a bay PC.'
    }
    elseif ($goodIntel -or $goodAmd) {
        $genText = ''
        if ($gen) { $genText = " Generation looks like $gen." }
        if ($gen -and $gen -lt 8 -and $goodIntel) {
            Add-Finding Check 'This PC' "Processor is $name.$genText Fine for older IDS. The 2024 FDRS dealer sheet asks for a 10th gen Intel Core i5 or equivalent, plus 16 GB of RAM. Programming will be slower on this CPU than Ford's current sheet." 'Usable for IDS. For daily FDRS programming, a newer i5 and 16 GB matches what Ford posted.'
        }
        elseif ($goodAmd) {
            Add-Finding Ok 'This PC' "Processor is $name. Ford's older sheet says Intel. The later FDRS bulletin says i5 10th gen or equivalent, and a current Ryzen 5/7 meets that in practice."
        }
        else {
            Add-Finding Ok 'This PC' "Processor is $name.$genText That is in the range Ford describes."
        }
    }
    else {
        Add-Finding Check 'This PC' "Processor is $name. Could not match it to the i5/i7 line Ford lists. If this is a recent desktop CPU it is probably fine. If it is a low-power part, FDRS will struggle." 'Compare the CPU to Core i5 10th gen before you commit this PC to a bay.'
    }

    if ($ramGb -lt 8) {
        Add-Finding Problem 'This PC' "Only $ramGb GB of RAM is installed. IDS minimum on the old sheet is 4 GB and the recommended number is 8 GB. FDRS dealer guidance is 16 GB. Under 8 GB, the installer and the session both get killed by Windows when memory runs out." 'Install at least 16 GB before using this PC for FDRS. 8 GB is the floor for IDS.'
    }
    elseif ($ramGb -lt 16) {
        Add-Finding Check 'This PC' "RAM is $ramGb GB. Enough for IDS (Ford's recommended number there is 8 GB). The 2024 FDRS sheet asks for 16 GB. Short RAM shows up as FDRS freezing while it downloads a module, not as a clear error." 'Add RAM up to 16 GB if this laptop is used for programming.'
    }
    else {
        Add-Finding Ok 'This PC' "RAM is $ramGb GB. That meets the 16 GB FDRS dealer recommendation."
    }

    $sysDrive = $env:SystemDrive
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$sysDrive'" -ErrorAction SilentlyContinue
    $freeGb = $null
    $sizeGb = $null
    if ($disk) {
        $freeGb = [math]::Round($disk.FreeSpace / 1GB, 1)
        $sizeGb = [math]::Round($disk.Size / 1GB, 1)
    }

    $media = 'unknown'
    $health = $null
    $physSizeGb = $null
    try {
        $letter = $sysDrive.TrimEnd(':')
        $part = Get-Partition -DriveLetter $letter -ErrorAction Stop
        $phys = Get-Disk -Number $part.DiskNumber -ErrorAction Stop | Get-PhysicalDisk -ErrorAction Stop
        $media = [string]$phys.MediaType
        $health = [string]$phys.HealthStatus
        if ($phys.Size) { $physSizeGb = [math]::Round($phys.Size / 1GB, 0) }
    }
    catch {
        try {
            $physList = @(Get-CimInstance -Namespace root\microsoft\windows\storage -ClassName MSFT_PhysicalDisk -ErrorAction Stop)
            if ($physList.Count -eq 1) {
                switch ([int]$physList[0].MediaType) {
                    3 { $media = 'HDD' }
                    4 { $media = 'SSD' }
                    5 { $media = 'SCM' }
                    default { $media = 'unspecified' }
                }
                $health = [string]$physList[0].HealthStatus
            }
        }
        catch { }
    }

    if ($null -ne $freeGb) {
        $mediaLabel = $media
        if (-not $mediaLabel) { $mediaLabel = 'unknown type' }
        $sizeLabel = $sizeGb
        if ($physSizeGb) { $sizeLabel = $physSizeGb }
        Add-Spec ("Disk {0} {1}, {2} GB, {3} GB free" -f $sysDrive, $mediaLabel, $sizeLabel, $freeGb)
    }

    if ($health -and $health -ne 'Healthy' -and $health -ne '0') {
        Add-Finding Problem 'This PC' "The system disk health is '$health'. A failing disk turns a Ford install into a random rollback, and it will corrupt a calibration download." 'Replace or repair the disk before installing IDS or programming a car.'
    }

    if ($media -eq 'HDD') {
        Add-Finding Check 'This PC' 'The Windows drive is a spinning hard drive. Ford''s spec for this software is an SSD (256 GB for the older IDS sheet, 500 GB on the 2024 FDRS sheet). On a hard drive, IDS takes a long time to open and programming sessions time out while the PC is still writing files.' 'Move Windows onto an SSD before this becomes the bay PC.'
    }
    elseif ($media -match 'SSD|SCM') {
        Add-Finding Ok 'This PC' "System drive is an $media. That is what Ford asks for."
        if ($physSizeGb -and $physSizeGb -lt 240) {
            Add-Finding Check 'This PC' "The SSD is about $physSizeGb GB. Ford's IDS recommendation is 256 GB, and the FDRS dealer sheet says 500 GB. IDS plus calibrations fills a small SSD, and then the next update fails halfway." 'Use a 256 GB SSD at minimum. 500 GB is what the later FDRS sheet lists.'
        }
        elseif ($physSizeGb -and $physSizeGb -lt 480) {
            Add-Finding Note 'This PC' "SSD is about $physSizeGb GB. Fine for the older 256 GB IDS recommendation. The 2024 FDRS dealer sheet lists 500 GB so the calibrations and module files are not always fighting for space."
        }
    }
    else {
        Add-Finding Note 'This PC' 'Could not tell whether the system drive is an SSD. Ford wants an SSD. If this laptop still has a spinning drive, plan on replacing it.'
    }

    if ($null -ne $freeGb -and $freeGb -lt 15) {
        Add-Finding Problem 'This PC' ("{0} only has {1} GB free. IDS with calibrations will not fit, and Windows Installer fails in confusing ways when the disk is this full." -f $sysDrive, $freeGb) 'Free at least 40 GB on the Windows drive before running setup. 15 GB is not enough.'
    }
    elseif ($null -ne $freeGb -and $freeGb -lt 40) {
        Add-Finding Check 'This PC' ("{0} has {1} GB free. The IDS full install plus calibrations wants more room than people expect. Under 40 GB free is where the installer dies near the end and leaves a half-installed program." -f $sysDrive, $freeGb) 'Clear space until the Windows drive has 40 GB or more free, then install.'
    }
    elseif ($null -ne $freeGb) {
        Add-Finding Ok 'This PC' ("{0} has {1} GB free. That is enough room to install." -f $sysDrive, $freeGb)
    }

    $usb = @(Get-CimInstance Win32_USBController -ErrorAction SilentlyContinue)
    $usb3 = @($usb | Where-Object { $_.Name -match 'xHCI|USB\s*3|3\.[0-9]' })
    Add-Spec ("USB host controllers: {0}, of which USB 3 / xHCI: {1}" -f $usb.Count, $usb3.Count)
    if ($usb.Count -eq 0) {
        Add-Finding Check 'This PC' 'No USB controller was reported. That is not normal on a laptop. The VCM cannot be installed if Windows does not see USB.' 'Check Device Manager for Universal Serial Bus controllers. If the list is empty, the chipset driver is missing.'
    }
    elseif ($usb3.Count -eq 0) {
        Add-Finding Check 'This PC' 'USB controllers are present, but none identified as USB 3 / xHCI. FDRS documentation asks for USB 3 ports. A USB 2-only port will sometimes see a VCM and then drop it during a long session.' 'Install the laptop chipset driver. Plug the VCM into a port that Device Manager lists under an xHCI / USB 3 controller. Avoid unpowered hubs.'
    }
    else {
        Add-Finding Ok 'This PC' ("Found {0} USB 3 / xHCI controller(s). Plug the VCM into a port on the laptop itself, not a cheap hub." -f $usb3.Count)
    }

    $batt = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($batt) {
        # 1 = discharging, 2 = AC
        if ($batt.BatteryStatus -eq 1) {
            Add-Finding Check 'This PC' 'The laptop is running on battery. Do not program a module like this. Sleep in the middle of a flash is how a module gets left blank, and it looks like a bad VCM.' 'Plug the laptop in. Keep the car battery on a maintainer too, about 12.6 to 13.6 volts. Windows cannot see the car battery from here.'
        }
        else {
            Add-Finding Ok 'This PC' 'Laptop is on AC power.'
        }
    }

    # basic display adapter = no real video driver, VCMM scope will not work
    $gpus = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)
    foreach ($gpu in $gpus) {
        $h = [int]$gpu.CurrentHorizontalResolution
        $v = [int]$gpu.CurrentVerticalResolution
        $gname = [string]$gpu.Name
        if ($h -gt 0 -and $v -gt 0) {
            Add-Spec "Screen: $gname, $h x $v"
        }
        else {
            Add-Spec "Video: $gname (no active resolution reported)"
        }
        if ($gname -match 'Basic Display|Microsoft Basic Render') {
            Add-Finding Problem 'This PC' "Video driver is '$gname'. That is the emergency driver Windows uses when the real one is missing. The VCMM scope software needs DirectX 11 (feature level 10.1 or higher). IDS will also draw wrong." 'Install the laptop maker''s graphics driver, reboot, and check this again.'
        }
        elseif ($h -gt 0 -and $h -lt 1600) {
            Add-Finding Check 'This PC' "Current screen is $h x $v. Ford's FDRS sheet lists 1600x900 as the minimum. Below that, FDRS cuts off buttons and people think the install is broken." 'Use the laptop at its native resolution or an external monitor at 1600x900 or higher. 1920x1080 is the comfortable size.'
        }
        elseif ($h -ge 1600) {
            Add-Finding Ok 'This PC' "Screen is $h x $v on $gname. That meets the 1600x900 minimum."
        }
    }
}

function Get-RuntimeCheck {
    Write-Host 'Checking .NET, Visual C++, and WebView2...'

    $rel = $null
    $netKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue
    if ($netKey) { $rel = [int]$netKey.Release }
    # 528040 = .NET Framework 4.8
    if ($rel -ge 528040) {
        Add-Finding Ok 'Windows components' ".NET Framework 4.8 is installed (release $rel). The Ford installers use it."
    }
    elseif ($rel) {
        Add-Finding Problem 'Windows components' ".NET Framework 4 is present but it is older than 4.8 (release $rel). IDS and FDRS setup fail part way through, usually with a generic 'installation ended prematurely' message." 'Install .NET Framework 4.8 from Microsoft, reboot, then run the Ford setup again.'
    }
    else {
        Add-Finding Problem 'Windows components' '.NET Framework 4.8 is not installed. The Ford installers depend on it.' 'Install .NET Framework 4.8, reboot, then run setup.'
    }

    $net35 = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5' -ErrorAction SilentlyContinue
    if (-not $net35 -or [int]$net35.Install -ne 1) {
        Add-Finding Check 'Windows components' '.NET Framework 3.5 is not turned on. Current FDRS often does not care. IDS on a lot of these PCs still pops a Windows Features box in the middle of setup and tries to download 3.5. On a PC with no internet, or with Windows Update blocked, that box never finishes and the install rolls back.' 'Before an IDS install, turn on the Windows feature NetFx3. If the PC cannot reach Windows Update, point that feature at Windows install media.'
    }
    else {
        Add-Finding Ok 'Windows components' '.NET Framework 3.5 is installed. IDS will not stop to download it.'
    }

    $apps = Get-UninstallEntries
    $script:Uninstall = $apps
    $vc = @($apps | Where-Object { $_.DisplayName -match 'Visual C\+\+ 2015-2022' })
    $hasX86 = @($vc | Where-Object { $_.DisplayName -match 'x86' }).Count -gt 0
    $hasX64 = @($vc | Where-Object { $_.DisplayName -match 'x64' }).Count -gt 0
    if ($hasX86 -and $hasX64) {
        Add-Finding Ok 'Windows components' 'Visual C++ 2015-2022 runtimes are installed for both 32-bit and 64-bit. IDS/FJDS are 32-bit programs, so the x86 runtime is the one that matters.'
    }
    elseif ($vc.Count -eq 0) {
        Add-Finding Check 'Windows components' 'Visual C++ 2015-2022 runtime is not installed yet. The Ford setup usually installs it. If setup rolls back in the middle, this is one of the usual reasons.' 'If an install rolls back, install both the x86 and x64 Visual C++ 2015-2022 redistributables from Microsoft, reboot, and run setup again.'
    }
    else {
        $which = 'x64'
        if ($hasX86) { $which = 'x86 only' }
        Add-Finding Check 'Windows components' "Visual C++ 2015-2022 is only present as $which. A 32-bit Ford program on 64-bit Windows needs the x86 runtime." 'Install the missing Visual C++ 2015-2022 architecture if the Ford setup rolls back.'
    }

    $wv = $null
    $wvKeys = @(
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
        'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    )
    foreach ($k in $wvKeys) {
        $item = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if ($item -and $item.pv) { $wv = [string]$item.pv; break }
    }
    $wvDir = Join-Path ${env:ProgramFiles(x86)} 'Microsoft\EdgeWebView\Application'
    if (-not $wv -and (Test-Path $wvDir)) { $wv = 'present' }
    if ($wv) {
        Add-Finding Ok 'Windows components' "WebView2 runtime is installed ($wv). Newer FDRS windows are drawn with it. Without it, FDRS opens a blank white window and people reinstall the whole program for nothing."
    }
    else {
        Add-Finding Check 'Windows components' 'WebView2 runtime is not installed. Newer FDRS builds use it. The symptom is a blank FDRS window, not an error about WebView2.' 'Install the Microsoft Edge WebView2 Evergreen runtime, then open FDRS again. You do not need to reinstall FDRS first.'
    }

    $msi = Get-Service msiserver -ErrorAction SilentlyContinue
    if ($msi -and $msi.StartType -eq 'Disabled') {
        Add-Finding Problem 'Windows components' 'The Windows Installer service is disabled. No MSI-based setup can finish, including the Ford packages.' 'Set the Windows Installer service back to Manual and start it before running setup.'
    }

    $reboot = $false
    $rebootWhy = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reboot = $true
        $rebootWhy += 'Windows component servicing'
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reboot = $true
        $rebootWhy += 'Windows Update'
    }
    $pending = $null
    try {
        $pending = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations
    }
    catch { }
    if ($pending) {
        $reboot = $true
        $rebootWhy += 'files waiting to be replaced'
        $fordPending = @($pending | Where-Object { $_ -match 'Ford|VCI|VCM|IDS|FDRS' })
        if ($fordPending.Count -gt 0) {
            Add-Finding Problem 'Windows components' 'Windows is waiting to replace Ford / VCI files on the next restart. Installing again on top of that piles a second copy on a half-updated driver. The VCM then shows the old firmware in VCI Manager no matter how many times you run the new setup.' 'Restart this PC before you install or update anything Ford. Do not skip the reboot.'
        }
    }
    if ($reboot -and -not ($fordPending -and $fordPending.Count -gt 0)) {
        Add-Finding Problem 'Windows components' ("Windows is waiting for a restart ({0}). Ford setup and the VCI driver both misbehave while this is set. Sometimes setup refuses to start. Sometimes it finishes and the device still fails until you reboot." -f ($rebootWhy -join ', ')) 'Restart the PC first. Then install.'
    }
    elseif (-not $reboot) {
        Add-Finding Ok 'Windows components' 'No pending restart is flagged. You can run an installer without that getting in the way.'
    }

    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress') {
        Add-Finding Problem 'Windows components' 'Windows Installer still has an install marked in progress. A second setup, including IDS or VCI Software, will sit there or fail with error 1618.' 'Reboot. If it is still sitting there after that, the last install crashed and the InProgress key has to be cleared by hand.'
    }
}

function Get-FordSoftwareCheck {
    Write-Host 'Checking installed Ford software...'
    $script:HasIds = $false
    $script:HasVci = $false
    if (-not $script:Uninstall) { $script:Uninstall = Get-UninstallEntries }
    $apps = $script:Uninstall

    $fordPattern = 'Integrated Diagnostic Software|\bIDS\b|FDRS|Ford Diagnostic|FJDS|VCI Manager|VCI Software|Vehicle Measurement|Ford Motor Company'
    $fordApps = @($apps | Where-Object {
        $_.DisplayName -match $fordPattern -or $_.Publisher -match 'Ford Motor Company'
    })

    # VCM3 manager is a Bosch package. Only count it if the name is the Ford VCI tool.
    $boschVci = @($apps | Where-Object { $_.DisplayName -match 'VCI Manager|VTX-VCI|VCI Software' -and $_.Publisher -match 'Bosch|Ford' })
    foreach ($b in $boschVci) {
        if ($fordApps.DisplayName -notcontains $b.DisplayName) {
            $fordApps += $b
        }
    }

    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Ford Motor Company'),
        (Join-Path $env:ProgramFiles 'Ford Motor Company'),
        (Join-Path $env:ProgramData 'Ford Motor Company')
    )
    $dirs = @()
    foreach ($r in $roots) {
        if (Test-Path $r) {
            $dirs += Get-ChildItem $r -Directory -ErrorAction SilentlyContinue
            Add-Spec "Folder: $r"
        }
    }

    if ($fordApps.Count -eq 0 -and $dirs.Count -eq 0) {
        Add-Finding Check 'Installed Ford software' 'IDS, FDRS, FJDS, VCI Manager, and VMS are not installed.' 'Install the diagnostic software, then install VCI Software. IDS or FJDS has to be on this same PC if you are also installing FDRS.'
        return
    }

    $seen = @{}
    foreach ($a in $fordApps) {
        $line = $a.DisplayName
        if ($a.DisplayVersion) { $line += "  version $($a.DisplayVersion)" }
        if ($seen.ContainsKey($line)) { continue }
        $seen[$line] = $true
        Add-Spec "Installed: $line"
        Add-Finding Note 'Installed Ford software' $line
    }

    $names = ($fordApps | ForEach-Object { $_.DisplayName }) -join ' | '
    $hasIds = $names -match '\bIDS\b|Integrated Diagnostic'
    $script:HasIds = [bool]$hasIds
    $hasFjds = $names -match 'FJDS'
    $hasFdrs = $names -match 'FDRS|Ford Diagnostic and Repair|Ford Diagnostic & Repair'
    $hasVci = $names -match 'VCI Manager|VCI Software|VTX-VCI'
    $script:HasVci = [bool]$hasVci
    $hasVms = $names -match 'Vehicle Measurement|\bVMS\b'

    if ($hasFdrs -and -not $hasIds -and -not $hasFjds) {
        Add-Finding Check 'Installed Ford software' 'FDRS is installed without IDS or FJDS. Ford''s licensing notes say the FDRS license is the IDS or FJDS license, on the same PC and the same Windows install. A standalone FDRS often gets to the login screen and then will not activate.' 'Install the IDS or FJDS subscription build on this same Windows, then open FDRS.'
    }
    elseif ($hasFdrs -and ($hasIds -or $hasFjds)) {
        Add-Finding Ok 'Installed Ford software' 'FDRS is on the same Windows as IDS or FJDS. That is how Ford says the shared license is set up.'
    }

    if (($hasIds -or $hasFdrs -or $hasFjds) -and -not $hasVci) {
        Add-Finding Check 'Installed Ford software' 'Diagnostic software is installed but VCI Software / VCI Manager is not in the installed programs list. Ford split the VCM II / VCMM / VCM3 drivers out into a separate download. IDS and FDRS do not install that package for you anymore. The car connection fails and the programs themselves look fine.' 'Download VCI Software from the Rotunda / Motorcraft software page and install it. Reboot when it asks. Then open VCI Manager and update the interface firmware before you connect to a car.'
    }
    elseif ($hasVci) {
        Add-Finding Ok 'Installed Ford software' 'VCI Software is installed. After any update, open VCI Manager and confirm the interface firmware matches. A PC reboot is required when the new version will not replace the old one.'
    }

    if (-not $hasVms) {
        Add-Finding Note 'Installed Ford software' 'VMS is not installed. That program is only for the VCMM (the interface that also does meter and scope). A plain VCM II or VCM3 does not need VMS.'
    }

    # leftover Ford folders after a bad uninstall. next setup usually rolls back.
    $folderNames = @($dirs | ForEach-Object { $_.Name })
    $expect = @{
        'IDS'  = $hasIds
        'FJDS' = $hasFjds
        'FDRS' = $hasFdrs
        'VMS'  = $hasVms
    }
    foreach ($key in $expect.Keys) {
        $dirHit = @($folderNames | Where-Object { $_ -eq $key -or $_ -like "$key*" })
        if ($dirHit.Count -gt 0 -and -not $expect[$key]) {
            Add-Finding Check 'Installed Ford software' ("The folder '{0}' is still on disk under Ford Motor Company, but {1} is not in Programs and Features. A leftover folder from a removed or failed install is a common reason the next setup rolls back at the end." -f ($dirHit -join ', '), $key) 'Uninstall through Ford''s VCI Software Uninstaller (Start > Ford Motor Company) if it is there, reboot, and install clean. Do not just delete the folder while an uninstall entry still exists.'
        }
    }

    $idsCount = @($fordApps | Where-Object { $_.DisplayName -match '\bIDS\b|Integrated Diagnostic' }).Count
    if ($idsCount -gt 1) {
        Add-Finding Check 'Installed Ford software' "There are $idsCount IDS entries in Programs and Features. Two copies installed is a known mess. One of them is usually a failed update that did not remove the old one." 'Remove the older IDS, reboot, and install the current full build once. Do not stack an update on a broken copy.'
    }

    # downloaded exe still marked as from the internet. SmartScreen stops it.
    $dl = Join-Path $env:USERPROFILE 'Downloads'
    if (Test-Path $dl) {
        $files = @(Get-ChildItem $dl -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.LastWriteTime -gt (Get-Date).AddDays(-45) -and
                $_.Name -match 'IDS|FDRS|FJDS|VCI|VMS|Ford' -and
                $_.Extension -match '\.(exe|zip|msi)$'
            } |
            Select-Object -First 15)
        foreach ($f in $files) {
            $zone = $null
            try { $zone = Get-Content -Path $f.FullName -Stream Zone.Identifier -ErrorAction Stop } catch { }
            if ($zone -match 'ZoneId=3') {
                Add-Finding Check 'Installed Ford software' ("Downloaded installer is still blocked by Windows: {0}. Setup either does nothing or shows 'Windows protected your PC'." -f $f.Name) 'Right-click the file, Properties, check Unblock, Apply. Then run it. You do not need to turn SmartScreen off for the whole PC.'
            }
        }
    }
}

function Get-SecurityCheck {
    Write-Host 'Checking firewall, antivirus, and startup protection...'

    $profiles = @()
    try { $profiles = @(Get-NetFirewallProfile -ErrorAction Stop) } catch { }
    if ($profiles.Count -eq 0) {
        $script:FirewallStatus.Add('Windows Firewall: could not read it. Run this as administrator.')
    }
    else {
        foreach ($p in $profiles) {
            $state = 'off'
            if ($p.Enabled) { $state = 'on' }
            Add-Spec ("Firewall {0}: {1}, inbound {2}" -f $p.Name, $state, $p.DefaultInboundAction)
        }
        $onNames = @($profiles | Where-Object { $_.Enabled -eq $true -or $_.Enabled -eq 'True' } | ForEach-Object { $_.Name })
        $offNames = @($profiles | Where-Object { $_.Name -notin $onNames } | ForEach-Object { $_.Name })
        if ($onNames.Count -eq $profiles.Count) {
            $script:FirewallStatus.Add(('Windows Firewall is on ({0}).' -f ($onNames -join ', ')))
        }
        elseif ($onNames.Count -eq 0) {
            $script:FirewallStatus.Add(('Windows Firewall is off ({0}).' -f ($offNames -join ', ')))
        }
        else {
            $script:FirewallStatus.Add(('Windows Firewall is on for {0} and off for {1}.' -f ($onNames -join ', '), ($offNames -join ', ')))
        }

        $logOn = @($profiles | Where-Object { $_.LogBlocked -eq $true -or $_.LogBlocked -eq 'True' } | ForEach-Object { $_.Name })
        if ($logOn.Count -eq 0) {
            $script:FirewallStatus.Add('Windows Firewall block logging is off.')
        }
        elseif ($logOn.Count -eq $profiles.Count) {
            $script:FirewallStatus.Add('Windows Firewall block logging is on.')
        }
        else {
            $script:FirewallStatus.Add(('Windows Firewall block logging is on for {0} and off for the other profiles.' -f ($logOn -join ', ')))
        }
    }

    try {
        $nets = @(Get-NetConnectionProfile -ErrorAction Stop)
        foreach ($n in $nets) {
            Add-Spec ("Network '{0}' on {1}: {2}" -f $n.Name, $n.InterfaceAlias, $n.NetworkCategory)
            if ([string]$n.NetworkCategory -eq 'Public') {
                Add-Finding Check 'Firewall' ("Windows has marked '{0}' ({1}) as a Public network. Public is the strict profile. Shop Wi-Fi set to Public blocks the VCM's network link and some of the Ford download traffic even after you think you allowed the program." -f $n.Name, $n.InterfaceAlias) 'If this is the shop network, set that connection to Private. Do this on the VCM adapter as well if Windows classified it as Public.'
            }
        }
    }
    catch { }

    # whole rule list can hang on a big policy, so give it 20 seconds and move on
    $rules = @()
    $ruleJob = Start-Job -ScriptBlock {
        Get-NetFirewallRule -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match 'Ford|FDRS|FJDS|VCI|VCM' -or ($_.DisplayName -match '\bIDS\b') } |
            Select-Object DisplayName, Enabled, Direction, Action, Profile
    }
    $finished = Wait-Job $ruleJob -Timeout 20
    if ($finished) {
        $rules = @(Receive-Job $ruleJob)
    }
    else {
        Stop-Job $ruleJob -ErrorAction SilentlyContinue
        Add-Finding Note 'Firewall' 'Looking up individual firewall rules took too long and was skipped. The profile results above still stand.'
    }
    Remove-Job $ruleJob -Force -ErrorAction SilentlyContinue

    $blocks = @($rules | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
    if ($blocks.Count -gt 0) {
        $names = ($blocks | Select-Object -ExpandProperty DisplayName -Unique) -join ', '
        Add-Finding Problem 'Firewall' "Firewall is set to Block for: $names. That stops IDS/FDRS or the VCM on purpose. The program opens and then cannot see the car or cannot reach Ford." 'Remove the Block rule or set it to Allow. Do not turn the whole firewall off.'
    }
    elseif ($rules.Count -gt 0) {
        $allowNames = ($rules | Select-Object -ExpandProperty DisplayName -Unique) -join ', '
        Add-Finding Ok 'Firewall' "Found firewall rules for: $allowNames. No Block rule in that list."
    }

    # Past blocks. The rule list only shows what is set right now.
    $logPaths = @()
    foreach ($p in $profiles) {
        if ($p.LogFileName) {
            $expanded = [Environment]::ExpandEnvironmentVariables($p.LogFileName)
            if ($logPaths -notcontains $expanded) { $logPaths += $expanded }
        }
    }
    $dropHits = New-Object System.Collections.Generic.List[string]
    $dropMatch = 'Ford Motor Company|\\IDS\.exe|\\FDRS|\\FJDS|VCI Manager|VCI Software|\\VCM|Vehicle Measurement'
    foreach ($lp in $logPaths) {
        if (-not (Test-Path -LiteralPath $lp)) { continue }
        $tail = @(Get-Content -LiteralPath $lp -Tail 4000 -ErrorAction SilentlyContinue)
        foreach ($line in $tail) {
            if ($line -notmatch '\sDROP\s') { continue }
            if ($line -notmatch $dropMatch) { continue }
            $bits = $line -split '\s+'
            $when = $bits[0] + ' ' + $bits[1]
            $app = $bits[$bits.Length - 1]
            $dropHits.Add(('{0}  {1}' -f $when, $app)) | Out-Null
        }
    }
    try {
        $secBlocks = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 5157
            StartTime = (Get-Date).AddDays(-14)
        } -MaxEvents 250 -ErrorAction Stop)
        foreach ($ev in $secBlocks) {
            if ($ev.Message -notmatch $dropMatch) { continue }
            $short = (($ev.Message -replace '\s+', ' ').Trim())
            if ($short.Length -gt 180) { $short = $short.Substring(0, 180) }
            $dropHits.Add(('Security log {0}: {1}' -f $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $short)) | Out-Null
        }
    }
    catch { }
    $dropHits = @($dropHits | Select-Object -Unique)
    if ($dropHits.Count -gt 0) {
        $shownDrops = $dropHits | Select-Object -First 6
        Add-Finding Problem 'Firewall' ("The firewall has blocked Ford software:`n{0}" -f ($shownDrops -join "`n")) 'Those blocks are already in the log. Allow IDS, FDRS, FJDS, and VCI Manager through the firewall on every network, including the VCM adapter. Do not turn the firewall off.'
    }

    $tpFw = @()
    $tpRead = $true
    try {
        $tpFw = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction Stop)
    }
    catch {
        $tpRead = $false
    }
    $tpLines = @()
    foreach ($fw in $tpFw) {
        $n = [string]$fw.displayName
        if (-not $n) { continue }
        if ($n -match 'Windows Firewall|Windows Defender') { continue }
        $onOff = 'installed'
        try {
            $st = [int]$fw.productState
            if (($st -band 0x1000) -eq 0x1000) { $onOff = 'on' }
            else { $onOff = 'off' }
        }
        catch { }
        $tpLines += ('{0} is {1}' -f $n, $onOff)
    }
    if (-not $tpRead) {
        $script:FirewallStatus.Add('Third-party firewall: could not read the list. Run this as administrator.')
    }
    elseif ($tpLines.Count -eq 0) {
        $script:FirewallStatus.Add('Third-party firewall: none.')
    }
    else {
        $script:FirewallStatus.Add(('Third-party firewall: {0}.' -f ($tpLines -join '; ')))
    }

    $avProducts = @()
    try {
        $avProducts = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)
    }
    catch {
        Add-Finding Note 'Antivirus' 'Could not read the antivirus list (Security Center). Run as administrator if you need this section filled in.'
    }

    $thirdParty = @()
    foreach ($av in $avProducts) {
        $n = [string]$av.displayName
        if (-not $n) { continue }
        $hex = '{0:X6}' -f [int]$av.productState
        $rtByte = $hex.Substring(2, 2)
        $rt = 'real-time status unknown'
        if ($rtByte -eq '10' -or $rtByte -eq '11') { $rt = 'real-time on' }
        elseif ($rtByte -eq '00' -or $rtByte -eq '01') { $rt = 'real-time off' }
        Add-Spec "Antivirus: $n ($rt)"
        if ($n -notmatch 'Windows Defender|Microsoft Defender') {
            $thirdParty += "$n ($rt)"
        }
    }

    if ($thirdParty.Count -gt 0) {
        Add-Finding Check 'Antivirus' ("Third-party antivirus: {0}. This is the usual reason a VCI Software install says it finished but VCI Manager still shows the old version, and the usual reason a VCM shows up for a second and then disappears. The scanner quarantines the driver as it unpacks. Ford's own FDRS programming notes also call out antivirus when the PC cannot download vehicle data." -f ($thirdParty -join '; ')) 'Have whoever manages this PC allow the Ford Motor Company folders, or pause this product for the install and turn it back on after. Do not leave it off. If an install already failed, reboot and install VCI Software again after it is allowed.'
    }
    elseif ($avProducts.Count -gt 0) {
        Add-Finding Ok 'Antivirus' 'Only Microsoft Defender is registered. That is the normal setup. Defender can still block a freshly downloaded installer. If setup dies instantly, use Unblock on the file before you turn Defender off.'
    }

    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.RealTimeProtectionEnabled) {
            Add-Finding Ok 'Antivirus' 'Defender real-time protection is on.'
        }
        else {
            Add-Finding Note 'Antivirus' 'Defender real-time protection is off. Something else may be managing it, or it was turned off for a previous install attempt and never turned back on.'
        }
        $pref = Get-MpPreference -ErrorAction Stop
        if ($pref.EnableControlledFolderAccess -eq 1) {
            Add-Finding Check 'Antivirus' 'Defender Controlled Folder Access (ransomware protection) is on. It blocks installers that unpack into Desktop, Documents, or other protected folders. The Ford setup looks like it starts and then dies with an access error.' 'Run the installer from a local folder such as C:\Temp, or allow the setup program through Controlled Folder Access for the install. Do not turn the feature off for the whole PC unless you have to.'
        }
        $excl = @($pref.ExclusionPath)
        $fordExcl = @($excl | Where-Object { $_ -match 'Ford Motor Company' })
        if ($fordExcl.Count -eq 0) {
            Add-Finding Note 'Antivirus' 'Defender does not have the Ford folders excluded. That is normal. Only add an exclusion if an install or a VCI driver keeps getting quarantined. An exclusion is a hole in the scanner, so do not add one "just in case".'
        }
        else {
            Add-Finding Note 'Antivirus' ("Defender already has Ford path exclusions: {0}" -f ($fordExcl -join '; '))
        }
    }
    catch {
        Add-Finding Note 'Antivirus' 'Defender status could not be read. A third-party product may have replaced it, or this window is not elevated.'
    }

    # Did Defender actually stop IDS, FDRS, FJDS, VCI Manager, or VMS.
    $toolMatch = 'Ford Motor Company|\\IDS\\|\\FDRS\\|\\FJDS\\|VCI Manager|VCI Software|\\VCM|Vehicle Measurement'
    $blocks = New-Object System.Collections.Generic.List[string]
    try {
        $detects = @(Get-MpThreatDetection -ErrorAction Stop)
        foreach ($det in $detects) {
            foreach ($res in @($det.Resources)) {
                if ($res -and $res -match $toolMatch) {
                    $blocks.Add(('Defender quarantined or blocked {0}' -f $res)) | Out-Null
                }
            }
        }
    }
    catch { }
    try {
        $defLog = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Windows Defender/Operational'
            Id = 1116, 1117, 1123
            StartTime = (Get-Date).AddDays(-30)
        } -MaxEvents 200 -ErrorAction Stop)
        foreach ($ev in $defLog) {
            if ($ev.Message -match $toolMatch) {
                $short = (($ev.Message -replace '\s+', ' ').Trim())
                if ($short.Length -gt 220) { $short = $short.Substring(0, 220) }
                $blocks.Add(('Defender event {0} on {1}: {2}' -f $ev.Id, $ev.TimeCreated.ToString('yyyy-MM-dd'), $short)) | Out-Null
            }
        }
    }
    catch { }
    $blocks = @($blocks | Select-Object -Unique)
    if ($blocks.Count -gt 0) {
        $shown = $blocks | Select-Object -First 5
        Add-Finding Problem 'Antivirus' ("Defender has blocked Ford software on this PC:`n{0}" -f ($shown -join "`n")) 'That file was stopped by antivirus, not by a bad install. Restore it from Defender protection history, or allow that file, then install VCI Software again and reboot.'
    }
    else {
        Add-Finding Ok 'Antivirus' 'No Defender block was found in the last 30 days for IDS, FDRS, FJDS, VCI Manager, VCM, or VMS.'
    }

    # memory integrity. old VCM driver comes up code 52 when this is on.
    $hvci = $false
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        if ($dg.SecurityServicesRunning -contains 2) { $hvci = $true }
    }
    catch { }
    if (-not $hvci) {
        $regHvci = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -ErrorAction SilentlyContinue
        if ($regHvci -and [int]$regHvci.Enabled -eq 1) { $hvci = $true }
    }
    if ($hvci) {
        Add-Finding Check 'Security settings' 'Memory integrity (Core isolation) is on. The VCM, VCMM, and VCM3 drivers are older kernel drivers. With Memory integrity on, Device Manager shows Code 39, 48, or 52 and the interface never comes online. The Ford program itself installs fine, which sends people down the wrong path.' 'If the VCM will not start, turn Memory integrity off, reboot, and install VCI Software again. Turning it off is a shop policy decision. If the VCM already works, leave the setting alone.'
    }
    else {
        Add-Finding Ok 'Security settings' 'Memory integrity is not running. That removes the usual cause of VCM driver Code 52.'
    }

    $sac = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue
    if ($sac -and $sac.VerifiedAndReputablePolicyState -eq 1) {
        Add-Finding Check 'Security settings' 'Smart App Control is on (Windows 11). It blocks installers that do not have a reputation yet. Ford''s packages get stopped before setup opens, with a message that the app was blocked.' 'For those installers, Smart App Control has to be off, and on current Windows turning it off is permanent. Try Unblock on the file first. If the block message is specifically Smart App Control, that setting is the cause.'
    }

    $ss = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue
    if ($ss -and [string]$ss.SmartScreenEnabled -match 'Off|0') {
        Add-Finding Note 'Security settings' 'SmartScreen is off. Downloaded Ford installers will not show the "protected your PC" prompt. Leave it off only if you meant to. The prompt itself is not a failed install.'
    }
    else {
        Add-Finding Note 'Security settings' 'SmartScreen is on. A Ford installer downloaded from the portal often shows "Windows protected your PC" because not every package is a commonly downloaded file. Click More info, then Run anyway. Or Unblock the file in Properties. That is not a reason to disable SmartScreen for the PC.'
    }

    # old .NET crypto setting. Ford site fails SSL and the browser still works.
    foreach ($p in @(
        'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    )) {
        $item = Get-ItemProperty $p -ErrorAction SilentlyContinue
        if ($item -and $null -ne $item.SchUseStrongCrypto -and [int]$item.SchUseStrongCrypto -eq 0) {
            Add-Finding Check 'Security settings' "SchUseStrongCrypto is 0 under $p. .NET programs are forced onto old encryption. FDRS and the download site then fail with an SSL / could-not-connect error and the internet otherwise works." 'Set SchUseStrongCrypto to 1 on both .NET 4 keys, then reboot.'
            break
        }
    }

    $tls = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -ErrorAction SilentlyContinue
    if ($tls -and (($tls.Enabled -eq 0) -or ($tls.DisabledByDefault -eq 1))) {
        Add-Finding Problem 'Security settings' 'TLS 1.2 is disabled for client connections. The Motorcraft / Ford sites will not load. IDS license checks and FDRS logins fail, and a browser test to the same site fails too.' 'Re-enable TLS 1.2. Do not turn on TLS 1.0 as a workaround.'
    }
}

function Get-NetworkCheck {
    Write-Host 'Checking internet path to Ford (a few seconds)...'

    $proxyOn = $false
    $inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($inet -and [int]$inet.ProxyEnable -eq 1) {
        $proxyOn = $true
        Add-Finding Check 'Network' ("A proxy is turned on for this user ({0}). FDRS is cloud based. If the proxy does not allow the Ford sites, FDRS opens and then cannot identify a vehicle. IDS license checks fail the same way." -f $inet.ProxyServer) 'Confirm the proxy allows *.dealerconnection.com, *.ford.com, and updates.installshield.com. A direct connection is simpler on a bay PC.'
    }

    $winhttp = ''
    try { $winhttp = (netsh winhttp show proxy) -join "`n" } catch { }
    if ($winhttp -match 'Proxy Server\(s\)' -and $winhttp -notmatch 'no proxy') {
        Add-Finding Check 'Network' 'WinHTTP has a proxy configured. Some of the Ford background downloads use WinHTTP, not the browser proxy setting. The browser can reach Ford while FDRS still cannot.' 'If a browser works and FDRS does not, compare WinHTTP proxy (netsh winhttp show proxy) with the browser. They are different settings.'
    }
    elseif (-not $proxyOn) {
        Add-Finding Ok 'Network' 'No proxy is set for this user or for WinHTTP.'
    }

    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $hostLines = @()
    try {
        $hostLines = @(Get-Content $hostsPath -ErrorAction Stop | Where-Object {
            $_ -notmatch '^\s*#' -and $_.Trim() -ne '' -and $_ -match 'ford|motorcraft|dealerconnection|installshield'
        })
    }
    catch { }
    if ($hostLines.Count -gt 0) {
        Add-Finding Problem 'Network' ("The hosts file redirects Ford-related names:`n{0}`nLicense checks and downloads will go to the wrong place and it looks like a bad login." -f ($hostLines -join "`n")) 'Remove those lines from C:\Windows\System32\drivers\etc\hosts. Leave the localhost lines alone.'
    }
    else {
        Add-Finding Ok 'Network' 'Hosts file does not redirect Ford, Motorcraft, or InstallShield names.'
    }

    # old PTS/IDS trusted sites. FDRS cares less, PTS still does.
    $zoneRoots = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains'
    )
    $need = @('dealerconnection.com', 'ford.com')
    $foundZones = @()
    foreach ($z in $zoneRoots) {
        if (-not (Test-Path $z)) { continue }
        foreach ($dom in $need) {
            $hit = Get-ChildItem $z -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq $dom -or $_.Name -match [regex]::Escape($dom) }
            if ($hit) { $foundZones += $dom }
        }
    }
    # some GPOs dump the sites in ZoneMapKey instead of the domain keys
    $zoneKey = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey' -ErrorAction SilentlyContinue
    if ($zoneKey) {
        foreach ($prop in $zoneKey.PSObject.Properties) {
            foreach ($dom in $need) {
                if ($prop.Name -match [regex]::Escape($dom)) { $foundZones += $dom }
            }
        }
    }
    $foundZones = @($foundZones | Select-Object -Unique)
    $missingZones = @($need | Where-Object { $foundZones -notcontains $_ })
    if ($missingZones.Count -eq 0) {
        Add-Finding Ok 'Network' 'Trusted Sites already include dealerconnection.com and ford.com.'
    }
    else {
        Add-Finding Check 'Network' ("Trusted Sites is missing: {0}. Ford's PTS / IDS internet settings sheet says to add *.dealerconnection.com, *.ford.com, and http://updates.installshield.com, with scripting allowed. FDRS cares less about Internet Explorer than PTS does. PTS pages that spin forever are this setting." -f ($missingZones -join ', ')) 'In Internet Options, Trusted Sites, add *.dealerconnection.com and *.ford.com. Uncheck "require https" so the wildcard sticks. This still applies when PTS is opened from Edge in IE mode.'
    }

    # Internet Options, Privacy tab. PopupMgr yes = blocker on. Missing value defaults to on.
    $popupOn = $true
    $popupFrom = 'default (Privacy checkbox has never been changed, Internet Explorer leaves it on)'
    $popupKey = Get-ItemProperty 'HKCU:\Software\Microsoft\Internet Explorer\New Windows' -ErrorAction SilentlyContinue
    if ($popupKey -and $null -ne $popupKey.PopupMgr) {
        $popupRaw = [string]$popupKey.PopupMgr
        if ($popupRaw -match '^(no|0)$') {
            $popupOn = $false
            $popupFrom = 'Privacy tab for this user'
        }
        elseif ($popupRaw -match '^(yes|1)$') {
            $popupOn = $true
            $popupFrom = 'Privacy tab for this user'
        }
    }
    $policyZones = @(
        'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
    )
    foreach ($pz in $policyZones) {
        $zv = Get-ItemProperty $pz -Name '1809' -ErrorAction SilentlyContinue
        if (-not $zv -or $null -eq $zv.'1809') { continue }
        if ([int]$zv.'1809' -eq 3) {
            $popupOn = $false
            $popupFrom = 'group policy (forced off)'
        }
        elseif ([int]$zv.'1809' -eq 0) {
            $popupOn = $true
            $popupFrom = 'group policy (forced on)'
        }
    }
    if ($popupOn) {
        $script:NetworkStatus.Add('Internet Options pop-up blocker is on.')
        Add-Finding Check 'Network' ("Internet Options pop-up blocker is on ({0}). PTS and the Motorcraft login open a second window. With the blocker on, that window never shows and the login looks like it did nothing." -f $popupFrom) 'Internet Options, Privacy, uncheck Turn on Pop-up Blocker. In Pop-up Blocker Settings, allow *.ford.com, *.motorcraftservice.com, and *.dealerconnection.com.'
    }
    else {
        $script:NetworkStatus.Add(('Internet Options pop-up blocker is off ({0}).' -f $popupFrom))
    }

    $targets = @(
        @{ Host = 'www.motorcraftservice.com'; Port = 443; What = 'Motorcraft Service' },
        @{ Host = 'www.fordtechservice.dealerconnection.com'; Port = 443; What = 'Ford tech service / software download' },
        @{ Host = 'updates.installshield.com'; Port = 443; What = 'InstallShield update service used by the IDS installer' }
    )
    $failed = @()
    foreach ($t in $targets) {
        $dnsOk = $false
        try {
            $null = [System.Net.Dns]::GetHostAddresses($t.Host)
            $dnsOk = $true
        }
        catch { }
        if (-not $dnsOk) {
            $failed += ("{0} ({1}) did not resolve in DNS" -f $t.What, $t.Host)
            continue
        }
        if (-not (Test-Tcp -Target $t.Host -Port $t.Port -TimeoutMs 5000)) {
            $failed += ("{0} ({1} port {2}) did not accept a connection" -f $t.What, $t.Host, $t.Port)
        }
    }
    $fordFailed = @($failed | Where-Object { $_ -notmatch 'InstallShield' })
    $shieldFailed = @($failed | Where-Object { $_ -match 'InstallShield' })
    if ($fordFailed.Count -eq 0 -and $shieldFailed.Count -eq 0) {
        Add-Finding Ok 'Network' 'This PC can resolve and reach the Motorcraft site, the Ford tech-service site, and the InstallShield update host on port 443. FDRS still needs this path at the car, every time. IDS needs it at least every 29 days or the license drops on day 30.'
    }
    elseif ($fordFailed.Count -eq 0) {
        Add-Finding Ok 'Network' 'Motorcraft and the Ford tech-service site answered on port 443. FDRS can use this path. The InstallShield line below is only the old IDS installer update host.'
    }
    if ($fordFailed.Count -gt 0) {
        Add-Finding Problem 'Network' ("Cannot reach Ford from this PC:`n{0}`nFDRS will not identify a vehicle or download a module without this. IDS will run offline only until the license validation expires (Ford's note is every 29 days online, disabled after a missed 30-day check)." -f ($fordFailed -join "`n")) 'Fix DNS, firewall, or proxy for those hosts before you blame the VCM. A phone hotspot is a fair test. If the hotspot works and the shop network does not, the shop firewall is the problem.'
    }
    if ($shieldFailed.Count -gt 0) {
        Add-Finding Check 'Network' ("The old InstallShield update host did not answer:`n{0}`nThat host is only used when an IDS installer pulls an update. FDRS and the Motorcraft site do not depend on it. If the two Ford sites above worked, do not treat this as an internet outage." -f ($shieldFailed -join "`n")) 'Ignore this unless an IDS install stops and says it cannot reach InstallShield. Then check whether the shop firewall blocks updates.installshield.com.'
    }

    $wlan = ''
    try { $wlan = (netsh wlan show interfaces) -join "`n" } catch { }
    if ($wlan -match '(?m)^\s+SSID\s+:\s+(.+?)\s*$') {
        $ssid = $Matches[1].Trim()
        if ($ssid -and $ssid -notmatch '^$') {
            Add-Spec "Wi-Fi SSID: $ssid"
            if ($ssid -match 'VCM|Ford') {
                Add-Finding Check 'Network' "Wi-Fi is joined to '$ssid'. That looks like the VCM's own wireless. IDS can talk to the car that way, but the laptop then has no internet, so FDRS cannot log in or download a module. People leave it like this and think Ford's site is down." 'Use a USB cable to the VCM for the car, and use shop Wi-Fi or a wire for the internet. Do not use the VCM wireless as the laptop''s only connection.'
            }
        }
    }

    $adapters = @(Get-CimInstance Win32_NetworkAdapter -ErrorAction SilentlyContinue | Where-Object { $_.NetEnabled -eq $true })
    $vcmNic = @($adapters | Where-Object { $_.Name -match 'VCM|VCMM|Vehicle Communication' -or $_.NetConnectionID -match 'VCM|VCMM' })
    if ($vcmNic.Count -gt 0) {
        foreach ($nic in $vcmNic) {
            $cfg = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "Index=$($nic.Index)" -ErrorAction SilentlyContinue
            $ips = @($cfg.IPAddress)
            $ipText = 'no IP address'
            if ($ips.Count -gt 0) { $ipText = ($ips -join ', ') }
            Add-Spec ("VCM adapter: {0} ({1})" -f $nic.NetConnectionID, $ipText)
            if ($nic.NetConnectionStatus -ne 2) {
                Add-Finding Problem 'Network' ("The VCM network adapter '{0}' is not connected. IDS uses that adapter like a network cable to the interface. If it is disabled, the software will not see the car." -f $nic.Name) 'Enable the adapter. In Windows Firewall, allow IDS and FDRS on it. Then reopen VCI Manager.'
            }
            elseif ($ips.Count -eq 0) {
                Add-Finding Check 'Network' ("The VCM adapter '{0}' has no IP address. The USB side may be up while the network side the software actually uses is not." -f $nic.Name) 'Reboot with the VCM unplugged, open VCI Manager, then plug the VCM directly into the laptop.'
            }
            else {
                Add-Finding Ok 'Network' ("VCM network adapter is up ({0})." -f $ipText)
            }
        }
    }

    $vpnHit = @($adapters | Where-Object {
        $_.Name -match 'Cisco|AnyConnect|GlobalProtect|Forti|Pulse|Juniper|WireGuard|OpenVPN|NordLynx|TAP-Windows|Zscaler|Palo Alto' -or
        $_.NetConnectionID -match 'VPN|Cisco|GlobalProtect|Forti'
    })
    if ($vpnHit.Count -gt 0) {
        $vpnNames = ($vpnHit | ForEach-Object { $_.NetConnectionID }) -join ', '
        Add-Finding Check 'Network' "A VPN adapter is active ($vpnNames). Shop VPNs split the route so the VCM adapter and the Ford sites end up on the wrong side. Symptom is FDRS logged in at the desk and dead at the car, or the reverse." 'Disconnect the VPN while diagnosing a no-communication complaint. If it works with the VPN off, the VPN needs a split for the VCM adapter and the Ford sites.'
    }

    $wired = @($adapters | Where-Object { $_.AdapterType -match 'Ethernet' -and $_.Name -notmatch 'VCM|Virtual|Bluetooth|VPN' -and $_.NetConnectionStatus -eq 2 })
    $wifi = @($adapters | Where-Object { $_.AdapterType -match 'Wireless' -and $_.NetConnectionStatus -eq 2 })
    if ($wifi.Count -gt 0 -and $wired.Count -eq 0) {
        Add-Finding Note 'Network' 'Internet is on Wi-Fi only. Ford''s FDRS programming sheet prefers a wired gigabit connection because module files are large and a weak radio looks like a failed session. Wi-Fi is acceptable for diagnosis. For programming, plug in if you can.'
    }
}

function Get-RegistryCheck {
    Write-Host 'Checking J2534 registry entries and USB filter drivers...'

    $devices = @(Get-J2534)
    if ($devices.Count -eq 0) {
        Add-Finding Note 'Registry' 'No J2534 pass-thru devices are registered (HKLM\SOFTWARE\PassThruSupport.04.04, 32-bit and 64-bit). That is normal before VCI Software or a J2534 interface is installed. After VCI Software is installed, an empty list means the driver package did not finish.'
    }
    else {
        $byName = @{}
        foreach ($d in $devices) {
            $label = $d.Vendor
            if ($d.Name) { $label = $d.Name }
            elseif ($d.Device) { $label = "$($d.Vendor) / $($d.Device)" }
            Add-Spec ("J2534 {0}: {1}" -f $d.Bits, $label)
            if (-not $byName.ContainsKey($label)) { $byName[$label] = @() }
            $byName[$label] += $d.Bits

            if ($d.Dll -and -not (Test-Path $d.Dll)) {
                Add-Finding Problem 'Registry' ("J2534 entry '{0}' ({1}) points to a DLL that is not on disk:`n{2}`nFDRS or FJDS will list the interface and fail as soon as you connect. Reinstalling the diagnostic program does not fix a missing driver DLL." -f $label, $d.Bits, $d.Dll) 'Reinstall the driver package for that interface (for a Ford box, that is VCI Software). Leftover entries from an uninstalled Autel, Snap-on, Bosch, or Drew Tech tool cause the same failure.'
            }
        }

        $vendors = @($devices | ForEach-Object { $_.Vendor } | Select-Object -Unique)
        if ($vendors.Count -gt 1) {
            $vlist = $vendors -join ', '
            Add-Finding Check 'Registry' "More than one J2534 vendor is registered: $vlist. FJDS and FDRS can grab the wrong box. The car is plugged into the Ford VCM and the software is talking to an Autel or a Snap-on that is not even connected. The error sounds like a bad cable." 'Pick the Ford interface on purpose. FJDS uses DisplayCheckJ2534.exe in the FJDS Runtime folder when the menu will not offer a choice. In FDRS, set the VCI before you identify the vehicle. Unplug the other interfaces while you do it.'
        }
        else {
            Add-Finding Ok 'Registry' ("J2534 list has one vendor ({0})." -f $vendors[0])
        }

        foreach ($label in $byName.Keys) {
            $bits = @($byName[$label] | Select-Object -Unique)
            if ($bits.Count -eq 1) {
                if ($bits[0] -eq '64-bit') {
                    Add-Finding Check 'Registry' "J2534 device '$label' is only in the 64-bit registry. IDS and FJDS are 32-bit and only read the 32-bit key (WOW6432Node\PassThruSupport.04.04). They will say no interface is installed even though Device Manager looks fine." 'Reinstall that interface''s 32-bit driver / J2534 package. Copying the registry key by hand is how this gets worse.'
                }
            }
        }
    }

    # extra USB filters. AV and other scan tools. VCM drops off mid session.
    $usbClass = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{36fc9e60-c465-11cf-8056-444553540000}'
    $usbReg = Get-ItemProperty $usbClass -ErrorAction SilentlyContinue
    $filters = @()
    if ($usbReg.UpperFilters) { $filters += @($usbReg.UpperFilters) }
    if ($usbReg.LowerFilters) { $filters += @($usbReg.LowerFilters) }
    $filters = @($filters | Where-Object { $_ -and $_ -notmatch '^(usbccgp|usbhub|usbhub3|ucx01000|USBXHCI|WinUSB|usbfilter)$' })
    if ($filters.Count -gt 0) {
        Add-Finding Check 'Registry' ("Extra USB filter drivers are loaded: {0}. Something other than Windows is sitting between the USB port and the VCM. Antivirus and other diagnostic tools do this. The VCM enumerates, beeps, and falls off, usually in the middle of a session." -f ($filters -join ', ')) 'If the VCM will not stay connected, pull that filter or uninstall whatever put it there.'
    }
    else {
        Add-Finding Ok 'Registry' 'No extra USB class filter drivers are installed. Nothing is hooked in front of the VCM at that layer.'
    }

    # debugger hooked on the exe. leftover from AV or someone testing.
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-Path $ifeo) {
        $traps = @()
        foreach ($name in @('IDS.exe', 'FDRS.exe', 'FJDS.exe', 'VCIManager.exe', 'VCI Manager.exe')) {
            $k = Join-Path $ifeo $name
            $item = Get-ItemProperty $k -ErrorAction SilentlyContinue
            if ($item -and $item.Debugger) {
                $traps += "$name -> $($item.Debugger)"
            }
        }
        if ($traps.Count -gt 0) {
            Add-Finding Problem 'Registry' ("A debugger is set on a Ford program (Image File Execution Options): {0}. The program will not start normally. This is left behind by an antivirus sandbox or by someone troubleshooting." -f ($traps -join '; ')) 'Remove the Debugger value for that exe. Do not delete the whole Image File Execution Options key.'
        }
    }

    $longPath = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -ErrorAction SilentlyContinue
    if (-not $longPath -or [int]$longPath.LongPathsEnabled -ne 1) {
        Add-Finding Check 'Registry' 'Long path support is off. IDS calibration folders get very deep. Setup then fails with a path-too-long error, often near the end after it has already been running for a long time.' 'Turn LongPathsEnabled on, reboot, and run the IDS install again.'
    }
    else {
        Add-Finding Ok 'Registry' 'Long path support is on. IDS calibration paths should be able to unpack.'
    }
}

function Get-DeviceCheck {
    Write-Host 'Checking for a connected VCM / VCMM / VCM3...'
    $all = @(Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue)
    $hits = @($all | Where-Object {
        $_.Name -match 'VCM|VCMM|VCI Manager|Vehicle Communication|VTX-VCI|Dearborn' -or
        ($_.Manufacturer -match 'Ford Motor|Dearborn Group' -and $_.PNPClass -match 'Net|USB|Ports|HIDClass|USBDevice')
    })

    if ($hits.Count -eq 0) {
        if ($script:HasIds -or $script:HasVci) {
            Add-Finding Check 'Hardware' 'Ford software is installed, but Windows does not see a VCM, VCM3, or VCMM at all. The driver is not installed, or the interface is unplugged. In Device Manager this is usually Other devices, Unknown Device, with no Ford driver listed.' 'Plug the interface into a USB port on the laptop. If it still does not appear by name, install VCI Software and reboot. That package is the driver.'
        }
        else {
            Add-Finding Check 'Hardware' 'No VCM, VCM3, or VCMM is connected. Windows does not see the interface or a driver for it.' 'Plug the interface into a USB port on the laptop and run this again. If it shows up as Unknown Device, install VCI Software and reboot.'
        }
    }

    # Plugged in, but Windows never got a driver. These do not have VCM in the name.
    $unknown = @($all | Where-Object {
        $code = [int]$_.ConfigManagerErrorCode
        $code -ne 0 -and $code -ne 45 -and $_.Name -match 'Unknown'
    })
    foreach ($dev in $unknown) {
        $why = Get-CmErrorText -Code ([int]$dev.ConfigManagerErrorCode)
        Add-Finding Problem 'Hardware' ("Windows sees '{0}' and does not have a driver for it. {1} If this is the VCM, VCI Software was not installed or the install did not finish." -f $dev.Name, $why) 'Install VCI Software, reboot, and plug the interface directly into the laptop. In Device Manager it should then show a Ford or VCM name, not Unknown Device.'
    }

    $problem = 0
    foreach ($dev in $hits) {
        $code = [int]$dev.ConfigManagerErrorCode
        $nm = [string]$dev.Name
        if ($code -eq 0) {
            Add-Finding Ok 'Hardware' "Windows sees '$nm' and reports it working."
        }
        elseif ($code -eq 45) {
            Add-Finding Check 'Hardware' "'$nm' is not connected. The driver was installed before, but the interface is unplugged right now." 'Plug the interface into a USB port on the laptop and run this again.'
        }
        else {
            $problem++
            $why = Get-CmErrorText -Code $code
            Add-Finding Problem 'Hardware' ("'{0}' is not working. {1}" -f $nm, $why) 'Install VCI Software, reboot, and move the USB plug to a port on the laptop. If the code is 48 or 52, deal with Memory integrity first (see the security section) and then reinstall VCI Software.'
        }
    }

    if ($hits.Count -gt 0 -and $problem -eq 0) {
        # already added per-device lines
    }
}

function Get-PowerCheck {
    Write-Host 'Checking power settings that drop the USB link...'

    $fast = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction SilentlyContinue
    if ($fast -and [int]$fast.HiberbootEnabled -eq 1) {
        Add-Finding Check 'Power' 'Fast Startup is on. Windows does not really shut down, and the VCM USB device comes back in a bad state the next morning. VCI Manager then shows a device that will not take a firmware update until you do a full reboot or pull the USB cable.' 'Turn Fast Startup off on a bay laptop, or get in the habit of Restart (not Shut down) before a programming job.'
    }
    else {
        Add-Finding Ok 'Power' 'Fast Startup is off. A shut down is a real shut down, which is what you want before a VCM firmware update.'
    }

    $usbOut = ''
    try {
        $usbOut = (powercfg /q SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226) -join "`n"
    }
    catch { }
    if ($usbOut -match 'Current AC Power Setting Index:\s+0x([0-9a-fA-F]+)') {
        $ac = [Convert]::ToInt32($Matches[1], 16)
        if ($ac -ne 0) {
            Add-Finding Check 'Power' 'USB selective suspend is enabled on AC power. Windows sleeps the USB port while IDS is sitting on a menu. The VCM drops and the next button press is a communication error.' 'In the power plan, under USB settings, turn USB selective suspend off. High performance plan is the simple version of the same fix.'
        }
        else {
            Add-Finding Ok 'Power' 'USB selective suspend is off while plugged in. The VCM will not be powered down mid-session by the power plan.'
        }
    }

    $sleepOut = ''
    try {
        $sleepOut = (powercfg /q SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da) -join "`n"
    }
    catch { }
    if ($sleepOut -match 'Current AC Power Setting Index:\s+0x([0-9a-fA-F]+)') {
        $sec = [Convert]::ToInt32($Matches[1], 16)
        if ($sec -gt 0 -and $sec -lt 900) {
            $min = [math]::Round($sec / 60, 0)
            Add-Finding Check 'Power' "This PC sleeps after about $min minutes on AC power. An FDRS module download or a long IDS session outlasts that. The laptop sleeps, the VCM drops, and the module flash fails." 'Set sleep to Never while plugged in on the bay laptop.'
        }
        elseif ($sec -eq 0) {
            Add-Finding Ok 'Power' 'Sleep is set to Never on AC power.'
        }
    }

    $active = ''
    try { $active = (powercfg /getactivescheme) -join ' ' } catch { }
    if ($active -match '\((.+?)\)') {
        Add-Spec ("Power plan: {0}" -f $Matches[1])
    }
}

function Get-EventCheck {
    Write-Host "Reading event logs for the last $Days days..."
    if (-not $script:IsAdmin) {
        Add-Finding Note 'Event log' 'Not running as administrator, so some log entries are hidden. Re-run elevated if this section looks too clean.'
    }

    $start = (Get-Date).AddDays(-1 * $Days)
    # whole word on IDS or it matches random junk in the log
    $pattern = 'Ford Motor|FDRS|FJDS|\bIDS\b|VCI Manager|VCI Software|\bVCM\b|VCMM|InstallShield|PassThru|J2534'
    $app = @(Get-MatchingEvents -LogName 'Application' -Start $start -Pattern $pattern -Max 500)
    $sys = @(Get-MatchingEvents -LogName 'System' -Start $start -Pattern 'VCM|VCMM|Ford Motor|VCI Manager|PassThru' -Max 300)
    $fw = @(Get-MatchingEvents -LogName 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' -Start $start -Pattern $pattern -Max 200)
    $sec = @(Get-SecurityBlocks -Start $start -Pattern $pattern)

    $all = @($app + $sys + $fw + $sec | Sort-Object Time -Descending)
    if ($all.Count -eq 0) {
        Add-Finding Ok 'Event log' "No errors or warnings mentioning Ford, IDS, FDRS, FJDS, or the VCM in the Application, System, Security, or Firewall logs for the last $Days days. That does not prove the car will connect. It does mean Windows has not been recording crashes from those programs."
        return
    }

    # same message 40 times is useless, show it once with a count
    $groups = $all | Group-Object { '{0}|{1}|{2}' -f $_.Provider, $_.Id, $_.Message.Substring(0, [Math]::Min(180, $_.Message.Length)) }
    $shown = 0
    foreach ($g in ($groups | Sort-Object Count -Descending | Select-Object -First 8)) {
        $sample = $g.Group | Select-Object -First 1
        $when = $sample.Time.ToString('yyyy-MM-dd HH:mm')
        $short = $sample.Message
        if ($short.Length -gt 280) { $short = $short.Substring(0, 280) + '...' }
        $times = ''
        if ($g.Count -gt 1) { $times = " ($($g.Count) times, last $when)" }
        else { $times = " ($when)" }

        $level = 'Check'
        if ($sample.Provider -eq 'Application Error' -or $sample.Id -eq 1000) { $level = 'Problem' }
        Add-Finding $level 'Event log' ("{0} event {1}{2}: {3}" -f $sample.Provider, $sample.Id, $times, $short)
        $shown++
    }

    if ($groups.Count -gt $shown) {
        Add-Finding Note 'Event log' ("{0} more matching messages were not printed. The ones above are the repeats." -f ($groups.Count - $shown))
    }

    Add-Finding Note 'Event log' 'How to read these: an Application Error for IDS or FDRS means that program crashed and the detail above is the Windows crash record, not a car fault. An MsiInstaller error means setup failed. A Kernel-PnP message about the VCM means Windows unloaded the USB driver. None of these are fixed by clearing the log.'
}

function Get-SoftwareLogCheck {
    Write-Host 'Reading IDS, FDRS, FJDS, VCI, and VMS logs...'

    $fordData = Join-Path $env:ProgramData 'Ford Motor Company'
    $roots = @(
        @{ Name = 'IDS';  Path = (Join-Path $fordData 'IDS\Log Files') },
        @{ Name = 'FJDS'; Path = (Join-Path $fordData 'FJDS\Log Files') },
        @{ Name = 'FDRS'; Path = (Join-Path $fordData 'FDRS') },
        @{ Name = 'VCI';  Path = (Join-Path $fordData 'VCI') },
        @{ Name = 'VCI';  Path = (Join-Path $fordData 'VCI Manager') },
        @{ Name = 'VCI';  Path = (Join-Path $env:ProgramData 'Bosch') },
        @{ Name = 'VMS';  Path = (Join-Path $fordData 'VMS') },
        @{ Name = 'VMS';  Path = (Join-Path $fordData 'Vehicle Measurement System') }
    )
    if ($env:LOCALAPPDATA) {
        $roots += @{ Name = 'FDRS'; Path = (Join-Path $env:LOCALAPPDATA 'Ford Motor Company\FDRS') }
    }

    $start = (Get-Date).AddDays(-1 * $Days)
    $files = @()
    $seenPath = @{}
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root.Path)) { continue }
        $found = @(Get-ChildItem -LiteralPath $root.Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '^\.(log|txt)$' -and $_.Length -gt 0 -and $_.Length -lt 40MB })
        foreach ($f in $found) {
            if ($seenPath.ContainsKey($f.FullName)) { continue }
            $seenPath[$f.FullName] = $true
            $files += [pscustomobject]@{ Product = $root.Name; File = $f }
        }
    }

    if ($files.Count -eq 0) {
        Add-Finding Check 'Software logs' 'No IDS, FDRS, FJDS, VCI, or VMS log files are on this PC. The programs either are not installed or have not been opened, so there is no software log to read.' 'Install and open the diagnostic software, reproduce the problem, then run this check again. IDS logs are in ProgramData\Ford Motor Company\IDS\Log Files. FJDS uses the same layout. FDRS writes fdrs-runtime.log under ProgramData\Ford Motor Company\FDRS.'
        return
    }

    $recent = @($files | Where-Object { $_.File.LastWriteTime -ge $start } | Sort-Object { $_.File.LastWriteTime } -Descending)
    if ($recent.Count -eq 0) {
        $newest = $files | Sort-Object { $_.File.LastWriteTime } -Descending | Select-Object -First 1
        $when = $newest.File.LastWriteTime.ToString('yyyy-MM-dd')
        Add-Finding Check 'Software logs' ("The newest software log is {0} from {1} ({2}). Nothing was written in the last {3} days, so this check cannot see a current failure." -f $newest.Product, $newest.File.Name, $when, $Days) 'Open the program, reproduce the problem, and run this check again while the log is still fresh.'
        return
    }

    # a few fresh files per program is enough
    $pick = @()
    $perProduct = @{}
    foreach ($item in $recent) {
        $n = 0
        if ($perProduct.ContainsKey($item.Product)) { $n = $perProduct[$item.Product] }
        if ($n -ge 4) { continue }
        $perProduct[$item.Product] = $n + 1
        $pick += $item
    }

    # whole words. "license" and "Exceptions" were marking good lines as failures.
    $badLine = '\berror\b|\bfatal\b|\bfailed\b|\bfailure\b|\bunable to\b|\bcannot\b|\bcould not\b|\btimeout\b|\btimed out\b|access is denied|\b0x800|hresult|\bcrash\b|no device|not connected'
    $skipLine = 'error code:\s*0\b|errorcount\s*[:=]\s*0|\b0 errors?\b|no error|successfully|\bsucceeded\b|information\]'

    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($item in $pick) {
        $text = ''
        try {
            $fs = [System.IO.File]::Open($item.File.FullName, 'Open', 'Read', 'ReadWrite')
            try {
                $take = [Math]::Min(400000, $fs.Length)
                if ($take -lt 1) { continue }
                $fs.Seek($fs.Length - $take, 'Begin') | Out-Null
                $buf = New-Object byte[] $take
                [void]$fs.Read($buf, 0, $take)
                $text = [System.Text.Encoding]::UTF8.GetString($buf)
            }
            finally {
                $fs.Close()
            }
        }
        catch {
            continue
        }

        foreach ($line in ($text -split "`r?`n")) {
            $line = ($line -replace '\s+', ' ').Trim()
            if ($line.Length -lt 12) { continue }
            if ($line -notmatch $badLine) { continue }
            if ($line -match $skipLine) { continue }
            if ($line.Length -gt 240) { $line = $line.Substring(0, 240) + '...' }
            $hits.Add([pscustomobject]@{
                Product = $item.Product
                Name    = $item.File.Name
                When    = $item.File.LastWriteTime
                Line    = $line
            }) | Out-Null
            if ($hits.Count -gt 400) { break }
        }
        if ($hits.Count -gt 400) { break }
    }

    $products = @($pick | ForEach-Object { $_.Product } | Select-Object -Unique) -join ', '
    if ($hits.Count -eq 0) {
        Add-Finding Ok 'Software logs' "Read the $products logs from the last $Days days. No error lines in the recent files."
        return
    }

    $groups = $hits | Group-Object { '{0}|{1}' -f $_.Product, $_.Line.Substring(0, [Math]::Min(140, $_.Line.Length)) }
    $shown = 0
    foreach ($g in ($groups | Sort-Object Count -Descending | Select-Object -First 8)) {
        $sample = $g.Group | Select-Object -First 1
        $when = $sample.When.ToString('yyyy-MM-dd HH:mm')
        $times = ''
        if ($g.Count -gt 1) { $times = " ($($g.Count) times, file $($sample.Name), $when)" }
        else { $times = " ($($sample.Name), $when)" }
        $level = 'Check'
        if ($sample.Line -match '\bfatal\b|access is denied|\b0x800|hresult|\bcrash\b') { $level = 'Problem' }
        Add-Finding $level 'Software logs' ("{0}{1}: {2}" -f $sample.Product, $times, $sample.Line)
        $shown++
    }

    if ($groups.Count -gt $shown) {
        Add-Finding Note 'Software logs' ("{0} more log lines were not printed. The ones above are the repeats." -f ($groups.Count - $shown))
    }
}

function Get-KnownIssueCheck {
    Write-Host 'Checking known Ford software conditions...'
    $before = $script:Findings.Count

    $smb = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -ErrorAction SilentlyContinue
    $smbOff = $true
    if ($smb -and $null -ne $smb.Start -and [int]$smb.Start -ne 4) { $smbOff = $false }
    if ($smbOff -and ($script:HasIds -or $script:HasVci)) {
        Add-Finding Check 'Common issues' 'SMB1 is turned off. VCM2 shows a red X in the corner of IDS, and VCI Manager will not connect, until SMB1 and SMB Direct are enabled under Windows Features. Restart after turning them on.' 'Turn on SMB1 and SMB Direct in Windows Features, then restart. This is the usual VCM2 fix when the cable and drivers are already good.'
    }
    elseif ($smbOff) {
        Add-Finding Note 'Common issues' 'SMB1 is off. Leave it off unless this PC is talking to a VCM2 and IDS shows a red X. That needs SMB1 and SMB Direct turned on, then a restart.'
    }

    $javaOk = $false
    foreach ($jk in @(
        'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment',
        'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment',
        'HKLM:\SOFTWARE\JavaSoft\JRE'
    )) {
        $j = Get-ItemProperty $jk -ErrorAction SilentlyContinue
        if ($j.CurrentVersion -match '^1\.8') { $javaOk = $true }
    }
    if ($script:HasIds -and -not $javaOk) {
        Add-Finding Check 'Common issues' 'Java 8 is not installed. IDS throws "IDS has detected a Windows Error" when Java is missing or too new. FDRS does not use this Java.' 'Install Java 8 for Windows. Do not install a newer Java over the top and expect IDS to accept it.'
    }

    $timeSvc = Get-Service W32Time -ErrorAction SilentlyContinue
    if ($timeSvc -and $timeSvc.Status -ne 'Running') {
        Add-Finding Check 'Common issues' 'Windows Time is not running. A clock that is off shows up as a Whitelabel error or a login failure, and the Ford site looks like it is down.' 'Right-click the clock, Adjust date/time, turn on Set time automatically, and click Sync now.'
    }

    $layers = @()
    foreach ($lk in @(
        'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
    )) {
        $item = Get-ItemProperty $lk -ErrorAction SilentlyContinue
        if ($item) { $layers += $item.PSObject.Properties }
    }
    $idsRunAs = $false
    foreach ($prop in $layers) {
        if ($prop.Name -match 'IDS\.exe$' -and [string]$prop.Value -match 'RUNASADMIN') { $idsRunAs = $true }
    }
    if ($script:HasIds -and -not $idsRunAs) {
        Add-Finding Check 'Common issues' 'IDS is not set to run as administrator. Error 740 is this. Right-click the IDS icon, Properties, Shortcut tab, Advanced, check Run as administrator. The Compatibility tab has the same checkbox.' 'Set the IDS shortcut to Run as administrator so you are not right-clicking it every time.'
    }

    $sessions = 'C:\ProgramData\Ford Motor Company\IDS\Sessions'
    if (Test-Path $sessions) {
        $sessionFiles = @(Get-ChildItem $sessions -Force -ErrorAction SilentlyContinue)
        if ($sessionFiles.Count -gt 0) {
            Add-Finding Check 'Common issues' ("IDS has {0} file(s) in the Sessions folder. A crash or a Testman error on connect is often fixed by emptying that folder. The script did not delete anything." -f $sessionFiles.Count) 'Close IDS. Delete the files in C:\ProgramData\Ford Motor Company\IDS\Sessions. Do not delete the folder itself.'
        }
    }

    $cal = 'C:\Program Files (x86)\Ford Motor Company\Calibration Files'
    if ($script:HasIds -and -not (Test-Path $cal)) {
        Add-Finding Check 'Common issues' 'The IDS calibration folder is missing. IDS will name the files it cannot find. Those get downloaded from Motorcraft Service, Diagnostic tool support, Software, IDS, Overview, Calibration Files at the bottom. Unzip them so the file sits in the Calibration Files folder, not inside another zip.' 'Create C:\Program Files (x86)\Ford Motor Company\Calibration Files and put the unzipped calibration files there.'
    }

    $extra = @(
        @{ Host = 'www.fordservicecontent.com'; What = 'Ford service content' },
        @{ Host = 'www.digicert.com'; What = 'DigiCert (certificate check)' }
    )
    $extraFail = @()
    foreach ($t in $extra) {
        $ok = $false
        try {
            $null = [System.Net.Dns]::GetHostAddresses($t.Host)
            $ok = Test-Tcp -Target $t.Host -Port 443 -TimeoutMs 4000
        }
        catch { $ok = $false }
        if (-not $ok) { $extraFail += $t.What }
    }
    if ($extraFail.Count -gt 0) {
        Add-Finding Check 'Common issues' ("Could not reach: {0}. Shops that will not turn the firewall off need these names allowed, along with *.ford.com, *.motorcraftservice.com, *.dealerconnection.com, *.flexnetoperations.com, and *.flexerasoftware.com." -f ($extraFail -join ', ')) 'Give that list to whoever runs the shop firewall. Do not turn the firewall off as the permanent fix.'
    }

    $hit = $false
    for ($i = $before; $i -lt $script:Findings.Count; $i++) {
        if ($script:Findings[$i].Level -in @('Problem', 'Check')) { $hit = $true }
    }
    if (-not $hit) {
        Add-Finding Ok 'Common issues' 'Usual list is fine: SMB1, Java 8, the clock, IDS running as admin, the Sessions folder, calibrations, and the extra Ford sites.'
    }
}

function Get-ConflictCheck {
    Write-Host 'Checking for other shop software that grabs the same USB / J2534 slot...'
    if (-not $script:Uninstall) { $script:Uninstall = Get-UninstallEntries }

    # other scan tools that drop their own J2534 driver in
    $patterns = @(
        @{ Name = 'Bosch ESI / Shop Foreman'; Match = 'Bosch ESI|Shop Foreman' },
        @{ Name = 'Snap-on'; Match = 'Snap-on|ShopKey' },
        @{ Name = 'Autel'; Match = '\bAutel\b|MaxiFlash' },
        @{ Name = 'Launch'; Match = '\bLaunch\b' },
        @{ Name = 'Drew Tech / Opus'; Match = 'Drew Tech|Opus IVS' },
        @{ Name = 'DG Technologies'; Match = 'DG Technologies|Dearborn Group' },
        @{ Name = 'Toyota Techstream'; Match = 'Techstream' },
        @{ Name = 'Honda HDS'; Match = '\bHDS\b' },
        @{ Name = 'VW ODIS'; Match = '\bODIS\b' },
        @{ Name = 'Mercedes Xentry'; Match = 'Xentry|XENTRY' },
        @{ Name = 'GM GDS / TLC'; Match = 'GDS 2|Techline Connect|\bTLC\b' }
    )

    $hits = @()
    foreach ($p in $patterns) {
        $m = @($script:Uninstall | Where-Object { $_.DisplayName -match $p.Match })
        if ($m.Count -gt 0) {
            $example = $m[0].DisplayName
            $hits += "$($p.Name) ($example)"
        }
    }
    if ($hits.Count -eq 0) {
        Add-Finding Ok 'Other shop software' 'No other common OEM diagnostic suite showed up in Programs and Features. If a J2534 tool is plugged in anyway, the registry section above is the list that matters.'
    }
    else {
        Add-Finding Check 'Other shop software' ("Other diagnostic software is installed: {0}. These are not automatically a problem. They become a problem when their J2534 driver is the one Ford opens, or when their USB filter is installed. Use the J2534 section above to see who is registered." -f ($hits -join '; ')) 'Unplug the other interfaces while you set up Ford. If Ford still opens the wrong tool, fix the J2534 selection. You do not have to uninstall the other suite unless its driver is the one crashing.'
    }
}

function ConvertTo-PdfText {
    param([string]$Text)
    if (-not $Text) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        $n = [int]$ch
        if ($ch -eq '\' -or $ch -eq '(' -or $ch -eq ')') {
            [void]$sb.Append('\').Append($ch)
        }
        elseif ($n -ge 32 -and $n -le 126) {
            [void]$sb.Append($ch)
        }
        else {
            [void]$sb.Append(' ')
        }
    }
    return $sb.ToString()
}

function Get-PdfWrap {
    param([string]$Text, [int]$Width)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($raw in ($Text -split "`r?`n")) {
        $line = ($raw -replace '\s+', ' ').Trim()
        if (-not $line) { continue }
        while ($line.Length -gt $Width) {
            $cut = $line.LastIndexOf(' ', $Width)
            if ($cut -lt 12) { $cut = $Width }
            $out.Add($line.Substring(0, $cut).Trim())
            $line = $line.Substring($cut).Trim()
        }
        if ($line) { $out.Add($line) }
    }
    if ($out.Count -eq 0) { $out.Add('') }
    return $out
}

function Write-DiagnosticPdf {
    param(
        [string]$Path,
        [System.Collections.Generic.List[string]]$Lines
    )

    # yellow on white washes out, check text stays amber
    $pageW = 612
    $pageH = 792
    $left = 48
    $right = 564
    $wrap = 88

    $cmds = New-Object System.Collections.Generic.List[string]
    $pages = New-Object System.Collections.Generic.List[object]
    $y = 0

    function Start-PdfPage {
        $script:cmds = New-Object System.Collections.Generic.List[string]
        $script:y = 718
        # navy bar
        $script:cmds.Add('0.102 0.165 0.290 rg')
        $script:cmds.Add("0 $([int]($pageH - 36)) $pageW 36 re f")
        $script:cmds.Add('BT /F2 11 Tf 1 1 1 rg 48 766 Td (ROTUNDA / FORD DIAGNOSTIC PC CHECK) Tj ET')
        $script:cmds.Add('BT /F1 9 Tf 0.820 0.863 0.910 rg 400 766 Td (IDS  FDRS  FJDS  VCI  VMS) Tj ET')
    }
    function End-PdfPage {
        $pages.Add($script:cmds)
    }
    function Need-PdfRoom {
        param([int]$Height)
        if (($script:y - $Height) -lt 46) {
            End-PdfPage
            Start-PdfPage
        }
    }

    Start-PdfPage

    Need-PdfRoom 28
    $script:cmds.Add('BT /F1 9 Tf 0.35 0.38 0.42 rg 48 1 Td ( ) Tj ET')
    $script:cmds.Add("BT /F2 9 Tf 0.60 0.11 0.11 rg 48 $($script:y) Td (PROBLEM) Tj ET")
    $script:cmds.Add("BT /F1 9 Tf 0.35 0.38 0.42 rg 108 $($script:y) Td (broken.) Tj ET")
    $script:cmds.Add("BT /F2 9 Tf 0.77 0.35 0.00 rg 230 $($script:y) Td (CHECK) Tj ET")
    $script:cmds.Add("BT /F1 9 Tf 0.35 0.38 0.42 rg 276 $($script:y) Td (needs a look.) Tj ET")
    $script:cmds.Add("BT /F2 9 Tf 0.00 0.45 0.22 rg 360 $($script:y) Td (OK) Tj ET")
    $script:cmds.Add("BT /F1 9 Tf 0.35 0.38 0.42 rg 382 $($script:y) Td (fine.) Tj ET")
    $script:y -= 22
    $script:cmds.Add('0.85 0.87 0.90 RG')
    $script:cmds.Add("48 $($script:y) m 564 $($script:y) l S")
    $script:y -= 18

    $items = New-Object System.Collections.Generic.List[object]
    $seenText = @{}
    foreach ($line in $Lines) {
        if (-not $line) { continue }
        $key = $line.Trim()
        if (-not $key) { continue }
        if ($key -match '^[-=]{10,}$') { continue }
        if ($key -match 'ROTUNDA / FORD DIAGNOSTIC') { continue }
        if ($key -match 'IDS, FDRS, FJDS') { continue }

        $kind = 'text'
        $text = $key
        if ($key -match '(?s)^\[PROBLEM\]\s*(.*)$') { $kind = 'problem'; $text = $Matches[1].Trim() }
        elseif ($key -match '(?s)^\[CHECK\]\s*(.*)$') { $kind = 'check'; $text = $Matches[1].Trim() }
        elseif ($key -eq 'OK') { $kind = 'ok'; $text = 'OK' }
        elseif ($key -match '(?s)^\[NOTE\]\s*(.*)$') { $kind = 'note'; $text = $Matches[1].Trim() }
        elseif ($key -cmatch '^[A-Z][A-Z0-9 /]{2,}$') { $kind = 'section' }

        if ($kind -eq 'problem' -or $kind -eq 'check' -or $kind -eq 'note') {
            if ($seenText.ContainsKey($text)) { continue }
            $seenText[$text] = $true
        }
        $items.Add([pscustomobject]@{ Kind = $kind; Text = $text }) | Out-Null
    }

    $pre = New-Object System.Collections.Generic.List[object]
    $sections = New-Object System.Collections.Generic.List[object]
    $cur = $null
    $inIssues = $false
    foreach ($it in $items) {
        if ($it.Kind -eq 'section' -and $it.Text -eq 'ISSUES FOUND') { $inIssues = $true; continue }
        if (-not $inIssues) { $pre.Add($it) | Out-Null; continue }
        if ($it.Kind -eq 'section') {
            $cur = [pscustomobject]@{ Name = $it.Text; Items = (New-Object System.Collections.Generic.List[object]) }
            $sections.Add($cur) | Out-Null
            continue
        }
        if (-not $cur) { continue }
        $cur.Items.Add($it) | Out-Null
    }

    foreach ($sec in $sections) {
        $body = @($sec.Items | Where-Object { $_.Kind -eq 'problem' -or $_.Kind -eq 'check' } | ForEach-Object { $_.Text })
        $keep = New-Object System.Collections.Generic.List[object]
        foreach ($it in $sec.Items) {
            if ($it.Kind -eq 'ok') { continue }
            if ($it.Kind -eq 'text' -and $body.Count -gt 0) {
                $drop = $false
                foreach ($b in $body) {
                    if ($b.StartsWith($it.Text.TrimEnd('.'))) { $drop = $true; break }
                }
                if ($drop) { continue }
            }
            $keep.Add($it) | Out-Null
        }
        $sec.Items = $keep
    }

    function Write-PdfLine {
        param([string]$Font, [string]$Rgb, [int]$X, [int]$Y, [string]$Text)
        $safe = ConvertTo-PdfText $Text
        $script:cmds.Add("BT $Font Tf $Rgb rg $X $Y Td ($safe) Tj ET")
    }

    foreach ($it in $pre) {
        if ($it.Kind -eq 'section') {
            Need-PdfRoom 36
            $script:y -= 8
            Write-PdfLine '/F2 12' '0.102 0.165 0.290' 48 $script:y $it.Text
            $script:y -= 8
            $script:cmds.Add('0.75 0.78 0.82 RG')
            $script:cmds.Add("48 $($script:y) m 208 $($script:y) l S")
            $script:y -= 16
            continue
        }
        $wrapped = Get-PdfWrap -Text $it.Text -Width 90
        Need-PdfRoom (8 + ($wrapped.Count * 15))
        $i = 0
        foreach ($part in $wrapped) {
            Write-PdfLine '/F1 10' '0.18 0.20 0.24' 58 ($script:y - ($i * 15)) $part
            $i++
        }
        $script:y -= ($wrapped.Count * 15 + 3)
    }

    if ($pre.Count -gt 0) { $script:y -= 8 }

    foreach ($sec in $sections) {
        $onlyClear = ($sec.Items.Count -eq 0)
        if ($onlyClear) {
            Need-PdfRoom 22
            Write-PdfLine '/F1 11' '0.20 0.24 0.30' 48 $script:y $sec.Name
            Write-PdfLine '/F2 11' '0.00 0.45 0.22' 500 $script:y 'OK'
            $script:y -= 6
            $script:cmds.Add('0.90 0.91 0.93 RG')
            $script:cmds.Add("48 $($script:y) m 564 $($script:y) l S")
            $script:y -= 14
            continue
        }

        $headNeed = 28
        Need-PdfRoom $headNeed
        $script:y -= 10
        Write-PdfLine '/F2 12' '0.102 0.165 0.290' 48 $script:y $sec.Name
        $script:y -= 16

        foreach ($it in $sec.Items) {
            if ($it.Kind -eq 'text' -or $it.Kind -eq 'note') {
                $wrapped = Get-PdfWrap -Text $it.Text -Width 88
                Need-PdfRoom (6 + ($wrapped.Count * 14))
                $rgb = '0.25 0.28 0.32'
                if ($it.Kind -eq 'note') { $rgb = '0.10 0.40 0.45' }
                $i = 0
                foreach ($part in $wrapped) {
                    Write-PdfLine '/F1 10' $rgb 58 ($script:y - ($i * 14)) $part
                    $i++
                }
                $script:y -= ($wrapped.Count * 14 + 6)
                continue
            }

            $label = 'CHECK'
            $stripe = '0.77 0.35 0.00'
            $fill = '1.00 0.97 0.93'
            $ink = '0.35 0.22 0.05'
            if ($it.Kind -eq 'problem') {
                $label = 'PROBLEM'
                $stripe = '0.60 0.11 0.11'
                $fill = '0.99 0.95 0.95'
                $ink = '0.45 0.10 0.10'
            }

            $wrapped = Get-PdfWrap -Text $it.Text -Width 84
            $lineH = 14
            $h = 28 + ($wrapped.Count * $lineH)
            Need-PdfRoom ($h + 8)
            $top = $script:y
            $script:cmds.Add("$fill rg")
            $script:cmds.Add("48 $($top - $h) 516 $h re f")
            $script:cmds.Add("$stripe rg")
            $script:cmds.Add("48 $($top - $h) 4 $h re f")
            Write-PdfLine '/F2 8' $stripe 62 ($top - 14) $label
            $i = 0
            foreach ($part in $wrapped) {
                Write-PdfLine '/F1 10' $ink 62 ($top - 28 - ($i * $lineH)) $part
                $i++
            }
            $script:y = $top - $h - 8
        }
        $script:y -= 6
    }

    # page number footer is stamped when the file is written
    End-PdfPage

    $objects = New-Object System.Collections.Generic.List[string]
    [void]$objects.Add('') # 0 unused
    $font1 = 3
    $font2 = 4
    $pageIds = @()
    $contentIds = @()
    $next = 5
    for ($p = 0; $p -lt $pages.Count; $p++) {
        $contentIds += $next
        $pageIds += ($next + 1)
        $next += 2
    }

    [void]$objects.Add('<< /Type /Catalog /Pages 2 0 R >>')
    $kids = ($pageIds | ForEach-Object { "$_ 0 R" }) -join ' '
    [void]$objects.Add("<< /Type /Pages /Kids [ $kids ] /Count $($pages.Count) >>")
    [void]$objects.Add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>')
    [void]$objects.Add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>')

    for ($p = 0; $p -lt $pages.Count; $p++) {
        $body = New-Object System.Collections.Generic.List[string]
        foreach ($c in $pages[$p]) { $body.Add($c) }
        $body.Add("BT /F1 8 Tf 0.40 0.44 0.48 rg 48 28 Td (Page $($p + 1) of $($pages.Count)) Tj ET")
        $stream = $body -join "`n"
        $len = [Text.Encoding]::ASCII.GetByteCount($stream)
        [void]$objects.Add("<< /Length $len >>`nstream`n$stream`nendstream")
        [void]$objects.Add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 $pageW $pageH] /Contents $($contentIds[$p]) 0 R /Resources << /Font << /F1 $font1 0 R /F2 $font2 0 R >> >> >>")
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("%PDF-1.4`n")
    $offsets = New-Object int[] ($objects.Count)
    for ($n = 1; $n -lt $objects.Count; $n++) {
        $offsets[$n] = [Text.Encoding]::ASCII.GetByteCount($sb.ToString())
        [void]$sb.Append("$n 0 obj`n")
        [void]$sb.Append($objects[$n])
        [void]$sb.Append("`nendobj`n")
    }
    $xrefAt = [Text.Encoding]::ASCII.GetByteCount($sb.ToString())
    [void]$sb.Append("xref`n0 $($objects.Count)`n")
    [void]$sb.Append("0000000000 65535 f `n")
    for ($n = 1; $n -lt $objects.Count; $n++) {
        [void]$sb.Append(('{0:0000000000} 00000 n ' -f $offsets[$n]))
        [void]$sb.Append("`n")
    }
    [void]$sb.Append("trailer << /Size $($objects.Count) /Root 1 0 R >>`n")
    [void]$sb.Append("startxref`n$xrefAt`n%%EOF")
    [IO.File]::WriteAllText($Path, $sb.ToString(), [Text.Encoding]::ASCII)
    return $Path
}

function Publish-Report {
    $lines = New-Object System.Collections.Generic.List[string]
    $stamp = Get-Date -Format 'dddd, MMMM d, yyyy h:mm tt'

    $null = $lines.Add('============================================================')
    $null = $lines.Add(' ROTUNDA / FORD DIAGNOSTIC PC CHECK')
    $null = $lines.Add(' IDS, FDRS, FJDS, VCI Manager, VMS')
    $null = $lines.Add('============================================================')
    $null = $lines.Add('')
    $null = $lines.Add('WHAT THIS PC IS')
    foreach ($s in $script:Specs) { $null = $lines.Add("  $s") }
    $null = $lines.Add('')
    $null = $lines.Add('============================================================')
    $null = $lines.Add("Computer : $env:COMPUTERNAME")
    $null = $lines.Add("User     : $env:USERNAME")
    $null = $lines.Add("When     : $stamp")
    if ($script:IsAdmin) {
        $null = $lines.Add('Ran as administrator : Yes')
    }
    else {
        $null = $lines.Add('Ran as administrator : No')
        $null = $lines.Add('Some firewall, antivirus, and log checks are incomplete until you re-run this elevated.')
    }
    $null = $lines.Add('============================================================')
    $null = $lines.Add('')
    $null = $lines.Add('ISSUES FOUND')
    $null = $lines.Add('============================================================')

    $order = @(
        'Windows',
        'This PC',
        'Windows components',
        'Installed Ford software',
        'Firewall',
        'Antivirus',
        'Security settings',
        'Network',
        'Registry',
        'Hardware',
        'Power',
        'Other shop software',
        'Software logs',
        'Event log',
        'Common issues'
    )
    $tag = @{
        Problem = 'PROBLEM'
        Check   = 'CHECK'
        Ok      = 'OK'
        Note    = 'NOTE'
    }

    $formatFinding = {
        param($Finding)
        $text = [string]$Finding.Text
        if (($Finding.Level -eq 'Problem' -or $Finding.Level -eq 'Check') -and $Finding.Fix) {
            $text = $text + "`nFix: " + [string]$Finding.Fix
        }
        return ('[{0}] {1}' -f $tag[$Finding.Level], $text)
    }

    $sections = @($order)
    $extraNames = @($script:Findings | ForEach-Object { $_.Section } | Where-Object { $order -notcontains $_ } | Select-Object -Unique)
    if ($extraNames.Count -gt 0) { $sections += $extraNames }

    foreach ($section in $sections) {
        $inSection = @($script:Findings | Where-Object { $_.Section -eq $section })
        $status = @()
        if ($section -eq 'Firewall') { $status = @($script:FirewallStatus) }
        if ($section -eq 'Network') { $status = @($script:NetworkStatus) }
        if ($inSection.Count -eq 0 -and $status.Count -eq 0) { continue }
        $issues = @($inSection | Where-Object { $_.Level -eq 'Problem' -or $_.Level -eq 'Check' -or $_.Level -eq 'Note' })
        $null = $lines.Add($section.ToUpper())
        foreach ($s in $status) { $null = $lines.Add($s) }
        if ($issues.Count -eq 0) {
            $null = $lines.Add('OK')
        }
        else {
            foreach ($f in $issues) {
                $null = $lines.Add((& $formatFinding $f))
                $null = $lines.Add('')
            }
        }
        $null = $lines.Add('')
    }

    $outFolder = Get-ResultFolder
    if (-not (Test-Path $outFolder)) { New-Item -ItemType Directory -Path $outFolder -Force | Out-Null }
    $pdfPath = Join-Path $outFolder ('Rotunda Diagnostic Report {0} {1:yyyy-MM-dd HHmm}.pdf' -f $env:COMPUTERNAME, (Get-Date))
    try { $null = Write-DiagnosticPdf -Path $pdfPath -Lines $lines } catch { $pdfPath = $null }

    foreach ($line in $lines) {
        if ($line -match '(?s)^\[(PROBLEM|CHECK|NOTE)\]\s*(.*)$') {
            $label = $Matches[1]
            $parts = @($Matches[2] -split "`r?`n")
            $esc = [char]27
            $labelColor = '0;180;170'
            $textColor = 'Cyan'
            if ($label -eq 'PROBLEM') {
                $labelColor = '153;27;27'
                $textColor = 'Red'
            }
            elseif ($label -eq 'CHECK') {
                $labelColor = '196;90;0'
                $textColor = 'Yellow'
            }
            Write-Host ("{0}[38;2;{1}m[{2}]{0}[0m " -f $esc, $labelColor, $label) -NoNewline
            Write-Host $parts[0] -ForegroundColor $textColor
            for ($i = 1; $i -lt $parts.Count; $i++) {
                $partColor = $textColor
                if ($parts[$i] -match '^Fix:') { $partColor = 'Gray' }
                Write-Host $parts[$i] -ForegroundColor $partColor
            }
            continue
        }
        $color = 'Gray'
        if ($line -match '^[-=]+$') { $color = 'White' }
        elseif ($line -eq 'OK') { $color = 'Green' }
        Write-Host $line -ForegroundColor $color
    }
    Write-Host ''
    Write-Host 'Read only. Firewall, antivirus, and the registry were left alone.'
    Write-Host ''
    if ($pdfPath) {
        Write-Host 'PDF:' -ForegroundColor Green
        Write-Host $pdfPath
    }
    else {
        Write-Host 'Could not write the PDF.' -ForegroundColor Red
    }
    return $pdfPath
}

$problems = 0
$checks = 0
try {
    if (-not $script:IsAdmin) {
        Write-Host ''
        Write-Host 'This window is not elevated. Right-click PowerShell, Run as administrator,' -ForegroundColor Yellow
        Write-Host 'and run the script again if a section comes back blank.' -ForegroundColor Yellow
        Write-Host ''
    }

    Get-OsCheck
    Get-HardwareCheck
    Get-RuntimeCheck
    Get-FordSoftwareCheck
    Get-SecurityCheck
    Get-NetworkCheck
    Get-RegistryCheck
    Get-DeviceCheck
    Get-PowerCheck
    Get-ConflictCheck
    Get-SoftwareLogCheck
    Get-EventCheck
    Get-KnownIssueCheck
}
catch {
    Add-Finding Problem 'Script' ("Stopped early: {0}" -f $_.Exception.Message) 'Run it again from an admin PowerShell. If it dies in the same spot, that message is why.'
}
finally {
    Publish-Report | Out-Null
}

foreach ($f in $script:Findings) {
    if ($f.Level -eq 'Problem') { $problems++ }
    elseif ($f.Level -eq 'Check') { $checks++ }
}

if (-not $NoPause -and $Host.Name -eq 'ConsoleHost') {
    Write-Host ''
    Write-Host 'Press Enter to close.'
    try { [void](Read-Host) } catch { }
}

if ($problems -gt 0) { exit 2 }
if ($checks -gt 0) { exit 1 }
exit 0
