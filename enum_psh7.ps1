# Server Connectivity Scan - FINAL FIXED VERSION (All Ports Show Correctly + Additional Ports)
# Requires PowerShell 7+ and Active Directory module
Import-Module ActiveDirectory
Write-Host "Querying Active Directory for servers..." -ForegroundColor Yellow

# Phase 1: Materialize OS properties reliably
$serverObjects = Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' -Properties DNSHostName, Name, OperatingSystem, OperatingSystemVersion |
    Select-Object @{
        Name = 'DNSHostName'
        Expression = { $_.DNSHostName }
    }, @{
        Name = 'NetBIOSName'
        Expression = { $_.Name }
    }, @{
        Name = 'OSName'
        Expression = {
            if ($_.OperatingSystem) { $_.OperatingSystem.ToString().Trim() }
            else { "Unknown" }
        }
    }, @{
        Name = 'OSVersion'
        Expression = {
            if ($_.OperatingSystemVersion) { $_.OperatingSystemVersion.ToString().Trim() }
            else { "Unknown" }
        }
    }

$scanDate = Get-Date
$reachableServers = [System.Collections.Concurrent.ConcurrentBag[psobject]]::new()

Write-Host "Phase 1: Testing DNS + ICMP reachability..." -ForegroundColor Yellow

# Phase 1: Reachability
$serverObjects | ForEach-Object -Parallel {
    $srv = $_
    $bag = $using:reachableServers
    $fqdn = $srv.DNSHostName
    $netbios = $srv.NetBIOSName
    if (-not $fqdn -and -not $netbios) { return }
    $ip = $null
    $testName = $null
    if ($fqdn) {
        try {
            $resolve = Resolve-DnsName -Name $fqdn -ErrorAction Stop | Where-Object QueryType -eq 'A' | Select-Object -First 1
            if ($resolve) { $ip = $resolve.IPAddress; $testName = $fqdn }
        } catch { }
    }
    if (-not $ip -and $netbios) {
        try {
            $resolve = Resolve-DnsName -Name $netbios -ErrorAction Stop | Where-Object QueryType -eq 'A' | Select-Object -First 1
            if ($resolve) { $ip = $resolve.IPAddress; $testName = $netbios }
        } catch { }
    }
    if (-not $ip -or -not $testName) { return }
    if (Test-NetConnection -ComputerName $testName -InformationLevel Quiet -WarningAction SilentlyContinue) {
        $obj = [pscustomobject]@{
            Server = if ($fqdn) { $fqdn } else { $netbios }
            IPAddress = $ip
            OperatingSystem = $srv.OSName
            OSVersion = $srv.OSVersion
        }
        $bag.Add($obj)
    }
} -ThrottleLimit 100

$reachableList = $reachableServers.ToArray() | Sort-Object Server
Write-Host "Phase 1 complete: $($reachableList.Count) servers reachable." -ForegroundColor Green

if ($reachableList.Count -eq 0) {
    Write-Host "No reachable servers found." -ForegroundColor Red
    return
}

# Phase 2: Full enrichment
$finalReport = [System.Collections.Concurrent.ConcurrentBag[psobject]]::new()
Write-Host "Phase 2: Checking ports, services, and WinRM data..." -ForegroundColor Yellow

$reachableList | ForEach-Object -Parallel {
    $entry = $_
    $server = $entry.Server
    $bag = $using:finalReport
    $scanDate = $using:scanDate

    # Updated ports list with SMB, RPC, SQL, SMTP, SMTPS
    $ports = @(
        @{Port=3389; Property='RDP'}
        @{Port=80;   Property='HTTP'}
        @{Port=443;  Property='HTTPS'}
        @{Port=21;   Property='FTP'}
        @{Port=22;   Property='SSH'}
        @{Port=389;  Property='LDAP'}
        @{Port=636;  Property='LDAPS'}
        @{Port=88;   Property='Kerberos'}
        @{Port=5985; Property='WinRM_Port'}
        @{Port=445;  Property='SMB'}
        @{Port=135;  Property='RPC'}
        @{Port=1433; Property='MSSQL'}
        @{Port=25;   Property='SMTP'}
        @{Port=465;  Property='SMTPS'}
    )

    $portResults = $ports | ForEach-Object -Parallel {
        $p = $_
        $result = Test-NetConnection -ComputerName $using:server -Port $p.Port -InformationLevel Quiet -WarningAction SilentlyContinue
        [pscustomobject]@{ Property = $p.Property; Open = $result.TcpTestSucceeded }
    } -ThrottleLimit 20

    # Start with base properties only (NO port properties yet)
    $obj = [pscustomobject]@{
        ScanDate = $scanDate
        Server = $server
        IPAddress = $entry.IPAddress
        OperatingSystem = $entry.OperatingSystem
        OSVersion = $entry.OSVersion
        Online = $true
        WMI = $false
        WinRM = $false
        RPC_over_SMB = $false
        InstallDate = $null
        UptimeDays = $null
    }

    # Dynamically ADD and set all standard port properties
    $portResults | Where-Object Property -ne 'WinRM_Port' | ForEach-Object {
        $obj | Add-Member -MemberType NoteProperty -Name $_.Property -Value $_.Open -Force
    }

    # WMI
    try {
        Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $server -OperationTimeoutSec 8 -ErrorAction Stop | Out-Null
        $obj.WMI = $true
    } catch { }

    # WinRM
    $winrmWorks = $false
    try {
        Test-WSMan -ComputerName $server -ErrorAction Stop | Out-Null
        $obj.WinRM = $true
        $winrmWorks = $true
    } catch {
        if (($portResults | Where-Object Property -eq 'WinRM_Port').Open) {
            $obj.WinRM = "PortOpenOnly"
        }
    }

    # WinRM extra data
    if ($winrmWorks) {
        try {
            $osInfo = Invoke-Command -ComputerName $server -ScriptBlock {
                $os = Get-CimInstance Win32_OperatingSystem
                [pscustomobject]@{
                    InstallDate = $os.InstallDate
                    LastBootUpTime = $os.LastBootUpTime
                }
            } -ErrorAction Stop
            $obj.InstallDate = $osInfo.InstallDate.ToString("yyyy-MM-dd")
            $uptime = (Get-Date) - $osInfo.LastBootUpTime
            $obj.UptimeDays = [math]::Round($uptime.TotalDays, 1)
        } catch {
            $obj.InstallDate = "Retrieve Failed"
            $obj.UptimeDays = "Retrieve Failed"
        }
    }

    # Admin share (tests RPC/DCOM over SMB)
    if (Test-Path "\\$server\C$" -ErrorAction SilentlyContinue) {
        $obj.RPC_over_SMB = $true
    }

    $bag.Add($obj)
} -ThrottleLimit 50

# Final results
$finalResults = $finalReport.ToArray() | Sort-Object Server

# Display all columns including new ports
$finalResults | Format-Table -AutoSize

$csvPath = "ServerConnectivityReport_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
$finalResults | Export-Csv -Path $csvPath -NoTypeInformation

Write-Host "Scan complete!" -ForegroundColor Green
Write-Host "Reachable servers : $($reachableList.Count)" -ForegroundColor Cyan
Write-Host "Full results : $($finalResults.Count)" -ForegroundColor Cyan
Write-Host "Report saved to : $(Resolve-Path $csvPath)" -ForegroundColor Cyan
