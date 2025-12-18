# Server Connectivity Scan - FINAL FIXED VERSION (Reliable Port Checks with .NET TcpClient)
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
            Server          = if ($fqdn) { $fqdn } else { $netbios }
            IPAddress       = $ip
            OperatingSystem = $srv.OSName
            OSVersion       = $srv.OSVersion
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

    # Ports to test
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

    # Reliable .NET TCP port check (2-second timeout)
    $portResults = $ports | ForEach-Object -Parallel {
        $p = $_
        $serverName = $using:server
        $open = $false
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $connect = $tcp.BeginConnect($serverName, $p.Port, $null, $null)
            $wait = $connect.AsyncWaitHandle.WaitOne(2000, $false)  # 2 sec timeout
            if ($wait -and $tcp.Connected) {
                $tcp.EndConnect($connect)
                $open = $true
            }
            $tcp.Close()
        } catch { }
        [pscustomobject]@{ Property = $p.Property; Open = $open }
    } -ThrottleLimit 30

    # Base object
    $obj = [pscustomobject]@{
        ScanDate        = $scanDate
        Server          = $server
        IPAddress       = $entry.IPAddress
        OperatingSystem = $entry.OperatingSystem
        OSVersion       = $entry.OSVersion
        Online          = $true
        WMI             = $false
        WinRM           = $false
        RPC_over_SMB    = $false
        InstallDate     = $null
        UptimeDays      = $null
    }

    # Add all port properties
    foreach ($pr in $portResults) {
        $obj | Add-Member -MemberType NoteProperty -Name $pr.Property -Value $pr.Open -Force
    }

    # Optional: Remove raw WinRM_Port column (recommended - we have smarter WinRM status)
    $obj.PSObject.Properties.Remove('WinRM_Port')

    # WMI check
    try {
        Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $server -OperationTimeoutSec 8 -ErrorAction Stop | Out-Null
        $obj.WMI = $true
    } catch { }

    # WinRM check
    $winrmWorks = $false
    try {
        Test-WSMan -ComputerName $server -ErrorAction Stop | Out-Null
        $obj.WinRM = $true
        $winrmWorks = $true
    } catch {
        # If raw port was open but Test-WSMan failed
        if ($portResults | Where-Object Property -eq 'WinRM_Port' | Select-Object -ExpandProperty Open) {
            $obj.WinRM = "PortOpenOnly"
        }
    }

    # WinRM extra data (install date + uptime)
    if ($winrmWorks) {
        try {
            $osInfo = Invoke-Command -ComputerName $server -ScriptBlock {
                $os = Get-CimInstance Win32_OperatingSystem
                [pscustomobject]@{
                    InstallDate    = $os.InstallDate
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

    # Admin share check (tests RPC/DCOM over SMB)
    if (Test-Path "\\$server\C$" -ErrorAction SilentlyContinue) {
        $obj.RPC_over_SMB = $true
    }

    $bag.Add($obj)
} -ThrottleLimit 50

# Final results
$finalResults = $finalReport.ToArray() | Sort-Object Server

# Display in interactive grid (best way to see all columns)
$finalResults | Out-GridView -Title "Server Connectivity Scan Results - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"

# Export to CSV (all columns included)
$csvPath = "ServerConnectivityReport_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
$finalResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Host "Scan complete!" -ForegroundColor Green
Write-Host "Reachable servers : $($reachableList.Count)" -ForegroundColor Cyan
Write-Host "Full results      : $($finalResults.Count)" -ForegroundColor Cyan
Write-Host "Report saved to   : $(Resolve-Path $csvPath)" -ForegroundColor Cyan
Write-Host "Tip: Open CSV in Excel via Data > From Text/CSV to see all columns properly." -ForegroundColor Yellow
