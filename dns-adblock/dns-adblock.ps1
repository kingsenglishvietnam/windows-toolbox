#Requires -RunAsAdministrator
<#
.SYNOPSIS
    dns-adblock.ps1 v1 - system-wide ad blocking via AdGuard DNS over HTTPS, with nothing in the
    network path for Hydra to trip over.

.DESCRIPTION
    Replaces AdBlock 360's driver-and-proxy filtering with name resolution: ad and tracker domains
    resolve to nothing, and every connection - including Hydra's loopback RDP, which never does a
    DNS lookup - is left alone. Uses Windows' built-in DNS over HTTPS client, so there is no
    service, driver or proxy to install.

    Default run:
      1  reports AdBlock 360 leftovers: service, driver, install folder, root certificates from its
         HTTPS filtering, and any system proxy. Stops if the service or driver is still there.
      2  registers AdGuard DNS (IPv4 and IPv6) with its DoH template. Plain-DNS fallback is
         allowed, and it still goes to AdGuard, so it still filters.
      3  points every physical adapter (Wi-Fi, USB Wi-Fi, USB Ethernet) at it
      4  flushes the cache and proves it: a normal domain must resolve, an ad domain must come
         back blocked, and the DNS client should hold an HTTPS connection to AdGuard

    -PurgeCerts  also deletes root certificates whose subject or issuer mentions AdBlock.
                 Windows asks for confirmation on any in the CurrentUser store.
    -Force       carries on even if AdBlock 360's service or driver is still registered.
    -Revert      puts every physical adapter back on DHCP-assigned DNS and removes the AdGuard
                 DoH entries.

.EXAMPLE
    & C:\Scripts\windows\dns-adblock.ps1

.EXAMPLE
    & C:\Scripts\windows\dns-adblock.ps1 -Revert

.NOTES
    v1  2026-10-15  initial
#>
[CmdletBinding()]
param(
    [switch]$Revert,
    [switch]$PurgeCerts,
    [switch]$Force
)

$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false

$template = 'https://dns.adguard-dns.com/dns-query'
$servers  = @('94.140.14.14', '94.140.15.15', '2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff')
$adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Sort-Object Name)

function Say {
    param([string]$Text = '', [ConsoleColor]$Color = 'Gray')
    Write-Host $Text -ForegroundColor $Color
}

# Returns $true if AdBlock 360's service or driver is still registered.
function Show-Leftovers {
    Say ''
    Say '== AdBlock 360 leftovers ==' 'Cyan'
    $found = $false
    $live  = $false
    foreach ($s in @(Get-CimInstance Win32_Service | Where-Object { "$($_.Name) $($_.PathName)" -match 'adblock' })) {
        Say "  service   $($s.Name) ($($s.State)) - uninstall AdBlock 360 first" 'Red'
        $found = $true
        $live  = $true
    }
    foreach ($d in @(Get-CimInstance Win32_SystemDriver | Where-Object { "$($_.Name) $($_.PathName)" -match 'adblock' })) {
        Say "  driver    $($d.Name) ($($d.State)) - still registered; reboot after uninstalling" 'Red'
        $found = $true
        $live  = $true
    }
    foreach ($p in 'C:\Program Files\AdBlock360', 'C:\Program Files (x86)\AdBlock360') {
        if (Test-Path -LiteralPath $p) { Say "  folder    $p" 'Yellow'; $found = $true }
    }
    $certs = @(Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root -ErrorAction SilentlyContinue |
        Where-Object { "$($_.Subject) $($_.Issuer)" -match 'adblock' })
    foreach ($c in $certs) {
        Say "  root CA   $($c.Subject)  [$($c.PSParentPath -replace '^.*::')]" 'Red'
        $found = $true
        if ($PurgeCerts) {
            Remove-Item -LiteralPath $c.PSPath -Force -ErrorAction Continue
            if (-not (Test-Path -LiteralPath $c.PSPath)) { Say '            removed' 'Green' }
        }
    }
    if ($certs.Count -and -not $PurgeCerts) { Say '            re-run with -PurgeCerts to delete' 'Yellow' }
    $winhttp = (& netsh winhttp show proxy) -join ' '
    if ($winhttp -notmatch 'Direct access') {
        Say "  WinHTTP   $(($winhttp -replace '\s+', ' ').Trim())" 'Yellow'
        $found = $true
    }
    $inet = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($inet.ProxyEnable -eq 1) { Say "  proxy     $($inet.ProxyServer) - make sure that's yours" 'Yellow'; $found = $true }
    if ($inet.AutoConfigURL)     { Say "  PAC       $($inet.AutoConfigURL) - make sure that's yours" 'Yellow'; $found = $true }
    if (-not $found) { Say '  none' 'Green' }
    return $live
}

function Set-AdGuard {
    Say ''
    Say '== DoH entries ==' 'Cyan'
    foreach ($ip in $servers) {
        $doh = @{ ServerAddress = $ip; DohTemplate = $template; AllowFallbackToUdp = $true; AutoUpgrade = $true }
        if (Get-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue) {
            Set-DnsClientDohServerAddress @doh | Out-Null
        } else {
            Add-DnsClientDohServerAddress @doh | Out-Null
        }
        Say "  $ip -> $template"
    }

    Say ''
    Say '== adapters ==' 'Cyan'
    if (-not $adapters.Count) { Say '  no physical adapters found' 'Red' }
    foreach ($a in $adapters) {
        $before = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue).ServerAddresses) -join ', '
        if (-not $before) { $before = 'none' }
        try {
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $servers -ErrorAction Stop
            Say ('  {0,-30} {1,-13} was {2}' -f $a.Name, $a.Status, $before) 'Green'
        } catch {
            Say ('  {0,-30} {1,-13} skipped: {2}' -f $a.Name, $a.Status, $_.Exception.Message) 'Yellow'
        }
    }
}

function Test-AdGuard {
    Clear-DnsClientCache
    Say ''
    Say '== proof ==' 'Cyan'
    $okIps = @(Resolve-DnsName -Name 'github.com' -Type A -DnsOnly -ErrorAction SilentlyContinue |
        Where-Object Type -eq 'A' | ForEach-Object IPAddress)
    if ($okIps.Count -and $okIps[0] -ne '0.0.0.0') {
        Say "  github.com        resolves ($($okIps[0]))" 'Green'
    } else {
        Say '  github.com        does not resolve - DNS is broken, run with -Revert' 'Red'
        return
    }
    $adIps = @(Resolve-DnsName -Name 'doubleclick.net' -Type A -DnsOnly -ErrorAction SilentlyContinue |
        Where-Object Type -eq 'A' | ForEach-Object IPAddress | Where-Object { $_ -ne '0.0.0.0' })
    if (-not $adIps.Count) {
        Say '  doubleclick.net   blocked' 'Green'
    } else {
        Say "  doubleclick.net   NOT blocked ($($adIps -join ', '))" 'Red'
    }
    Start-Sleep -Seconds 1
    $conn = @(Get-NetTCPConnection -State Established -RemotePort 443 -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -in $servers })
    if ($conn.Count) {
        Say "  DNS over HTTPS    active ($($conn[0].RemoteAddress):443)" 'Green'
    } else {
        Say '  DNS over HTTPS    not seen - plain-DNS fallback to AdGuard, still filtered' 'Yellow'
    }
}

Say "dns-adblock v1  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" 'Cyan'

if ($Revert) {
    Say ''
    Say '== revert ==' 'Cyan'
    foreach ($a in $adapters) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses -ErrorAction Stop
            Say "  $($a.Name): back to DHCP-assigned DNS" 'Green'
        } catch {
            Say "  $($a.Name): skipped: $($_.Exception.Message)" 'Yellow'
        }
    }
    foreach ($ip in $servers) { Remove-DnsClientDohServerAddress -ServerAddress $ip -Confirm:$false -ErrorAction SilentlyContinue }
    Clear-DnsClientCache
    Say '  AdGuard DoH entries removed, cache flushed' 'Green'
    return
}

$stillThere = Show-Leftovers
if ($stillThere -and -not $Force) {
    Say ''
    Say 'AdBlock 360 is still installed or its driver is still registered. Uninstall it, reboot,' 'Red'
    Say 'then re-run: its HTTPS filtering would sit in front of the DoH connection and muddy the' 'Red'
    Say 'proof. -Force skips this check.' 'Red'
    return
}

Set-AdGuard
Test-AdGuard

Say ''
Say 'Hydra is untouched: nothing here sits between mstsc and TermService, and loopback never asks DNS.' 'Cyan'
