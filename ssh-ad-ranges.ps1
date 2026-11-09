& {
# One range per line in $env:TEMP\ssh-ad-ranges.txt
#   10.1.10.1-20
#   10.1.11.0/24
# Or, before pasting, set:
#   $Ranges = @('10.1.10.1-20','10.1.11.0/24')

$Port = 22

$ErrorActionPreference = 'Continue'
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -Scope Global -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

if ($env:OS -ne 'Windows_NT') {
    throw 'Run this in Windows PowerShell on a domain-joined PC.'
}
if (-not $env:USERDOMAIN -or $env:USERDOMAIN -eq $env:COMPUTERNAME) {
    throw "This session is not an AD logon (USERDOMAIN=$env:USERDOMAIN). Sign in with a domain account."
}
if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue)) {
    throw 'OpenSSH Client is not installed (ssh.exe was not found).'
}
$nmap = Get-Command nmap.exe -ErrorAction SilentlyContinue
if (-not $nmap) { $nmap = Get-Command nmap -ErrorAction SilentlyContinue }
if (-not $nmap) { throw 'nmap was not found.' }

$klist = & klist.exe 2>&1 | Out-String
if ($klist -notmatch 'krbtgt/') {
    Write-Warning 'No Kerberos TGT found. SSH can only use your current AD login when klist shows a krbtgt ticket.'
}

$timeoutSec = 5

function Get-RangeList {
    $handed = Get-Variable -Name Ranges -Scope Global -ErrorAction SilentlyContinue
    $source = @()
    if ($handed -and @($handed.Value).Count -gt 0) {
        $source = @($handed.Value)
    } else {
        $path = Join-Path $env:TEMP 'ssh-ad-ranges.txt'
        if (-not (Test-Path -LiteralPath $path)) {
            throw "No ranges. Add one range per line to $path, or set `$Ranges, then paste this script again."
        }
        $source = @(Get-Content -LiteralPath $path)
    }
    $clean = foreach ($item in $source) {
        foreach ($line in ("$item" -split "`r?`n")) {
            $text = $line.Trim()
            if ($text -and -not $text.StartsWith('#')) { $text }
        }
    }
    return @($clean | Select-Object -Unique)
}

function Get-OpenHostsFromNmap {
    param($Text, [int]$Port)
    $hosts = New-Object System.Collections.Generic.List[string]
    $current = $null
    $ipRe = '\d{1,3}(?:\.\d{1,3}){3}'

    foreach ($raw in @($Text)) {
        foreach ($line in ("$raw" -split "`r?`n")) {
            if ($line -match "^Host:\s+($ipRe)\b") {
                $ip = $Matches[1]
                $current = $null
                if ($line -match "\b$Port/open/") { $hosts.Add($ip) }
                continue
            }
            if ($line -match '^Nmap scan report for\s+(.+?)\s*$') {
                $rest = $Matches[1].Trim()
                if ($rest -match "\(($ipRe)\)") { $current = $Matches[1] }
                elseif ($rest -match "^($ipRe)$") { $current = $Matches[1] }
                else { $current = ($rest -split '\s+')[0] }
                continue
            }
            if ($current -and $line -match "^\s*$Port/tcp\s+open\b") {
                $hosts.Add($current)
                $current = $null
            }
        }
    }
    return @($hosts | Select-Object -Unique)
}

function Invoke-AdSshLogin {
    param(
        [string]$Ip,
        [int]$Port,
        [string]$User,
        [int]$TimeoutSec,
        [string]$KnownHosts
    )
    $knownArg = 'UserKnownHostsFile="{0}"' -f $KnownHosts
    $sshArgs = @(
        '-p', "$Port",
        '-o', 'BatchMode=yes',
        '-o', "ConnectTimeout=$TimeoutSec",
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', $knownArg,
        '-o', 'GlobalKnownHostsFile=NUL',
        '-o', 'GSSAPIAuthentication=yes',
        '-o', 'GSSAPIDelegateCredentials=no',
        '-o', 'PreferredAuthentications=gssapi-with-mic',
        '-o', 'PubkeyAuthentication=no',
        '-o', 'PasswordAuthentication=no',
        '-o', 'NumberOfPasswordPrompts=0',
        '-o', 'LogLevel=ERROR',
        "$User@$Ip",
        'whoami'
    )
    $output = & ssh.exe @sshArgs 2>&1
    $code = $LASTEXITCODE
    $text = ((@($output) | ForEach-Object { "$_" }) -join ' ').Trim()
    if ($text.Length -gt 180) { $text = $text.Substring(0, 180) }
    if ($code -eq 0) {
        if (-not $text) { $text = 'login succeeded' }
        return [pscustomobject]@{ Ok = $true; Detail = $text }
    }
    if (-not $text) { $text = "ssh exited $code" }
    return [pscustomobject]@{ Ok = $false; Detail = $text }
}

$ranges = @(Get-RangeList)
if ($ranges.Count -eq 0) {
    throw 'The range list is empty.'
}

$listFile = Join-Path $env:TEMP 'ssh-ad-ranges-targets.txt'
$nmapFile = Join-Path $env:TEMP 'ssh-ad-ranges.gnmap'
Set-Content -LiteralPath $listFile -Value $ranges -Encoding ascii

Write-Host "Scanning $($ranges.Count) range(s) for TCP $Port"
foreach ($range in $ranges) { Write-Host "  $range" }

& $nmap.Source -n -Pn -T4 -p "$Port" --open -oN - -oG $nmapFile -iL $listFile
$nmapCode = $LASTEXITCODE
if (-not (Test-Path -LiteralPath $nmapFile)) {
    throw "nmap exited $nmapCode and did not write $nmapFile"
}
if ($nmapCode -ne 0) {
    Write-Warning "nmap exited $nmapCode. Continuing with the hosts it wrote."
}

$user = $env:USERNAME
$ips = @(Get-OpenHostsFromNmap -Text (Get-Content -LiteralPath $nmapFile) -Port $Port)
if ($ips.Count -eq 0) {
    Write-Host "No hosts in the nmap output have TCP $Port open."
    return
}
if ($ips.Count -gt 1024) {
    throw "Nmap reported $($ips.Count) open hosts. Use fewer ranges (1024 or fewer open hosts)."
}

$knownHosts = Join-Path $env:TEMP 'ssh-ad-ranges-known_hosts'
Write-Host "SSH login to $($ips.Count) host(s) on port $Port as $env:USERDOMAIN\$user"
Write-Host "Host keys are stored in $knownHosts"
foreach ($ip in $ips) { Write-Host "  open  $ip" -ForegroundColor Green }

$results = foreach ($ip in $ips) {
    Write-Host $ip
    $login = Invoke-AdSshLogin -Ip $ip -Port $Port -User $user -TimeoutSec $timeoutSec -KnownHosts $knownHosts
    if ($login.Ok) {
        Write-Host "  login ok  $($login.Detail)" -ForegroundColor Green
    } else {
        Write-Host "  login failed  $($login.Detail)" -ForegroundColor Yellow
    }
    [pscustomobject]@{ IP = $ip; Login = $login.Ok; Result = $login.Detail }
}

$results | Format-Table -AutoSize -Wrap
$loggedIn = @($results | Where-Object Login).Count
Write-Host ("Done. Scanned {0} range(s). Nmap listed {1} host(s) with TCP {2} open, {3} accepted the current AD login." -f $ranges.Count, $ips.Count, $Port, $loggedIn)
}
