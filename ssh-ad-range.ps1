# Edit $Range and $Port, then paste this whole script into a
# Windows PowerShell window. Input is not read from the keyboard,
# so the paste cannot be swallowed by a prompt.
#
# Nmap finds addresses with the SSH port open, then each of those
# hosts is tried over SSH as the domain account you are already
# signed in with (Kerberos / GSSAPI). No password is read or stored.
#
# Needs: domain-joined Windows session, Nmap on PATH, OpenSSH Client,
# and SSH servers that accept GSSAPI for that account.
# Check the ticket first with: klist

$Range = '10.1.10.1-10.1.10.20'   # start-end, CIDR (/22 to /32), or one IP
$Port = 22

$ErrorActionPreference = 'Continue'
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
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
$nmapCmd = @(Get-Command nmap.exe, nmap -ErrorAction SilentlyContinue) | Select-Object -First 1
if (-not $nmapCmd) {
    throw 'nmap was not found. Install Nmap and ensure it is on PATH.'
}

$klist = & klist.exe 2>&1 | Out-String
if ($klist -notmatch 'krbtgt/') {
    Write-Warning 'No Kerberos TGT found. SSH can only use your current AD login when klist shows a krbtgt ticket.'
}

$timeoutSec = 5

function ConvertTo-UInt32IP {
    param([string]$Ip)
    $bytes = [System.Net.IPAddress]::Parse($Ip.Trim()).GetAddressBytes()
    if ($bytes.Length -ne 4) { throw "Not an IPv4 address: $Ip" }
    [Array]::Reverse($bytes)
    return [uint64][BitConverter]::ToUInt32($bytes, 0)
}

function ConvertFrom-UInt32IP {
    param([uint64]$Value)
    $bytes = [BitConverter]::GetBytes([uint32]$Value)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-IPRangeList {
    param([string]$Spec)
    $spec = $Spec.Trim()
    $max = 1024

    if ($spec -match '^(?<a>\d{1,3}(\.\d{1,3}){3})\s*-\s*(?<b>\d{1,3}(\.\d{1,3}){3})$') {
        $start = ConvertTo-UInt32IP $Matches.a
        $end = ConvertTo-UInt32IP $Matches.b
        if ($end -lt $start) { throw 'End IP is lower than start IP.' }
        $count = $end - $start + 1
        if ($count -gt $max) { throw "That range has $count addresses. Use 1024 or fewer." }
        $i = $start
        while ($true) {
            ConvertFrom-UInt32IP $i
            if ($i -ge $end) { break }
            $i++
        }
        return
    }

    if ($spec -match '^(?<a>\d{1,3}(\.\d{1,3}){3})/(?<p>\d{1,2})$') {
        $prefix = [int]$Matches.p
        if ($prefix -lt 22 -or $prefix -gt 32) {
            throw 'CIDR must be /22 through /32 (1024 addresses or fewer).'
        }
        $ip = ConvertTo-UInt32IP $Matches.a
        $hostBits = 32 - $prefix
        $size = [uint64]1 -shl $hostBits
        $mask = (([uint64]4294967295) -shr $hostBits) -shl $hostBits
        $network = $ip -band $mask
        for ($i = [uint64]0; $i -lt $size; $i++) { ConvertFrom-UInt32IP ($network + $i) }
        return
    }

    if ($spec -match '^\d{1,3}(\.\d{1,3}){3}$') {
        ConvertFrom-UInt32IP (ConvertTo-UInt32IP $spec)
        return
    }

    throw 'Use start-end (10.1.10.1-10.1.10.50), CIDR (10.1.10.0/24), or a single IP.'
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

$user = $env:USERNAME
$allIps = @(Get-IPRangeList $Range)
$knownHosts = Join-Path $env:TEMP 'ssh-ad-range-known_hosts'
$targetFile = Join-Path $env:TEMP 'ssh-ad-range-targets.txt'
$nmapErrFile = Join-Path $env:TEMP 'ssh-ad-range-nmap.err'
$openPattern = "^Host:\s+(\d{1,3}(?:\.\d{1,3}){3})\b.*\b$Port/open/"

Write-Host "Scanning $($allIps.Count) address(es) for TCP $Port as $env:USERDOMAIN\$user"
Set-Content -Path $targetFile -Value $allIps -Encoding ascii

$openIps = New-Object System.Collections.Generic.List[string]
$nmapExit = 0
try {
    # -Pn checks every address, including hosts that do not answer ping.
    # stderr goes to a file so PowerShell does not treat Nmap's progress as errors.
    $nmapArgs = @('-n', '-Pn', '-T4', '-p', "$Port", '--open', '-oG', '-', '-iL', $targetFile)
    $nmapOutput = & $nmapCmd.Source @nmapArgs 2>$nmapErrFile
    $nmapExit = $LASTEXITCODE
    foreach ($line in @($nmapOutput)) {
        if ("$line" -match $openPattern) {
            $openIps.Add($Matches[1])
            Write-Host "  open  $($Matches[1])" -ForegroundColor Green
        }
    }
} finally {
    Remove-Item -LiteralPath $targetFile -ErrorAction SilentlyContinue
}

if ($nmapExit -and $nmapExit -ne 0) {
    Write-Warning "nmap exited with code $nmapExit."
    if (Test-Path -LiteralPath $nmapErrFile) {
        Get-Content -LiteralPath $nmapErrFile | Write-Host
    }
}
Remove-Item -LiteralPath $nmapErrFile -ErrorAction SilentlyContinue

$ips = @($openIps | Select-Object -Unique)
if ($ips.Count -eq 0) {
    Write-Host "No hosts have TCP $Port open."
} else {
    Write-Host "SSH login to $($ips.Count) host(s) on port $Port as $env:USERDOMAIN\$user"
    Write-Host "Host keys are stored in $knownHosts"

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
    Write-Host ("Done. Nmap found {0} host(s) with TCP {1} open, {2} accepted the current AD login." -f $ips.Count, $Port, $loggedIn)
}
