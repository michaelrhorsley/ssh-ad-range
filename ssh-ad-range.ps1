& {
# nmap -n -Pn -T4 -p 22 --open -oG - 10.1.10.1-20 | Tee-Object -Variable NmapText

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

$klist = & klist.exe 2>&1 | Out-String
if ($klist -notmatch 'krbtgt/') {
    Write-Warning 'No Kerberos TGT found. SSH can only use your current AD login when klist shows a krbtgt ticket.'
}

$timeoutSec = 5

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

$nmapVar = Get-Variable -Name NmapText -Scope Global -ErrorAction SilentlyContinue
if (-not $nmapVar) {
    throw "No nmap output in `$NmapText. Run nmap first, then paste this script again."
}

$user = $env:USERNAME
$ips = @(Get-OpenHostsFromNmap -Text $nmapVar.Value -Port $Port)
if ($ips.Count -eq 0) {
    Write-Host "No hosts in the nmap output have TCP $Port open."
    return
}
if ($ips.Count -gt 1024) {
    throw "Nmap reported $($ips.Count) open hosts. Use a smaller range (1024 or fewer)."
}

$knownHosts = Join-Path $env:TEMP 'ssh-ad-range-known_hosts'
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
Write-Host ("Done. Nmap listed {0} host(s) with TCP {1} open, {2} accepted the current AD login." -f $ips.Count, $Port, $loggedIn)
}
