<#
.SYNOPSIS
    Default-deny inbound Windows Firewall for competition hosts.

.DESCRIPTION
    Scans listening ports, keeps the ones that look like real services, blocks
    everything else inbound, and rolls back automatically unless you confirm.
    Domain controllers are detected and get the AD ports they need. Works on
    Windows Server 2016+ (incl. Server Core) and Windows 10/11, PowerShell 5.1+.

    Rules live in the "CCDC-FW" rule group. Every other inbound rule is disabled
    and the default inbound action is set to Block on all profiles.

.EXAMPLE
    .\ccdc-fw.ps1 -Action Scan                         # dry run
    .\ccdc-fw.ps1 -Action Apply                        # auto-revert in 120s unless confirmed
    .\ccdc-fw.ps1 -Action Confirm
    .\ccdc-fw.ps1 -Action Apply -Allow 8080,5000/TCP -Deny 3389 -Yes
    .\ccdc-fw.ps1 -Action Apply -Allow '1433/TCP@192.168.220.0/24'
    .\ccdc-fw.ps1 -Action Persist                      # re-check every minute and at boot
#>
[CmdletBinding()]
param(
    [ValidateSet('Scan', 'Apply', 'Confirm', 'Revert', 'Off', 'Status', 'Enforce', 'Persist', 'Unpersist')]
    [string]$Action = 'Scan',
    # PORT[-PORT][/TCP|UDP][@CIDR|LocalSubnet]
    [string[]]$Allow = @(),
    # PORT[/TCP|UDP] - never auto-allow
    [string[]]$Deny = @(),
    # Allow everything from these addresses (e.g. your team's jump host)
    [string[]]$Trust = @(),
    [ValidateRange(30, 3600)]
    [int]$RollbackSeconds = 120,
    # Don't ask about unknown listeners (they get blocked)
    [switch]$Yes,
    # Internal: set when the rollback task calls Revert
    [switch]$Timer
)

$ErrorActionPreference = 'Stop'
$StateDir = Join-Path $env:ProgramData 'ccdc-fw'
$Script = Join-Path $StateDir 'ccdc-fw.ps1'
$Group = 'CCDC-FW'
$RollbackTask = 'CCDC-FW-Rollback'
$EnforceTask = 'CCDC-FW-Enforce'

$KnownPorts = @{
    '21/TCP' = 'ftp'; '22/TCP' = 'ssh'; '23/TCP' = 'telnet(insecure!)'; '25/TCP' = 'smtp'
    '53/TCP' = 'dns'; '53/UDP' = 'dns'; '69/UDP' = 'tftp'; '80/TCP' = 'http'
    '88/TCP' = 'kerberos'; '88/UDP' = 'kerberos'; '110/TCP' = 'pop3'; '123/UDP' = 'ntp'
    '137/UDP' = 'netbios-ns'; '138/UDP' = 'netbios-dgm'; '139/TCP' = 'netbios-ssn'; '143/TCP' = 'imap'
    '161/UDP' = 'snmp'; '389/TCP' = 'ldap'; '389/UDP' = 'ldap'; '443/TCP' = 'https'; '443/UDP' = 'https-quic'
    '445/TCP' = 'smb'; '464/TCP' = 'kpasswd'; '464/UDP' = 'kpasswd'; '465/TCP' = 'smtps'
    '587/TCP' = 'submission'; '636/TCP' = 'ldaps'; '990/TCP' = 'ftps'; '993/TCP' = 'imaps'
    '995/TCP' = 'pop3s'; '1194/TCP' = 'openvpn'; '1194/UDP' = 'openvpn'; '1433/TCP' = 'mssql'
    '3268/TCP' = 'ldap-gc'; '3269/TCP' = 'ldaps-gc'; '3306/TCP' = 'mysql'; '3389/TCP' = 'rdp'
    '3389/UDP' = 'rdp'; '5432/TCP' = 'postgresql'; '5900/TCP' = 'vnc'; '5901/TCP' = 'vnc'
    '8080/TCP' = 'http-alt'; '8443/TCP' = 'https-alt'; '27017/TCP' = 'mongodb'
}

# Listen by default, not needed from the network.
$NoisePorts = @{
    '135/TCP' = 'rpc endpoint mapper (only needed on DCs)'; '500/UDP' = 'ike'; '4500/UDP' = 'ike-nat'
    '1900/UDP' = 'ssdp'; '2179/TCP' = 'hyper-v vmms'; '3702/UDP' = 'wsd'; '5040/TCP' = 'cdpsvc'
    '5050/UDP' = 'cdpsvc'; '5353/UDP' = 'mdns'; '5355/UDP' = 'llmnr'; '5357/TCP' = 'wsd'
    '5358/TCP' = 'wsd'; '7680/TCP' = 'delivery optimization'; '47001/TCP' = 'winrm (local)'
}

$ServerProcs = 'w3wp', 'inetinfo', 'httpd', 'nginx', 'java', 'node', 'tomcat*', 'php-cgi', 'dotnet',
    'sqlservr', 'mysqld', 'mariadbd', 'postgres', 'mongod', 'dns', 'ismserv', 'dfsrs', 'certsrv',
    'hMailServer', 'filezilla*server*', 'sshd', 'winvnc', 'tvnserver', 'vncserver', 'openvpn*',
    'jellyfin*', 'Plex*', 'Microsoft.Exchange*', 'MSExchange*', 'snmp'

$ShellProcs = 'nc', 'nc64', 'ncat', 'netcat', 'socat', 'powershell', 'pwsh', 'cmd', 'rundll32',
    'regsvr32', 'mshta', 'wscript', 'cscript', 'certutil', 'bitsadmin'

$SuspiciousPaths = '\\AppData\\', '\\Temp\\', '\\Users\\Public\\', '\\Downloads\\', '\\PerfLogs\\', '\\\$Recycle\.Bin\\'

# Fixed domain controller ports. RPC dynamic range and ADWS are limited to the local subnet.
$DcRules = @(
    @{ Proto = 'TCP'; Port = '53'; Name = 'dns' }, @{ Proto = 'UDP'; Port = '53'; Name = 'dns' },
    @{ Proto = 'TCP'; Port = '88'; Name = 'kerberos' }, @{ Proto = 'UDP'; Port = '88'; Name = 'kerberos' },
    @{ Proto = 'UDP'; Port = '123'; Name = 'ntp' }, @{ Proto = 'TCP'; Port = '135'; Name = 'rpc-epmap' },
    @{ Proto = 'UDP'; Port = '137-138'; Name = 'netbios' }, @{ Proto = 'TCP'; Port = '139'; Name = 'netbios-ssn' },
    @{ Proto = 'TCP'; Port = '389'; Name = 'ldap' }, @{ Proto = 'UDP'; Port = '389'; Name = 'ldap' },
    @{ Proto = 'TCP'; Port = '445'; Name = 'smb' }, @{ Proto = 'TCP'; Port = '464'; Name = 'kpasswd' },
    @{ Proto = 'UDP'; Port = '464'; Name = 'kpasswd' }, @{ Proto = 'TCP'; Port = '636'; Name = 'ldaps' },
    @{ Proto = 'TCP'; Port = '3268-3269'; Name = 'global-catalog' },
    @{ Proto = 'TCP'; Port = '9389'; Name = 'adws'; Remote = 'LocalSubnet' },
    @{ Proto = 'TCP'; Port = '49152-65535'; Name = 'rpc-dynamic'; Remote = 'LocalSubnet' }
)

function Write-Log([string]$msg) {
    if (Test-Path $StateDir) {
        Add-Content -Path (Join-Path $StateDir 'ccdc-fw.log') -Value ("{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg)
    }
}

function Assert-Admin {
    $id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this from an elevated (Administrator) PowerShell.'
    }
}

function Initialize-StateDir {
    if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir | Out-Null }
    # Only SYSTEM and Administrators: the enforcer runs this script as SYSTEM.
    & icacls.exe $StateDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($PSCommandPath -and ($PSCommandPath -ne $Script)) { Copy-Item -LiteralPath $PSCommandPath -Destination $Script -Force }
}

function Get-State {
    $f = Join-Path $StateDir 'state.json'
    if (Test-Path $f) { return Get-Content $f -Raw | ConvertFrom-Json }
    return [pscustomobject]@{ Status = 'none' }
}

function Set-State([string]$status) {
    [pscustomobject]@{ Status = $status; Updated = (Get-Date).ToString('s') } |
        ConvertTo-Json | Set-Content (Join-Path $StateDir 'state.json')
}

function ConvertTo-Spec([string]$spec, [string]$defaultRemote = 'Any') {
    if ($spec -notmatch '^(\d+(-\d+)?)(/(tcp|udp))?(@(.+))?$') { throw "Bad port spec: $spec" }
    $proto = if ($Matches[4]) { $Matches[4].ToUpper() } else { 'TCP' }
    $remote = if ($Matches[6]) { $Matches[6] } else { $defaultRemote }
    return @{ Proto = $proto; Port = $Matches[1]; Remote = $remote }
}

function Get-Listeners {
    $procs = @{}
    foreach ($p in Get-CimInstance Win32_Process) { $procs[[int]$p.ProcessId] = $p }
    $svcs = @{}
    foreach ($s in Get-CimInstance Win32_Service -Filter "State='Running'") {
        $k = [int]$s.ProcessId
        if (-not $svcs.ContainsKey($k)) { $svcs[$k] = @() }
        $svcs[$k] += $s.Name
    }
    $raw = @()
    foreach ($c in Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue) {
        $raw += [pscustomobject]@{ Proto = 'TCP'; Port = [int]$c.LocalPort; Addr = $c.LocalAddress; ProcId = [int]$c.OwningProcess }
    }
    foreach ($u in Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
        # Skip ephemeral client sockets (the DNS server alone opens thousands).
        if ($u.LocalPort -ge 49152) { continue }
        $raw += [pscustomobject]@{ Proto = 'UDP'; Port = [int]$u.LocalPort; Addr = $u.LocalAddress; ProcId = [int]$u.OwningProcess }
    }
    $raw | Where-Object { $_.Addr -notmatch '^(127\.|::1$|fe80:)' } |
        Group-Object Proto, Port | ForEach-Object {
            $l = $_.Group[0]
            $p = $procs[$l.ProcId]
            $name = if ($l.ProcId -eq 4) { 'System' } elseif ($p) { [IO.Path]::GetFileNameWithoutExtension($p.Name) } else { '?' }
            [pscustomobject]@{
                Proto    = $l.Proto
                Port     = $l.Port
                Process  = $name
                ProcId   = $l.ProcId
                Path     = if ($p) { $p.ExecutablePath } else { $null }
                Services = if ($svcs.ContainsKey($l.ProcId)) { $svcs[$l.ProcId] -join ',' } else { '' }
            }
        } | Sort-Object Proto, Port
}

function Test-Like([string]$value, [string[]]$patterns) {
    foreach ($pat in $patterns) { if ($value -like $pat) { return $true } }
    return $false
}

function Get-Decision($l, [bool]$isDc, [bool]$hasShares, [string[]]$denied) {
    $key = "$($l.Port)/$($l.Proto)"
    if ($denied -contains $key) { return 'DENY', '-Deny' }
    if (Test-Like $l.Process $ShellProcs) { return 'DENY', 'SUSPICIOUS: shell/netcat-style process' }
    foreach ($sp in $SuspiciousPaths) {
        if ($l.Path -and $l.Path -match $sp) { return 'DENY', "SUSPICIOUS: runs from $($l.Path)" }
    }
    if ($isDc -and $l.Proto -eq 'TCP' -and $l.Port -ge 49152) { return 'ALLOW', 'dc rpc-dynamic (local subnet)' }
    if ($l.Proto -eq 'TCP' -and $l.Port -ge 49152 -and
        (Test-Like $l.Process 'lsass', 'wininit', 'services', 'spoolsv', 'svchost')) {
        return 'DENY', 'dynamic rpc (not a DC)'
    }
    if ($NoisePorts.ContainsKey($key) -and -not ($isDc -and $key -eq '135/TCP')) { return 'DENY', "not needed ($($NoisePorts[$key]))" }
    if ($key -eq '445/TCP' -and -not $isDc -and -not $hasShares) { return 'DENY', 'smb: no file shares on this host' }
    if ($KnownPorts.ContainsKey($key)) { return 'ALLOW', $KnownPorts[$key] }
    if (Test-Like $l.Process $ServerProcs) { return 'ALLOW', 'server process' }
    if ($key -in '5985/TCP', '5986/TCP') { return 'ASK', 'winrm remote management (red team favourite)' }
    return 'ASK', 'unknown'
}

# Returns the list of allow rules; prints the decision table.
function Get-Plan([bool]$interactive) {
    $isDc = [bool](Get-Service NTDS -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')
    $hasShares = [bool](Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(ADMIN|IPC|print|[A-Z])\$$' })
    $denied = @($Deny | ForEach-Object { $s = ConvertTo-Spec $_; "$($s.Port)/$($s.Proto)" })
    $rules = New-Object System.Collections.ArrayList
    $rows = New-Object System.Collections.ArrayList

    if ($isDc) { Write-Host 'Domain controller detected: AD ports are always allowed.' -ForegroundColor Cyan }
    foreach ($l in Get-Listeners) {
        $dec, $why = Get-Decision $l $isDc $hasShares $denied
        if ($dec -eq 'ASK' -and $interactive) {
            $q = "  ? $($l.Port)/$($l.Proto) by $($l.Process) (pid $($l.ProcId) $($l.Services) $($l.Path)) - allow? [y/N]"
            if ((Read-Host $q) -match '^[yY]') { $dec, $why = 'ALLOW', 'you said yes' } else { $dec, $why = 'DENY', 'you said no' }
        } elseif ($dec -eq 'ASK' -and $Action -ne 'Scan') {
            $dec, $why = 'DENY', "unknown (open it with -Allow $($l.Port)/$($l.Proto))"
        }
        [void]$rows.Add([pscustomobject]@{ Port = $l.Port; Proto = $l.Proto; Process = $l.Process; Service = $l.Services; Action = $dec; Why = $why })
        if ($dec -eq 'ALLOW' -and -not ($isDc -and $l.Proto -eq 'TCP' -and $l.Port -ge 49152)) {
            [void]$rules.Add(@{ Proto = $l.Proto; Port = "$($l.Port)"; Remote = 'Any'; Name = $why })
        }
    }
    if ($isDc) {
        foreach ($r in $DcRules) {
            $rr = $r.Clone(); if (-not $rr.Remote) { $rr.Remote = 'Any' }; $rr.Name = "dc $($rr.Name)"
            [void]$rules.Add($rr)
        }
    }
    foreach ($a in $Allow) {
        $s = ConvertTo-Spec $a
        [void]$rows.Add([pscustomobject]@{ Port = $s.Port; Proto = $s.Proto; Process = ''; Service = ''; Action = 'ALLOW'; Why = "-Allow (from $($s.Remote))" })
        [void]$rules.Add(@{ Proto = $s.Proto; Port = $s.Port; Remote = $s.Remote; Name = 'user-allow' })
    }
    foreach ($t in $Trust) {
        [void]$rows.Add([pscustomobject]@{ Port = 'all'; Proto = 'any'; Process = ''; Service = ''; Action = 'ALLOW'; Why = "-Trust $t" })
        [void]$rules.Add(@{ Proto = 'Any'; Port = ''; Remote = $t; Name = 'trusted' })
    }
    [void]$rules.Add(@{ Proto = 'ICMPv4'; Port = ''; Remote = 'Any'; Name = 'ping' })

    $rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

    # Deduplicate identical rules (DC list overlaps with what is listening).
    $seen = @{}
    $out = @()
    foreach ($r in $rules) {
        $k = "$($r.Proto)|$($r.Port)|$($r.Remote)"
        if (-not $seen.ContainsKey($k)) { $seen[$k] = 1; $out += [pscustomobject]$r }
    }
    return , $out
}

# Never pipe an empty set into Remove-/Disable-NetFirewallRule: with no input they can hit every rule.
function Remove-OurRules { Remove-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue }

function Get-OtherInboundRules {
    @(Get-NetFirewallRule -Direction Inbound -Enabled True |
        Where-Object { $_.Group -ne $Group -and $_.DisplayGroup -ne 'Core Networking' })
}

# Makes the live firewall match $rules.
function Set-Policy($rules) {
    Remove-OurRules
    foreach ($r in $rules) {
        $p = @{
            DisplayName = "$Group $($r.Port)/$($r.Proto) $($r.Name)".Replace('  ', ' ')
            Group = $Group; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any'
            Protocol = $r.Proto; RemoteAddress = $r.Remote
        }
        if ($r.Proto -in 'TCP', 'UDP') { $p.LocalPort = $r.Port }
        if ($r.Proto -eq 'ICMPv4') { $p.IcmpType = 8 }
        New-NetFirewallRule @p | Out-Null
    }
    # Everything else inbound goes, except Core Networking (DHCP, IPv6 neighbour discovery).
    $others = Get-OtherInboundRules
    if ($others.Count) { Disable-NetFirewallRule -InputObject $others }
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block `
        -DefaultOutboundAction Allow -AllowInboundRules True -NotifyOnListen False -LogBlocked True `
        -LogMaxSizeKilobytes 32767
    & netsh.exe advfirewall set global statefulftp enable | Out-Null
}

function Test-Drift($rules) {
    foreach ($p in Get-NetFirewallProfile) {
        if ($p.Enabled -ne 'True' -or $p.DefaultInboundAction -ne 'Block' -or $p.AllowInboundRules -eq 'False') { return 'profile settings changed' }
    }
    $ours = @(Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue)
    if ($ours.Count -ne $rules.Count) { return "expected $($rules.Count) CCDC-FW rules, found $($ours.Count)" }
    if ($ours | Where-Object { $_.Enabled -ne 'True' -or $_.Action -ne 'Allow' }) { return 'CCDC-FW rule disabled/changed' }
    $extra = Get-OtherInboundRules
    if ($extra.Count) { return "new inbound rule(s): $(($extra | Select-Object -First 5 -ExpandProperty DisplayName) -join '; ')" }
    return $null
}

function Show-GpoWarning {
    $gpo = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { $_.PolicyStoreSourceType -eq 'GroupPolicy' -and $_.Action -eq 'Allow' })
    if ($gpo.Count) {
        Write-Warning "$($gpo.Count) inbound allow rule(s) come from Group Policy and override local policy:"
        $gpo | Select-Object -First 10 | ForEach-Object { Write-Warning "  $($_.DisplayName)" }
    }
}

function Stop-RollbackTask { Unregister-ScheduledTask -TaskName $RollbackTask -Confirm:$false -ErrorAction SilentlyContinue }

function Invoke-Revert {
    Stop-RollbackTask
    $backup = Join-Path $StateDir 'pre-apply.wfw'
    if (-not (Test-Path $backup)) { throw "No backup at $backup" }
    & netsh.exe advfirewall import $backup | Out-Null
    $prevRules = Join-Path $StateDir 'rules.prev.json'
    if (Test-Path $prevRules) {
        Move-Item $prevRules (Join-Path $StateDir 'rules.json') -Force
        Set-State 'confirmed'
        Write-Log 'reverted to previous confirmed rules'
        Write-Host 'Reverted to the previous confirmed rules.'
    } else {
        Set-State 'reverted'
        Write-Log 'reverted to pre-script firewall policy'
        Write-Host 'Reverted to the firewall policy from before the last apply.'
    }
}

switch ($Action) {
    'Scan' {
        $rules = Get-Plan $false
        Write-Host 'Rules that Apply would create:'
        $rules | Format-Table Proto, Port, Remote, Name -AutoSize | Out-String | Write-Host
        Write-Host 'ASK ports are asked about during Apply, or blocked with -Yes.'
        Write-Host 'Apply also disables every other inbound rule (except Core Networking) and sets inbound default to Block.'
        Show-GpoWarning
    }
    'Apply' {
        Assert-Admin
        Initialize-StateDir
        $interactive = (-not $Yes) -and [Environment]::UserInteractive
        $rules = Get-Plan $interactive
        $state = Get-State

        $backup = Join-Path $StateDir 'pre-apply.wfw'
        if ($state.Status -ne 'pending') {
            Remove-Item $backup -ErrorAction SilentlyContinue
            & netsh.exe advfirewall export $backup | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'netsh export failed; nothing applied' }
            $baseline = Join-Path $StateDir 'baseline.wfw'
            if (-not (Test-Path $baseline)) { Copy-Item $backup $baseline }
            $cur = Join-Path $StateDir 'rules.json'
            if ($state.Status -eq 'confirmed' -and (Test-Path $cur)) { Copy-Item $cur (Join-Path $StateDir 'rules.prev.json') -Force }
            else { Remove-Item (Join-Path $StateDir 'rules.prev.json') -ErrorAction SilentlyContinue }
        }
        ConvertTo-Json @($rules) -Depth 3 | Set-Content (Join-Path $StateDir 'rules.json')

        # Rollback runs as SYSTEM from Task Scheduler, so it fires even if your RDP session dies.
        $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Script`" -Action Revert -Timer"
        $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds($RollbackSeconds)
        $pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $RollbackTask -Action $act -Trigger $trg -Principal $pr -Force | Out-Null
        Set-State 'pending'

        try { Set-Policy $rules } catch { Write-Warning "Apply failed: $_"; Invoke-Revert; throw }
        Write-Log ("applied: " + (($rules | ForEach-Object { "$($_.Port)/$($_.Proto)" }) -join ' '))
        Show-GpoWarning

        Write-Host ''
        Write-Host "Rules are live. They roll back in $RollbackSeconds s unless confirmed." -ForegroundColor Yellow
        Write-Host 'Check your services now (and try a NEW RDP/SSH connection).'
        if ($interactive) {
            if ((Read-Host 'Keep these rules? [y/N]') -match '^[yY]') {
                if ((Get-State).Status -ne 'pending') { throw 'Too late: the rollback already ran. Apply again.' }
                Stop-RollbackTask; Remove-Item (Join-Path $StateDir 'rules.prev.json') -ErrorAction SilentlyContinue
                Set-State 'confirmed'; Write-Log 'confirmed'; Write-Host 'Confirmed.'
            } else { Invoke-Revert }
        } else {
            Write-Host "Then run: $Script -Action Confirm"
        }
    }
    'Confirm' {
        Assert-Admin
        if ((Get-State).Status -ne 'pending') { throw "Nothing pending (status: $((Get-State).Status))." }
        Stop-RollbackTask
        Remove-Item (Join-Path $StateDir 'rules.prev.json') -ErrorAction SilentlyContinue
        Set-State 'confirmed'; Write-Log 'confirmed'
        Write-Host "Confirmed. Run '$Script -Action Persist' to re-check every minute."
    }
    'Revert' {
        if ($Timer -and (Get-State).Status -ne 'pending') { Stop-RollbackTask; return }
        if ($Timer) { Write-Log 'rollback timer fired' } else { Assert-Admin }
        Invoke-Revert
    }
    'Off' {
        Assert-Admin
        Stop-RollbackTask
        Unregister-ScheduledTask -TaskName $EnforceTask -Confirm:$false -ErrorAction SilentlyContinue
        $baseline = Join-Path $StateDir 'baseline.wfw'
        if (Test-Path $baseline) { & netsh.exe advfirewall import $baseline | Out-Null }
        else { Remove-OurRules }
        Set-State 'off'; Write-Log 'off'
        Write-Host 'Restored the firewall policy from before the first apply.'
    }
    'Status' {
        Write-Host "Status: $((Get-State).Status)"
        Write-Host "Rollback task pending: $([bool](Get-ScheduledTask -TaskName $RollbackTask -ErrorAction SilentlyContinue))"
        Write-Host "Enforcer installed:    $([bool](Get-ScheduledTask -TaskName $EnforceTask -ErrorAction SilentlyContinue))"
        Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize | Out-String | Write-Host
        Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Sort-Object DisplayName |
            Format-Table DisplayName, Enabled -AutoSize | Out-String -Width 200 | Write-Host
        Show-GpoWarning
        $log = Join-Path $StateDir 'ccdc-fw.log'
        if (Test-Path $log) { Write-Host 'Recent log:'; Get-Content $log -Tail 10 | Write-Host }
    }
    'Enforce' {
        if ((Get-State).Status -ne 'confirmed') { return }
        $rules = @(Get-Content (Join-Path $StateDir 'rules.json') -Raw | ConvertFrom-Json)
        $drift = Test-Drift $rules
        if ($drift) {
            Write-Log "TAMPER: $drift - re-applying"
            Set-Policy $rules
        }
    }
    'Persist' {
        Assert-Admin
        if ((Get-State).Status -ne 'confirmed') { throw 'Confirm the rules first.' }
        Initialize-StateDir
        $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Script`" -Action Enforce"
        $every = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
        $boot = New-ScheduledTaskTrigger -AtStartup
        $pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
        Register-ScheduledTask -TaskName $EnforceTask -Action $act -Trigger $every, $boot -Principal $pr -Settings $set -Force | Out-Null
        Write-Log 'persist enabled'
        Write-Host "Enforcer installed (scheduled task '$EnforceTask', every minute + at boot)."
    }
    'Unpersist' {
        Assert-Admin
        Unregister-ScheduledTask -TaskName $EnforceTask -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log 'persist disabled'
        Write-Host 'Enforcer removed.'
    }
}
