<#
.SYNOPSIS
    Collects read-only evidence from a Windows endpoint for an Essential Eight (ML1) assessment.

.DESCRIPTION
    Gathers OS and patch state, installed software, local administrators, AppLocker / WDAC
    status, Office macro policies, browser policies, Defender, firewall and BitLocker state,
    and writes them to a JSON file for e8checker to analyse.

    Evidence schema 2 (collector 0.2.0) adds an "ml2" section for Maturity Level Two readiness:
    Defender attack surface reduction rules, PowerShell logging policy, process creation
    auditing, LAPS, LSA protection and Credential Guard.

    The script only reads configuration. It changes nothing on the machine and sends nothing
    over the network. Run it from an elevated PowerShell prompt for complete results
    (BitLocker and Windows optional features need administrator rights).

.PARAMETER OutputPath
    Where to write the evidence file. Defaults to .\e8-evidence-<COMPUTERNAME>.json

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Collect-E8Evidence.ps1
    python -m e8checker assess .\e8-evidence-PC01.json -f html -o report.html

.NOTES
    Compatible with Windows PowerShell 5.1 and PowerShell 7.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath "e8-evidence-$env:COMPUTERNAME.json")
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$CollectorVersion = '0.2.0'
$AdminsSid = 'S-1-5-32-544'
$OfficeApps = @('Word', 'Excel', 'PowerPoint')

# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------

function Invoke-Safely {
    <# Runs a scriptblock and returns $Default instead of throwing, so one unreadable
       setting never stops the whole collection. #>
    param([scriptblock]$Script, $Default = $null, [string]$What = 'value')
    try { & $Script }
    catch {
        Write-Verbose "Could not read ${What}: $($_.Exception.Message)"
        $Default
    }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    Invoke-Safely -What "$Path\$Name" -Script {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        $item.$Name
    }
}

function Test-IsElevated {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-IntOrNull {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    try { [int]$Value } catch { $null }
}

function ConvertTo-IsoDate {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    try { ([datetime]$Value).ToString('s') } catch { $null }
}

# ---------------------------------------------------------------------------------------------
# Host and interactive user
# ---------------------------------------------------------------------------------------------

function Get-InteractiveUser {
    $cs = Invoke-Safely -What 'Win32_ComputerSystem' -Script { Get-CimInstance -ClassName Win32_ComputerSystem }
    $name = if ($cs -and $cs.UserName) { $cs.UserName } else { [Security.Principal.WindowsIdentity]::GetCurrent().Name }
    $sid = Invoke-Safely -What 'user SID' -Script {
        (New-Object Security.Principal.NTAccount($name)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    [pscustomobject]@{ Name = $name; Sid = $sid; DomainJoined = [bool]($cs -and $cs.PartOfDomain) }
}

function Get-LocalAdminMembers {
    # Get-LocalGroupMember throws on orphaned or Entra ID SIDs, so fall back to ADSI.
    $members = Invoke-Safely -What 'Get-LocalGroupMember' -Script {
        Get-LocalGroupMember -SID $AdminsSid | ForEach-Object {
            $enabled = $true
            if ($_.PrincipalSource -eq 'Local' -and $_.ObjectClass -eq 'User') {
                $local = Get-LocalUser -SID $_.SID -ErrorAction SilentlyContinue
                if ($local) { $enabled = [bool]$local.Enabled }
            }
            [ordered]@{ name = "$($_.Name)"; sid = "$($_.SID)"; enabled = $enabled }
        }
    }
    if ($null -eq $members) {
        $members = Invoke-Safely -What 'ADSI Administrators' -Script {
            $groupName = (New-Object Security.Principal.SecurityIdentifier($AdminsSid)).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
            $group = [ADSI]"WinNT://$env:COMPUTERNAME/$groupName,group"
            @($group.Invoke('Members')) | ForEach-Object {
                $path = $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
                [ordered]@{ name = ($path -replace '^WinNT://', '' -replace '/', '\'); sid = $null; enabled = $true }
            }
        }
    }
    @($members)
}

function Test-UserIsAdmin {
    param($User, $Admins)
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($User.Sid -and $current.User.Value -eq $User.Sid) {
        # Running as the interactive user: the token includes nested and deny-only groups.
        return [bool]($current.Groups | Where-Object { $_.Value -eq $AdminsSid })
    }
    # Running as someone else: fall back to direct membership (nested groups are not expanded).
    [bool]($Admins | Where-Object { ($_.sid -and $_.sid -eq $User.Sid) -or $_.name -eq $User.Name })
}

# ---------------------------------------------------------------------------------------------
# Patching
# ---------------------------------------------------------------------------------------------

function Get-OsInfo {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    [ordered]@{
        caption   = "$($os.Caption)".Trim()
        version   = "$($os.Version)"
        build     = [int]$os.BuildNumber
        last_boot = ConvertTo-IsoDate $os.LastBootUpTime
    }
}

function Get-Hotfixes {
    @(Invoke-Safely -What 'Get-HotFix' -Default @() -Script {
        Get-HotFix | ForEach-Object {
            [ordered]@{ id = "$($_.HotFixID)"; installed_on = ConvertTo-IsoDate $_.InstalledOn }
        }
    })
}

function Get-WindowsUpdateState {
    $svc = Invoke-Safely -What 'wuauserv' -Script { Get-Service -Name wuauserv }
    [ordered]@{
        service_start_type    = if ($svc) { "$($svc.StartType)" } else { $null }
        no_auto_update_policy = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
    }
}

function Get-InstalledSoftware {
    param([string]$UserSid)
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    if ($UserSid) { $roots += "Registry::HKEY_USERS\$UserSid\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    $seen = @{}
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($key in Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue) {
            $p = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if (-not $p -or -not ($p.PSObject.Properties.Name -contains 'DisplayName') -or -not $p.DisplayName) { continue }
            $version = if ($p.PSObject.Properties.Name -contains 'DisplayVersion') { "$($p.DisplayVersion)" } else { '' }
            $id = "$($p.DisplayName)|$version"
            if ($seen.ContainsKey($id)) { continue }
            $seen[$id] = $true
            [ordered]@{
                name      = "$($p.DisplayName)"
                version   = $version
                publisher = if ($p.PSObject.Properties.Name -contains 'Publisher') { "$($p.Publisher)" } else { '' }
            }
        }
    }
}

# ---------------------------------------------------------------------------------------------
# Application control
# ---------------------------------------------------------------------------------------------

function Get-AppLockerState {
    $collections = [ordered]@{}
    foreach ($type in 'Exe', 'Script', 'Msi', 'Dll', 'Appx') {
        $collections[$type] = [ordered]@{ mode = 'NotConfigured'; rule_count = 0 }
    }
    $xml = Invoke-Safely -What 'AppLocker policy' -Script { [xml](Get-AppLockerPolicy -Effective -Xml) }
    if ($xml) {
        foreach ($rc in @($xml.SelectNodes('//RuleCollection'))) {
            $mode = $rc.GetAttribute('EnforcementMode')
            $collections[$rc.Type] = [ordered]@{
                mode       = if ($mode) { $mode } else { 'NotConfigured' }
                rule_count = @($rc.ChildNodes).Count
            }
        }
    }
    $svc = Invoke-Safely -What 'AppIDSvc' -Script { Get-Service -Name AppIDSvc }
    [ordered]@{
        appidsvc_running = [bool]($svc -and $svc.Status -eq 'Running')
        collections      = $collections
    }
}

function Get-WdacState {
    $dg = Invoke-Safely -What 'Win32_DeviceGuard' -Script {
        Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
    }
    # UsermodeCodeIntegrityPolicyEnforcementStatus: 0 = off, 1 = audit, 2 = enforced
    $umci = if ($dg -and ($dg.PSObject.Properties.Name -contains 'UsermodeCodeIntegrityPolicyEnforcementStatus')) {
        [int]$dg.UsermodeCodeIntegrityPolicyEnforcementStatus
    } else { 0 }
    [ordered]@{ policy_present = ($umci -gt 0); enforced = ($umci -eq 2) }
}

# ---------------------------------------------------------------------------------------------
# Office macros (policy hives only, so a value present means users cannot change it)
# ---------------------------------------------------------------------------------------------

function Get-OfficePolicyValue {
    param([string]$UserSid, [string]$SubPath, [string]$Name)
    $paths = @()
    if ($UserSid) { $paths += "Registry::HKEY_USERS\$UserSid\Software\Policies\Microsoft\Office\16.0\$SubPath" }
    $paths += "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\$SubPath"
    foreach ($path in $paths) {
        $value = Get-RegValue $path $Name
        if ($null -ne $value) { return [int]$value }
    }
    $null
}

function Get-OfficeState {
    param([string]$UserSid, $Software)
    $installed = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration') -or
        [bool]($Software | Where-Object { $_.name -match '^Microsoft (365|Office)' })
    $apps = [ordered]@{}
    $anyPolicy = $false
    foreach ($app in $OfficeApps) {
        $vba = Get-OfficePolicyValue $UserSid "$($app.ToLower())\security" 'VBAWarnings'
        $block = Get-OfficePolicyValue $UserSid "$($app.ToLower())\security" 'blockcontentexecutionfrominternet'
        if ($null -ne $vba -or $null -ne $block) { $anyPolicy = $true }
        $apps[$app] = [ordered]@{ vba_warnings = $vba; block_internet_macros = $block }
    }
    $scan = Get-OfficePolicyValue $UserSid 'common\security' 'macroruntimescanscope'
    [ordered]@{
        installed                = $installed
        policy_present           = $anyPolicy
        macro_runtime_scan_scope = $scan
        apps                     = $apps
    }
}

# ---------------------------------------------------------------------------------------------
# Browsers
# ---------------------------------------------------------------------------------------------

function Get-ForcedExtensions {
    param([string]$PolicyPath)
    $key = Join-Path $PolicyPath 'ExtensionInstallForcelist'
    if (-not (Test-Path -LiteralPath $key)) { return @() }
    $props = Get-ItemProperty -LiteralPath $key
    @($props.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object { "$($_.Value)" })
}

function Test-PolicyKey {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $item = Get-Item -LiteralPath $Path
    ($item.ValueCount -gt 0) -or ($item.SubKeyCount -gt 0)
}

function Get-BrowserState {
    param([int]$Build)
    $pf = $env:ProgramFiles
    $pf86 = ${env:ProgramFiles(x86)}

    $ie = Invoke-Safely -What 'IE optional feature' -Script {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName 'Internet-Explorer-Optional-amd64'
        [bool]($feature -and $feature.State -eq 'Enabled')
    }
    if ($null -eq $ie -and $Build -ge 22000) { $ie = $false }  # IE11 is not part of Windows 11

    $edgePolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    $chromePolicy = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
    $ffPolicy = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
    $ffJson = Join-Path $pf 'Mozilla Firefox\distribution\policies.json'

    $chromeInstalled = (Test-Path (Join-Path $pf 'Google\Chrome\Application\chrome.exe')) -or
        ($pf86 -and (Test-Path (Join-Path $pf86 'Google\Chrome\Application\chrome.exe')))
    $ffInstalled = Test-Path (Join-Path $pf 'Mozilla Firefox\firefox.exe')
    $ffPolicyText = ''
    if (Test-Path $ffJson) { $ffPolicyText += (Get-Content -LiteralPath $ffJson -Raw) }
    $ffExt = Get-RegValue $ffPolicy 'ExtensionSettings'
    if ($ffExt) { $ffPolicyText += "$ffExt" }

    [ordered]@{
        ie_enabled = $ie
        edge       = [ordered]@{
            installed         = ($pf86 -and (Test-Path (Join-Path $pf86 'Microsoft\Edge\Application\msedge.exe'))) -or
                                (Test-Path (Join-Path $pf 'Microsoft\Edge\Application\msedge.exe'))
            managed           = Test-PolicyKey $edgePolicy
            forced_extensions = Get-ForcedExtensions $edgePolicy
        }
        chrome     = [ordered]@{
            installed         = [bool]$chromeInstalled
            managed           = Test-PolicyKey $chromePolicy
            forced_extensions = Get-ForcedExtensions $chromePolicy
        }
        firefox    = [ordered]@{
            installed     = [bool]$ffInstalled
            managed       = (Test-PolicyKey $ffPolicy) -or (Test-Path $ffJson)
            ublock_forced = ($ffPolicyText -match 'uBlock0@raymondhill\.net' -and $ffPolicyText -match 'force_installed')
        }
    }
}

# ---------------------------------------------------------------------------------------------
# Supporting controls
# ---------------------------------------------------------------------------------------------

function Get-DefenderState {
    $mp = Invoke-Safely -What 'Get-MpComputerStatus' -Script { Get-MpComputerStatus }
    $thirdParty = Invoke-Safely -What 'SecurityCenter2' -Script {
        $products = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct
        # Bit 0x1000 of productState means the product is switched on.
        $active = $products | Where-Object { $_.displayName -notmatch 'Defender' -and ($_.productState -band 0x1000) }
        if ($active) { ($active | ForEach-Object { $_.displayName }) -join ', ' } else { $null }
    }
    [ordered]@{
        antivirus_enabled  = if ($mp) { [bool]$mp.AntivirusEnabled } else { $null }
        realtime_enabled   = if ($mp) { [bool]$mp.RealTimeProtectionEnabled } else { $null }
        signature_age_days = if ($mp) { [int]$mp.AntivirusSignatureAge } else { $null }
        third_party_av     = $thirdParty
    }
}

function Get-FirewallState {
    @(Invoke-Safely -What 'firewall profiles' -Default @() -Script {
        Get-NetFirewallProfile | ForEach-Object {
            [ordered]@{ profile = "$($_.Name)"; enabled = ("$($_.Enabled)" -eq 'True') }
        }
    })
}

function Get-BitLockerState {
    $status = Invoke-Safely -What 'BitLocker' -Script {
        "$((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus)"
    }
    [ordered]@{ os_volume_protection = $status }
}

# ---------------------------------------------------------------------------------------------
# Maturity Level Two readiness (schema 2)
# ---------------------------------------------------------------------------------------------

function Get-AsrRules {
    <# Returns @{ <rule guid, lower case> = <action> } where 0 = off, 1 = Block, 2 = Audit, 6 = Warn. #>
    $rules = [ordered]@{}
    $pref = Invoke-Safely -What 'Get-MpPreference' -Script { Get-MpPreference }
    if ($pref -and $pref.AttackSurfaceReductionRules_Ids) {
        $ids = @($pref.AttackSurfaceReductionRules_Ids)
        $actions = @($pref.AttackSurfaceReductionRules_Actions)
        for ($i = 0; $i -lt $ids.Count; $i++) {
            $action = if ($i -lt $actions.Count) { ConvertTo-IntOrNull $actions[$i] } else { $null }
            $rules["$($ids[$i])".ToLower()] = $action
        }
    }
    if ($rules.Count -eq 0) {
        # Defender cmdlets can be unavailable (third-party AV, Server Core); read the policy instead.
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        if (Test-Path -LiteralPath $key) {
            $props = Get-ItemProperty -LiteralPath $key
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -match '^[0-9a-fA-F-]{36}$') { $rules[$prop.Name.ToLower()] = ConvertTo-IntOrNull $prop.Value }
            }
        }
    }
    $rules
}

function Get-ProcessCreationAudit {
    <# True when 'Audit Process Creation' records Success events. Needs an elevated prompt.
       The subcategory GUID is used so the query works on non-English Windows. #>
    Invoke-Safely -What 'auditpol' -Script {
        $csv = & auditpol.exe /get '/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}' /r | Where-Object { $_ } | ConvertFrom-Csv
        $setting = @($csv)[0].'Inclusion Setting'
        if ($null -eq $setting) { $null } else { [bool]("$setting" -match 'Success') }
    }
}

function Get-Ml2State {
    $psPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    $lapsBackup = $null
    foreach ($path in 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS') {
        $value = ConvertTo-IntOrNull (Get-RegValue $path 'BackupDirectory')
        if ($null -ne $value) { $lapsBackup = $value; break }
    }
    $dg = Invoke-Safely -What 'Win32_DeviceGuard' -Script {
        Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard
    }
    # SecurityServicesRunning contains 1 when Credential Guard is running.
    $credentialGuard = [bool]($dg -and ($dg.PSObject.Properties.Name -contains 'SecurityServicesRunning') -and
        (@($dg.SecurityServicesRunning) -contains 1))

    [ordered]@{
        asr_rules                = Get-AsrRules
        powershell_logging       = [ordered]@{
            module        = ConvertTo-IntOrNull (Get-RegValue "$psPolicy\ModuleLogging" 'EnableModuleLogging')
            script_block  = ConvertTo-IntOrNull (Get-RegValue "$psPolicy\ScriptBlockLogging" 'EnableScriptBlockLogging')
            transcription = ConvertTo-IntOrNull (Get-RegValue "$psPolicy\Transcription" 'EnableTranscripting')
        }
        process_creation         = [ordered]@{
            audit_success        = Get-ProcessCreationAudit
            include_command_line = ConvertTo-IntOrNull (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled')
        }
        laps                     = [ordered]@{
            windows_laps_backup_directory = $lapsBackup
            legacy_admpwd_enabled         = ConvertTo-IntOrNull (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled')
        }
        lsa_run_as_ppl           = ConvertTo-IntOrNull (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL')
        credential_guard_running = $credentialGuard
    }
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------

$elevated = Test-IsElevated
if (-not $elevated) {
    Write-Warning 'Not running elevated: BitLocker, Internet Explorer and process auditing state may be missing.'
}

Write-Host 'Collecting Essential Eight evidence (read-only)...'
$user = Get-InteractiveUser
$admins = Get-LocalAdminMembers
$os = Get-OsInfo
$software = @(Get-InstalledSoftware -UserSid $user.Sid)

$evidence = [ordered]@{
    schema_version    = 2
    collector_version = $CollectorVersion
    collected_at      = (Get-Date).ToString('s')
    host              = [ordered]@{
        hostname                  = $env:COMPUTERNAME
        domain_joined             = $user.DomainJoined
        interactive_user          = $user.Name
        interactive_user_is_admin = Test-UserIsAdmin -User $user -Admins $admins
        collector_elevated        = $elevated
    }
    os                = $os
    hotfixes          = Get-Hotfixes
    windows_update    = Get-WindowsUpdateState
    software          = $software
    local_admins      = $admins
    applocker         = Get-AppLockerState
    wdac              = Get-WdacState
    office            = Get-OfficeState -UserSid $user.Sid -Software $software
    browsers          = Get-BrowserState -Build $os.build
    defender          = Get-DefenderState
    firewall          = Get-FirewallState
    bitlocker         = Get-BitLockerState
    ml2               = Get-Ml2State
}

$json = $evidence | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($OutputPath, $json, (New-Object Text.UTF8Encoding($false)))
Write-Host "Evidence written to $OutputPath"
Write-Host "Next: python -m e8checker assess `"$OutputPath`" -f html -o e8-report.html"
