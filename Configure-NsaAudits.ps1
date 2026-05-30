<#
.SYNOPSIS
    Enables advanced Windows audit subcategories required by IBM QRadar
    WinCollect's NSA filter.

.DESCRIPTION
    Locale-independent (uses GUIDs), idempotent, with backup/restore,
    -WhatIf support, structured logging and per-subcategory error checks.

    Equivalent to configure-nsa-audits.cmd but as PowerShell for richer
    operational features.

.PARAMETER BackupDir
    Folder to store the auditpol backup before applying changes.
    Defaults to .\backups under the script directory.

.PARAMETER LogPath
    Path of the rolling log file. Defaults to .\logs\Configure-NsaAudits.log.

.PARAMETER Rollback
    Path to a previous backup CSV to restore. Use this to undo a prior run.

.PARAMETER WhatIf
    Built-in. Shows what would change without applying anything.

.EXAMPLE
    .\Configure-NsaAudits.ps1
    Applies the full NSA-recommended audit policy.

.EXAMPLE
    .\Configure-NsaAudits.ps1 -WhatIf
    Dry run: shows what would change.

.EXAMPLE
    .\Configure-NsaAudits.ps1 -Rollback .\backups\auditpol_backup_20260530_120000.csv
    Restores the previous configuration.

.NOTES
    Author    : windows-audit contributors
    License   : GPL-3.0
    Version   : 2.0.0
    Requires  : PowerShell 5.1+, Administrator privileges, Windows 10/Server 2016+
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$BackupDir = (Join-Path $PSScriptRoot 'backups'),
    [string]$LogPath   = (Join-Path $PSScriptRoot 'logs\Configure-NsaAudits.log'),
    [string]$Rollback
)

# ------------------------ Subcategory table ------------------------
# (Name, GUID, Success, Failure) — locale-independent via GUID.
# Reference: Microsoft docs + NSA "Spotting the Adversary" guide.
$Subcategories = @(
    # System
    @{ Name='Security State Change';              Guid='{0CCE9210-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Security System Extension';          Guid='{0CCE9211-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='System Integrity';                   Guid='{0CCE9212-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='IPsec Driver';                       Guid='{0CCE9213-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$false }
    # Logon/Logoff
    @{ Name='Logon';                              Guid='{0CCE9215-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Logoff';                             Guid='{0CCE9216-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$false }
    @{ Name='Account Lockout';                    Guid='{0CCE9217-69AE-11D9-BED3-505054503030}'; Success=$false; Failure=$true }
    @{ Name='IPsec Extended Mode';                Guid='{0CCE921A-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$false }
    @{ Name='Special Logon';                      Guid='{0CCE921B-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Other Logon/Logoff Events';          Guid='{0CCE921C-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Network Policy Server';              Guid='{0CCE9243-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    # Object Access
    @{ Name='File Share';                         Guid='{0CCE9224-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$false }
    @{ Name='Filtering Platform Connection';      Guid='{0CCE9226-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$false }
    @{ Name='Filtering Platform Packet Drop';     Guid='{0CCE9225-69AE-11D9-BED3-505054503030}'; Success=$false; Failure=$true }
    @{ Name='Detailed File Share';                Guid='{0CCE9244-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Handle Manipulation';                Guid='{0CCE9223-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Application Generated';              Guid='{0CCE9222-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Other Object Access Events';         Guid='{0CCE9227-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Kernel Object';                      Guid='{0CCE921F-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='SAM';                                Guid='{0CCE9220-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$false }
    @{ Name='Certification Services';             Guid='{0CCE9221-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    # Privilege Use
    @{ Name='Sensitive Privilege Use';            Guid='{0CCE9228-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Non Sensitive Privilege Use';        Guid='{0CCE9229-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    # Detailed Tracking
    @{ Name='Process Creation';                   Guid='{0CCE922B-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Process Termination';                Guid='{0CCE922C-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$false }
    @{ Name='DPAPI Activity';                     Guid='{0CCE922D-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='RPC Events';                         Guid='{0CCE922E-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Plug and Play Events';               Guid='{0CCE9248-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$false }
    # Policy Change
    @{ Name='Audit Policy Change';                Guid='{0CCE922F-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Authentication Policy Change';       Guid='{0CCE9230-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Authorization Policy Change';        Guid='{0CCE9231-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='MPSSVC Rule-Level Policy Change';    Guid='{0CCE9232-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Filtering Platform Policy Change';   Guid='{0CCE9233-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Other Policy Change Events';         Guid='{0CCE9234-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    # Account Management
    @{ Name='User Account Management';            Guid='{0CCE9235-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Computer Account Management';        Guid='{0CCE9236-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Security Group Management';          Guid='{0CCE9237-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Distribution Group Management';      Guid='{0CCE9238-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Application Group Management';       Guid='{0CCE9239-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Other Account Management Events';    Guid='{0CCE923A-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    # DS Access (DCs only)
    @{ Name='Directory Service Access';           Guid='{0CCE923B-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Directory Service Changes';          Guid='{0CCE923C-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Directory Service Replication';      Guid='{0CCE923D-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$false }
    @{ Name='Detailed DS Replication';            Guid='{0CCE923E-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$false }
    # Account Logon
    @{ Name='Credential Validation';              Guid='{0CCE923F-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Kerberos Service Ticket Operations'; Guid='{0CCE9240-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Other Account Logon Events';         Guid='{0CCE9241-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
    @{ Name='Kerberos Authentication Service';    Guid='{0CCE9242-69AE-11D9-BED3-505054503030}'; Success=$true; Failure=$true  }
)

# ------------------------ Helpers ------------------------
function Write-Log {
    param(
        [Parameter(Mandatory)] [string] $Message,
        [ValidateSet('INFO','OK','WARN','ERROR','DEBUG')] [string] $Level = 'INFO'
    )
    $line = "[{0:yyyy-MM-dd HH:mm:ss}] [{1,-5}] {2}" -f (Get-Date), $Level, $Message
    $color = @{INFO='Gray'; OK='Green'; WARN='Yellow'; ERROR='Red'; DEBUG='DarkGray'}[$Level]
    Write-Host $line -ForegroundColor $color
    try { Add-Content -Path $LogPath -Value $line -ErrorAction Stop } catch { }
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "Este script requiere privilegios de Administrador." 'ERROR'
        throw "Run as Administrator."
    }
}

function Invoke-Auditpol {
    param([Parameter(Mandatory)] [string[]] $Args)
    $proc = Start-Process -FilePath 'auditpol.exe' -ArgumentList $Args `
        -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$env:TEMP\auditpol.out" `
        -RedirectStandardError "$env:TEMP\auditpol.err"
    return $proc.ExitCode
}

# ------------------------ Init ------------------------
$null = New-Item -ItemType Directory -Force -Path (Split-Path $LogPath -Parent)
$null = New-Item -ItemType Directory -Force -Path $BackupDir
Write-Log "=== Configure-NsaAudits v2.0.0 ===" 'INFO'

# ------------------------ Rollback mode ------------------------
if ($Rollback) {
    Assert-Admin
    if (-not (Test-Path $Rollback)) {
        Write-Log "Backup file no encontrado: $Rollback" 'ERROR'
        exit 4
    }
    if ($PSCmdlet.ShouldProcess($Rollback, 'auditpol /restore')) {
        $rc = Invoke-Auditpol @('/restore', "/file:$Rollback")
        if ($rc -eq 0) { Write-Log "Restauracion OK desde $Rollback" 'OK'; exit 0 }
        else           { Write-Log "Restauracion fallo (rc=$rc)" 'ERROR'; exit 5 }
    }
    exit 0
}

# ------------------------ Normal run ------------------------
Assert-Admin
Write-Log "Privilegios admin: OK" 'OK'

# Backup
$ts          = Get-Date -Format 'yyyyMMdd_HHmmss'
$backupFile  = Join-Path $BackupDir "auditpol_backup_$ts.csv"
$beforeFile  = Join-Path $BackupDir "auditpol_before_$ts.txt"
$afterFile   = Join-Path $BackupDir "auditpol_after_$ts.txt"

if ($PSCmdlet.ShouldProcess($backupFile, 'auditpol /backup')) {
    $rc = Invoke-Auditpol @('/backup', "/file:$backupFile")
    if ($rc -ne 0) { Write-Log "Backup fallo (rc=$rc). Abortando." 'ERROR'; exit 2 }
    Invoke-Auditpol @('/get', '/category:*') > $null
    Move-Item "$env:TEMP\auditpol.out" $beforeFile -Force -ErrorAction SilentlyContinue
    Write-Log "Backup creado: $backupFile" 'OK'
    Write-Log "Restaurar con: .\Configure-NsaAudits.ps1 -Rollback $backupFile" 'INFO'
}

# Apply subcategories
$ok = 0; $fail = 0
Write-Log "Aplicando $($Subcategories.Count) subcategorias..." 'INFO'

foreach ($s in $Subcategories) {
    $success = if ($s.Success) { 'enable' } else { 'disable' }
    $failure = if ($s.Failure) { 'enable' } else { 'disable' }
    $target  = "{0} (success={1} failure={2})" -f $s.Name, $success, $failure

    if ($PSCmdlet.ShouldProcess($target, "auditpol /set $($s.Guid)")) {
        $rc = Invoke-Auditpol @(
            '/set', "/subcategory:$($s.Guid)",
            "/success:$success", "/failure:$failure"
        )
        if ($rc -eq 0) {
            $ok++; Write-Log "  $($s.Name)" 'OK'
        } else {
            $fail++; Write-Log "  $($s.Name) -- rc=$rc" 'ERROR'
        }
    }
}

# Dump after-state
if (-not $WhatIfPreference) {
    Invoke-Auditpol @('/get', '/category:*') > $null
    Move-Item "$env:TEMP\auditpol.out" $afterFile -Force -ErrorAction SilentlyContinue
}

# Summary
Write-Log "============================================================" 'INFO'
Write-Log " Aplicadas OK : $ok" 'OK'
if ($fail -gt 0) { Write-Log " Con error    : $fail" 'WARN' }
Write-Log " Backup       : $backupFile" 'INFO'
Write-Log " Antes        : $beforeFile" 'INFO'
Write-Log " Despues      : $afterFile"  'INFO'
Write-Log "============================================================" 'INFO'

if ($fail -gt 0) {
    Write-Log "Hubo errores. Revisa el log: $LogPath" 'WARN'
    exit 3
}

Write-Log "Configuracion completada." 'OK'
Write-Log "NOTA: Si el equipo esta en dominio con GPO de auditoria, gpupdate puede sobrescribir estos cambios." 'WARN'
exit 0
