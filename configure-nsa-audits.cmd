@echo off
REM ============================================================
REM  configure-nsa-audits.cmd
REM  Habilita las subcategorias de auditoria avanzada de Windows
REM  requeridas por el filtro NSA de IBM QRadar WinCollect.
REM
REM  Mejoras vs version anterior:
REM   - Usa GUIDs (idioma-agnostico: funciona en Windows EN/ES/PT/etc).
REM   - Deduplicado (50% menos lineas, sin overrides accidentales).
REM   - Backup REAL y restaurable antes de modificar (auditpol /backup).
REM   - Verifica privilegios admin.
REM   - Checkea errorlevel de cada operacion.
REM   - Codepage UTF-8 para output legible en cualquier locale.
REM
REM  Referencias:
REM   - NSA "Spotting the Adversary with Windows Event Log Monitoring"
REM   - https://learn.microsoft.com/windows/security/threat-protection/auditing/
REM   - Subcategory GUIDs: documentacion oficial Microsoft.
REM ============================================================
chcp 65001 >nul 2>&1
setlocal EnableDelayedExpansion
set "SCRIPT_VERSION=2.0.0"
set "FAILED=0"
set "OK_COUNT=0"

echo.
echo ============================================================
echo  Configure NSA Audit Subcategories  v%SCRIPT_VERSION%
echo  IBM QRadar WinCollect - NSA filter requirements
echo ============================================================
echo.

REM --- 1) Verificar privilegios administrativos --------------
net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Este script requiere privilegios de Administrador.
    echo         Cierra esta ventana, click derecho en cmd.exe y
    echo         selecciona "Ejecutar como administrador".
    pause
    exit /b 1
)
echo [OK] Privilegios de administrador confirmados.
echo.

REM --- 2) Backup restaurable de la configuracion actual ------
set "BACKUP_DIR=%~dp0backups"
if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%"
set "TS=%date:~-4%%date:~3,2%%date:~0,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "TS=%TS: =0%"
set "BACKUP_FILE=%BACKUP_DIR%\auditpol_backup_%TS%.csv"
set "READABLE_FILE=%BACKUP_DIR%\auditpol_before_%TS%.txt"

echo [INFO] Creando backup restaurable en:
echo        %BACKUP_FILE%
auditpol /backup /file:"%BACKUP_FILE%" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] No se pudo crear el backup. Abortando.
    exit /b 2
)
auditpol /get /category:* > "%READABLE_FILE%" 2>&1
echo [OK] Backup creado. Para restaurar:
echo      auditpol /restore /file:"%BACKUP_FILE%"
echo.

REM --- 3) Habilitar subcategorias por GUID -------------------
echo [INFO] Aplicando configuracion NSA filter...
echo.

REM === SYSTEM ======================================
call :set_sub "Security State Change"          "{0CCE9210-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Security System Extension"      "{0CCE9211-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "System Integrity"               "{0CCE9212-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "IPsec Driver"                   "{0CCE9213-69AE-11D9-BED3-505054503030}" enable disable

REM === LOGON/LOGOFF ================================
call :set_sub "Logon"                          "{0CCE9215-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Logoff"                         "{0CCE9216-69AE-11D9-BED3-505054503030}" enable disable
call :set_sub "Account Lockout"                "{0CCE9217-69AE-11D9-BED3-505054503030}" disable enable
call :set_sub "IPsec Extended Mode"            "{0CCE921A-69AE-11D9-BED3-505054503030}" enable disable
call :set_sub "Special Logon"                  "{0CCE921B-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Other Logon/Logoff Events"      "{0CCE921C-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Network Policy Server"          "{0CCE9243-69AE-11D9-BED3-505054503030}" enable enable

REM === OBJECT ACCESS ===============================
call :set_sub "File Share"                     "{0CCE9224-69AE-11D9-BED3-505054503030}" enable disable
call :set_sub "Filtering Platform Connection"  "{0CCE9226-69AE-11D9-BED3-505054503030}" enable disable
call :set_sub "Filtering Platform Packet Drop" "{0CCE9225-69AE-11D9-BED3-505054503030}" disable enable
call :set_sub "Detailed File Share"            "{0CCE9244-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Handle Manipulation"            "{0CCE9223-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Application Generated"          "{0CCE9222-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Other Object Access Events"     "{0CCE9227-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Kernel Object"                  "{0CCE921F-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "SAM"                            "{0CCE9220-69AE-11D9-BED3-505054503030}" enable disable
call :set_sub "Certification Services"         "{0CCE9221-69AE-11D9-BED3-505054503030}" enable enable

REM === PRIVILEGE USE ===============================
call :set_sub "Sensitive Privilege Use"        "{0CCE9228-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Non Sensitive Privilege Use"    "{0CCE9229-69AE-11D9-BED3-505054503030}" enable enable

REM === DETAILED TRACKING ===========================
call :set_sub "Process Creation"               "{0CCE922B-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Process Termination"            "{0CCE922C-69AE-11D9-BED3-505054503030}" enable disable
call :set_sub "DPAPI Activity"                 "{0CCE922D-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "RPC Events"                     "{0CCE922E-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Plug and Play Events"           "{0CCE9248-69AE-11D9-BED3-505054503030}" enable disable

REM === POLICY CHANGE ===============================
call :set_sub "Audit Policy Change"            "{0CCE922F-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Authentication Policy Change"   "{0CCE9230-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Authorization Policy Change"    "{0CCE9231-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "MPSSVC Rule-Level Policy Change" "{0CCE9232-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Filtering Platform Policy Chg." "{0CCE9233-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Other Policy Change Events"     "{0CCE9234-69AE-11D9-BED3-505054503030}" enable enable

REM === ACCOUNT MANAGEMENT ==========================
call :set_sub "User Account Management"        "{0CCE9235-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Computer Account Management"    "{0CCE9236-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Security Group Management"      "{0CCE9237-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Distribution Group Management"  "{0CCE9238-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Application Group Management"   "{0CCE9239-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Other Account Management Events" "{0CCE923A-69AE-11D9-BED3-505054503030}" enable enable

REM === DS ACCESS (solo Domain Controllers) =========
call :set_sub "Directory Service Access"       "{0CCE923B-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Directory Service Changes"      "{0CCE923C-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Directory Service Replication"  "{0CCE923D-69AE-11D9-BED3-505054503030}" enable disable
call :set_sub "Detailed DS Replication"        "{0CCE923E-69AE-11D9-BED3-505054503030}" enable disable

REM === ACCOUNT LOGON ===============================
call :set_sub "Credential Validation"          "{0CCE923F-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Kerberos Service Ticket Ops"    "{0CCE9240-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Other Account Logon Events"     "{0CCE9241-69AE-11D9-BED3-505054503030}" enable enable
call :set_sub "Kerberos Authentication Service" "{0CCE9242-69AE-11D9-BED3-505054503030}" enable enable

REM --- 4) Dump del estado final ------------------------------
set "AFTER_FILE=%BACKUP_DIR%\auditpol_after_%TS%.txt"
auditpol /get /category:* > "%AFTER_FILE%" 2>&1

REM --- 5) Resumen --------------------------------------------
echo.
echo ============================================================
echo  Resumen
echo ============================================================
echo  Subcategorias aplicadas OK : %OK_COUNT%
echo  Subcategorias con error    : %FAILED%
echo.
echo  Backup restaurable : %BACKUP_FILE%
echo  Antes              : %READABLE_FILE%
echo  Despues            : %AFTER_FILE%
echo.
if %FAILED% GTR 0 (
    echo [WARN] Hubo errores. Revisa la salida arriba.
    echo        Para restaurar: auditpol /restore /file:"%BACKUP_FILE%"
    exit /b 3
)
echo [OK] Configuracion completada sin errores.
echo.
echo NOTA: Si este equipo esta en dominio con GPO de auditoria,
echo       el siguiente gpupdate puede sobrescribir estos cambios.
echo       Para que persistan, ajusta la GPO en su lugar.
echo.
exit /b 0

REM ============================================================
REM Subrutina :set_sub
REM   %~1 = nombre descriptivo (solo para log)
REM   %~2 = GUID de la subcategoria
REM   %~3 = success enable|disable
REM   %~4 = failure enable|disable
REM ============================================================
:set_sub
auditpol /set /subcategory:%~2 /success:%~3 /failure:%~4 >nul 2>&1
if errorlevel 1 (
    set /a FAILED+=1
    echo   [FAIL] %~1
) else (
    set /a OK_COUNT+=1
    echo   [ OK ] %~1
)
exit /b 0
