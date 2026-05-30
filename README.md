# windows-audit

> Habilita las **subcategorías de auditoría avanzada de Windows** requeridas por el **filtro NSA** de IBM QRadar WinCollect, de forma idempotente, idioma-agnóstica y con backup/rollback.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2B%20%2F%20Server%202016%2B-blue)
![Status](https://img.shields.io/badge/status-stable-green)

---

## ¿Qué resuelve?

El filtro **NSA** de IBM QRadar WinCollect espera que el host Windows tenga habilitadas ~45 subcategorías de auditoría avanzada para poder filtrar eventos según las guías de la NSA (*Spotting the Adversary with Windows Event Log Monitoring*). Configurarlas manualmente con `auditpol` es propenso a errores:

- Los nombres de subcategoría dependen del idioma del SO (`"Logon"` en inglés, `"Inicio de sesión"` en español).
- Falla silenciosamente si un nombre no existe en esa versión de Windows.
- No hay un mecanismo nativo de "configura todas las del filtro NSA de una".

Este repo provee dos scripts equivalentes (elige según tu entorno):

| Script | Mejor para |
|---|---|
| [`configure-nsa-audits.cmd`](configure-nsa-audits.cmd) | Entornos donde solo está disponible CMD. Mínimas dependencias. |
| [`Configure-NsaAudits.ps1`](Configure-NsaAudits.ps1) | Entornos modernos. Soporta `-WhatIf`, logging estructurado, rollback parametrizado. |

---

## Características

- ✅ **Locale-independent** — usa GUIDs de subcategoría (idioma-agnóstico). Funciona en Windows EN, ES, PT, etc.
- ✅ **Backup restaurable** antes de aplicar cambios (`auditpol /backup` formato CSV).
- ✅ **Verificación de privilegios admin** al inicio.
- ✅ **Error checking** por subcategoría (no falla silenciosamente).
- ✅ **Resumen final** con conteo de éxitos/errores.
- ✅ **Sin duplicados** (la versión anterior tenía ~50% de líneas duplicadas con configuraciones contradictorias).
- ✅ **Rollback nativo** vía `auditpol /restore`.
- ✅ **PowerShell `-WhatIf`** para dry-run.

---

## Requisitos

- Windows 10 / Windows Server 2016 o superior.
- Privilegios de Administrador.
- (Para la versión PowerShell) PowerShell 5.1 o superior.
- IBM QRadar WinCollect instalado y configurado en otro lado del pipeline.

---

## Uso rápido

### CMD

```cmd
:: Abre cmd.exe como Administrador
cd C:\ruta\al\repo
configure-nsa-audits.cmd
```

### PowerShell

```powershell
# Dry-run primero (recomendado):
.\Configure-NsaAudits.ps1 -WhatIf

# Aplicar:
.\Configure-NsaAudits.ps1

# Rollback con el backup que el script dejó:
.\Configure-NsaAudits.ps1 -Rollback .\backups\auditpol_backup_20260530_120000.csv
```

Salida típica:

```
[2026-05-30 12:00:01] [INFO ] === Configure-NsaAudits v2.0.0 ===
[2026-05-30 12:00:01] [OK   ] Privilegios admin: OK
[2026-05-30 12:00:02] [OK   ] Backup creado: .\backups\auditpol_backup_20260530_120000.csv
[2026-05-30 12:00:02] [INFO ] Aplicando 47 subcategorias...
[2026-05-30 12:00:02] [OK   ]   Security State Change
[2026-05-30 12:00:02] [OK   ]   Security System Extension
...
[2026-05-30 12:00:05] [OK   ]  Aplicadas OK : 47
[2026-05-30 12:00:05] [OK   ] Configuracion completada.
```

---

## Subcategorías habilitadas

| Categoría | Subcategorías habilitadas |
|---|---|
| **System** | Security State Change, Security System Extension, System Integrity, IPsec Driver |
| **Logon/Logoff** | Logon, Logoff, Account Lockout, IPsec Extended Mode, Special Logon, Other Logon/Logoff Events, Network Policy Server |
| **Object Access** | File Share, Filtering Platform Connection, Filtering Platform Packet Drop, Detailed File Share, Handle Manipulation, Application Generated, Other Object Access Events, Kernel Object, SAM, Certification Services |
| **Privilege Use** | Sensitive Privilege Use, Non Sensitive Privilege Use |
| **Detailed Tracking** | Process Creation, Process Termination, DPAPI Activity, RPC Events, Plug and Play Events |
| **Policy Change** | Audit Policy Change, Authentication Policy Change, Authorization Policy Change, MPSSVC Rule-Level Policy Change, Filtering Platform Policy Change, Other Policy Change Events |
| **Account Management** | User Account Management, Computer Account Management, Security Group Management, Distribution Group Management, Application Group Management, Other Account Management Events |
| **DS Access** *(DCs only)* | Directory Service Access, Directory Service Changes, Directory Service Replication, Detailed DS Replication |
| **Account Logon** | Credential Validation, Kerberos Service Ticket Operations, Other Account Logon Events, Kerberos Authentication Service |

Total: **47 subcategorías**.

Para ver exactamente cuáles success/failure aplica cada una, ver la tabla `$Subcategories` en [`Configure-NsaAudits.ps1`](Configure-NsaAudits.ps1#L46) o las líneas `call :set_sub` en [`configure-nsa-audits.cmd`](configure-nsa-audits.cmd).

---

## Backup y rollback

Antes de cualquier cambio, los scripts crean automáticamente:

```
backups/
├── auditpol_backup_<TS>.csv     ← backup REAL restaurable
├── auditpol_before_<TS>.txt     ← snapshot legible del estado previo
└── auditpol_after_<TS>.txt      ← snapshot del estado final
```

Para revertir al estado previo:

```cmd
auditpol /restore /file:backups\auditpol_backup_20260530_120000.csv
```

O con la versión PowerShell:

```powershell
.\Configure-NsaAudits.ps1 -Rollback .\backups\auditpol_backup_20260530_120000.csv
```

---

## ⚠️ Advertencias importantes

### Impacto en el volumen de eventos

Habilitar estas subcategorías incrementa significativamente el volumen de eventos generados en el Event Viewer (típicamente 5-20× según el rol del servidor). Asegúrate de:

- Tener configurado un tamaño adecuado del log de seguridad (>= 256 MB recomendado).
- Tener WinCollect / agente de envío funcionando antes de aplicar.
- Dimensionar correctamente la EPS (events per second) en QRadar.

### Conflicto con GPO de dominio

Si el equipo está en dominio con una **Group Policy** de auditoría aplicada, los cambios locales **se sobrescriben** en el próximo `gpupdate`. Opciones:

- Aplicar estas subcategorías en la GPO directamente (recomendado).
- Bloquear la herencia de GPO en la OU correspondiente (no recomendado en producción).
- Usar `auditpol /set` después de cada `gpupdate` (parche temporal).

### Subcategorías que solo aplican en Domain Controllers

Las siguientes solo tienen sentido en un DC. En workstations no causan error pero no generan eventos:

- Directory Service Access / Changes / Replication / Detailed Replication

---

## Versiones probadas

| Windows | Estado |
|---|---|
| Windows 10 21H2+ | ✅ |
| Windows 11 22H2+ | ✅ |
| Windows Server 2016 | ✅ |
| Windows Server 2019 | ✅ |
| Windows Server 2022 | ✅ |
| Windows 7 / Server 2008 R2 | ⚠️ Algunas subcategorías nuevas (Plug and Play Events) no existen |

---

## Changelog

### v2.0.0 (refactor)

- 🔴 Fix: línea truncada que rompía el script en la versión 1.0 (`Sensitive Priv` sin cerrar).
- 🔴 Fix: nombres de subcategoría sustituidos por GUIDs (idioma-agnóstico).
- 🔴 Fix: duplicados eliminados (~50% de las líneas) que causaban configuraciones contradictorias.
- 🔴 Fix: corregidas inconsistencias (ej. `"Non Sensitive Privilege Use"` vs `"Non-Sensitive"`).
- 🟠 Add: verificación de privilegios admin al inicio.
- 🟠 Add: backup restaurable con `auditpol /backup` (CSV, no solo texto).
- 🟠 Add: `errorlevel` check por cada `auditpol /set` y conteo de éxitos/errores.
- 🟠 Add: versión PowerShell con `-WhatIf`, logging y `-Rollback`.
- 🟢 Add: `.gitignore` (evita commit de backups generados).
- 🟢 Add: README estructurado con tabla de subcategorías, versiones probadas, advertencia GPO.

### v1.0 (versión inicial)

Configuración batch monolítica con todas las subcategorías por nombre en inglés.

---

## Contribuciones

Issues y PRs bienvenidos. Antes de abrir un PR:

1. Verifica que el cambio funciona en Windows EN **y** ES (locale-independence es la feature clave).
2. No agregues subcategorías que no estén en la guía NSA original sin justificación.
3. No commits de archivos en `backups/` o `logs/`.

---

## Licencia

GPL v3 — ver [LICENSE](LICENSE).

---

## Referencias

- [NSA — Spotting the Adversary with Windows Event Log Monitoring](https://media.defense.gov/2019/Jul/16/2002158056/-1/-1/0/CSI-SPOTTING-THE-ADVERSARY-WITH-WINDOWS-EVENT-LOG-MONITORING.PDF) (PDF)
- [Microsoft Docs — Advanced security audit policy settings](https://learn.microsoft.com/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [Microsoft Docs — auditpol](https://learn.microsoft.com/windows-server/administration/windows-commands/auditpol)
- [IBM QRadar WinCollect — Documentation](https://www.ibm.com/docs/en/qsip/7.5?topic=collect-wincollect)
