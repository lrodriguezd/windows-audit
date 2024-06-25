@echo off
echo Habilitando la auditoría de Event IDs...
echo.
auditpol /get /category:* > configuracion_actual.txt
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /success:enable
auditpol /set /subcategory:"IPsec Extended Mode" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Network Policy Server" /success:enable
auditpol /set /subcategory:"Application Generated" /success:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Application Group Management" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Replication" /success:enable
auditpol /set /subcategory:"Detailed Directory Service Replication" /success:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable
auditpol /set /subcategory:"RPC Events" /success:enable
auditpol /set /subcategory:"Plug and Play Events" /success:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable
auditpol /set /subcategory:"IPsec Driver" /success:enable
auditpol /set /subcategory:"IPsec IKE" /success:enable
auditpol /set /subcategory:"IPsec AuthIP" /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable
auditpol /set /subcategory:"Kernel Object" /success:enable
auditpol /set /subcategory:"SAM" /success:enable
auditpol /set /subcategory:"Certification Services" /success:enable
auditpol /set /subcategory:"Application Group Management" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable
auditpol /set /subcategory:"Other Policy Change Events" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Process Termination" /success:enable
auditpol /set /subcategory:"DPAPI Activity" /success:enable
auditpol /set /subcategory:"RPC Events" /success:enable
auditpol /set /subcategory:"Plug and Play Events" /success:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable
auditpol /set /subcategory:"IPsec Driver" /success:enable
auditpol /set /subcategory:"IPsec IKE" /success:enable
auditpol /set /subcategory:"IPsec AuthIP" /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable
auditpol /set /subcategory:"Kernel Object" /success:enable
auditpol /set /subcategory:"SAM" /success:enable
auditpol /set /subcategory:"Certification Services" /success:enable
auditpol /set /subcategory:"DPAPI Activity" /success:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Distribution Group Management" /success:enable
auditpol /set /subcategory:"Application Group Management" /success:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable
auditpol /set /subcategory:"Security State Change" /success:enable
auditpol /set /subcategory:"Security System Extension" /success:enable
auditpol /set /subcategory:"System Integrity" /success:enable
auditpol /set /subcategory:"IPsec Driver" /success:enable
auditpol /set /subcategory:"IPsec IKE" /success:enable
auditpol /set /subcategory:"IPsec AuthIP" /success:enable
auditpol /set /subcategory:"Non-Sensitive Privilege Use" /success:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable
auditpol /set /subcategory:"Directory Service Replication" /success:enable
auditpol /set /subcategory:"Detailed Directory Service Replication" /success:enable
auditpol /set /subcategory:"IPsec Driver" /success:enable
auditpol /set /subcategory:"IPsec IKE" /success:enable
auditpol /set /subcategory:"IPsec AuthIP" /success:enable
auditpol /set /subcategory:"Non-Sensitive Privilege Use" /success:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable
auditpol /set /subcategory:"Directory Service Replication" /success:enable
auditpol /set /subcategory:"Detailed Directory Service Replication" /success:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable
auditpol /set /subcategory:"Application Group Management" /success:enable
auditpol /set /subcategory:"Other Policy Change Events" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Distribution Group Management" /success:enable
auditpol /set /subcategory:"Application Group Management" /success:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable
auditpol /set /subcategory:"Security State Change" /success:enable
auditpol /set /subcategory:"Security System Extension" /success:enable
auditpol /set /subcategory:"System Integrity" /success:enable
auditpol /set /subcategory:"IPsec Driver" /success:enable
auditpol /set /subcategory:"IPsec IKE" /success:enable
auditpol /set /subcategory:"IPsec AuthIP" /success:enable
auditpol /set /subcategory:"Non-Sensitive Privilege Use" /success:enable
auditpol /set /subcategory:"Sensitive Priv
auditpol /get /category:* > configuracion_nueva.txt
echo ¡Configuración completa!
echo.
