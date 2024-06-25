# windows-audit

Descripción
Este script automatiza la configuración de auditorías necesarias para el filtro NSA de IBM Security QRadar WinCollect. El filtro NSA (National Security Agency) requiere configuraciones específicas para asegurar la recolección adecuada de datos en entornos regulados o de alta seguridad.

Requisitos
IBM Security QRadar WinCollect: Debe estar instalado y configurado correctamente.
Referencia: https://www.ibm.com/community/101/qradar/installs/

Privilegios administrativos: El script debe ejecutarse con privilegios de administrador en el sistema donde se realiza la configuración.

Exportar la configuración actual de auditoría:
Abrir una ventana de PowerShell o CMD como administrador:
En Windows, busca PowerShell (o CMD), haz clic derecho y selecciona "Ejecutar como administrador".
Utiliza el comando auditpol /backup /file:<ruta_del_archivo> para exportar la configuración actual de auditoría a un archivo.

Por ejemplo:
C:\Users\Administrator\Desktop>auditpol /backup /file:C:\auditoria_backup.txt
The command was successfully executed.

Esto guardará la configuración actual de auditoría en el archivo especificado (auditoria_backup.txt en el ejemplo) en la ubicación C:\ruta\.

Verificar que el archivo de respaldo se ha creado:
Una vez que se ejecute el comando, verifica que el archivo auditoria_backup.txt (o el nombre que hayas elegido) se haya creado correctamente en la ubicación especificada.

Instrucciones de Uso
Descarga del Script:
Clona este repositorio o descarga el archivo del script configure-nsa-audits.cmd.


Ejecución del Script:
Abrir una ventana de PowerShell o CMD como administrador:
En Windows, busca PowerShell (o CMD), haz clic derecho y selecciona "Ejecutar como administrador".

C:\ruta\hacia\el\script> .\configure-nsa-audits.cmd

Confirmación de Auditorías:

El script mostrará las auditorías que serán habilitadas o configuradas.
auditpol /get /category:* > configuracion_actual.txt


Verificación:
El script mostrará las auditorías que serán habilitadas o configuradas.
auditpol /get /category:* > configuracion_nueva.txt

Después de la ejecución, verifica en IBM Security QRadar WinCollect que las auditorías necesarias estén activas y configuradas según lo esperado.

Notas Importantes:

Impacto del Cambio: Habilitar auditorías adicionales puede aumentar el volumen de datos recolectados.
Configuración Personalizada: Si es necesario, ajusta el script según los requisitos específicos de tu entorno.

Ejemplo de Uso
CMD

Microsoft Windows [Version 10.0.17763.4645]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>C:\Users\Administrator\Desktop\configure-nsa-audits.cmd
Habilitando la auditorφa de Event IDs...

The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
The command was successfully executed.
¡Configuración completa!

Notas adicionales:
Restauración de configuraciones de auditoría: Para restaurar la configuración desde el archivo de respaldo, puedes utilizar el comando auditpol /restore /file:<ruta_del_archivo>.
Permiso de administrador: Es importante ejecutar PowerShell o CMD como administrador para poder realizar operaciones de auditoría con auditpol.
Documentación adicional: Puedes consultar la ayuda de auditpol para más detalles utilizando auditpol /?.

Contribuciones
Si encuentras algún problema o tienes alguna mejora para sugerir, no dudes en abrir un issue o enviar un pull request. Tus contribuciones son bienvenidas para mejorar este script y hacerlo más útil para la comunidad.
