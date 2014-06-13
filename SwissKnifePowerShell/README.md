**SK-PS** a.k.a. Swiss Knife es un proyecto (de momento) de kit de scripts en PowerShell con funciones orientadas a diferentes aspectos de la seguridad.

<center><img src="http://i.imgur.com/LcG6SpN.jpg" WIDTH="50%" HEIGHT="50%"></center>

Los aspectos que pretende cubrir:

Análisis:
* Análisis de binarios.
* Análisis de memoria.
* Análisis de redes.
* Auditorías de seguridad.
* Detección de hashes.

Modificación:
* Modificación de binarios.
  * [Patch-Bin.ps1](https://github.com/spageek/hacktools/blob/master/SwissKnifePowerShell/Patch-Bin.ps1): Modifica _n_ bytes de una dirección en el fichero en concreto.
* Modificación de registros de memoria.
* Abertura e inyección de datos a través de sockets.
* Remediación en fallos de configuración de sistemas.

