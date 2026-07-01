# Guia de Mitigacion de Ataque DDoS (SYN Flood + Exfiltracion de Datos)

Esta guia documenta, paso a paso, como detectar y mitigar un ataque combinado de SYN Flood (Capa 4) y exfiltracion de archivos via HTTP (Capa 7) sobre un servidor web Apache en Ubuntu Server, utilizando herramientas nativas de Linux (`ss`, `nload`, `tcpdump`, `iptables`).

Pensada como referencia de laboratorio para practicas de seguridad defensiva. Los valores de IP, interfaces de red y umbrales deben adaptarse al entorno propio.

## Tabla de contenidos

1. Requisitos previos
2. Diagnostico del entorno de red
3. Deteccion del ataque
4. Analisis de causa raiz
5. Plan de mitigacion
6. Despliegue de las reglas
7. Verificacion post-mitigacion
8. Automatizacion preventiva
9. Notas finales

---

## 1. Requisitos previos

- Servidor victima: Ubuntu Server con Apache2 activo.
- Acceso `sudo` sobre el servidor.
- Herramientas instaladas: `nload`, `ss`, `tcpdump`, `htop`, `iostat` (paquete `sysstat`), `iptables`.
- Entorno de laboratorio virtualizado (VMware, VirtualBox) con un nodo atacante en la misma subred, o datos de trafico ya capturados si se esta replicando el analisis sobre logs existentes.

```bash
sudo apt update
sudo apt install nload sysstat tcpdump htop iptables -y
```

---

## 2. Diagnostico del entorno de red

Antes de analizar el ataque, se debe confirmar que la interfaz de red este correctamente configurada.

```bash
ip a
```

Si la IP asignada no coincide con la esperada, revisar el archivo de Netplan:

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

Problema comun: si el laboratorio fue clonado o importado desde una plantilla, la direccion MAC declarada en Netplan puede no coincidir con la MAC generada por el hipervisor al crear la maquina virtual, lo que impide que `netplan apply` asigne la IP estatica esperada.

Solucion: igualar manualmente la MAC virtual (en la configuracion avanzada del adaptador de red del hipervisor) con la que exige el archivo YAML, o bien actualizar el YAML con la MAC real de la interfaz. Luego:

```bash
sudo netplan apply
ip a
```

---

## 3. Deteccion del ataque

### 3.1 Ancho de banda (nload)

```bash
nload ens33 -u M -t 200
```

Que observar: trafico de salida (Outgoing) anormalmente alto en comparacion con el de entrada. Un TX elevado y sostenido en un servidor web suele indicar que algo esta forzando descargas masivas de datos.

### 3.2 Estado de sockets (ss)

```bash
ss -antp | grep -E 'ESTAB|SYN-RECV'
```

Que observar: un volumen masivo de conexiones en estado SYN-RECV sobre el puerto atacado (por ejemplo, el 80), provenientes de IPs de origen dispersas, invalidas o de rangos no enrutables. Esto es indicativo de IP spoofing dentro de un SYN Flood: el kernel responde con SYN-ACK pero nunca recibe el ACK final, dejando el backlog de conexiones saturado.

### 3.3 Logs de aplicacion (tail + grep)

```bash
tail -f /var/log/apache2/access.log | grep "<recurso_sospechoso>"
```

Que observar: peticiones repetidas al mismo recurso pesado (por ejemplo, un dump de base de datos), en rafagas de milisegundos, desde una unica IP real (a diferencia de las IPs spoofeadas del punto anterior) y con un User-Agent de herramienta automatizada (curl, wget, scripts propios).

### 3.4 Consumo de CPU y memoria (htop)

```bash
htop
```

Que observar: en un SYN Flood puro, el consumo de CPU y RAM de los procesos de Apache suele mantenerse bajo. El cuello de botella no es de computo, sino de saturacion en la pila de red.

### 3.5 I/O de disco (iostat)

```bash
iostat -x 1
```

Que observar: si `%util` se mantiene bajo pese a las descargas repetidas, es senal de que el archivo se esta sirviendo desde cache (Page Cache), lo que descarta un problema de hardware de almacenamiento.

---

## 4. Analisis de causa raiz

### Captura de paquetes (tcpdump)

```bash
sudo tcpdump -i ens33 -n port 80 -c 20
```

Permite confirmar visualmente los flags `[S]` (SYN) provenientes de multiples IPs falsificadas hacia el puerto objetivo.

### Por que no sirve bloquear IP por IP con iptables -A INPUT -s IP -j DROP

En un ataque con spoofing, cada paquete trae una IP de origen distinta y efimera. Crear una regla por cada IP saturaria la tabla de Netfilter y consumiria mas CPU de la que ahorraria, provocando una denegacion de servicio auto-infligida.

### Por que mitigar en el kernel (iptables/Netfilter) y no en espacio de usuario (/etc/hosts.allow)

TCP Wrappers actua en espacio de usuario: el sistema ya reservo memoria, creo el socket y consulto un archivo en disco antes de decidir si bloquea. Bajo rafagas masivas de trafico, este mecanismo colapsa.

Netfilter/iptables actua en espacio de kernel, en las fases tempranas de la pila de red (por ejemplo, PREROUTING), descartando paquetes maliciosos antes de que consuman recursos del sistema. Esto permite procesar un volumen alto de paquetes concurrentes sin degradar el rendimiento de la maquina.

---

## 5. Plan de mitigacion

Se definen dos frentes de accion, de forma no destructiva (el servicio permanece en linea) e idempotente (el script puede ejecutarse varias veces sin duplicar reglas):

| Capa | Vector | Contramedida |
|------|--------|---------------|
| 4 (Red) | SYN Flood / IPs spoofeadas | Rate limiting de conexiones SYN al puerto 80 |
| 7 (Aplicacion) | Exfiltracion de archivo via HTTP | Filtrado de paquetes por firma de cadena (string matching) |

---

## 6. Despliegue de las reglas

Guardar como `mitigar.sh` en el repositorio:

```bash
#!/bin/bash
set -e

echo "=== Aplicando mitigacion DDoS ==="

# 1. Idempotencia: limpiar reglas previas
sudo iptables -F
sudo iptables -X

# 2. Capa 4: limitar tasa de nuevas conexiones SYN al puerto 80
sudo iptables -A INPUT -p tcp --syn --dport 80 -m limit --limit 10/s --limit-burst 5 -j ACCEPT
sudo iptables -A INPUT -p tcp --syn --dport 80 -j DROP

# 3. Capa 7: bloquear peticiones que contengan la firma del recurso comprometido
sudo iptables -A INPUT -p tcp --dport 80 -m string --algo bm --string "<recurso_sospechoso>" -j DROP

echo "=== Reglas aplicadas ==="
```

```bash
chmod +x mitigar.sh
sudo ./mitigar.sh
```

Alternativa con connlimit (limita conexiones concurrentes por IP en lugar de tasa global):

```bash
sudo iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 10 -j DROP
```

---

## 7. Verificacion post-mitigacion

### Contadores del firewall

```bash
sudo iptables -L -n -v
```

Confirmar que los contadores `pkts`/`bytes` de las reglas DROP esten incrementando, lo cual indica que el trafico hostil esta siendo interceptado.

### Ancho de banda

```bash
nload ens33
```

El trafico de salida deberia volver a niveles normales (kbps en lugar de decenas de MB/s).

### Carga de CPU y disco

```bash
iostat -x 1
```

Un `%idle` cercano al 100% y un `%util` de disco en valores bajos confirman que el sistema ya no esta bajo presion.

### Prueba funcional

Acceder al servicio desde un cliente externo y confirmar que responde con normalidad:

```text
http://<IP_DEL_SERVIDOR>
```

---

## 8. Automatizacion preventiva

Para no dejar el firewall restringido de forma permanente, conviene activar la mitigacion solo cuando se detecte una anomalia.

`centinela.sh` (script de monitoreo):

```bash
#!/bin/bash

UMBRAL=100
CONEXIONES=$(ss -ant | grep -c SYN-RECV)

if [ "$CONEXIONES" -gt "$UMBRAL" ]; then
  echo "$(date): posible SYN Flood detectado ($CONEXIONES conexiones SYN-RECV)" >> /var/log/syslog
  /ruta/absoluta/mitigar.sh
fi
```

Programacion con cron (revision cada minuto):

```bash
crontab -e
```

```cron
* * * * * /ruta/absoluta/centinela.sh
```

De esta forma, el firewall solo se endurece cuando el trafico supera el umbral definido, y permanece en un estado normal de operacion el resto del tiempo.

---

## 9. Notas finales

- Ajustar el umbral de conexiones SYN-RECV y la tasa de `limit` segun el trafico legitimo normal del servicio, para evitar falsos positivos.
- El filtrado por cadena (`-m string`) es util como mitigacion puntual, pero a mediano plazo conviene reforzar el control de acceso a nivel de aplicacion (autenticacion, WAF, permisos de archivos) para evitar que recursos sensibles, como dumps de base de datos, queden expuestos en la raiz web.
- Las reglas de iptables no persisten tras un reinicio por defecto; considerar `iptables-persistent` o migrar a `nftables` si se requiere persistencia.

---

Autor: (nombre / usuario de GitHub)
Licencia: MIT (o la que se prefiera)
