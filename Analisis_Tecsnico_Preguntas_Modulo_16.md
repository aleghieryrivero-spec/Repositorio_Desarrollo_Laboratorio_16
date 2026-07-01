# Analisis Tecnico: Preguntas de Profundizacion sobre Mitigacion DDoS

Este documento amplia, con fundamento tecnico, diez preguntas derivadas del caso de mitigacion de un ataque combinado de SYN Flood e Filtracion de Datos (db.sql) sobre un servidor Apache. El objetivo es ir mas alla de la respuesta operativa e incluir el mecanismo interno que explica cada comportamiento.

---

## Indice

01. Consumo de recursos en un handshake que nunca se completa
02. Efecto de omitir la regla ESTABLISHED,RELATED
03. Limitaciones del filtrado por cadena de texto sobre HTTPS
04. Riesgo de duplicar reglas por falta de limpieza previa
05. Impacto de la saturacion de disco sobre la trazabilidad
06. Por que TCP Wrappers no detiene un SYN Flood
07. Riesgo de bloquear la propia puerta de enlace
08. Mitigacion de trafico legitimo detras de NAT compartido
09. Limites del filtrado de firma ante trafico distribuido y Keep-Alive
10. Arquitectura de observabilidad para deteccion temprana

---

## 1. El atacante usa IP Spoofing enviando paquetes SYN. El handshake TCP nunca se completa. Por que esto consume recursos si la conexion no llega a establecerse

El consumo de recursos no depende de que la conexion se complete, sino de que el kernel reserva memoria en el instante en que **recibe** el primer paquete SYN, no cuando el handshake termina.

Cuando llega un SYN, el sistema operativo no puede saber de antemano si es legitimo o falso, de modo que actua de buena fe: crea una estructura de control en el espacio de memoria del kernel (el equivalente a un Transmission Control Block en estado embrionario), reserva un lugar en la cola de conexiones semiabiertas (SYN backlog) y responde con un SYN-ACK. A partir de ahi, el socket queda en estado SYN-RECV a la espera del ACK final.

El problema aparece por volumen y por la naturaleza del spoofing: si el atacante falsifica miles de IPs de origen distintas, el ACK final jamas llegara, porque esas IPs no existen o pertenecen a hosts que nunca solicitaron nada y simplemente descartan el SYN-ACK inesperado. Cada una de esas entradas permanece en el backlog durante el tiempo del timeout de retransmision del kernel (que puede implicar varios reintentos de SYN-ACK antes de expirar). Si la tasa de llegada de SYN falsos supera la tasa de expiracion de entradas antiguas, la cola se llena por completo, y a partir de ese punto el kernel empieza a descartar silenciosamente cualquier SYN adicional, incluidos los de usuarios legitimos. El resultado es una denegacion de servicio lograda no por fuerza bruta de ancho de banda, sino por agotamiento de una estructura de datos finita del sistema operativo.

---

## 2. Que ocurriria con los jugadores de la aplicacion en linea si se omite la regla ESTABLISHED,RELATED y solo se deja un Rate Limiting estricto

Sin una regla de seguimiento de estado, iptables perderia la capacidad de distinguir entre un paquete que abre una conexion nueva y un paquete que pertenece a una sesion ya validada. En ese escenario, cada paquete de cada partida en curso volveria a recorrer la cadena `INPUT` completa, evaluandose contra todas las reglas de rate limiting como si fuera una conexion nueva.

Esto tiene dos consecuencias directas. La primera es de rendimiento: el modulo `connlimit` o `limit` de iptables mantiene contadores por IP o globales; si cada paquete de trafico legitimo tiene que pasar por esa contabilizacion en lugar de ser aceptado por el atajo de estado, la latencia percibida por el jugador aumenta de forma perceptible, especialmente en una aplicacion interactiva como un juego en tiempo real. La segunda consecuencia es de exactitud: un jugador que ya establecio conexion y esta enviando multiples paquetes por segundo (por ejemplo, cada movimiento del tablero) podria terminar contando contra su propio limite de tasa, siendo bloqueado por su propio trafico legitimo, no por el atacante.

El modulo `conntrack` (detras de las reglas ESTABLISHED, RELATED) mantiene una tabla de conexiones ya inspeccionadas. Su funcion es exactamente evitar ese reprocesamiento: si el paquete pertenece a una conexion que el firewall ya autorizo, se acepta de inmediato sin volver a evaluar el resto de las reglas. Omitir esa regla no solo genera latencia, tambien contradice el principio de diseño de un firewall con estado (stateful firewall), que existe precisamente para no tratar cada paquete como un evento aislado.

---

## 3. Se bloqueo la cadena db.sql a nivel de iptables. Que sucederia si el servidor usara HTTPS por el puerto 443. Seguiria funcionando esa regla

No funcionaria en absoluto, y es importante entender por que a nivel de protocolo, no solo como una limitacion practica.

El modulo `string` de iptables inspecciona el contenido en texto plano de la carga util (payload) del paquete TCP, comparandolo byte a byte contra el patron definido (en este caso, mediante el algoritmo Boyer-Moore). Esto funciona sobre HTTP porque las cabeceras y la ruta solicitada (`GET /db.sql HTTP/1.1`) viajan sin cifrar. En HTTPS, en cambio, todo el contenido de la capa de aplicacion —incluida la linea de peticion, las cabeceras y el cuerpo— esta cifrado mediante TLS antes de salir del navegador o cliente. Lo unico que un firewall a nivel de Netfilter puede observar en un flujo HTTPS son los metadatos de la capa de transporte (IP origen y destino, puertos, tamaño de paquete y, en el mejor de los casos, el SNI del handshake TLS inicial), pero nunca la ruta del recurso solicitado.

Para lograr un filtrado equivalente sobre trafico cifrado existen dos caminos. El primero es terminar el TLS antes del servidor de aplicacion, mediante un proxy inverso (Nginx, HAProxy) o un balanceador que descifre el trafico, inspeccione la peticion en texto plano y la vuelva a cifrar (o la envie sin cifrar) hacia el backend; esto traslada el punto de inspeccion a una capa donde el contenido ya es legible. El segundo es delegar la inspeccion a un Web Application Firewall de Capa 7 que se integre directamente en ese punto de terminacion TLS, aplicando reglas sobre URI, cabeceras o cuerpo de la peticion ya descifrada. En ambos casos, la inspeccion deja de ser un problema de Netfilter y pasa a ser un problema de arquitectura de terminacion TLS.

---

## 4. El script usa iptables -A. Que pasaria si un cron job lo ejecuta cada 5 minutos durante un mes y se olvida el iptables -F inicial

El efecto seria una degradacion progresiva y autoinfligida del propio servidor, no atribuible al atacante.

`-A` (append) añade la regla al final de la cadena sin verificar si una regla identica ya existe. Sin una limpieza previa (`iptables -F` para vaciar las reglas y `iptables -X` para eliminar cadenas personalizadas), cada ejecucion del cron duplicaria integramente el conjunto de reglas de mitigacion. Con una frecuencia de ejecucion cada 5 minutos, en una hora se acumularian 12 copias del mismo conjunto de reglas, en un dia 288, y a lo largo de un mes la cifra superaria las 8,000 reglas identicas apiladas en la cadena `INPUT`.

El impacto no es solo cosmetico. iptables evalua las reglas de una cadena de forma secuencial hasta encontrar una coincidencia; cuantas mas reglas existan antes de la que finalmente decide el destino del paquete, mayor es el numero de comparaciones que el kernel debe realizar por cada paquete entrante. Con miles de reglas redundantes, el costo de CPU por paquete crece de forma lineal con el tamaño de la cadena, y bajo trafico legitimo de volumen normal el sistema podria empezar a experimentar la misma sintomatologia que un ataque: latencia elevada, colas de procesamiento saturadas y, en el limite, agotamiento de CPU. Es, en esencia, una denegacion de servicio generada por el propio equipo de defensa, razon por la cual la idempotencia (poder ejecutar el script multiples veces sin efectos acumulativos) no es un detalle de estilo, sino un requisito de seguridad operativa.

---

## 5. Si el disco llega al 100 por ciento de uso durante el ataque, como afecta esto a los logs de Apache y al diagnostico

El efecto es una perdida de visibilidad justo en el momento en que mas se necesita, lo que en analisis forense se conoce como punto ciego operativo.

Apache escribe cada peticion HTTP en `access.log` de forma sincrona con la atencion de la peticion; esa escritura es, en el fondo, una operacion de I/O sobre el disco. Si el subsistema de almacenamiento llega al 100 por ciento de utilizacion (por ejemplo, por una cola de escrituras saturada, a diferencia del escenario real del caso analizado donde el disco se mantuvo ocioso porque el archivo se serviciaba desde cache), las nuevas operaciones de escritura deben esperar en cola. Los procesos de trabajo de Apache (`www-data`) que atienden peticiones nuevas quedarian bloqueados en estado de espera de I/O (`iowait`), incapaces de continuar hasta que el kernel logre completar la escritura pendiente en el log.

La consecuencia para el analisis del incidente es doble. Primero, se pierde el registro cronologico exacto de las peticiones que llegaron durante el pico de saturacion, justamente el tramo mas critico para identificar el patron del atacante (IP de origen, recurso solicitado, frecuencia). Segundo, la ausencia de logs no significa ausencia de trafico: el atacante puede seguir enviando peticiones que Apache ni siquiera llega a registrar por estar bloqueado en I/O, generando una falsa sensacion de calma en el archivo de logs mientras el servidor colapsa. Por esta razon, en un diagnostico riguroso conviene correlacionar los logs de aplicacion con metricas de kernel (`ss`, `nload`, `iostat`) que no dependen de la misma ruta de escritura en disco y que siguen siendo visibles incluso cuando la capa de aplicacion deja de registrar eventos.

---

## 6. Por que un ataque SYN Flood no puede ser detenido por TCP Wrappers (hosts.deny)

La razon de fondo es que ambos mecanismos operan en capas distintas del modelo de red, y TCP Wrappers depende de una condicion que el SYN Flood nunca cumple.

TCP Wrappers intercepta conexiones a nivel de aplicacion, evaluando el archivo `hosts.allow` o `hosts.deny` en el momento en que un servicio compilado contra la libreria `libwrap` acepta una conexion entrante ya establecida. Esto implica, por definicion, que el handshake TCP de tres vias (SYN, SYN-ACK, ACK) debe haberse completado antes de que TCP Wrappers tenga oportunidad de evaluar nada: solo despues de ese punto el sistema operativo entrega el socket al proceso de aplicacion, que es donde vive la logica de TCP Wrappers.

Un SYN Flood, por construccion, nunca completa ese handshake: el atacante envia el SYN inicial y luego abandona la conexion (o directamente falsifica una IP de origen que nunca respondera con el ACK final). El paquete jamas sale del ambito del kernel de red, nunca llega a ser entregado a un proceso de aplicacion, y por lo tanto TCP Wrappers ni siquiera se entera de que la peticion existio. Es una carrera perdida de antemano: el ataque ocurre exactamente en la capa que TCP Wrappers no supervisa. Esta es la misma razon estructural por la que la mitigacion debe aplicarse en Netfilter/iptables, que si intercepta el trafico en las fases tempranas del stack de red, antes de que el paquete alcance el nivel de aplicacion.

---

## 7. Que pasaria si el atacante falsifica la direccion IP de la propia puerta de enlace (Gateway)

Este es uno de los vectores mas delicados porque convierte al mecanismo de defensa en el instrumento del propio ataque.

Si el atacante logra que los paquetes maliciosos aparenten provenir de la IP del router o gateway del servidor, y el script de mitigacion aplica bloqueos automaticos basados unicamente en la IP de origen que genera mas trafico anomalo, el sistema de defensa terminaria emitiendo una regla `DROP` contra la propia puerta de enlace. El efecto practico es una interrupcion total de la conectividad del servidor hacia el exterior: todo el trafico de salida legitimo que depende de enrutarse a traves de ese gateway quedaria bloqueado, no por el atacante, sino por la propia regla defensiva.

Esto ilustra por que un sistema de mitigacion automatizado no deberia bloquear IPs de forma ciega sin contexto topologico. Una arquitectura mas robusta incorporaria una lista de exclusion explicita (allowlist) para las IPs de infraestructura critica propia (gateway, DNS interno, servidores de administracion), de modo que ninguna regla generada dinamicamente pueda alcanzarlas, junto con validaciones adicionales como el filtrado de rutas inversas (reverse path filtering, `rp_filter` en Linux) que ayuda a descartar paquetes cuya IP de origen no es coherente con la interfaz por la que llegaron, dificultando el spoofing de direcciones internas de la propia red.

---

## 8. Como resuelve un servicio como Cloudflare el problema de bloquear a toda una red que sale bajo una unica IP publica compartida (NAT)

El problema de fondo es que, detras de un NAT de gran escala (una universidad, un ISP movil, una oficina corporativa), miles de usuarios reales comparten una sola IP publica visible desde el exterior. Un bloqueo binario por IP en ese escenario penalizaria a todos los usuarios legitimos junto con el atacante, un efecto colateral inaceptable a escala de un proveedor de proteccion como Cloudflare.

La solucion no pasa por bloqueos absolutos (`DROP` categorico), sino por mecanismos de validacion de cliente que discriminan por comportamiento en lugar de por identidad de red. Estos sistemas despliegan desafios en el navegador —ejecucion de JavaScript que un script automatizado normalmente no procesa, resolucion de un CAPTCHA, o verificacion de las caracteristicas del entorno de ejecucion (fingerprinting del navegador, tiempos de respuesta, comportamiento del raton)— antes de conceder acceso pleno al recurso solicitado. Un navegador real, operado por una persona, completa ese desafio sin friccion perceptible; un script o bot que solo emite peticiones HTTP crudas normalmente falla la prueba o ni siquiera la ejecuta.

De esta forma, el filtrado deja de basarse en "de donde viene el trafico" para basarse en "que tan probable es que este trafico provenga de un humano usando un navegador real", lo que permite proteger el servicio sin sacrificar el acceso legitimo de miles de usuarios que, por accidente de arquitectura de red, comparten una misma direccion IP publica.

---

## 9. Si el atacante envia 100,000 peticiones por segundo contra index.html en lugar de db.sql, seguiria siendo efectivo el script de mitigacion actual

No completamente, y el motivo revela una limitacion estructural del enfoque basado en firma de contenido especifico.

La regla de Capa 7 implementada busca exclusivamente la cadena `db.sql` dentro del contenido de la peticion. Un ataque redirigido contra `index.html`, un recurso legitimo y de acceso constante, simplemente no contiene esa cadena, por lo que pasaria la inspeccion del modulo `string` sin ser detectado. La defensa fue diseñada para un patron de exfiltracion muy especifico, no para un ataque volumetrico generico contra cualquier recurso publico.

A esto se suma un problema adicional si el atacante utiliza conexiones HTTP persistentes (Keep-Alive): una vez que una conexion TCP logra establecerse, el atacante puede enviar miles de peticiones HTTP sucesivas sobre esa misma conexion sin necesidad de abrir nuevos handshakes SYN. Como la regla de rate limiting del script opera sobre el flag SYN (`--syn --dport 80`), esas peticiones adicionales dentro de una conexion ya aceptada no vuelven a pasar por el limitador de tasa, dejando efectivamente sin proteccion ese vector.

La solucion pasa por trasladar parte del control desde la capa de red hacia la capa de aplicacion. Herramientas como `mod_evasive` para Apache permiten limitar el numero de peticiones por segundo que una misma IP puede realizar contra cualquier recurso, independientemente de si abre una conexion nueva o reutiliza una existente. De forma complementaria, un proxy inverso o un balanceador con capacidades de limitacion de tasa a nivel HTTP (por ejemplo, `limit_req` en Nginx) permite aplicar controles mas granulares por ruta, por metodo o por patron de comportamiento, cerrando la brecha que un filtro de firma estatica como el implementado no puede cubrir por diseño.

---

## 10. Para automatizar este diagnostico antes de que el servidor caiga, que herramienta se implementaria y que metrica se monitorearia

El objetivo de una solucion de observabilidad no es reaccionar despues de que el servicio ya esta degradado, sino detectar la tendencia mientras aun hay margen de accion, lo cual requiere metricas continuas y alertamiento basado en umbrales, no revision manual puntual.

Una arquitectura razonable combinaria Prometheus como motor de recoleccion y almacenamiento de series temporales, junto con Node Exporter instalado en el servidor para exponer metricas de sistema operativo (uso de CPU, memoria, I/O de disco, y contadores de red a nivel de kernel), y Grafana como capa de visualizacion para construir paneles que muestren la evolucion de esas metricas en tiempo real. Esta combinacion permite ver no solo el estado actual, sino la velocidad de cambio, lo que es determinante para diferenciar un pico de trafico normal de un ataque en curso.

Las metricas prioritarias a vigilar serian dos, elegidas precisamente porque fueron las que revelaron el ataque durante el analisis manual del incidente. La primera es el numero de sockets en estado `SYN_RECV`, obtenible mediante `ss -ant | grep -c SYN-RECV`, ya que su crecimiento sostenido es la señal mas directa de un SYN Flood en curso, antes incluso de que el ancho de banda se vea comprometido. La segunda es el porcentaje de espera de I/O (`iowait`) reportado por `iostat`, que permite detectar si el cuello de botella se esta desplazando hacia el subsistema de almacenamiento, un indicio de que el servidor podria estar a punto de perder su capacidad de registrar logs.

Sobre esa base, Alertmanager (el componente de alertamiento nativo del ecosistema Prometheus) se configuraria con una regla que dispare una notificacion cuando el conteo de conexiones `SYN_RECV` supere un umbral definido (por ejemplo, 100 conexiones) de forma sostenida durante mas de un minuto, evitando falsos positivos por picos momentaneos. Esa alerta se enrutaria hacia un canal operativo de respuesta rapida, como un webhook de Slack o un bot de Telegram, permitiendo que el equipo de infraestructura active la mitigacion (o que un script de automatizacion la active por si mismo, como se describe en la seccion de automatizacion preventiva del informe original) antes de que el servicio llegue al punto de indisponibilidad total.

---

## Nota final

Estas respuestas amplian el razonamiento tecnico detras de cada decision de mitigacion, pero no sustituyen la validacion practica en un entorno de laboratorio controlado. Cualquier regla de iptables, script de automatizacion o umbral de alerta debe probarse primero en un entorno aislado antes de desplegarse contra trafico de produccion.
