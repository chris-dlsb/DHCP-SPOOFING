# 🛡️ PoC: DHCP-Spoofing-Rogue-Server-

![Status](https://img.shields.io/badge/Estado-Finalizado-green)
![Python](https://img.shields.io/badge/Python-3.x-blue)
![Scapy](https://img.shields.io/badge/Library-Scapy-yellow)

## 📋 Descripción Técnica
Este repositorio contiene una Prueba de Concepto (PoC) desarrollada en Python utilizando el framework **Scapy**. 
**Objetivo:** Desplegar un servidor DHCP no autorizado para realizar un ataque de Man-in-the-Middle (MitM). La herramienta responde a las peticiones DHCP DISCOVER más rápido que el servidor legítimo, asignando al cliente una puerta de enlace (Gateway) controlada por el atacante (10.14.14.6) y servidores DNS maliciosos.

El script demuestra vulnerabilidades críticas en la Capa 2 (Enlace de Datos) del modelo OSI, permitiendo auditar la seguridad de la infraestructura de red conmutada.

## 🗺️ Topología y Escenario

El entorno de pruebas fue desplegado utilizando **GNS3** con emulación de hardware Cisco (IOU) y máquinas virtuales atacantes.

| Dispositivo | Rol | IP / Interfaz | Detalles |
| :--- | :--- | :--- | :--- |
| **Kali Linux** | Atacante | `10.14.14.6` / `eth0` | Origen de la inyección de paquetes. |
| **Cisco router L3** | Gateway (Víctima) | `10.14.14.1` / `e0/0` | Router/Switch de borde. |
| **Cisco IOU L2** | Switch de Acceso | N/A (Capa 2) | Dispositivo donde se inyecta tráfico. |
| **VLAN** | Segmento | VLAN 1 (Nativa) | Red `10.14.14.0/24`. |

### Diagrama Lógico
<img width="428" height="402" alt="Screenshot 2026-02-17 105444" src="https://github.com/user-attachments/assets/b7cd4ad5-a369-4287-93e2-464882c1a3f7" />


## ⚙️ Requisitos y Dependencias

Para ejecutar esta herramienta se requiere:
* **Sistema Operativo:** Linux (Kali Linux, Parrot OS, Ubuntu).
* **Python:** Versión 3.8 o superior.
* **Permisos:** Acceso **Root** (sudo) es mandatorio para la manipulación de sockets raw.
* **Librerías:**
    ```bash
    pip install scapy
    ```

## 🚀 Instalación y Uso

1.  **Clonar el repositorio:**
    ```bash
    git clone [[https://github.com/tu-usuario/nombre-repo.git](https://github.com/tu-usuario/nombre-repo.git)](https://github.com/chris-dlsb/DHCP-Spoofing-Rogue-Server-.git)
    cd nombre-repo
    ```

2.  **Ejecutar el script:**
    ```bash
    sudo python3 dhcp_spoofing.py
    ```

### Parámetros Configurados
* **Interfaz:** `eth0` (Hardcoded o por argumento, según tu script).
* **Target:** Broadcast `ff:ff:ff:ff:ff:ff` o Multicast STP `01:80:c2:00:00:00`.

## 📸 Evidencia de Funcionamiento (PoC)

**1. Ejecución del Ataque:**
<img width="556" height="130" alt="image" src="https://github.com/user-attachments/assets/f9bccbb3-5d8a-4c58-bd8c-50c811fdd261" />

##--------------------------------------------------------------

**2. Impacto en la Víctima:**
<img width="723" height="185" alt="image" src="https://github.com/user-attachments/assets/23e2acc5-b4d1-4063-88f7-e8fda7441ae5" />


## 🛡️ Medidas de Mitigación

Para proteger la infraestructura contra este vector de ataque, se recomienda implementar:

[MITIGACIONES ESPECÍFICAS]:

DHCP Snooping: Configurar todos los puertos de acceso como "Untrusted" (No confiables) y solo el puerto del servidor legítimo como "Trusted". Esto bloqueará cualquier paquete DHCP OFFER proveniente de puertos de usuarios.

Source Guard: Verificar que la IP de origen coincida con la asignada por el DHCP legítimo.

---
*Descargo de Responsabilidad: Este software fue creado únicamente con fines académicos para la asignatura de Ciberseguridad del ITLA. El autor no se hace responsable del mal uso de esta herramienta.*

**Autor:** Cristopher De Los Santos  
**Matrícula:** 2024-1414
