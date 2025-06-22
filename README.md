# Moonlight mDNS Sniffer (PSVita & Windows)

**Autor:** AorsiniYT (2025)

---

Sniffer UDP mDNS multiplataforma para detectar servicios Moonlight/Sunshine (GameStream) en la red local. Modular, fácil de integrar y sin dependencias externas.

- **PSVita:** API tipo librería (`udp_sniffer_vita.h`), callback por detección, resultados en pantalla y consola.
- **Windows:** API modular (`udp_sniffer_win.h`), callback, ejemplo de uso incluido.

---

## Build rápido

```sh
# PSVita (VPK y despliegue)
./maketest
# Windows (MinGW, ejecutable en build_win/)
./maketest win
```

---

## Uso básico (ambas plataformas)

```c
// PSVita: #include "udp_sniffer_vita.h"
// Windows: #include "udp_sniffer_win.h"

void moonlight_found(int idx, const char* host, const char* pcname, const char* ip, int port) {
    // ...
}

// Registra el callback y llama periódicamente a poll
udp_sniffer_*_set_callback(moonlight_found); // *_vita o *_win
udp_sniffer_*_init(); // Solo Windows
while (1) {
    udp_sniffer_*_poll();
    // ...
}
```

---

## ¿Qué hace?
- Solo detecta Moonlight/Sunshine (`_nvstream._tcp.local`).
- Callback solo si hay host, nombre PC, IP y puerto.
- Sin dependencias mdns externas.

---

## Créditos
- Desarrollo: **AorsiniYT**

---

MIT o similar. ¿Port a otra plataforma? ¡Pídelo!
