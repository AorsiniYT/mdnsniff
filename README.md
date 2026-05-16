# Moonlight/Sunshine mDNS UDP Sniffer for PSVita, Wii U, and Windows

## Author
AorsiniYT (2025)

---

## Description
This project implements a cross-platform mDNS UDP sniffer to detect Moonlight/Sunshine (GameStream) services on the local network. It allows discovering hosts compatible with GeForce Experience or Sunshine, showing their host, PC name, IP, and port, on PSVita (VitaSDK), Wii U (WUT/CafeOS), and Windows (MinGW).

- **PSVita:** The sniffer is modular, easy to integrate as a library, and notifies detections via callback. Results are shown on screen and console.
- **Wii U:** Features an optimized UDP sniffer using the native `nsysnet` stack, properly draining packets without blocking the main OS thread.
- **Windows:** Modular implementation, ready to be integrated as a library in other projects, with an included usage example.

If you need it implemented on another platform, let me know and I will do it.

---

## Project Structure

- `udp_sniffer_vita.c/h`  — mDNS Sniffer for PSVita, modular API and callback.
- `udp_sniffer_wiiu.c/h`  — mDNS Sniffer for Wii U (optimized for nsysnet).
- `udp_sniffer_win.c/h`   — mDNS Sniffer for Windows (modular, with callback and usage example).
- `main.c`                — Cross-platform integration example (Vita/Wii U/Win).
- `maketest`              — Build and deployment script for Vita/Windows.
- `makefast`              — Build script tailored for fast Wii U (WUHB/RPX) builds.
- `toolchain-mingw.cmake` — Toolchain to compile on Windows with MinGW.
- `CMakeLists.txt`        — Cross-platform CMake configuration.

---

## Using the Build Scripts

### PSVita / Windows
```sh
# Compile and deploy on PSVita (default)
./maketest
# or explicitly
./maketest vita

# Compile for Windows (MinGW, executable in build_win/)
./maketest win
```

### Wii U
```sh
# Compile and build the WUHB bundle for Wii U
./makefast wiiu
```

- For PSVita, the script compiles, packages the VPK, and sends it via FTP to the console.
- For Wii U, `makefast wiiu` uses the WUT toolchain to generate a `.rpx` and `.wuhb` bundle in `build_wiiu/`.
- For Windows, it generates the executable in `build_win/` using the MinGW toolchain.

---

## Prerequisites

To use the build scripts, you need to have the following installed:

### 1. VitaSDK (to compile for PSVita)

- Install basic dependencies:
  ```sh
  sudo apt update && sudo apt install git cmake build-essential python3
  ```
- Download and install VitaSDK:
  ```sh
  git clone https://github.com/vitasdk/vdpm.git
  cd vdpm
  ./bootstrap-vitasdk.sh
  export VITASDK="$HOME/vitasdk"
  export PATH="$VITASDK/bin:$PATH"
  # You can add the two previous lines to your ~/.bashrc so they are always loaded
  ```
- Install required VitaSDK packages:
  ```sh
  vdpm install zlib libpng freetype
  ```

### 2. WUT (to compile for Wii U)

- Follow the devkitPro getting started guide to install `wut` and the `wiiu-dev` packages.
- Ensure `/opt/devkitpro/portlibs/wiiu/bin` is in your PATH.

### 3. MinGW and Windows dependencies

- Install MinGW and necessary tools:
  ```sh
  sudo apt install mingw-w64 cmake make gcc-mingw-w64 g++-mingw-w64
  ```
- No additional external libraries are required; `toolchain-mingw.cmake` is ready to compile the modular sniffer for Windows.

---

## Library Integration

### PSVita
1. Include `udp_sniffer_vita.h` in your project.
2. Register your callback with `udp_sniffer_vita_set_callback()`.
3. Call `udp_sniffer_vita_poll()` periodically in your main loop.

### Wii U
1. Include `udp_sniffer_wiiu.h` in your project.
2. Call `udp_sniffer_wiiu_init()` once during startup.
3. Register your callback with `udp_sniffer_wiiu_set_callback()`.
4. Call `udp_sniffer_wiiu_poll()` periodically in your main loop.
5. Clean up with `udp_sniffer_wiiu_deinit()` when exiting.

### Windows
1. Include `udp_sniffer_win.h` in your project.
2. Register your callback with `udp_sniffer_win_set_callback()`.
3. Call `udp_sniffer_win_init()` once before use.
4. Call `udp_sniffer_win_poll()` periodically in your main loop.
5. Call `udp_sniffer_win_deinit()` when finished.

---

## What does it detect?
- Only Moonlight/Sunshine mDNS services (`_nvstream._tcp.local`).
- Properly associates PTR, SRV, and A records.
- Deduplicates and only notifies when all data is present.
- The callback is invoked only when host, PC name, IP, and port are fully populated.
- The result is printed uniformly across all platforms.

---

## Credits
- Development and adaptation: **AorsiniYT**
- Cross-platform implementation scaled from a standard Windows mDNS UDP sniffer logic, adapted to PSVita (VitaSDK) and Wii U (WUT/nsysnet).

---

## Notes
- The code is professional, modular, and easy to integrate into other projects (e.g., Moonlight Vita / Moonlight Wii U).
- The sniffers do not depend on bloated external mDNS libraries.
- The `maketest` and `makefast` scripts automate the entire build and deployment flow.
- The Windows executable only compiles the modular sniffer, without unnecessary dependencies.

---

## License
MIT or similar. You can use, modify, and share this code as long as you credit the author.
