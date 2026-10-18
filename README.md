# Sandboxie-Plus Unlocker

<p align="center">
  <img src="https://img.shields.io/badge/Windows-10_%7C_11_x64-0078d6?logo=windows&logoColor=white" alt="Windows 10 / 11 x64" />
  <img src="https://img.shields.io/badge/C-MSVC_2022-555555?logo=c&logoColor=white" alt="C" />
  <img src="https://img.shields.io/github/v/release/CriDos/sandboxie_unlocker?label=Release" alt="Release" />
  <img src="https://img.shields.io/github/actions/workflow/status/CriDos/sandboxie_unlocker/ci.yml?label=CI" alt="CI" />
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="MIT" />
</p>

> **EDUCATIONAL PURPOSE ONLY.** This project is a reverse-engineering research
> artifact intended solely for educational and security-research use. It
> demonstrates kernel-level ECDSA key replacement, code-signing bypass, and
> driver IOCTL exploitation in a controlled lab environment. Do **not** use
> this to circumvent licensing in any commercial or production deployment.
> The authors take no responsibility for misuse.

Full kernel-level certificate unlock for Sandboxie-Plus **1.17.x–1.18.x** (tested on 1.17.9, 1.18.0, 1.18.2, 1.18.7 and 1.18.8) via a single `version.dll` proxy. No test-signing, no files needed in the install directory — everything is embedded in one DLL.

**Windows x64 only** (the embedded kernel driver is 64-bit and the module enumeration uses x64 struct layouts). Tested on:

| OS | Build | Sandboxie-Plus |
|----|-------|----------------|
| Windows 10 Pro 22H2 | 19045.6691 | 1.18.8 |
| Windows 11 24H2 | 26100 | 1.17.9 – 1.18.8 |

The self-map base lookup is independent of the Windows build: it was cross-checked against Microsoft public symbols on 19045 and 26100, where the global it picks is `nt!MmPteBase` on both.

## How it works

Sandboxie-Plus uses ECDSA P-256 to validate supporter certificates. The public key is hardcoded in `SbieDrv.sys` (`KphpTrustedPublicKey`). Without a valid certificate, security features are enforced by the kernel driver — processes are killed after 5 minutes or terminated immediately.

This tool replaces the public key in the running kernel with a freshly generated keypair, writes a self-signed `Certificate.dat`, and re-signs all `.exe.sig` files so SandMan's integrity check passes.

1. `version.dll` placed next to `SandMan.exe` — Windows loads it before SandMan initializes, and all 17 exports are forwarded to the real `System32\version.dll` via lazy-resolved function pointers
2. A background thread stages the embedded driver (Dell-signed `dbutil_2_3.sys`, CVE-2021-21551) to `%WINDIR%\Temp` with a restrictive DACL, loads it as a service, finds `SbieDrv.sys` in the kernel module list and the ECDSA key RVA in the driver image on disk
3. Generates an ECDSA P-256 keypair via Windows CNG and overwrites the public key in kernel memory (1.18.7+ keeps the key read-only — see [Kernel key layout](#kernel-key-layout))
4. Writes a self-signed `Certificate.dat` (type: ETERNAL, all features), backs up and re-signs all `.exe.sig` files
5. Asks the driver to re-read the certificate — SbieDrv caches it from driver load time, so the swap alone would only take effect after a service restart — and logs whether the certificate is now active
6. SandMan reads the certificate from the driver — full unlock

At startup the DLL also logs an OS security-state snapshot (vulnerable-driver blocklist flags, Smart App Control, VBS/HVCI, Secure Boot, Driver Verifier, active WDAC policies) to `version_hook.log`, so blocked loads can be diagnosed from the log alone.

## Usage

**End users:** download the release zip, extract `version.dll` and `unlock.bat` to the same folder, run `unlock.bat` as administrator, pick **[1] Install Hook**. You can also just copy `version.dll` into the Sandboxie-Plus installation folder directly.

**From source:** clone the repo and run `_build.bat` (requires VS 2022+ Build Tools with the C++ workload and Windows SDK 10 — auto-detected via `vswhere.exe`). Output lands in `dist/`, then run `dist\unlock.bat`. No external dependencies — links against `bcrypt.lib`, `user32.lib`, `advapi32.lib`, `ntdll.lib`; the driver is embedded as a C byte array (`driver_bin.h`).

After a reboot the kernel patch is gone, but the hook stays in the installation directory and applies it again on the next SandMan start — no service reconfiguration and no second start needed. Install Hook is only required to install or refresh the hook, or to force a SandMan restart. The keypair saved in `keypair.dat` is reused, so the certificate and `.sig` files do not need regeneration.

## Driver blocklist

Windows 11 22H2+ (including 24H2) ships the **Microsoft Vulnerable Driver Blocklist** enabled by default. It blocks the embedded Dell-signed helper driver (`dbutil_2_3.sys`) at load time with `StartService` error `0x800B010C`, even though the Authenticode signature is valid — the blocklist checks the binary hash, not the signature.

Windows 10 keeps the same switch (`CI\Config\VulnerableDriverBlocklistEnable`) but ships it off, so the helper driver loads there without any change.

To use the unlocker on a machine where the blocklist refuses the driver:

1. Run `dist\unlock.bat` as administrator, option **[4] Disable Vulnerable Driver Blocklist** (or set it manually):
   ```
   reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f
   ```
2. **Reboot** — the change only takes effect after a restart.
3. Run Install Hook ([1]) as usual.

Restore the default protection at any time with option **[5]** (also requires a reboot).

Notes:

- If **Memory Integrity (VBS/HVCI)** is turned on, the blocklist is enforced unconditionally — the registry flag is ignored. Disable Memory Integrity first (`Windows Security` → `Device security` → `Core isolation` → `Memory integrity` off, reboot), then disable the blocklist.
- Smart App Control and WDAC policies, if active, are separate mechanisms; their state is reported in `version_hook.log`.

## Removing the hook

Remove Hook mirrors the official installer stop sequence: kills GUI processes, runs `KmdUtil scandll_silent` to terminate sandboxed processes, stops `SbieSvc` and polls for STOPPED, then unloads `SbieDrv` via `KmdUtil stop SbieDrv` (which calls `API_UNLOAD_DRIVER` — requires `Api_UseCount == 1`, i.e. SbieSvc fully stopped). It restores the original `.sig` files from `sig_backup/`, deletes generated files, resets the safe-fail state and restarts services. SandMan reloads `SbieDrv.sys` with the original key — no reboot required.

A backup is only useful while it matches the installed executables, so it is
maintained, not written once: it is refreshed whenever the installed `.sig`
is still vendor-signed (fresh install, or after a Sandboxie repair), a valid
backup is kept as-is, and a stale one is reported in `version_hook.log` —
repair Sandboxie once and run Install Hook again to refresh it before
removing the hook.

## Crash safety

Safe-fail state in `HKCU\SOFTWARE\sandboxie_unlocker` survives reboots. The DLL marks an active unlock attempt before the risky work starts; if the previous attempt was interrupted, the next run increments `fail_count`. After 3 interrupted attempts, the DLL enters safe mode — a transparent proxy without kernel unlock.

Controlled failures clear the active marker without incrementing `fail_count`. A successful unlock resets both values. Manual reset via `unlock.bat` option [3].

## Technical details

### Certificate format

```
NAME: HardTest
DATE: 25.06.2026
TYPE: ETERNAL
SOFTWARE: Sandboxie-Plus
OPTIONS: SBOX,EBOX,NETI,DESK
SIGNATURE: <base64 raw R||S ECDSA P-256>
```

- UTF-8, no BOM
- SHA-256 of `name:value` pairs (excluding SIGNATURE line)
- Signature: 64-byte raw R||S (not DER), matches `BCryptVerifySignature`

### Kernel key layout

72-byte BCRYPT ECCPUBLIC_BLOB at RVA `0x39590` in `.data` for 1.17.x - 1.18.2:

| Offset | Field | Value |
|--------|-------|-------|
| 0 | Magic | `ECS1` (4 bytes) |
| 4 | KeySize | `0x20` (4 bytes, LE) |
| 8 | X | 32 bytes, big-endian |
| 40 | Y | 32 bytes, big-endian |

SbieDrv 1.18.7 declares the key `const`, moving it into the read-only
`.rdata` section (RVA `0x330C0`).  The helper driver's memmove has no SEH, so
writing there directly is the 0xBE bugcheck users hit on 1.18.7+.  The
unlocker therefore checks the key's section flags in `SbieDrv.sys` on disk:
a writable section is written directly, a read-only one through a writable
alias of the same physical frame (the PTE of a throwaway user page is
repointed at it, so the original read-only mapping and its TLB entries stay
untouched).  The page-table self-map base is randomized per boot since
Windows 10 RS1.  It is found the same way on every build: getting from an
address to its PTE is always a shift plus a scale, so the code of the mapped
ntoskrnl is scanned for references to globals that are followed by `shr 9` /
`shl 3` / `lea *8`.  Those references vote for the global, and the busiest
global whose value has the self-map shape (canonical, 64 GB aligned, PML4
index in the kernel half) is the base - no compiler idiom is matched, so a
new register or a `lea` does not break the lookup.  Finding nothing is a
controlled refusal, never a guess, and the base is validated against an
owned page before any write.
Pre-RS1 kernels use the fixed classic base (gated on the OS build), 5-level
paging (LA57) is refused, and on Memory Integrity the alias PTE is writable
but non-executable to stay within the hypervisor's W^X rule.

### Driver IOCTLs (dbutil_2_3.sys, METHOD_BUFFERED)

| IOCTL | Function |
|-------|----------|
| `0x9B0C1EC4` | Kernel memory read (`memmove`) |
| `0x9B0C1EC8` | Kernel memory write (`memmove`) |

Buffer: `[cookie:8][base:8][offset:8][data:N]` — cookie=0 bypasses driver cookie check.

The driver also exposes (unused here) physical memory read/write via
`MmMapIoSpace` (`0x9B0C1F44` / `0x9B0C1F40`), a contiguous-buffer alloc/free
pair (`0x9B0C1EC0` / `0x9B0C1ECC`) and vendor status calls — an option only
if a future SbieDrv build hides the key where a PTE alias cannot reach.

No SEH in driver — invalid page causes BSOD. Key RVA validated via `ECS1` magic before write.

## Source layout

```
sandboxie_unlocker/
├── dist/              # unlock.bat + build output
│   └── unlock.bat     # Install / remove / reset menu
├── src/
│   ├── version_hook.c   # DLL proxy + unlock thread + crash safety
│   ├── driver_bin.h     # dbutil_2_3.sys as C byte array (embedded, 14840 bytes)
│   ├── ecrypto.h        # ECDSA P-256 via CNG (bcrypt.dll), keypair save/load
│   ├── fileio.h         # Read whole file + stale staging cleanup
│   ├── kdrv.h           # Kernel R/W via IOCTLs, service management
│   ├── pagemap.h        # Writes into read-only pages: PTE alias + nt!MmPteBase locator
│   ├── kmod.h           # NtQuerySystemInformation: kernel module enumeration
│   ├── pesearch.h       # PE parsing: find key RVA, store original key
│   ├── certgen.h        # Certificate.dat generation + .sig re-signing
│   ├── safety.h         # Safe-fail state machine (interrupted-attempt counter)
│   ├── hostguard.h      # Host process gate (unlock only inside SandMan.exe)
│   ├── sysguard.h       # OS security-state snapshot (blocklist, VBS/HVCI, WDAC, ...)
│   ├── sbieapi.h        # Certificate reload + licence state via SbieDll
│   ├── log.h            # File logger (version_hook.log)
│   ├── version.h        # Version + author metadata
│   └── version.rc       # PE version info resource
├── tests/
│   ├── testfw.h         # Minimal test framework (groups, PASS/FAIL/SKIP, filter)
│   ├── selftest.c       # Unit + filesystem tests (crypto, PE, cleanup, DACL, ...)
│   ├── proxytest.c      # Loads the built DLL: export forwarding, host filter
│   └── ptelive.c        # Admin live check: read-only page write via alias
├── _tests.bat         # Builds and runs the whole suite, non-zero exit on failure
├── _ptelive.bat       # Builds and runs the admin-only PTE live check
├── _build.bat         # MSVC build script (outputs to dist/)
├── _msvc_env.bat      # Shared toolchain discovery for the three scripts above
├── .github/workflows/ # CI + release automation
├── LICENSE            # MIT
└── README.md
```

## Testing

`_tests.bat` builds and runs the suite (MSVC, no external dependencies). It is safe on any machine: kernel and live-Sandboxie paths are never exercised. Started without arguments (e.g. double-click) the console stays open after the run; pass any argument (CI) to exit immediately.

- `selftest.c` — base64 vectors, ECDSA sign/verify round-trips via CNG, keypair persistence (blob + file with admin-DACL awareness), certificate body hash, PE offset→RVA mapping on a real file plus a synthetic SbieDrv-like fixture (original key, patched fallback, multi-magic, truncated key, bogus headers, writable/read-only section reporting, refusal of a key blob that crosses a section boundary), section-table offset arithmetic, fileio edge cases, logger append + rotation at the size cap, stale staging cleanup, certificate layout, restrictive DACL behavior per token elevation, safe-fail state machine, host-filter predicate, staged-driver byte verification, PTE alias math, the self-map base search and its reference ranking, `.sig` backup policy, SbieDll-backed calls without Sandboxie, kernel module lookup smoke.
- `proxytest.c` — loads the built `dist\version.dll` into a non-SandMan process: all 17 exports resolvable, version-resource query round-trips through the real version.dll (FileVersion == build version), failure hosts degrade gracefully, host filter logs the skip line, host safe-fail registry state untouched.
- `ptelive.c` (`_ptelive.bat`) — admin-only live check of the read-only-page write path, not part of the suite: stages and loads the embedded helper driver, locates and validates `nt!MmPteBase`, then writes through a page alias into a page this process made read-only and confirms the page is still read-only for user code.

CI runs the suite on every push (`.github/workflows/ci.yml`).

## Runtime artifacts

| File | Description |
|------|-------------|
| `%WINDIR%\Temp\sbie_unlock_<pid>.sys` | Staged kernel driver; restrictive DACL, locked while mapped, cleaned on later runs |
| `Certificate.dat` | Self-signed certificate (ETERNAL, all features) |
| `keypair.dat` | Saved ECDSA P-256 private key (reused after reboot) |
| `sig_backup/` | Original `.exe.sig` files (refreshed while the installed pair is still vendor-signed) |
| `version_hook.log` | Debug log with timestamps (rotated to `.old.log` at 1 MB) |
