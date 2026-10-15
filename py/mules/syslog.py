#!/usr/bin/python
# -*- coding: utf-8 -*-

# syslog.py: independent worker process as a syslog server
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import asyncio
import collections
import functools
import socket
import time
import logging
import re
import os
import selectors
import shutil
import struct
import subprocess
import sys
import threading
import config
from concurrent.futures import ThreadPoolExecutor

from libs.db import db_device, db_AA, db_events, db_sysconfig, db_budget
from libs.db.db import database, release_db_connection, tune_process_db_pool, TRANSIENT_DB_ERRORS
from libs import util, logsetup
try:
    import uwsgi
except ImportError:
    uwsgi = None
try:
    from libs import utilpro, syslog_regex_pro
    ISPRO=True
except ImportError:
    ISPRO=False
    pass

logsetup.init_logging()   # same log output in the free tier (Pro gets it via libs.webutil)
log = logging.getLogger("SYSLOG")

# Every syslog message is kept: nothing is dropped when busy, it waits in the backlog.
SYSLOG_WORKERS = 256           # messages processed concurrently (always different devices); coroutines,
                               # so routers waiting on a slow API call never hold up the others
API_THREADS_MIN, API_THREADS_MAX = 4, 16   # router API calls (local-user list, syslog re-config):
API_DEVICES_PER_THREAD = 100               # one thread per 100 devices, within these limits
USER_FETCH_BACKOFF = 60        # after a failed local-user fetch, don't ask that router again for this long
DB_RETRY_SECONDS = 300         # keep retrying a DB call this long on pool / connection errors
BACKLOG_WARN = 5000            # backlog size that is reported as a warning
STATS_INTERVAL = 60
SOCKET_RCVBUF = 8 * 1024 * 1024
RECV_BATCH = 2000              # datagrams handed from the receiver thread to the event loop at once
READER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "syslog_reader.py")
READER_HDR = struct.Struct("!dIHH")     # syslog_reader.py record: receipt time, IPv4, port, length
BIND_RETRY_SECONDS = 15        # a previous mule's reader may hold port 5014 for a moment after a restart
READER_READY_TIMEOUT = 15      # seconds to wait for a started reader to read the socket
# Several syslog mules (PYSRV_SYSLOG_MULES, opt-in): mule k > 0 receives its routers' messages from
# the reader of mule 0 on this Unix socket
SHARD_SOCKET_DIR = os.getenv("SYSLOG_SHARD_DIR", "/tmp")
UNKNOWN_IP_TTL = 30            # cache "no device with this IP" so unknown senders don't hit the DB

stats = {"received": 0, "processed": 0, "failed": 0, "db_retries": 0}
_executors = {}
_last_retry_warning = {"at": 0.0}


def _get_executor(kind):
    """'db': one thread per pooled connection of this process; 'api': router API calls.
    Threads in both release their DB connection after every job (see release_db_connection)."""
    ex = _executors.get(kind)
    if ex is None:
        if kind == "db":
            tune_process_db_pool("syslog")
            size = max(1, getattr(database, "_max_connections", 3) or 3)
            ex = ThreadPoolExecutor(max_workers=size, thread_name_prefix="syslog-db")
            log.info(f"Syslog DB executor: {size} thread(s)")
        else:
            ex = ThreadPoolExecutor(max_workers=api_threads(0), thread_name_prefix="syslog-api")
        _executors[kind] = ex
    return ex


def api_threads(devices):
    return max(API_THREADS_MIN, min(API_THREADS_MAX, devices // API_DEVICES_PER_THREAD))


def _device_count():
    return db_device.Devices.select().count()


@release_db_connection
def _released(fn, *args, **kwargs):
    return fn(*args, **kwargs)


async def run_db(fn, *args, **kwargs):
    """Run a blocking DB call in the syslog DB executor. Pool / connection errors are retried
    for DB_RETRY_SECONDS so a busy or restarting database does not lose the event."""
    loop = asyncio.get_running_loop()
    call = functools.partial(_released, fn, *args, **kwargs)
    deadline = time.time() + DB_RETRY_SECONDS
    delay = 0.5
    while True:
        try:
            return await loop.run_in_executor(_get_executor("db"), call)
        except TRANSIENT_DB_ERRORS as e:
            if time.time() + delay > deadline:
                raise
            stats["db_retries"] += 1
            now = time.time()
            if now - _last_retry_warning["at"] >= 30:
                _last_retry_warning["at"] = now
                log.warning(f"Syslog DB call {getattr(fn, '__name__', fn)} failed ({str(e).strip()[:120]}); retrying")
            await asyncio.sleep(delay)
            delay = min(delay * 2, 10)


async def run_api(fn, *args, **kwargs):
    """Run a blocking router API call outside the DB executor so slow routers never stall DB work."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_get_executor("api"), functools.partial(_released, fn, *args, **kwargs))


class OrderedDispatcher:
    """Runs messages concurrently across devices but strictly in arrival order per device
    (link down before link up, login before logout). Nothing is dropped: the backlog is
    limited only by memory and is reported by the stats line."""

    def __init__(self, handler, workers):
        self._handler = handler
        self._workers = workers
        self._ready = asyncio.Queue()
        self._pending = {}
        self._tasks = []
        self.backlog = 0

    def start(self):
        self._tasks = [asyncio.create_task(self._run()) for _ in range(self._workers)]

    def submit(self, key, item):
        self.backlog += 1
        dq = self._pending.get(key)
        if dq is not None:
            dq.append(item)
            return
        self._pending[key] = collections.deque([item])
        self._ready.put_nowait(key)

    async def _run(self):
        while True:
            key = await self._ready.get()
            dq = self._pending[key]
            item = dq.popleft()
            try:
                await self._handler(*item)
            except Exception as e:
                log.exception(f"Syslog worker error: {e}")
            finally:
                self.backlog -= 1
                if dq:
                    self._ready.put_nowait(key)   # back of the line: one busy device can't starve others
                else:
                    del self._pending[key]


class UdpReceiver(threading.Thread):
    """Reads the syslog socket in its own thread and hands the datagrams to the event loop in
    batches. asyncio's UDP transport reads ONE datagram per loop iteration, and an iteration also
    runs every ready worker step: under load (bursts, busy DB threads) the reads fall behind and
    the kernel drops datagrams when its socket buffer is full. This thread waits without holding
    the GIL and then drains the socket completely, so reading never waits for processing."""

    def __init__(self, loop, protocol, host, port, rcvbuf=SOCKET_RCVBUF):
        super().__init__(name="syslog-recv", daemon=True)
        self.loop, self.protocol = loop, protocol
        self.sock = _bind_udp(host, port, rcvbuf)
        self.sock.setblocking(False)
        self.port = self.sock.getsockname()[1]
        self._closing = threading.Event()

    def run(self):
        sel = selectors.DefaultSelector()
        sel.register(self.sock, selectors.EVENT_READ)
        try:
            while not self._closing.is_set():
                if not sel.select(timeout=1.0):
                    continue
                batch = []
                while len(batch) < RECV_BATCH:
                    try:
                        data, addr = self.sock.recvfrom(65535)
                    except (BlockingIOError, InterruptedError):
                        break
                    batch.append((data, addr, time.time()))
                if batch:
                    self.loop.call_soon_threadsafe(self.protocol.receive_batch, batch)
        except (OSError, ValueError, RuntimeError) as e:
            if not self._closing.is_set():
                log.error(f"Syslog receiver stopped: {e}")
        finally:
            sel.close()

    def close(self):
        self._closing.set()
        self.join(timeout=3)
        self.sock.close()


def _bind_udp(host, port, rcvbuf=SOCKET_RCVBUF):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Large receive buffer absorbs bursts (mass reboot / firmware rollout). The kernel caps it at
    # net.core.rmem_max; the effective size is logged so a too-small cap is visible.
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        effective = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        if effective < rcvbuf:
            log.warning(f"Syslog UDP receive buffer is {effective} bytes (wanted {rcvbuf}); "
                        f"raise net.core.rmem_max to absorb larger bursts")
    except OSError as e:
        log.warning(f"Could not set syslog UDP receive buffer: {e}")
    deadline = time.time() + BIND_RETRY_SECONDS
    while True:
        try:
            sock.bind((host, port))
            return sock
        except OSError as e:
            if time.time() > deadline:
                sock.close()
                raise
            log.warning(f"Syslog port {port} busy ({e}); retrying")
            time.sleep(1)


def get_syslog_shard_config():
    """(shard index, number of syslog mules). (0, 1) = one syslog mule: every normal installation.
    PYSRV_SYSLOG_MULES lists the syslog mule ids (uwsgi.ini order); SYSLOG_SHARD_INDEX /
    SYSLOG_TOTAL_SHARDS override it (tests, custom wrappers)."""
    env_shard, env_total = os.getenv("SYSLOG_SHARD_INDEX"), os.getenv("SYSLOG_TOTAL_SHARDS")
    if env_shard is not None and env_total is not None:
        try:
            return int(env_shard), max(1, int(env_total))
        except ValueError:
            pass
    cfg = getattr(config, "SYSLOG_MULES", "") or ""
    ids = [int(x) for x in str(cfg).replace(" ", "").split(",") if x.isdigit()]
    if len(ids) < 2 or uwsgi is None:
        return 0, 1
    try:
        mid = uwsgi.mule_id() if callable(getattr(uwsgi, "mule_id", None)) else int(getattr(uwsgi, "mule_id", 0) or 0)
    except Exception as e:
        log.warning(f"Could not read the uwsgi mule id: {e}")
        return 0, 1
    if mid not in ids:
        log.warning(f"PYSRV_SYSLOG_MULES={cfg} does not list this syslog mule ({mid}): running as the only one")
        return 0, 1
    # every listed id must be a syslog mule of uwsgi.ini: otherwise the reader would queue those
    # routers' messages for a mule that never comes. A wrong list -> one syslog mule (all routers).
    try:
        layout = db_budget._mule_list(getattr(uwsgi, "opt", {}) or {})
    except Exception:
        layout = []
    if layout:
        wrong = [i for i in ids if not (0 < i <= len(layout) and "syslog" in layout[i - 1])]
        if wrong:
            log.error(f"PYSRV_SYSLOG_MULES={cfg}: mule(s) {wrong} are not syslog mules in uwsgi.ini - "
                      f"ignoring it, the first syslog mule stores all syslog messages")
            return 0, 1
    return ids.index(mid), len(ids)


def shard_socket_path(shard):
    return os.path.join(SHARD_SOCKET_DIR, "mikrowizard-syslog-{}.sock".format(shard))


def _parse_records(buf, protocol, loop):
    """Hand the complete syslog_reader.py records in buf to the event loop; keep a partial one."""
    hdr = READER_HDR
    batch, off, end = [], 0, len(buf)
    while end - off >= hdr.size:
        ts, ip, port, n = hdr.unpack_from(buf, off)
        if end - off - hdr.size < n:
            break
        start = off + hdr.size
        batch.append((bytes(buf[start:start + n]), (socket.inet_ntoa(struct.pack("!I", ip)), port), ts))
        off = start + n
    del buf[:off]
    if batch:
        loop.call_soon_threadsafe(protocol.receive_batch, batch)


class ShardReceiver(threading.Thread):
    """Syslog mule k > 0 of several (PYSRV_SYSLOG_MULES): the reader process of mule 0 connects to
    this Unix socket and streams the messages of the routers assigned to this mule. While this
    mule restarts, the reader keeps them in memory and sends them after it reconnects."""

    def __init__(self, loop, protocol, shard):
        super().__init__(name="syslog-shard", daemon=True)
        self.loop, self.protocol, self.shard = loop, protocol, shard
        self.path = shard_socket_path(shard)
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.path)
        self.server.listen(1)
        self.server.settimeout(1.0)
        self.port = None
        self.sock = None
        self._closing = threading.Event()

    def run(self):
        while not self._closing.is_set():
            try:
                conn, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(1.0)
            log.info(f"Syslog shard {self.shard}: reader connected")
            buf = bytearray()
            try:
                while not self._closing.is_set():
                    try:
                        chunk = conn.recv(1 << 20)
                    except socket.timeout:
                        continue
                    if not chunk:
                        log.warning(f"Syslog shard {self.shard}: reader disconnected; waiting for it")
                        break
                    buf += chunk
                    _parse_records(buf, self.protocol, self.loop)
            except (OSError, RuntimeError) as e:
                if not self._closing.is_set():
                    log.error(f"Syslog shard {self.shard}: stream error: {e}")
            finally:
                conn.close()

    def close(self):
        self._closing.set()
        self.join(timeout=3)
        self.server.close()
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass


def _reader_python():
    # Inside uWSGI sys.executable can be the uwsgi binary
    if os.path.basename(sys.executable).startswith("python"):
        return sys.executable
    return shutil.which("python3") or "python3"


class ReaderProcessReceiver(threading.Thread):
    """Syslog UDP is read by syslog_reader.py, a separate process with its own GIL: it is never
    starved by this process' DB / API threads, so bursts are not dropped by the kernel even with
    the default socket buffer. It queues in memory and streams the datagrams here; this thread
    parses them and hands them to the event loop in batches. When this process is busy the data
    waits in the stream / the reader's memory - nothing is dropped. A reader that dies is restarted."""

    def __init__(self, loop, protocol, host, port, rcvbuf=SOCKET_RCVBUF, shard_paths=()):
        super().__init__(name="syslog-stream", daemon=True)
        self.loop, self.protocol = loop, protocol
        self.shard_paths = list(shard_paths)    # mules 1..N-1 of several syslog mules (opt-in)
        self.sock = _bind_udp(host, port, rcvbuf)
        self.port = self.sock.getsockname()[1]
        self._closing = threading.Event()
        self.proc = self.stream = None
        self._spawn()

    def _spawn(self):
        if self.stream is not None:
            self.stream.close()
        self.stream, child_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.proc = subprocess.Popen(
                [_reader_python(), READER_SCRIPT, str(self.sock.fileno()), str(child_end.fileno())] + self.shard_paths,
                pass_fds=(self.sock.fileno(), child_end.fileno()), close_fds=True)
        finally:
            child_end.close()
        # wait until the reader reads the socket (its first byte); until then the kernel buffer holds
        # the datagrams, so the window must stay short
        self.stream.settimeout(READER_READY_TIMEOUT)
        try:
            ready = self.stream.recv(1)
        except socket.timeout:
            ready = b""
        if ready != b"R":
            self.proc.kill()
            raise RuntimeError("syslog reader did not start")
        self.stream.settimeout(1.0)
        log.info(f"Syslog reader process started (pid {self.proc.pid})")

    def run(self):
        buf = bytearray()
        while not self._closing.is_set():
            try:
                chunk = self.stream.recv(1 << 20)
            except socket.timeout:
                continue
            except OSError as e:
                if self._closing.is_set():
                    break
                chunk = b""
                log.error(f"Syslog reader stream error: {e}")
            if not chunk:
                if self._closing.is_set():
                    break
                log.error(f"Syslog reader process exited (code {self.proc.poll()}); restarting it")
                buf.clear()
                time.sleep(1)
                try:
                    self._spawn()
                except Exception as e:
                    log.error(f"Could not restart the syslog reader: {e}")
                continue
            buf += chunk
            try:
                _parse_records(buf, self.protocol, self.loop)
            except RuntimeError:              # event loop closed: shutting down
                break

    def close(self):
        self._closing.set()
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.join(timeout=3)
        self.stream.close()
        self.sock.close()


def start_receiver(loop, protocol, host, port, shard=0, shards=1):
    """One syslog mule (default): reader process, in-process receiver thread as a fallback.
    Several (PYSRV_SYSLOG_MULES): mule 0 also hands the other mules their routers' messages;
    mules 1..N-1 receive them on their Unix socket."""
    if shards > 1 and shard > 0:
        receiver = ShardReceiver(loop, protocol, shard)
        receiver.start()
        return receiver
    paths = [shard_socket_path(k) for k in range(1, shards)]
    try:
        receiver = ReaderProcessReceiver(loop, protocol, host, port, shard_paths=paths)
    except Exception as e:
        log.warning(f"Syslog reader process not started ({e}); reading the socket in-process"
                    + (" - this mule stores ALL syslog messages (the other syslog mules get none)" if paths else ""))
        receiver = UdpReceiver(loop, protocol, host, port)
    receiver.start()
    return receiver


def _device_by_ip(ip):
    # Not db_device.query_device_by_ip: it returns False on DB errors, which would drop the message
    return db_device.Devices.select().where(db_device.Devices.ip == ip).first() or False


def _fix_link_down(dev_id, iface):
    events = list(db_events.get_events_by_src_and_status("syslog", 0, dev_id).dicts())
    return util.check_or_fix_event(events, 'state', f"Link Down: {iface}")


def _udp_rcvbuf_errors():
    """Kernel counter of UDP datagrams dropped because a socket buffer was full (this network namespace)."""
    try:
        with open("/proc/net/snmp") as f:
            rows = [line.split() for line in f if line.startswith("Udp:")]
        if len(rows) >= 2 and "RcvbufErrors" in rows[0]:
            return int(rows[1][rows[0].index("RcvbufErrors")])
    except (OSError, ValueError):
        pass
    return None


def _terminal_gateway_login(dev_id, username, ts):
    """True if this local login is the Terminal Gateway's own device login."""
    try:
        return db_AA.Auth.is_terminal_gateway_event(dev_id, username, 'loggedin', ts)
    except TRANSIENT_DB_ERRORS:
        raise   # retried by run_db
    except Exception as e:
        log.warning(f"Terminal Gateway login check failed for device {dev_id}: {e}")
        return False

# Cache for devices and users to reduce DB calls
# NOTE: asyncio event loop is single-threaded — these dicts are safe
# to read/write from coroutines without any locking.
device_cache = {}
user_cache = {}
user_fetch_failed = {}   # dev_id -> time of the last failed local-user fetch (USER_FETCH_BACKOFF)
message_cache = {}  # Deduplication cache
CACHE_TTL = 300          # 5 minutes for devices
USER_CACHE_TTL = 30      # 30 seconds for users (frequent role/perm changes)
MESSAGE_DEDUP_TTL = 5   # 5 seconds for message deduplication
last_cleanup = 0
CLEANUP_INTERVAL = 600  # 10 minutes

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    fixing_devices = set()  # Track devices currently being re-configured
    @staticmethod
    async def get_cached_device(ip):
        """Get device from cache or database — awaits DB lookup so event loop stays free."""
        now = time.time()
        if ip in device_cache:
            dev, timestamp = device_cache[ip]
            if now - timestamp < (CACHE_TTL if dev else UNKNOWN_IP_TTL):
                return dev
        # Cache miss or expired — run blocking DB query in the DB executor
        dev = await run_db(_device_by_ip, ip)
        device_cache[ip] = (dev, now)
        return dev

    @staticmethod
    async def get_cached_users(dev_id, opts):
        """Get users from cache or router API — awaits so event loop stays free.
        opts: API options, or a callable building them (only called on a cache miss)."""
        now = time.time()
        stale = None
        if dev_id in user_cache:
            users, timestamp = user_cache[dev_id]
            if now - timestamp < USER_CACHE_TTL:
                return users
            stale = users
        # A router whose API just failed (down, hanging until the timeout) is not asked again for
        # USER_FETCH_BACKOFF seconds: each attempt would hold its messages for the API timeout
        failed_at = user_fetch_failed.get(dev_id)
        if failed_at and now - failed_at < USER_FETCH_BACKOFF:
            return stale if stale is not None else []
        # Cache miss — options need the DB, the user list needs the router API
        if callable(opts):
            opts = await run_db(opts)
        users = await run_api(util.get_local_users, opts)
        if users:
            user_cache[dev_id] = (users, now)
            user_fetch_failed.pop(dev_id, None)
            return users
        # get_local_users returns False on API error and [] when the router has no
        # local users. On failure, fall back to the last-known-good list instead of
        # silently returning [] (which would classify every login as radius).
        if users is False:
            user_fetch_failed[dev_id] = time.time()
            log.warning(f"[Syslog] Local-user fetch failed for device {dev_id}; using cached list "
                        f"(next attempt in {USER_FETCH_BACKOFF}s)")
            if stale is not None:
                return stale
        return []
    
    @staticmethod
    def is_duplicate_message(addr, message, now=None):
        """Check if message is duplicate within dedup window (now = time the message was received,
        so a backlog never makes two separate messages look like one).
        Safe without a lock — asyncio event loop is single-threaded."""
        now = now or time.time()
        key = f"{addr[0]}:{hash(message)}"
        if key in message_cache:
            last_seen = message_cache[key]
            if now - last_seen < MESSAGE_DEDUP_TTL:
                return True
        message_cache[key] = now
        return False

    @staticmethod
    def cleanup_cache_if_needed():
        """Periodic cache cleanup — no lock needed (single-threaded event loop)."""
        global last_cleanup
        now = time.time()
        if now - last_cleanup > CLEANUP_INTERVAL:
            last_cleanup = now
            device_cutoff = now - CACHE_TTL
            user_cutoff = now - USER_CACHE_TTL
            message_cutoff = now - MESSAGE_DEDUP_TTL
            for ip in list(device_cache.keys()):
                if device_cache[ip][1] <= device_cutoff:
                    del device_cache[ip]
            for dev_id in list(user_cache.keys()):
                if user_cache[dev_id][1] <= user_cutoff:
                    del user_cache[dev_id]
            for dev_id in list(user_fetch_failed.keys()):
                if user_fetch_failed[dev_id] <= now - USER_FETCH_BACKOFF:
                    del user_fetch_failed[dev_id]
            for key in list(message_cache.keys()):
                if message_cache[key] <= message_cutoff:
                    del message_cache[key]
    # Pre-compiled regex patterns for better performance
    DEVICE_ID_REGEX = re.compile(r'(.*),?(info.*|warning|critical|error) mikrowizard(\d+):.*')
    LOGIN_REGEX = re.compile(r"user (.*) logged (in|out) from (..*)via.(.*)")
    LOGIN_FAILURE_REGEX = re.compile(r"login failure for user (.*) from (..*)via.(.*)")
    REBOOT_REGEX = re.compile(r'system,error,critical mikrowizard\d+: (.*)')
    SYSTEM_INFO_REGEX = re.compile(r"system,info mikrowizard\d+: (.*) (changed|added|removed|unscheduled) by (winbox-\d.{1,3}\d\/.*\(winbox\)|mac-msg\(winbox\)|tcp-msg\(winbox\)|ssh|telnet|api|api-ssl|console|.*\/web|ftp|www-ssl).*:(.*)@(.*) \((.*)\)")
    BUGGED_REGEX = re.compile(r"system,info mikrowizard\d+: (.*) (changed|added|removed|unscheduled) by  \((.*)\)")
    FALLBACK_REGEX = re.compile(r"system,info mikrowizard\d+: (.*) (changed|added|removed|unscheduled) by (.*)")
    LINK_REGEX = re.compile(r"interface,info mikrowizard\d+: (.*) link (down|up).*")
    DHCP_REGEX = re.compile(r'dhcp,.* mikrowizard\d+: (.*)')
    WIRELESS_REGEX = re.compile(r'wireless,info mikrowizard\d+: ([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})@(.*): (connected|disconnected), (signal strength|.*)? (-?\d{2})?.*')
    def extract_data_from_regex(self, regex, line):
        try:
            matches = re.finditer(regex, line, re.MULTILINE)
            sgroups = []
            for matchNum, match in enumerate(matches, start=1):
                for groupNum in range(0, len(match.groups())):
                    groupNum = groupNum + 1
                    sgroups.append(match.group(groupNum))
            return sgroups
        except Exception as e:
            log.error(f"Regex error: {e}")
            return None

    def safe_extract_info(self, compiled_regex, message, min_groups=0):
        """Safely extract regex groups with bounds checking"""
        try:
            info = self.extract_data_from_regex(compiled_regex.pattern, message)
            if info is None or len(info) < min_groups:
                return None
            return info
        except Exception as e:
            log.error(f"Error extracting regex data: {e}")
            return None

    async def _fix_device_syslog(self, dev):
        """Background task to fix device syslog configuration"""
        dev_id = dev.id
        ip = dev.ip
        
        if dev_id in self.fixing_devices:
            return
            
        self.fixing_devices.add(dev_id)
        try:
            log.warning(f"Starting background syslog reconfiguration for {ip} (ID: {dev_id})...")
            # Run the synchronous check_syslog_config in a thread
            result = await run_api(util.check_syslog_config, dev, None, True)
            if result:
                log.warning(f"Successfully re-configured syslog for {ip}")
                # Update cache to reflect that it might be fixed (optional, device ID mismatch will stop anyway)
            else:
                log.error(f"Failed to re-configure syslog for {ip}")
        except Exception as e:
            log.error(f"Error during syslog reconfiguration for {ip}: {e}")
        finally:
            # Wait a bit before allowing another fix attempt to avoid spamming the router
            await asyncio.sleep(30)
            self.fixing_devices.discard(dev_id)

    def __init__(self, dispatcher=None):
        super().__init__()
        self.dispatcher = dispatcher

    def receive_batch(self, batch):
        """Datagrams read by UdpReceiver: [(data, addr, received_at), ...], queued in order."""
        stats["received"] += len(batch)
        for data, addr, received_at in batch:
            self.dispatcher.submit(addr[0], (data, addr, received_at))

    def datagram_received(self, data, addr):
        """Called when a datagram is received: only queue it, so the socket is always drained."""
        stats["received"] += 1
        if self.dispatcher is not None:
            self.dispatcher.submit(addr[0], (data, addr, time.time()))
        else:
            asyncio.create_task(self.handle_log(data, addr))

    async def handle_log(self, data, addr, received_at=None):
        """Process one message; any failure is logged together with the message itself."""
        received_at = received_at or time.time()
        try:
            await self._process_log(data, addr, received_at)
            stats["processed"] += 1
        except Exception as e:
            stats["failed"] += 1
            log.error(f"Syslog message from {addr[0]} NOT stored ({type(e).__name__}: {e}): "
                      f"{data.strip().decode('utf-8', errors='ignore')}")

    async def _process_log(self, data, addr, received_at):
        message = data.strip().decode('utf-8', errors='ignore')

        # Check for duplicate messages
        if self.is_duplicate_message(addr, message, received_at):
            return

        if os.getenv("DEV_MODE") == "true":
            log.info(f"Received syslog message from {addr[0]}: {message}")
        ts = int(received_at)

        # Periodic non-blocking cache cleanup
        self.cleanup_cache_if_needed()

        # Await async cache lookup (DB call runs in the DB executor on cache miss).
        # A DB failure propagates to handle_log and is reported with the message.
        dev = await self.get_cached_device(addr[0])
        if not dev:
            return

        try:
            info = self.safe_extract_info(self.DEVICE_ID_REGEX, message, 3)
            if not info:
                return

            try:
                device_id = int(info[2])
                if dev.id != device_id:
                    if dev.id not in self.fixing_devices:
                        log.error(f"Device id mismatch for ip: {addr[0]} (DB ID: {dev.id}, Syslog ID: {device_id}). Triggering fix...")
                        force_syslog = await run_db(db_sysconfig.get_sysconfig, 'force_syslog')
                        if force_syslog == "True":
                            asyncio.create_task(self._fix_device_syslog(dev))
                    return
            except (ValueError, IndexError) as e:
                log.error(f"Invalid device ID in message: {e}")
                return

            # API options (DB queries + decryption) are built only when the local-user list
            # has to be fetched (login messages, user cache miss) - never on the event loop
            opts = functools.partial(util.build_api_options, dev)
            users = None  # Lazy load users only when needed
        except Exception as e:
            log.error(f"Error in handle_log: {e}")
            return
            
        if ISPRO:
            # Every message goes through the custom regexes (matches write events -> DB executor)
            await run_db(syslog_regex_pro.process_custom_syslog_regex, dev, message)

        if 'mikrowizard' in message and 'via api' not in message:
            if 'system,info,account' in message:
                # Process 1 second after receipt to avoid race condition with RADIUS accounting inserts
                # (relative to receipt: messages that waited in the backlog are not delayed again).
                await asyncio.sleep(max(0.0, received_at + 1 - time.time()))

                login_info = self.safe_extract_info(self.LOGIN_REGEX, message, 4)
                if login_info:
                    try:
                        if users is None:
                            # Await async user lookup
                            users = await self.get_cached_users(dev.id, opts)
                        msg = 'local' if login_info[0] in users else 'radius'
                        # Terminal Gateway sessions have their own Auth row (WebBox / Terminal-Gateway-<protocol>)
                        # attributed to the real customer: drop the router's local login event of
                        # the gateway's device account. Its logout is matched in Auth.add_log.
                        if msg == 'local' and 'logged in' in message:
                            is_gw = await run_db(_terminal_gateway_login, dev.id, login_info[0], ts)
                            if is_gw:
                                return
                        if 'logged in' in message and 'via api' not in message:
                            await run_db(
                                db_AA.Auth.add_log, dev.id, 'loggedin',
                                login_info[0], login_info[2], login_info[3],
                                timestamp=ts, message=msg
                            )
                        elif 'logged out' in message and login_info[0] in users:
                            await run_db(
                                db_AA.Auth.add_log, dev.id, 'loggedout',
                                login_info[0], login_info[2], login_info[3],
                                timestamp=ts, message=msg
                            )
                    except Exception as e:
                        log.error(f"Error processing login: {e}")
                        log.error(message)
            elif 'system,error,critical' in message:
                if "login failure" in message:
                    failure_info = self.safe_extract_info(self.LOGIN_FAILURE_REGEX, message, 3)
                    if failure_info:
                        if users is None:
                            users = await self.get_cached_users(dev.id, opts)
                        msg = 'local' if failure_info[0] in users else 'radius'
                        await run_db(
                            db_AA.Auth.add_log, dev.id, 'failed',
                            failure_info[0], failure_info[1], failure_info[2],
                            timestamp=ts, message=msg
                        )
                elif "rebooted" in message:
                    reboot_info = self.safe_extract_info(self.REBOOT_REGEX, message, 1)
                    if reboot_info:
                        await run_db(
                            db_events.state_event, dev.id, "syslog",
                            "Unexpected Reboot", "Critical", 1, reboot_info[0]
                        )

            elif 'system,info mikrowizard' in message:
                if ISPRO:
                    # Only queues the cloner sync job (bounded executor in utilpro)
                    utilpro.do_pro("syslog", False, dev, message)

                system_info = self.safe_extract_info(self.SYSTEM_INFO_REGEX, message, 6)
                if system_info:
                    address = system_info[4].split('/')
                    ctype = self._determine_connection_type(system_info[2], address)
                    await run_db(
                        db_AA.Account.add_log, dev.id, system_info[0],
                        system_info[1], system_info[3], message, ctype,
                        address[0], system_info[5]
                    )
                else:
                    bugged_info = self.safe_extract_info(self.BUGGED_REGEX, message, 3)
                    if bugged_info:
                        await run_db(
                            db_AA.Account.add_log, dev.id, bugged_info[0],
                            bugged_info[1], "Unknown (Mikrotik Bug)", message,
                            config=bugged_info[2]
                        )
                    elif "rebooted" in message:
                        await run_db(
                            db_events.state_event, dev.id, "syslog",
                            "Router Rebooted", "info", 1, info[0]
                        )
                    elif "resetting system configuration" in message:
                        await run_db(
                            db_events.state_event, dev.id, "syslog",
                            "Router reset", "info", 1, info[0]
                        )
                    else:
                        fallback_info = self.safe_extract_info(self.FALLBACK_REGEX, message, 3)
                        if fallback_info:
                            await run_db(
                                db_AA.Account.add_log, dev.id, fallback_info[0],
                                fallback_info[1], fallback_info[2], message
                            )
            elif 'interface,info mikrowizard' in message:
                if "link down" in message:
                    link_info = self.safe_extract_info(self.LINK_REGEX, message, 1)
                    if link_info:
                        await run_db(
                            db_events.state_event, dev.id, "syslog",
                            f"Link Down: {link_info[0]}", "Warning", 0,
                            f"Link is down for {link_info[0]}"
                        )
                elif "link up" in message:
                    link_info = self.safe_extract_info(self.LINK_REGEX, message, 1)
                    if link_info:
                        # open events are loaded only here, in the same DB job that resolves them
                        await run_db(_fix_link_down, dev.id, link_info[0])
            elif any(term in message for term in ["dhcp,info", "dhcp,critical", "dhcp,warning", "dhcp,error"]):
                client_type = 'client' if " dhcp-client on" in message else 'server'
                
                dhcp_info = self.safe_extract_info(self.DHCP_REGEX, message, 1)
                if not dhcp_info:
                    return
                    
                # Determine database level and status
                level = "info"
                status = 1  # Default to archived/silent
                
                if "dhcp,warning" in message:
                    level = "Warning"
                elif "dhcp,critical" in message:
                    level = "Critical"
                elif "dhcp,error" in message:
                    level = "Error"

                # Check for critical errors that should hit the monitoring wall (status=0)
                if "pool" in message and "empty" in message:
                    detail = "dhcp pool empty"
                    level = "Warning"
                    status = 0
                elif "std failure: timeout" in message:
                    detail = "dhcp resource timeout"
                    level = "Error"
                    status = 0
                else:
                    # Generic detail for history/logs
                    if client_type == 'server':
                        if "deassigned" in message:
                            detail = "dhcp deassigned"
                        elif "assigned" in message:
                            detail = "dhcp assigned"
                        else:
                            detail = "dhcp server event"
                    else:
                        detail = "dhcp client event"

                # Store the event
                await run_db(
                    db_events.state_event, dev.id, "syslog", detail, level, status, dhcp_info[0]
                )
            elif "wireless,info mikrowizard" in message:
                if ISPRO:
                    await run_db(utilpro.wireless_syslog_event, dev, message)
                else:
                    wireless_info = self.safe_extract_info(self.WIRELESS_REGEX, message, 3)
                    if wireless_info:
                        strength = wireless_info[4] if len(wireless_info) > 4 else ""
                        await run_db(
                            db_events.state_event, dev.id, "syslog", "wireless client", "info", 1,
                            f"{wireless_info[0]} {wireless_info[1]} {wireless_info[2]} {wireless_info[3]} {strength}"
                        )
            else:
                if os.getenv("DEV_MODE") == "true":
                    log.info("Unhandled syslog message: %s", message)

    def _determine_connection_type(self, connection_info, address):
        """Determine connection type from syslog info"""
        ctype = ''
        if 'winbox' in connection_info:
            ctype = 'winbox'
            if 'tcp' in connection_info:
                ctype = 'winbox-tcp'
            elif 'mac' in connection_info:
                ctype = 'winbox-mac'
            if 'terminal' in address:
                ctype += '/terminal'
        elif 'ssh' in connection_info:
            ctype = 'ssh'
        elif 'telnet' in connection_info:
            ctype = 'telnet'
        elif '/web' in connection_info:
            parts = connection_info.split('/')
            ctype = f"{parts[1]} ({parts[0]})"
        elif 'api' in connection_info:
            ctype = 'api'
        elif 'console' in connection_info:
            ctype = 'console'
        return ctype

async def report_stats(dispatcher):
    """Throughput / backlog / loss line every STATS_INTERVAL seconds (warning when something needs attention)."""
    last = dict(stats)
    last_drops = _udp_rcvbuf_errors()
    while True:
        await asyncio.sleep(STATS_INTERVAL)
        cur = dict(stats)
        drops = _udp_rcvbuf_errors()
        kernel_drops = (drops - last_drops) if (drops is not None and last_drops is not None) else 0
        delta = {k: cur[k] - last[k] for k in cur}
        line = (f"Syslog stats ({STATS_INTERVAL}s): received {delta['received']}, processed {delta['processed']}, "
                f"failed {delta['failed']}, DB retries {delta['db_retries']}, backlog {dispatcher.backlog}, "
                f"kernel UDP buffer drops {kernel_drops}")
        if kernel_drops or delta["failed"] or dispatcher.backlog > BACKLOG_WARN:
            log.warning(line)
        elif delta["received"] or os.getenv("DEV_MODE") == "true":
            log.info(line)
        last, last_drops = cur, drops


async def main():
    """Main async function to start the UDP server"""
    loop = asyncio.get_running_loop()
    _get_executor("db")   # size the DB executor from this process' pool before traffic arrives
    # router API threads by fleet size (a fleet that grows is picked up on the next restart)
    try:
        devices = await run_db(_device_count)
    except Exception as e:
        log.warning(f"Could not count devices for the API executor: {e}")
        devices = 0
    _executors["api"] = ThreadPoolExecutor(max_workers=api_threads(devices), thread_name_prefix="syslog-api")
    log.info(f"Syslog API executor: {api_threads(devices)} thread(s) for {devices} device(s)")
    # Startup code (imports, license init) may have checked out a connection on this thread - the
    # event loop thread, which never releases it by itself. Give it back to the DB executor.
    database.close()

    protocol_handler = SyslogUDPProtocol()
    dispatcher = OrderedDispatcher(protocol_handler.handle_log, SYSLOG_WORKERS)
    protocol_handler.dispatcher = dispatcher
    dispatcher.start()

    # UDP server: read by the reader process (ReaderProcessReceiver), in-process as a fallback.
    # Several syslog mules (PYSRV_SYSLOG_MULES, opt-in): mule 0 reads, the others get their share.
    shard, shards = get_syslog_shard_config()
    if shards > 1:
        log.info(f"Syslog mule {shard + 1} of {shards}" + (" (reads UDP 5014)" if shard == 0 else ""))
    try:
        receiver = start_receiver(loop, protocol_handler, '0.0.0.0', 5014, shard, shards)
    except OSError as e:
        # another syslog mule already reads UDP 5014 (uwsgi.ini has several, PYSRV_SYSLOG_MULES
        # unset or not listing this one): stay idle instead of failing and being restarted forever
        log.error(f"Syslog mule idle: cannot read UDP 5014 ({e}). With several syslog mules in "
                  f"uwsgi.ini list all of them in PYSRV_SYSLOG_MULES.")
        await asyncio.Future()
    asyncio.create_task(report_stats(dispatcher))

    log.info("Async syslog server started on port 5014")
    
    try:
        await asyncio.Future()  # Run forever
    except KeyboardInterrupt:
        log.info("Shutting down server")
    finally:
        receiver.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Server stopped")

