#!/usr/bin/python
# -*- coding: utf-8 -*-

# syslog_reader.py: UDP reader process of the syslog mule (py/mules/syslog.py starts it)
# MikroWizard.com , Mikrotik router management solution
#
# Reads the syslog UDP socket and nothing else, in its own process (its own GIL): it is never
# held up by the mule's DB / API threads, so the kernel socket buffer does not overflow when the
# mule is busy. Datagrams are queued in memory (no limit: none is dropped) and written to the
# mule over a local stream socket, which waits instead of dropping when the mule reads slowly.
#
#   syslog_reader.py UDP_FD STREAM_FD [SHARD_SOCKET ...]
#
# With several syslog mules (PYSRV_SYSLOG_MULES, opt-in) the extra arguments are the Unix sockets
# of mules 2..N: every router (source address) is assigned to one mule (crc32 % N), so its messages
# stay in order; each mule has its own queue, so a slow or restarting mule never holds up the others.
#
# Record on the stream: struct "!dIHH" (receipt time, IPv4 address, port, length) + datagram.
# Only the standard library: no MikroWizard import, no DB, nothing else to start.
# Exits when the mule (parent process) goes away.

import collections
import ctypes
import os
import selectors
import signal
import socket
import struct
import sys
import threading
import time
import zlib

HDR = struct.Struct("!dIHH")
SEND_CHUNK = 256 * 1024
QUEUE_WARN = 100000
DRAIN_MAX = 5000           # datagrams read per wake-up before handing them to the sender
READY = b"R"               # first byte on the stream: the reader is reading the socket


class Shard(object):
    """Messages of one syslog mule: an in-memory queue (no limit) and its condition."""

    def __init__(self):
        self.queue = collections.deque()
        self.cv = threading.Condition()

    def take(self, parent):
        """Next chunk of records (blocks; exits when the mule process is gone)."""
        with self.cv:
            while not self.queue:
                if not self.cv.wait(1.0) and os.getppid() != parent:
                    os._exit(0)
            parts, size = [], 0
            while self.queue and size < SEND_CHUNK:
                rec = self.queue.popleft()
                parts.append(rec)
                size += len(rec)
            return b"".join(parts), len(self.queue)


def _warn_backlog(name, pending, state):
    if pending > QUEUE_WARN and time.time() - state[0] > 60:
        state[0] = time.time()
        sys.stderr.write("syslog_reader: %d messages waiting for %s\n" % (pending, name))


def _send_to_path(shard, index, path, parent):
    """Syslog mule `index` (> 0) of several: connect to its Unix socket, stream its records, and
    reconnect when it restarts. A chunk interrupted by a disconnect is sent again in full to the
    new connection (at least once: the restarted mule may see a few messages twice, never none)."""
    sock, chunk, warned = None, None, [0.0]
    down_since, down_warned = time.time(), 0.0
    while True:
        if sock is None:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect(path)
                sock = s
                down_since = None
            except OSError:
                s.close()
                if os.getppid() != parent:
                    os._exit(0)
                now = time.time()
                down_since = down_since or now
                if now - down_since > 60 and now - down_warned > 60:
                    down_warned = now
                    sys.stderr.write("syslog_reader: syslog mule %d (%s) not reachable for %d s; its routers' "
                                     "messages wait in memory (%d). Check PYSRV_SYSLOG_MULES / uwsgi.ini\n"
                                     % (index + 1, path, now - down_since, len(shard.queue)))
                time.sleep(0.5)
                continue
        if chunk is None:
            chunk, pending = shard.take(parent)
            _warn_backlog("syslog mule %d" % (index + 1), pending, warned)
        try:
            sock.sendall(chunk)
            chunk = None
        except OSError:
            sock.close()
            sock = None


def main():
    udp = socket.socket(fileno=int(sys.argv[1]))
    out = socket.socket(fileno=int(sys.argv[2]))
    paths = sys.argv[3:]               # several syslog mules (PYSRV_SYSLOG_MULES): mules 1..N-1
    parent = os.getppid()
    try:
        ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM)    # PR_SET_PDEATHSIG
    except Exception:
        pass
    if os.getppid() != parent:
        return
    udp.setblocking(False)
    shards = [Shard() for _ in range(1 + len(paths))]
    count = len(shards)
    routers = {}                       # ip -> (packed address, shard): a router always goes to one mule

    def receive():
        # wait without the GIL, then read until the socket is empty: one lock / wake-up per batch
        sel = selectors.DefaultSelector()
        sel.register(udp, selectors.EVENT_READ)
        recvfrom, pack, now = udp.recvfrom, HDR.pack, time.time
        while True:
            if not sel.select(timeout=1.0):
                if os.getppid() != parent:
                    os._exit(0)
                continue
            batches = [[] for _ in shards]
            n_read = 0
            while n_read < DRAIN_MAX:
                try:
                    data, (ip, port) = recvfrom(65535)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    os._exit(0)
                r = routers.get(ip)
                if r is None:
                    packed = socket.inet_aton(ip)
                    r = routers[ip] = (struct.unpack("!I", packed)[0], zlib.crc32(packed) % count)
                batches[r[1]].append(pack(now(), r[0], port, len(data)) + data)
                n_read += 1
            for shard, batch in zip(shards, batches):
                if batch:
                    with shard.cv:
                        shard.queue.extend(batch)
                        shard.cv.notify()

    threading.Thread(target=receive, name="udp-recv", daemon=True).start()
    for k, path in enumerate(paths, 1):
        threading.Thread(target=_send_to_path, args=(shards[k], k, path, parent), name="shard-%d" % k,
                         daemon=True).start()
    out.sendall(READY)
    warned = [0.0]
    while True:
        chunk, pending = shards[0].take(parent)
        _warn_backlog("the syslog mule", pending, warned)
        try:
            out.sendall(chunk)
        except OSError:
            os._exit(0)          # mule gone


if __name__ == "__main__":
    main()
