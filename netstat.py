#!/usr/bin/env python3

"""Show openend ports (netstat -nlp) and their associated processes."""

import types
import socket

import psutil


AF_INET6 = getattr(socket, "AF_INET6", object())
PROTO_MAP = {
    (socket.AF_INET, socket.SOCK_STREAM): "tcp",
    (AF_INET6, socket.SOCK_STREAM): "tcp6",
    (socket.AF_INET, socket.SOCK_DGRAM): "udp",
    (AF_INET6, socket.SOCK_DGRAM): "udp6",
}


def process_names():
    """Get process names."""
    proc_names = {}
    for process in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        proc = types.SimpleNamespace(**process.info)
        proc_names[proc.pid] = proc.name
    return proc_names


def main():
    """Show openend ports (netstat -nlp) and their associated processes."""
    templ = "%-5s %40s:%-10s %-6s %s"
    print(templ % ("Proto", "Local address", "Port", "PID", "Program name"))

    proc_names = process_names()

    def _sort(connection):
        return proc_names.get(connection.pid, "?")

    for connection in sorted(psutil.net_connections(), key=_sort):
        if connection.status not in ["LISTEN", "NONE"]:
            continue

        addr = connection.laddr[0]
        port = connection.laddr[1]
        proto = PROTO_MAP[(connection.family, connection.type)]
        proc = proc_names[connection.pid] if connection.pid else "kernel-rpc"
        print(templ % (proto, addr, port, connection.pid or "-", proc))


if __name__ == "__main__":
    main()
