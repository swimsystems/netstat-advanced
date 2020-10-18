#!/usr/bin/env python3

"""Show openend ports (netstat -nlp) and their associated processes."""

import os
import re
import socket
import subprocess
import types

import psutil


AF_INET6 = getattr(socket, "AF_INET6", object())
PROTO_MAP = {
    (socket.AF_INET, socket.SOCK_STREAM): "tcp",
    (AF_INET6, socket.SOCK_STREAM): "tcp6",
    (socket.AF_INET, socket.SOCK_DGRAM): "udp",
    (AF_INET6, socket.SOCK_DGRAM): "udp6",
}


def kernel_process_by_port(proto, address):
    """Find open kernel RPC port (rpcinfo)."""
    result = "?"
    try:
        rpcinfo_output = subprocess.run(["rpcinfo"], stdout=subprocess.PIPE, check=True)
    except FileNotFoundError:
        return result
    lines = rpcinfo_output.stdout.decode("ascii").splitlines()[:-1]
    regex = re.compile(
        r"\s+(?:\d+)\s+(?:\d)\s+(\w+)\s+" r"([.:0-9]+)\.(\d+)\.(\d+)\s+(\w+)\s+(?:\w+)"
    )
    processes = []
    for line in lines:
        match = regex.match(line)
        if match:
            processes.append(
                (
                    match.group(1),
                    "{}:{}".format(
                        match.group(2), 256 * int(match.group(3)) + int(match.group(4))
                    ),
                    match.group(5),
                )
            )

    for item in processes:
        if item[0] == proto and item[1] == address:
            return "rpc.{}".format(item[2])
    return result


def process_names():
    """Get process names."""
    proc_names = {}
    for process in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        proc = types.SimpleNamespace(**process.info)
        if proc.name == 'python':                                                         
            python_script = os.path.basename(proc.cmdline[1])                             
            proc_names[proc.pid] = proc.name + ' ' + python_script
        else:
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
        proc = (
            proc_names[connection.pid]
            if connection.pid
            else kernel_process_by_port(proto, "{}:{}".format(addr, port))
        )
        print(templ % (proto, addr, port, connection.pid or "-", proc))


if __name__ == "__main__":
    main()
