"""Controlled loopback-only TCP connect scanner; never scans remote addresses."""
import errno
import math
import socket
import time


def scan_local_port(port: int, timeout: float = 0.5) -> dict:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Port must be an integer between 1 and 65535')
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 5):
        raise ValueError('Timeout must be a finite number in (0, 5]')
    start = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        rc = sock.connect_ex(('127.0.0.1', port))
    status = ('OPEN' if rc == 0 else 'CLOSED'
              if rc in (errno.ECONNREFUSED, 10061) else 'FILTERED/UNKNOWN')
    return {'host': '127.0.0.1', 'port': port, 'status': status,
            'response_ms': round((time.perf_counter() - start) * 1000, 2)}
