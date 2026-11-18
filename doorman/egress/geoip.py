"""Which country an IPv4 address is in, for the owner's country block list.

The table is DB-IP's free "IP to Country Lite" CSV (CC BY 4.0; rows of start,end,country), which the proxy
downloads once a month. Only the IPv4 rows are kept, as two sorted arrays of range starts and ends plus two
bytes of country code per range, found with a binary search: the IPv4 part is about 300,000 ranges, a few
MB this way, where a dict or a list of tuples would take ten times that in the proxy's small container.
IPv6 addresses get no country (other than IPv4-mapped ones): the agent's network has no IPv6.
"""

from __future__ import annotations

import csv
import gzip
import io
import ipaddress
import os
import re
import socket
from array import array
from bisect import bisect_right

_DATE = re.compile(r"dbip-country-lite-(\d{4}-\d{2})\.csv(?:\.gz)?$")


def _ipv4(text: str) -> int | None:
    try:
        return int.from_bytes(socket.inet_pton(socket.AF_INET, text.strip()), "big")
    except (OSError, ValueError):
        return None


class GeoIP:
    def __init__(self, starts: array, ends: array, codes: bytes, date: str | None = None):
        self.starts = starts
        self.ends = ends
        self.codes = codes  # two ASCII letters per range
        self.date = date

    @property
    def rows(self) -> int:
        return len(self.starts)

    @classmethod
    def load(cls, path: str) -> GeoIP:
        with open(path, "rb") as f:
            packed = f.read(2) == b"\x1f\x8b"
        raw = gzip.open(path, "rb") if packed else open(path, "rb")
        starts, ends, codes = array("L"), array("L"), bytearray()
        with io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="") as f:
            for record in csv.reader(f):
                if len(record) < 3 or ":" in record[0]:
                    continue  # IPv6, or not a row
                start, end, code = _ipv4(record[0]), _ipv4(record[1]), record[2].strip().upper()
                if start is None or end is None or end < start or len(code) != 2 or not code.isascii() \
                        or not code.isalpha():
                    continue
                starts.append(start)
                ends.append(end)
                codes += code.encode("ascii")
        if any(starts[i] < starts[i - 1] for i in range(1, len(starts))):
            # DB-IP's file is sorted; a hand-made one may not be
            order = sorted(range(len(starts)), key=starts.__getitem__)
            starts, ends = array("L", (starts[i] for i in order)), array("L", (ends[i] for i in order))
            codes = bytearray(b"".join(codes[2 * i:2 * i + 2] for i in order))
        match = _DATE.search(os.path.basename(path))
        return cls(starts, ends, bytes(codes), match.group(1) if match else None)

    def country(self, ip: str) -> str | None:
        n = _ipv4(ip)
        if n is None:
            try:
                mapped = ipaddress.IPv6Address(ip.strip("[]")).ipv4_mapped
            except ValueError:
                return None
            if mapped is None:
                return None
            n = int(mapped)
        i = bisect_right(self.starts, n) - 1
        if i < 0 or n > self.ends[i]:
            return None
        code = self.codes[2 * i:2 * i + 2].decode("ascii")
        return None if code == "ZZ" else code  # ZZ: DB-IP's "unknown or reserved"
