from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .errors import DeepTraceError


@dataclass(slots=True)
class SubnetInfo:
    address: str
    prefix: int
    subnet_mask: str
    network: str
    broadcast: str
    first_usable: str
    last_usable: str
    usable_hosts: int
    private: bool
    address_binary: str
    mask_binary: str


def dotted_binary(value: int) -> str:
    return ".".join(f"{(value >> shift) & 0xff:08b}" for shift in (24, 16, 8, 0))


def calculate(cidr: str) -> SubnetInfo:
    try:
        interface = ipaddress.IPv4Interface(cidr)
    except ValueError as exc:
        raise DeepTraceError(f"invalid IPv4 network: {exc}") from exc
    network = interface.network
    count = network.num_addresses
    if network.prefixlen == 32:
        first = last = network.network_address
        usable = 1
    elif network.prefixlen == 31:
        first, last, usable = network.network_address, network.broadcast_address, 2
    else:
        first = ipaddress.IPv4Address(int(network.network_address) + 1)
        last = ipaddress.IPv4Address(int(network.broadcast_address) - 1)
        usable = max(0, count - 2)
    return SubnetInfo(
        str(interface.ip), network.prefixlen, str(network.netmask), str(network.network_address),
        str(network.broadcast_address), str(first), str(last), usable, interface.ip.is_private,
        dotted_binary(int(interface.ip)), dotted_binary(int(network.netmask)),
    )
