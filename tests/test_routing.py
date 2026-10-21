import ipaddress

import pytest

from deeptrace.errors import DeepTraceError
from deeptrace.routing import _parse_windows_route_table, _parse_windows_selected_route


WINDOWS_ROUTES = """
===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.123.0.1      10.123.0.53     35
          8.8.0.0      255.255.0.0       10.123.0.2      10.123.0.53     50
          8.8.8.0    255.255.255.0       10.123.0.3      10.123.0.53     80
          8.8.8.0    255.255.255.0       10.123.0.4      10.123.0.53     20
       10.123.0.0    255.255.255.0         On-link       10.123.0.53    291
===========================================================================
"""


def test_windows_route_table_uses_longest_prefix_then_metric():
    network, gateway, interface = _parse_windows_route_table(WINDOWS_ROUTES, ipaddress.IPv4Address("8.8.8.8"))
    assert str(network) == "8.8.8.0/24"
    assert gateway == "10.123.0.4"
    assert interface == "10.123.0.53"


def test_windows_route_table_accepts_localized_on_link_text():
    text = "10.123.0.0 255.255.255.0 Sur la liaison 10.123.0.53 25"
    network, gateway, interface = _parse_windows_route_table(text, ipaddress.IPv4Address("10.123.0.90"))
    assert str(network) == "10.123.0.0/24"
    assert gateway == "on-link"
    assert interface == "10.123.0.53"


def test_windows_selected_route_json():
    text = '{"DestinationPrefix":"0.0.0.0/0","NextHop":"10.123.0.1","InterfaceAlias":"Wi-Fi","InterfaceIndex":9,"SourceAddress":"10.123.0.53"}'
    network, gateway, interface = _parse_windows_selected_route(text, ipaddress.IPv4Address("8.8.8.8"))
    assert str(network) == "0.0.0.0/0"
    assert gateway == "10.123.0.1"
    assert interface == "Wi-Fi"


def test_windows_route_table_reports_no_match():
    with pytest.raises(DeepTraceError, match="no matching"):
        _parse_windows_route_table("Active Routes:\nNone", ipaddress.IPv4Address("8.8.8.8"))
