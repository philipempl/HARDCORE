#!/usr/bin/env python3

"""
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2016-2020 Dominik Pataky <software+pynetflow@dpataky.eu>
Licensed under MIT License. See LICENSE.
"""

import struct
from typing import Union, Dict

from modules.netflow_tmp.ipfix import IPFIXExportPacket


class UnknownExportVersion(Exception):
    def __init__(self, data, version):
        self.data = data
        self.version = version
        r = repr(data)
        data_str = ("{:.25}..." if len(r) >= 28 else "{}").format(r)
        super().__init__(
            "Unknown NetFlow version {} for data {}".format(version, data_str)
        )


def get_export_version(data):
    return struct.unpack('!H', data[:2])[0]


def parse_packet(data: Union[str, bytes], templates: Dict = None) -> IPFIXExportPacket:
    """
    Parse an exported packet, either from string (hex) or from bytes.

    NetFlow version 9 and IPFIX use dynamic templates, which are sent by the exporter in regular intervals.
    These templates must be cached in between exports and are re-used for incoming new export packets.

    The following pseudo-code might help to understand the use case better. First, the collector is started, a new
    templates dict is created with default keys and an empty list for buffered packets is added. Then the receiver
    loop is started. For each arriving packet, it is tried to be parsed. If parsing fails due to unknown templates,
    the packet is queued for later re-parsing (this functionality is not handled in this code snippet).

    ```
    collector = netflow.collector
    coll = collector.start('0.0.0.0', 2055)
    templates = {"netflow": [], "ipfix": []}
    packets_with_unrecognized_templates = []
    while coll.receive_export():
        packet = coll.get_received_export_packet()
        try:
            parsed_packet = parse_packet(packet, templates)
        except (V9TemplateNotRecognized, IPFIXTemplateNotRecognized):
            packets_with_unrecognized_templates.append(packet)
    ```

    See the reference implementation of the collector for more information on how to use this function with templates.

    :raises ValueError: When the templates parameter was not passed, but templates must be used (v9, IPFIX).
    :raises UnknownExportVersion: When the exported version is not recognized.

    :param data: The export packet as string or bytes.
    :param templates: The templates dictionary with keys 'netflow' and 'ipfix' (created if not existing).
    :return: The parsed packet, or an exception.
    """
    if type(data) == str:
        # hex dump as string
        data = bytes.fromhex(data)
    elif type(data) == bytes:
        # check representation based on utf-8 decoding result
        try:
            # hex dump as bytes, but not hex
            dec = data.decode()
            data = bytes.fromhex(dec)
        except UnicodeDecodeError:
            # use data as given, assuming hex-formatted bytes
            pass

    version = get_export_version(data)

    if version in [10] and templates is None:
        raise ValueError("IPFIX packet detected, but no templates dict was passed! For correct parsing of packets with "
                         "templates, create a 'templates' dict and pass it into the 'parse_packet' function.")

    if version == 1:
        return None
    elif version == 5:
        return None
    elif version == 9:
        return None
    elif version == 10:
        if "ipfix" not in templates:
            templates["ipfix"] = []
        return IPFIXExportPacket(data, templates["ipfix"])
    raise UnknownExportVersion(data, version)