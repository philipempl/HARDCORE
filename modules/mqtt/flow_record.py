"""
A module containing classes for describing MQTT PCAP records and flows.
"""

import datetime
import hashlib
from ipaddress import ip_address
import json
from modules.mqtt.ipfix_template import MqttIpfix
import csv   
from datetime import datetime

control_types_mapping = {  # control type mapping
    0: "Reserved",
    1: "CONNECT", 2: "CONNACK",
    3: "PUBLISH", 4: "PUBACK", 5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP",
    8: "SUBSCRIBE", 9: "SUBACK",
    10: "UNSUBSCRIBE", 11: "UNSUBACK",
    12: "PINGREQ", 13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH"}

incomplete_control_types = [2, 4, 5, 6, 7, 9, 11, 13]  # incomplete control types (typically when sniffing starts)
# reversed flows for control packets
reversed_flows = [2, 4, 5, 7, 9, 11, 13]
# max packets per flow for each control packet. Publish (3) + QoS(0) = 30
max_flow_mapping = {1: 2, 30: 1, 31: 2, 32: 4, 8: 2, 10: 2, 12: 2, 14: 1, 15: 1}

client_id_mapping = {}  # client ids


class Layer3And4():
    """
    A class for describing Layer 3 and 4 of a MQTT PCAP record.
    """

    def __init__(self, packet):
        self.timestamp = packet.sniff_time
        self.source_ip = ip_address(packet.ip.src)
        self.source_port = int(packet.tcp.srcport)
        self.destination_ip = ip_address(packet.ip.dst)
        self.destination_port = int(packet.tcp.dstport)
        self.protocol = int(packet.ip.proto)

    def __str__(self):
        return json.dumps(self.__dict__, default=str)

    def get_layer3_and_3(self) -> dict:
        """
        Returns a dictionary containing the layer 3 and 4 of a MQTT PCAP record.
        """
        return {
            "timestamp": self.timestamp,
            "source_ip": str(self.source_ip),
            "source_port": self.source_port,
            "destination_ip": str(self.destination_ip),
            "destination_port": self.destination_port,
            "protocol": self.protocol
        }


class MqttFixedHeader():
    """
    A class for describing the fixed header of a MQTT PCAP record.
    """

    def __init__(self, packet):
        self.qos = int(packet.mqtt.qos) if hasattr(packet.mqtt, 'qos') else 0
        self.duplicate = packet.mqtt.dupflag if hasattr(packet.mqtt, 'dupflag') else None
        self.retain = packet.mqtt.retain if hasattr(packet.mqtt, 'retain') else None
        self.control_type = int(packet.mqtt.msgtype) if hasattr(packet.mqtt, 'msgtype') else None
        self.reserved = packet.mqtt.reserved if hasattr(packet.mqtt, 'reserved') else None
        client_ids = self.__get_client_ids(packet)
        self.src_client_id = client_ids["src"]
        self.dst_client_id = client_ids["dst"]

    def __str__(self):
        return json.dumps(self.__dict__, default=str)

    def __get_client_ids(self, packet) -> dict:
        """
        Handles the client id of a MQTT PCAP record.
        """
        client_keys = {
            "src": f"{packet.ip.src}:{packet.tcp.srcport}",
            "dst": f"{packet.ip.dst}:{packet.tcp.dstport}"
        }
        client_ids = {
            "src": None,
            "dst": None
        }

        if self.control_type == 1:
            client_id_mapping[client_keys["src"]] = packet.mqtt.clientid
            if self.__find_client_id(client_keys["dst"]) is None:
                client_id_mapping[client_keys["dst"]] = "Unknown client, probably a broker."

        for key, value in client_keys.items():
            client_id = self.__find_client_id(value)
            if client_id is not None:
                client_ids[key] = client_id
            else:
                client_ids[key] = "Unknown client"

        if self.control_type == 14:
            client_id_mapping.pop(client_keys["src"], None)
            client_id_mapping.pop(client_keys["dst"], None)

        return client_ids

    def __find_client_id(self, key: str) -> str or None:
        """
        Finds the client id of a MQTT PCAP record.
        """
        return client_id_mapping.get(key) if key in client_id_mapping else None

    def get_mqtt_fixed_header(self) -> dict:
        """
        Returns a dictionary containing the fixed header of a MQTT PCAP record.
        """
        return {
            "qos": self.qos,
            "duplicate": self.duplicate,
            "retain": self.retain,
            "control_type": self.control_type,
            "reserved": self.reserved,
            "src_client_id": self.src_client_id,
            "dst_client_id": self.dst_client_id
        }


class MqttVariableHeader():
    """
    A class for describing the variable header of a MQTT PCAP record.
    """

    def __init__(self, packet, control_type: int, qos: int):
        self.packet_id = int(packet.mqtt.msgid) if hasattr(packet.mqtt, 'msgid') else None
        self.topic = packet.mqtt.topic if hasattr(packet.mqtt, 'topic') else None
        self.message = packet.mqtt.msg if hasattr(packet.mqtt, 'msg') else None
        self.message_len = packet.mqtt.len if hasattr(packet.mqtt, 'len') else None
        # check if topic is broker specific
        if(self.topic is not None and "$SYS" in self.topic):
            self.sys_topic = True
        else:
            self.sys_topic = False
        self.correlation_data = self.__parse_correlation_data(packet.tcp.payload, control_type, qos)

    def __str__(self):
        return json.dumps(self.__dict__, default=str)

    def __parse_correlation_data(self, tcp_payload: str, control_type: int, qos: int) -> str or None:
        if control_type == 3:
            payload_bytes = bytearray.fromhex(tcp_payload.replace(':', ''))
            current_offset = 0

            try:
                current_offset = payload_bytes.index(b'\x00')
                topic_length = payload_bytes[current_offset + 1]
                current_offset += topic_length + 2

                if qos > 0:
                    current_offset += 2

                properties_length = payload_bytes[current_offset]
                properties = payload_bytes[current_offset + 1:current_offset + properties_length + 1]

                correlation_data = self.__find_correlation_data(properties, 0)

                if correlation_data is not None:
                    return correlation_data.decode('utf-8')
            except ValueError as e:
                print(e)

            return None
        return None

    def __find_correlation_data(self, properties: bytearray, current_offset: int) -> bytearray or None:
        try:
            current_offset = properties.index(b'\x09', current_offset)
            if properties[current_offset + 1] == 0x00:
                correlation_data_length = properties[current_offset + 2]
                correlation_data = properties[current_offset + 3:current_offset + 3 + correlation_data_length]
            else:
                correlation_data = self.__find_correlation_data(properties, current_offset + 1)
            return correlation_data
        except ValueError:
            return None

    def get_mqtt_variable_header(self) -> dict:
        """
        Returns a dictionary containing the variable header of a MQTT PCAP record.
        """
        return {
            "packet_id": self.packet_id,
            "topic": self.topic,
            "message": self.message,
            "message_len": self.message_len,
            "sys_topic": self.sys_topic
        }


class MqttRecord():
    """
    A class for describing MQTT PCAP records and flows.
    """

    def __init__(self, packet):
        # general fields layer 3 and 4
        self.layer3_and_4 = Layer3And4(packet)
        # mqtt fixed header fields
        self.fixed_header = MqttFixedHeader(packet)
        # mqtt variable header and payload
        self.variable_header = MqttVariableHeader(packet, self.fixed_header.control_type, self.fixed_header.qos)
        # flow specific data
        self.timestamps = {}
        self.timestamps[self.fixed_header.control_type] = self.layer3_and_4.timestamp
        self.record_id = self.__get_record_id()
        self.max_flows = 0

    def __str__(self):
        return json.dumps(self.__dict__, default=str)

    # Theory: each odd message control type is a request to the server while each even control type is a resposne
    # We need to reverse only even control types
    # not correct --> check if it is a reversed flow (see reversed_flows[])
    # CONNECT (1), CONNACK (2),
    # UNSUBSCRIBE (10), UNSUBACK (11),
    # PINGREQ (12), PINGRESP (13),
    # DISCONNECT (14),
    # AUTH (15) are identifiable by IPv4 tuples (source_ip, src_port, destination_ip,destination_port, protocol)
    #
    # PUBLISH (3), PUBACK (4), PUBREC (5), PUBREL (6), PUBCOMP (7),
    # SUBSCRIBE (8), SUBACK (9) need a different identifier
    # QoS(2) = IPv4 tuple and packet identifier
    # QoS(1) = IPv4 tuple and packet identifier
    # QoS(0) = TODO??
    def __get_record_id(self):
        """
        Get the record id of a MQTT PCAP record.
        """
        quintuple = ''
        # normal control flow
        if self.fixed_header.control_type not in reversed_flows:
            # packet identifier only available if qos > 0
            if self.variable_header.packet_id is not None:
                quintuple = (self.layer3_and_4.source_ip,
                             self.layer3_and_4.source_port,
                             self.layer3_and_4.destination_ip,
                             self.layer3_and_4.destination_port,
                             self.layer3_and_4.protocol,
                             self.variable_header.packet_id)
            else:
                quintuple = (self.layer3_and_4.source_ip,
                             self.layer3_and_4.source_port,
                             self.layer3_and_4.destination_ip,
                             self.layer3_and_4.destination_port,
                             self.layer3_and_4.protocol)
        # reversed control flow
        else:
            # packet identifier only available if qos > 0
            if self.variable_header.packet_id is not None:
                quintuple = (self.layer3_and_4.destination_ip,
                             self.layer3_and_4.destination_port,
                             self.layer3_and_4.source_ip,
                             self.layer3_and_4.source_port,
                             self.layer3_and_4.protocol,
                             self.variable_header.packet_id)
            else:
                quintuple = (self.layer3_and_4.destination_ip,
                             self.layer3_and_4.destination_port,
                             self.layer3_and_4.source_ip,
                             self.layer3_and_4.source_port,
                             self.layer3_and_4.protocol)
        return hashlib.sha256(repr(quintuple).encode('utf-8')).hexdigest()

    def get_max_flows(self):
        """
        Set the maximum number of flows for the current record.
        """
        if self.fixed_header.control_type != 3:
            return max_flow_mapping[self.fixed_header.control_type]
        return max_flow_mapping[int(str(self.fixed_header.control_type)+str(self.fixed_header.qos))]

    def get_ipfix_rep(self) -> dict:
        """
        Returns the IPFIX representation of the record
        """
        ipfix_object = MqttIpfix()
        ipfix_object.source_ipv4_address = self.layer3_and_4.source_ip
        ipfix_object.destination_ipv4_address = self.layer3_and_4.destination_ip
        ipfix_object.protocol_identifier = self.layer3_and_4.protocol
        ipfix_object.source_transport_port = self.layer3_and_4.source_port
        ipfix_object.destination_transport_port = self.layer3_and_4.destination_port
        ipfix_object.flow_start_nanoseconds = self.timestamps[min(self.timestamps.keys())]
        ipfix_object.flow_end_nanoseconds = self.timestamps[max(self.timestamps.keys())]
        start_ns = ipfix_object.flow_start_nanoseconds.timestamp() * 1e9
        end_ns = ipfix_object.flow_end_nanoseconds.timestamp() * 1e9
        ipfix_object.flow_duration_microseconds = round((end_ns - start_ns) / 1e6)
        ipfix_object.mqtt_qos = self.fixed_header.qos
        ipfix_object.mqtt_control_type = self.fixed_header.control_type
        ipfix_object.mqtt_packet_id = self.variable_header.packet_id if self.variable_header.packet_id is not None else 0
        ipfix_object.mqtt_topic = self.variable_header.topic if self.variable_header.topic is not None else "NULL"
        ipfix_object.mqtt_src_client_id = self.fixed_header.src_client_id
        ipfix_object.mqtt_dst_client_id = self.fixed_header.dst_client_id
        ipfix_object.mqtt_correlation_data = self.variable_header.correlation_data if self.variable_header.correlation_data is not None else 'NULL'


        return ipfix_object.get_dict(),ipfix_object
