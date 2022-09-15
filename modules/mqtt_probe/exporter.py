"""
A module for creating and exporting MQTT-IPFIX flows.
"""

import socket
import ipfix.ie
import ipfix.message
import ipfix.template
from modules.mqtt.ipfix_template import MqttIpfixTemplate
from modules.mqtt.flow_record import MqttRecord, control_types_mapping
import csv   
from datetime import datetime
import psutil

# initialize socket for sending IPFIX flows to collector
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


class MqttIpfixExporter():
    """
    An exporter for exporting MQTT-based IPFIX messages to a collector.
    """

    def __init__(self, collector_ip, port, logger):
        self.collector_ip = collector_ip
        self.port = port
        self.logger = logger
        self.counter = 0
        self.qos= "qos0"

    def get_ipfix_template(self):
        """
        Initializes an IPFIX template
        """
        for index, info_ele in enumerate(MqttIpfixTemplate.mqtt_specific_ipfix_ies, start=1):
            ie_string = f"{info_ele[1]}(9999/{index})<{info_ele[2]}>"
            if info_ele[2] == "string":
                ie_string += "[255]"
            ipfix.ie.for_spec(ie_string)
        ipfix.ie.use_iana_default()
        ipfix.ie.use_5103_default()
        return ipfix.template.from_ielist(256, ipfix.ie.spec_list(MqttIpfixTemplate.get_current_ipfix_template()))

    def __get_ipfix_message_buffer(self):
        """
        Initializes an IPFIX message buffer based on the IPFIX template provided in
        >>> self.__get_ipfix_template()
        """
        ipfix_message = ipfix.message.MessageBuffer()
        ipfix_message.begin_export(odid=2)
        ipfix_message.add_template(self.get_ipfix_template(), export=True)
        ipfix_message.export_ensure_set(256)
        return ipfix_message

    # send IPFIX message to collector
    def export_mqtt_ipfix(self, flow: MqttRecord):
        """
        Sends an IPFIX message to the collector.
        """
        ipfix_message_buffer = self.__get_ipfix_message_buffer()
        flow_ipfix, ipfix_object = flow.get_ipfix_rep()
        self.benchmark(ipfix_object)
        ipfix_message_buffer.export_namedict(flow_ipfix)
        s.sendto(ipfix_message_buffer.to_bytes(), (self.collector_ip, self.port))
        self.logger.info('\033[0;36m' +
                         f"IPFIX message ({control_types_mapping[flow.fixed_header.control_type]}) sent to {self.collector_ip}:{self.port}" +
                         '\033[0m')

    def benchmark(self, flow):
        """
        Benchmarks the performance of the probe
        """
        # start_ns = flow.flow_start_nanoseconds.timestamp() * 1e9
        # end_ns = flow.flow_end_nanoseconds.timestamp() * 1e9
        # time1 = start_ns
        # time2 = datetime.now().timestamp()
       
        file_name = f"/root/evaluation/HARDCORE/evaluation/probe_{self.qos}_{self.counter}.csv"
        if flow.mqtt_src_client_id == "DIVIDER" and flow.mqtt_control_type== 1:
            self.counter = self.counter + 10
            file_name = f"/root/evaluation/HARDCORE/evaluation/probe_{self.qos}_{self.counter}.csv"
            with open(file_name, 'w',newline='') as outcsv:
                writer = csv.writer(outcsv)
                writer.writerow(["client_send_time", "sniff_time", "export_time", "latency_client_sniff","cpu_percent","memory_percent"])

        if "temperature-sensor" in flow.mqtt_src_client_id and flow.mqtt_control_type== 3:
            latency = datetime.now() - datetime.strptime(flow.mqtt_correlation_data,'%Y-%m-%d %H:%M:%S.%f')
            fields = [datetime.strptime(flow.mqtt_correlation_data,'%Y-%m-%d %H:%M:%S.%f'),flow.flow_start_nanoseconds.strftime('%Y-%m-%d %H:%M:%S.%f'), datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'), latency, psutil.cpu_percent(),psutil.virtual_memory().percent]
            with open(file_name, 'a',newline='') as f:
                writer = csv.writer(f)
                writer.writerow(fields)
