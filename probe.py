"""
Module for sniffing PCAP traffic, extract MQTT flows, and export them as IPFIX netflows.
"""

import argparse
import logging
import threading
import pyshark
from modules.mqtt.flow_record import MqttRecord
from modules.mqtt_probe.flow_table import FlowTable

# logging
logger = logging.getLogger('mqtt_probe')
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


class MqttProbe:
    """
    A probe to sniff and export MQTT traffic
    """
    def __init__(self, interface: str, capture_filter: str, sys_topic: bool, flows_table: FlowTable):
        self.__capture = None
        self.interface = interface
        self.capture_filter = capture_filter
        self.sys_topic = sys_topic
        self.__flow_table = flows_table

    def run(self):
        """
        Sniffs MQTT traffic and process each packet.
        """
        logger.debug('Probing MQTT traffic in live capturing mode...')
        # capture packets
        self.__capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=self.capture_filter)
        
        counter = 1
        for packet in self.__capture:
            threading.Thread(name=f"packet{counter}", target=self.process_packet(packet)).start()
            counter +=1

    def process_packet(self, packet):
        # get mqtt packet
        mqtt_packet = self.__retrieve_mqtt_packet(packet)
        # filter out non MQTT packets
        if mqtt_packet is not None:
            # pcap to flow conversion
            self.__flow_table.process_flow(mqtt_packet)

    def stop(self):
        """
        Stops the capturing of packets.
        """
        self.__capture.close()

    # get MQTT packet and filter out SYS topics and none mqtt packets
    def __retrieve_mqtt_packet(self, packet) -> MqttRecord:
        """
        Converts packets to MQTT packets. None-MQTT packets are filtered out.
        If the packet is a SYS topic, it is filtered out when the sys-topic flag is set to false.
        """
        # check if packet is a mqtt packet
        if hasattr(packet, 'mqtt'):
            mqtt_packet = MqttRecord(packet)
            # check if config allows the capturing of SYS topcis
            if (mqtt_packet.variable_header.sys_topic is True and self.sys_topic):
                # logger.debug('Processing $SYS MQTT packet...')
                return mqtt_packet
            if mqtt_packet.variable_header.sys_topic is False:
                # print(mqtt_packet)
                return mqtt_packet
        return None


if __name__ == "mqtt-probe.probe":
    logger.error("The probe is currently meant to be used as a CLI tool only.")
    logger.error("Use 'python3 -m mqtt-probe.probe -h' in your console for additional help.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A probe for sniffing and exporting MQTT traffic.")
    # required arguments
    parser.add_argument("--interface", "-i", help="The interface to sniff on.", required=True)
    parser.add_argument("--collector", "-c", help="IP of the collector to use for exporting flows.", required=True)
    parser.add_argument("--port", "-p", help="Port of the collector to use for exporting flows.", required=True)
    # optional arguments
    parser.add_argument("--filter", "-f", default="", help="The filter to use for sniffing.")
    parser.add_argument("--sys-topic", "-s", action="store_true", help="Allow the capturing of SYS topics.")
    parser.add_argument("--log-level", "-l", help="The log level to use.", default="INFO")
    # parse arguments
    args = parser.parse_args()

    #   set log level
    logger.setLevel(args.log_level)
    ch.setLevel(args.log_level)

    try:
        # initializing the flow table
        logger.debug('Setting up flow table')
        flow_table = FlowTable(args.collector, int(args.port), logger)
        # start sniffing
        sniffer = MqttProbe(args.interface, args.filter, args.sys_topic, flow_table)
        sniffer.run()
    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt, exiting...")
        sniffer.stop()
