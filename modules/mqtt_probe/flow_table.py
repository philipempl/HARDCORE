"""
A module for a flow table that stores MQTT-IPFIX flows.
"""

from modules.mqtt.flow_record import MqttRecord, incomplete_control_types, control_types_mapping
from modules.mqtt_probe.exporter import MqttIpfixExporter


class FlowTable():
    """
    A hash table used to store the flow records.
    """

    def __init__(self, collector, port, logger):
        self.flow_table = {}
        self.collector = collector
        self.port = port
        self.logger = logger
        self.exporter = MqttIpfixExporter(self.collector, self.port, logger)

    def process_flow(self, flow: MqttRecord):
        """
        Processes a mqtt packet and updates the flow table.
        If the packet fits an existing flow, the flow is updated. If not, a new entry in the flow table is created.
        If the packet completes an existing flow, the flow is exported to the collector.
        """
        # TO-DO timeout flows
        if self.__find(flow) is None:  # check if flow is already listed in flow table
            # if not, check if mqttrecord is a starting packet (typically found when sniffing starts within a flow)
            if int(flow.fixed_header.control_type) not in incomplete_control_types:
                self.__insert(flow)  # insert new flow into flow table
        else:
            self.__update(flow)  # update existing flow in flow table

    def __insert(self, flow: MqttRecord):
        """
        Inserts a new flow record into the flow table.
        The position of the flow record in the flow table is determined by the record id of the packet.
        """
        flow.max_flows = flow.get_max_flows()  # add size to flow
        self.flow_table[flow.record_id] = flow  # insert new flow into flow table
        self.logger.debug("Inserted flow: %s (%s)", flow.record_id, control_types_mapping[flow.fixed_header.control_type])
        if flow.max_flows == len(flow.timestamps):  # if max size of flow is reached
            self.__export_and_remove(flow)  # export flows

    def __find(self, packet: MqttRecord) -> MqttRecord or None:
        """
        Retrieves a flow record from the flow table based on its record id.
        """
        return self.flow_table[packet.record_id] if packet.record_id in self.flow_table else None

    def __update(self, flow: MqttRecord):
        """
        Updates a flow record in the flow table. If the updated flow record is complete, the flow is exported to the collector.
        """
        # update flow record by adding timestamp of corresponding control type
        self.flow_table[flow.record_id].timestamps[flow.fixed_header.control_type] = flow.layer3_and_4.timestamp
        self.logger.debug("Updated flow: %s (%s)", flow.record_id, control_types_mapping[flow.fixed_header.control_type])
        if self.flow_table[flow.record_id].max_flows == len(self.flow_table[flow.record_id].timestamps):  # if max size of flow is reached
            self.__export_and_remove(self.flow_table[flow.record_id])  # export flows

    def __export_and_remove(self, flow: MqttRecord):
        """
        Exports a flow record to the collector.
        """
        self.logger.debug("Exported flow: %s (%s)", flow.record_id, control_types_mapping[flow.fixed_header.control_type])
        self.exporter.export_mqtt_ipfix(flow)  # export flow to collector via ipfix exporter
        del self.flow_table[flow.record_id]  # remove flow from flow table

    def get_flow_table_length(self) -> int:
        """
        Get the count of flows held within the flow table.
        """
        return len(self.flow_table)
