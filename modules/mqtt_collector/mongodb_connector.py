"""
A module for connecting the collector to MongoDB.
"""

from ipaddress import ip_address
import logging
import pymongo

logger = logging.getLogger("mqtt_collector")
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


class MongoDbConnector():
    """
    A class for connecting the collector to MongoDB.
    """

    def __init__(self, mongor_url, mongor_collection):
        self.__client = pymongo.MongoClient(mongor_url)
        dblist = self.__client.list_database_names()
        if "mqtt" in dblist:
            print("The database exists.")
        self.__db = self.__client[str(mongor_collection)]
        self.collection = self.__db["mqtt"]
        logger.info("Successfully connected to " + mongor_url + " storing flows in collection " + mongor_collection)

    def insert_one(self, flow):
        """
        Insert a single MQTT-IPFIX flow into the database.
        """
        mqtt_flow = {
            "sourceIPv4Address": ip_address(flow['sourceIPv4Address']).exploded,
            "sourceTransportPort": flow['sourceTransportPort'],
            "destinationIPv4Address": ip_address(flow['destinationIPv4Address']).exploded,
            "destinationTransportPort": flow['destinationTransportPort'],
            "protocol": flow['protocolIdentifier'],
            "flowStartNanoseconds": flow['flowStartNanoseconds'],
            "flowEndNanoseconds": flow['flowEndNanoseconds'],
            "flowDurationMicroseconds": flow['flowDurationMicroseconds'],
            "mqttTopic": flow['mqttTopic'],
            "mqttPacketId": flow['mqttPacketId'],
            "mqttQoS": flow['mqttQoS'],
            "mqttControlType": flow['mqttControlType'],
            "mqttSrcClientId": flow['mqttSrcClientId'],
            "mqttDstClientId": flow['mqttDstClientId'],
            "mqttCorrelationData": flow['mqttCorrelationData']
        }

        inserted_object = self.collection.insert_one(mqtt_flow)
        print(f"Inserted object with id {inserted_object.inserted_id}")

    def insert_many(self, flows):
        """
        Insert a series of MQTT-IPFIX flows into the database.
        """
        for flow in flows:
            self.insert_one(flow)

    def close(self):
        """
        Close the connection to the database.
        """
        self.__client.close()
