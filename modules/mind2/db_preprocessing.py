"""
Module for preprocessing the mqtt-based network flows in the mongodb database.
"""

# pylint: disable=too-few-public-methods, too-many-branches

import logging
import sys
from pymongo import UpdateOne
from modules.mqtt_collector import MongoDbConnector

logger = logging.getLogger('db_preprocessing')
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


class DbPreprocessor:
    """
    Class for preprocessing.
    """

    def __init__(self, db_connector: MongoDbConnector):
        self.__db = db_connector
        self.broker_keys = ["192.168.2.180:1883", "192.168.21.105:1883"]

    def update_client_ids(self):
        """
        Updating the client ids.
        MQTT-Brokers are given.
        Clients with known names are persisted with their full name, other are stored as 'ip:port'.
        Changes are written as bulk to the db instead of writting them one by one.
        """
        db_updates = []
        client_ids_mapping = {}

        for broker_key in self.broker_keys:
            client_ids_mapping[broker_key] = "MQTT Broker"

        flows_with_client_ids = self.__db.collection.find({"mqttSrcClientId": {"$exists": True}})
        for flow in flows_with_client_ids:
            flow_changed = False
            src_key = f"{flow['sourceIPv4Address']}:{flow['sourceTransportPort']}"
            dst_key = f"{flow['destinationIPv4Address']}:{flow['destinationTransportPort']}"

            if src_key in self.broker_keys and "MQTT Broker" not in flow['mqttSrcClientId']:
                flow_changed = True
                flow['mqttSrcClientId'] = client_ids_mapping[src_key]
            if dst_key in self.broker_keys and "MQTT Broker" not in flow['mqttDstClientId']:
                flow_changed = True
                flow['mqttDstClientId'] = client_ids_mapping[dst_key]

            if "Unknown" in flow['mqttSrcClientId']:
                flow_changed = True
                flow['mqttSrcClientId'] = src_key
            if "Unknown" in flow['mqttDstClientId']:
                flow_changed = True
                flow['mqttDstClientId'] = dst_key

            if src_key not in client_ids_mapping:
                client_ids_mapping[src_key] = flow['mqttSrcClientId']
            if dst_key not in client_ids_mapping:
                client_ids_mapping[dst_key] = flow['mqttDstClientId']

            if flow_changed:
                logger.debug("Need to update client_ids of flow: %s", flow["_id"])
                db_updates.append(UpdateOne({"_id": flow["_id"]}, {"$set": flow}))

        flows_without_client_ids = self.__db.collection.find({"mqttSrcClientId": {"$exists": False}})
        for flow in flows_without_client_ids:
            src_key = f"{flow['sourceIPv4Address']}:{flow['sourceTransportPort']}"
            dst_key = f"{flow['destinationIPv4Address']}:{flow['destinationTransportPort']}"

            if src_key in client_ids_mapping:
                flow['mqttSrcClientId'] = client_ids_mapping[src_key]
            else:
                flow['mqttSrcClientId'] = src_key

            if dst_key in client_ids_mapping:
                flow['mqttDstClientId'] = client_ids_mapping[dst_key]
            else:
                flow['mqttDstClientId'] = dst_key

            logger.debug("Need to update client_ids of flow: %s", flow["_id"])
            db_updates.append(UpdateOne({"_id": flow["_id"]}, {"$set": flow}))

        if len(db_updates) > 0:
            logger.debug("Updating %d flows due to client_ids...", len(db_updates))
            self.__db.collection.bulk_write(db_updates)


def start_preprocessing():
    """
    Start preprocessing.
    """
    logger.setLevel("DEBUG")
    ch.setLevel("DEBUG")
    #__db = MongoDbConnector("mongodb://192.168.2.171:27017/", "evaluation")
    __db = MongoDbConnector("mongodb://localhost:27017/", "yummy")

    try:
        logger.info("Starting preprocessing of flows...")
        db_preprocessor = DbPreprocessor(__db)
        db_preprocessor.update_client_ids()
        __db.close()
        logger.info("Preprocessing finished.")
    except KeyboardInterrupt:
        logger.error("Preprocessing interrupted. Exiting...")
        __db.close()
        sys.exit(0)
