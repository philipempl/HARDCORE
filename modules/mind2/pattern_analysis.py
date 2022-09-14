"""
Module for pattern analysis of mqtt-based network flows
which are stored in a mongodb database.
"""

# pylint: disable=too-many-locals

import pymongo
import pandas as pd
import numpy as np
from modules.mqtt_collector.mongodb_connector import MongoDbConnector


def get_base_dataframe(flows: list) -> pd.DataFrame:
    """
    Create base dataframe from mongodb documents
    """
    rows = []

    for flow in flows:
        # timestamp = datetime.datetime.fromtimestamp(int(flow["flowStartMilliseconds"])/1e3)
        timestamp = flow["flowStartNanoseconds"]
        client = flow["mqttSrcClientId"]
        topic = flow["mqttTopic"]

        if client == 'MQTT Broker':
            src_name = topic
            dst_name = flow['mqttDstClientId']
        else:
            src_name = flow['mqttSrcClientId']
            dst_name = topic
        name = f"{src_name} to {dst_name}"

        rows.append([timestamp, name])

    return pd.DataFrame(rows, columns=["timestamp", "name"])


def start_analysis():
    """
    Get flows as documents from mongodb, create time-windows (buckets) and fill them with the corresponding flows.
    """
    limit = 100000

    _db = MongoDbConnector("mongodb://192.168.2.171:27017/")
    flows = _db.collection.find({"mqttControlType": 3}).limit(limit).sort("flowStartNanoseconds", direction=pymongo.ASCENDING)

    _df = get_base_dataframe(list(flows))

    limit = 200

    # calculate number of necessary time buckets
    time_bucket_size = 10000
    first_timestamp = _df.iloc[0]['timestamp'] - time_bucket_size
    last_timestamp = _df.iloc[limit - 1]['timestamp'] + 2 * time_bucket_size
    bucket_count = round((last_timestamp - first_timestamp) / time_bucket_size)

    # calculate starting points of time buckets within an array and build collection of dataframes (one dataframe for each time bucket)
    bucket_list = np.array([], dtype=int)
    bucket_collection = {}
    for _ in range(0, bucket_count):
        bucket_list = np.append(bucket_list, first_timestamp)
        bucket_collection[first_timestamp] = pd.DataFrame(columns=['timestamp', 'name'])
        first_timestamp += time_bucket_size

    # assign each flow from the db to a specific intervall (i.e., time bucket)
    bucket_intervalls = pd.DataFrame(pd.cut(_df['timestamp'], bucket_list))

    # iterate over time buckets, find the respective flows belonging to this bucket and add them to the respective dataframe of the bucket_collection
    for index, bucket in enumerate(bucket_list):
        next_bucket = bucket if index + 1 >= len(bucket_list) else bucket_list[index + 1]
        rslt = pd.arrays.IntervalArray(bucket_intervalls['timestamp']).overlaps(pd.Interval(bucket, next_bucket))
        if True in rslt:
            flow_index = np.where(rslt is True)[0]
            frame = pd.concat(objs=[bucket_collection[bucket], _df.iloc[flow_index]], ignore_index=True)
            bucket_collection[bucket] = [v for k, v in frame[['name']].to_dict('index').items()]

    # move bucket_collection into an array with each bucket being an inner array
    baskets = []
    for key, value in bucket_collection.items():
        baskets.append(value)
        print(key)
