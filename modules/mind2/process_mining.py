"""
Module for process mining based on mqtt network flows.
"""

import datetime
import pandas as pd
import pm4py
from pm4py.algo.filtering.dfg import dfg_filtering
from pm4py.visualization.dfg import visualizer as dfg_visualizer
from modules.mqtt_collector.mongodb_connector import MongoDbConnector


def petri_net_heuristic_miner(data_frame: pd.DataFrame, dependency_threshold: float ):
    """
    Process mining based on heuristic miner with a petri net as output.
    """
    net, initial_marking, final_marking = pm4py.discover_petri_net_heuristics(data_frame, dependency_threshold=dependency_threshold)
    gviz = pm4py.visualization.petri_net.visualizer.apply(
        net,
        initial_marking,
        final_marking,
        variant=pm4py.visualization.petri_net.visualizer.Variants.PERFORMANCE,
        parameters={"format": "svg"})
    pm4py.visualization.petri_net.visualizer.view(gviz)
    return (net, initial_marking, final_marking)


def petri_net_inductive_miner(data_frame, noise_threshold):
    """
    Process mining based on inductive miner with a petri net as output.
    """
    net, initial_marking, final_marking = pm4py.discover_petri_net_inductive(data_frame, noise_threshold=noise_threshold)
    pm4py.view_petri_net(net, initial_marking, final_marking)

    tree = pm4py.discover_process_tree_inductive(data_frame)

    pm4py.view_process_tree(tree)   


def directly_follows_graph(data_frame):
    """
    Process mining based on directly follows grap logic.
    """
    _dfg, _sa, _ea = pm4py.discover_directly_follows_graph(data_frame)
    activities_count = pm4py.get_event_attribute_values(data_frame, "concept:name")

    _dfg, _sa, _ea, activities_count = dfg_filtering.filter_dfg_on_activities_percentage(_dfg, _sa, _ea, activities_count, 0.75)

    act_freq = dict(data_frame["concept:name"].value_counts())
    gviz_freq = dfg_visualizer.apply(_dfg, variant=dfg_visualizer.Variants.FREQUENCY, activities_count=act_freq, parameters={"format": "svg"})
    dfg_visualizer.view(gviz_freq)
    #gviz_perf = dfg_visualizer.apply(_dfg, variant=dfg_visualizer.Variants.PERFORMANCE, activities_count=act_freq, parameters={"format": "svg"})
    #dfg_visualizer.view(gviz_perf)
    #pm4py.view_dfg(_dfg, _sa, _ea, format="svg")


def start_process_mining():
    """
    Get flows as documents from mongodb, build dataframe and apply process mining in the dataframe.
    """
    limit = 100000

    # get data from db
    #_db = MongoDbConnector("mongodb://192.168.2.171:27017/", "evaluation")
    _db = MongoDbConnector("mongodb://localhost:27017/", "yummy")


    # build dataframe with relevant data from db results
    rows = []
    for flow in list(_db.collection.find({"mqttControlType": 3}).limit(limit).sort('flowStartNanoseconds')):
        timestamp = datetime.datetime.fromtimestamp(int(str(flow['flowStartNanoseconds'][0])+str(flow['flowStartNanoseconds'][1]))/1e9)
        correlation_data = flow['mqttCorrelationData']
        topic = flow['mqttTopic']

        if flow['mqttSrcClientId'] == 'NODE-RED' or flow['mqttSrcClientId'] == '192.168.2.171:50758':
            continue

        if flow['mqttSrcClientId'] == 'MQTT Broker':
            client = flow['mqttTopic']
        else:
            client = flow['mqttSrcClientId']

        rows.append([timestamp, correlation_data, client, topic])

    _df = pd.DataFrame(rows, columns=['time:timestamp', 'case:concept:name', 'concept:name', 'concept:resource'])
    print(len(_df))

    _net, _im, _fm = petri_net_heuristic_miner(_df, 0.7)
    #directly_follows_graph(_df)
    #petri_net_inductive_miner(_df, 0.99)
    # from pm4py.algo.conformance.tokenreplay import algorithm as token_replay
    # replayed_traces = token_replay.apply(df.tail(10000), net, im, fm)
    # print("Token based replay heuristic petri net: ")
    # print(replayed_traces[0]["trace_fitness"])
