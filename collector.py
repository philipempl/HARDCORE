"""
A module for collecting MQTT IPFIX-netflows and export them to a MongoDB database.
"""
import argparse
import json
import logging
import queue
import signal
import socket
import socketserver
import threading
import time
from collections import namedtuple

from modules.mqtt.ipfix_template import MqttIpfixTemplate
from modules.mqtt_collector.mongodb_connector import MongoDbConnector
from modules.netflow_tmp.utils import UnknownExportVersion, parse_packet
from modules.netflow_tmp.ipfix import IPFIXTemplateNotRecognized

MqttIpfixTemplate.add_mqtt_ies_to_netflow_lib()

RawPacket = namedtuple('RawPacket', ['ts', 'client', 'data'])
ParsedPacket = namedtuple('ParsedPacket', ['ts', 'client', 'export'])

# Amount of time to wait before dropping an undecodable ExportPacket
PACKET_TIMEOUT = 60 * 60

logger = logging.getLogger("mqtt_collector")
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


class QueuingRequestHandler(socketserver.BaseRequestHandler):
    """
    A queueing server that receives packets from the collector and stores them in a queue.
    """
    def handle(self):
        data = self.request[0]  # get content, [1] would be the socket
        self.server.queue.put(RawPacket(time.time(), self.client_address, data))
        logger.debug("Received %s bytes of data from %s:%s", len(data), self.client_address[0], self.client_address[1])


class QueuingUDPListener(socketserver.ThreadingUDPServer):
    """A threaded UDP server that adds a (time, data) tuple to a queue for
    every request it sees
    """

    def __init__(self, interface, request_queue):
        self.queue = request_queue

        # If IPv6 interface addresses are used, override the default AF_INET family
        if ":" in interface[0]:
            self.address_family = socket.AF_INET6

        super().__init__(interface, QueuingRequestHandler)


class ThreadedIpfixListener(threading.Thread):
    """A thread that listens for incoming IPFIX packets, processes them, and
    makes them available to consumers.

    - When initialized, will start listening for NetFlow packets on the provided
      host and port and queuing them for processing.
    - When started, will start processing and parsing queued packets.
    - When stopped, will shut down the listener and stop processing.
    - When joined, will wait for the listener to exit

    For example, a simple script that outputs data until killed with CTRL+C:
    >>> listener = ThreadedNetFlowListener('0.0.0.0', 2055)
    >>> print("Listening for NetFlow packets")
    >>> listener.start() # start processing packets
    >>> try:
    ...     while True:
    ...         ts, export = listener.get()
    ...         print("Time: {}".format(ts))
    ...         for f in export.flows:
    ...             print(" - {IPV4_SRC_ADDR} sent data to {IPV4_DST_ADDR}"
    ...                   "".format(**f))
    ... finally:
    ...     print("Stopping...")
    ...     listener.stop()
    ...     listener.join()
    ...     print("Stopped!")
    """

    def __init__(self, host: str, port: int):
        logger.info("Starting the IPFIX listener on %s:%s", host, port)
        self.output = queue.Queue()
        self.input = queue.Queue()
        self.server = QueuingUDPListener((host, port), self.input)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self._shutdown = threading.Event()
        super().__init__()

    def get(self, block=True, timeout=None) -> ParsedPacket:
        """Get a processed flow.

        If optional args 'block' is true and 'timeout' is None (the default),
        block if necessary until a flow is available. If 'timeout' is
        a non-negative number, it blocks at most 'timeout' seconds and raises
        the queue.Empty exception if no flow was available within that time.
        Otherwise ('block' is false), return a flow if one is immediately
        available, else raise the queue.Empty exception ('timeout' is ignored
        in that case).
        """
        return self.output.get(block, timeout)

    def run(self):
        # Process packets from the queue
        try:
            templates = {"netflow": {}, "ipfix": {}}
            to_retry = []
            while not self._shutdown.is_set():
                try:
                    # 0.5s delay to limit CPU usage while waiting for new packets
                    pkt = self.input.get(block=True, timeout=0.5)  # type: RawPacket
                except queue.Empty:
                    continue

                try:
                    # templates is passed as reference, updated in V9ExportPacket
                    parsed_packet = parse_packet(pkt.data, templates)
                except UnknownExportVersion as error:
                    logger.error("%s, ignoring the packet", error)
                    continue
                except IPFIXTemplateNotRecognized:
                    if time.time() - pkt.ts > PACKET_TIMEOUT:
                        logger.warning("Dropping an old and undecodable v9/IPFIX ExportPacket")
                    else:
                        to_retry.append(pkt)
                        logger.debug("Failed to decode a v9/IPFIX ExportPacket - will "
                                     "re-attempt when a new template is discovered")
                    continue

                if parsed_packet.header.version == 10:
                    logger.debug("Processed an IPFIX ExportPacket with length %d.", parsed_packet.header.length)

                # If any new templates were discovered, dump the unprocessable
                # data back into the queue and try to decode them again
                if parsed_packet.header.version in [9, 10] and parsed_packet.contains_new_templates and to_retry:
                    logger.debug("Received new template(s)")
                    logger.debug("Will re-attempt to decode %d old v9/IPFIX ExportPackets", len(to_retry))
                    for packet in to_retry:
                        self.input.put(packet)
                    to_retry.clear()

                self.output.put(ParsedPacket(pkt.ts, pkt.client, parsed_packet))
        finally:
            # Only reached when while loop ends
            self.server.shutdown()
            self.server.server_close()

    def stop(self):
        """Stop the listener"""
        logger.info("Shutting down the IPFIX listener")
        self._shutdown.set()

    def join(self, timeout=None):
        self.thread.join(timeout=timeout)
        super().join(timeout=timeout)


def get_export_packets(host: str, port: int) -> ParsedPacket:
    """A threaded generator that will yield ExportPacket objects until it is killed
    """
    def handle_signal(input_signal, handler):
        logger.debug("Received signal %d, raising %d: StopIteration", input_signal, handler)
        raise StopIteration

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    listener = ThreadedIpfixListener(host, port)
    listener.start()

    try:
        while True:
            yield listener.get()
    except StopIteration:
        pass
    finally:
        listener.stop()
        listener.join()


if __name__ == "mqtt-probe.collector":
    logger.error("The collector is currently meant to be used as a CLI tool only.")
    logger.error("Use 'python3 -m mqtt-probe.collector -h' in your console for additional help.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A collector for MQTT-based IPFIX.")
    parser.add_argument("--host", type=str, default="127.0.0.1",
                        help="collector listening address")
    parser.add_argument("--port", "-p", type=int, default=2055,
                        help="collector listener port")
    parser.add_argument("--mongo_url", type=str, default="mongodb://localhost:27017",
                        help="mongodb address")
    parser.add_argument("--mongo_collection", type=str, default="mind2",
                        help="custom collection name of mongodb")
    parser.add_argument("--file", "-o", type=str, dest="output_file",
                        default=f"{int(time.time())}.gz",
                        help="collector export multiline JSON file")
    parser.add_argument("--debug", "-D", action="store_true",
                        help="Enable debug output")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)

    db = MongoDbConnector(args.mongo_url, args.mongo_collection)

    try:
        for ts, client, export in get_export_packets(args.host, args.port):
            for flow in export.flows:
                db.insert_one(flow.data)
            entry = {ts: {
                "client": client,
                "header": export.header.to_dict(),
                "flows": [flow.data for flow in export.flows]}
            }
            line = json.dumps(entry).encode() + b"\n"  # byte encoded line
            '''with gzip.open(args.output_file, "ab") as fh:  # open as append, not reading the whole file
                fh.write(line)'''
    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt, passing through")
