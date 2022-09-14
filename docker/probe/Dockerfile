FROM python:latest
ENV DEBIAN_FRONTEND noninteractive
ENV INTERFACE 'utun7'
ENV COLLECTOR '127.0.0.1'
ENV PORT '1883'
ENV LOG_LEVEL 'INFO'
RUN apt update && apt-get install -y tshark
COPY requirements.txt requirements.txt
COPY modules/mqtt/ modules/mqtt/
COPY modules/mqtt_probe/ modules/mqtt_probe/
COPY modules/mqtt_collector/ modules/mqtt_collector/
COPY modules/netflow_tmp/ modules/netflow_tmp/
COPY probe.py probe.py
RUN pip install -r requirements.txt
CMD ["sh", "-c", "python3 -m probe --collector ${COLLECTOR} --port ${PORT} --interface ${INTERFACE} --log-level ${LOG_LEVEL}"]