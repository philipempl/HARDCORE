FROM python:latest
ENV DEBIAN_FRONTEND noninteractive
ENV COLLECTOR '0.0.0.0'
ENV COLLECTOR_PORT '1883'
ENV MONGO_URL: 'mongodb://localhost:27017/'
RUN apt update && apt-get install -y tshark
COPY requirements.txt requirements.txt
COPY modules/mqtt/ modules/mqtt/
COPY modules/mqtt_probe/ modules/mqtt_probe/
COPY modules/mqtt_collector/ modules/mqtt_collector/
COPY modules/netflow_tmp/ modules/netflow_tmp/
COPY collector.py collector.py
RUN pip install -r requirements.txt
CMD ["sh", "-c", "python3 -m collector --host ${HOST} --port ${PORT} --mongo_url ${MONGO_URL} --mongo_collection ${MONGO_COLLECTION} --debug"]