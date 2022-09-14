# MQTT Probe

## Installation

pip install -r requirements.txt

## Configuration

Change interface in [/config/config.py](https://git.uni-regensburg.de/iot-monitoring/mqtt-probe/-/blob/master/config/config.py).

## Deployment

py probe.py -i "LAN-Verbindung 2" -f "tcp" -c "192.168.2.171" -p 2055 -l "DEBUG"
