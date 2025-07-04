import paho.mqtt.client as mqtt
import ssl
import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config import MQTT_BROKER, MQTT_PORT, MQTT_PATH, MQTT_USERNAME,MQTT_PASSWORD


AGENT_ID = "klri90-w38jd-klsqp-45nmd2"
MQTT_TOPIC = "topic/OUT/agent/all"

def on_connect(client, userdata, flags, reasonCode, properties):
    print("[Listener] Connected with reason code:", reasonCode)
    client.subscribe(MQTT_TOPIC)
    print(f"[Listener] Subscribed to {MQTT_TOPIC}")

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        print(f"[Listener] Received reply:\n{json.dumps(payload, indent=2)}")

        # Example handling:
        if payload.get("flag") == "reply":
            task_id = payload.get("task_id")
            status = payload.get("return_reason", "unknown")
            print(f"[Listener] Task {task_id} status: {status}")

            # TODO: save to DB, notify frontend, etc.

    except Exception as e:
        print("[Listener] Error processing message:", e)

client = mqtt.Client(client_id=f"agent-{AGENT_ID}",transport="websockets", protocol=mqtt.MQTTv5)
client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
client.ws_set_options(path=MQTT_PATH)
client.tls_set(tls_version=ssl.PROTOCOL_TLS_CLIENT)
client.on_connect = on_connect
client.on_message = on_message
print(f"[Agent {AGENT_ID}] Connecting to {MQTT_BROKER}:{MQTT_PORT} ...")
client.connect(MQTT_BROKER, MQTT_PORT)
client.loop_forever()
