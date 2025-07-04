import paho.mqtt.client as mqtt
import ssl
import json
import traceback
import socket
import uuid
from config import MQTT_BROKER, MQTT_PORT, MQTT_PATH, MQTT_USERNAME,MQTT_PASSWORD


def publish_task(agent_id: str, payload: dict):
    try:
        topic = "topic/IN/agent/all"
        # client = mqtt.Client(transport="websockets")
        client = mqtt.Client(client_id="resize-agent", transport="websockets", protocol=mqtt.MQTTv5)
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD) 
        # Enable TLS  
        client.tls_set(tls_version=ssl.PROTOCOL_TLS_CLIENT)
        client.ws_set_options(path=MQTT_PATH)
        # Connect and publish
        print(f"[DEBUG] MQTT Protocol Version: {client._protocol}")
        print("Resolved IP:", socket.gethostbyname(MQTT_BROKER))
        client.connect(MQTT_BROKER, MQTT_PORT, 120)
        
        client.loop_start()
        client.publish(topic, json.dumps(payload),retain=False)
        client.loop_stop()
        client.disconnect()
        print(f"[MQTT] Published to {topic}: {payload}")

    except Exception as e:
        print("**exception**",e)


def publish_reply(agent_id, task_id, return_code, return_reason):
    try:
        payload = {
        "task_id": task_id,
        "agent_id": agent_id,
        "flag": "reply",
        "return_code": return_code,
        "return_reason": return_reason,
        "timestamp": "2025-07-02T19:00:00"
    }

        topic = "topic/OUT/agent/all"
        client = mqtt.Client(client_id=f"agent-reply-{uuid.uuid4()}", transport="websockets", protocol=mqtt.MQTTv5)
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
        client.ws_set_options(path=MQTT_PATH)
        client.tls_set(tls_version=ssl.PROTOCOL_TLS_CLIENT)

        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        client.loop_start()
        client.publish(topic, json.dumps(payload), retain=False)
        client.loop_stop()
        client.disconnect()

        print(f"[MQTT] Published reply to {topic}: {payload}")
    except Exception as e:
        print("[MQTT Exception]", e)