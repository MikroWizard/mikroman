import paho.mqtt.client as mqtt
import ssl
import json
import socket
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


from config import MQTT_BROKER, MQTT_PORT, MQTT_PATH, MQTT_USERNAME,MQTT_PASSWORD


RESULT_TOPIC = "topic/OUT/agent/+"


def on_connect(client, userdata, flags, rc):
    print(f"[Resize Agent-0] Connected with result code {rc}")
    if rc == 0:
        print(f"[Resize Agent-1] Subscribing to {RESULT_TOPIC}")
        client.subscribe(RESULT_TOPIC)
    else:
        print("[Resize Agent-2] Failed to connect")

def on_message(client, userdata, msg):
    print(f"[Resize Agent-3] Received on topic {msg.topic}: {msg.payload.decode()}")
    try:
        reply = json.loads(msg.payload.decode())
        task_id = reply.get("task_id")
        status = reply.get("status")
        message = reply.get("message")
        # You can optionally store to DB or print
        print(f"[Listener] Task {task_id} completed with status: {status}")
        print(f"[Listener] Message: {message}")

    except Exception as e:
        print(f"[Resize Agent-5] Error: {e}")

# ⬇️ THESE LINES MUST BE OUTSIDE THE FUNCTIONS
if __name__ == "__main__":
    try :
        client = mqtt.Client(client_id="backend-listener", transport="websockets", protocol=mqtt.MQTTv311)
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD) 
        client.on_connect = on_connect
        client.on_message = on_message

        print("[Resize Agent-6] Setting WebSocket path…")
        client.ws_set_options(path=MQTT_PATH)


        print("[Resize Agent-7] Setting up TLS…")
        client.tls_set(tls_version=ssl.PROTOCOL_TLS_CLIENT)
        client.enable_logger()
        print(f"[Resize Agent-8] Connecting to {MQTT_BROKER}:{MQTT_PORT} …")
        
        print("Resolved IP:", socket.gethostbyname(MQTT_BROKER))
        client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)

        print("[Resize Agent-9] Starting loop_forever()")
        client.loop_forever()
        print(f"[Listener] Connecting to {MQTT_BROKER}:{MQTT_PORT}...")
    
    

    except Exception as e:
        print("error",e)
