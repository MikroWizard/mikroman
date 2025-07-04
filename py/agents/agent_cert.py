import paho.mqtt.client as mqtt
import ssl
import json
import subprocess
import uuid
import time
import os
import sys


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from libs.mqtt_util import publish_reply
from libs.dogtag_client import submit_csr, retrieve_cert
from libs.cert_utils import generate_csr

from config import MQTT_BROKER, MQTT_PORT, MQTT_PATH, MQTT_USERNAME,MQTT_PASSWORD


AGENT_ID = "klri90-w38jd-klsqp-45nmd2"
MQTT_TOPIC = "topic/IN/agent/all"

AGENT_CN = "router1.cicrleprotect.io"
KEY_PATH = "/opt/pki/cert/private.key"
CSR_PATH = "/opt/pki/cert/request.csr"
CERT_PATH = "/opt/pki/cert/generated.crt"


def run_ansible(endpoint:dict):
    inventory_host = endpoint["ip"]
    remote_cert_path = endpoint["auth_path"]
    local_cert_path = CERT_PATH

    extra_vars = {
    "local_cert_path": local_cert_path,
    "remote_cert_path": remote_cert_path
    }       

    cmd = [
    "ansible-playbook", "ansible/install_cert.yml",
    "-i", f"{inventory_host},",
    "--extra-vars", json.dumps(extra_vars)
    ]   
    print(f"[Agent {AGENT_ID}] Running Ansible: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[Agent {AGENT_ID}] Ansible success:\n{result.stdout}")
        return 200, "completed"
    except subprocess.CalledProcessError as e:
        print(f"[Agent {AGENT_ID}] Ansible error:\n{e.stderr}{e}")
        return 500, "error"



def on_connect(client, userdata, flags, reasonCode,properties):
    print(f"[Agent {AGENT_ID}] Connected with result code {reasonCode}")
    if reasonCode == 0:
        client.subscribe(MQTT_TOPIC)
        print(f"[Agent {AGENT_ID}] Subscribed to {MQTT_TOPIC}")
    else:
        print("[Agent] Connection failed")


def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        print(f"[Agent {AGENT_ID}] Received on {msg.topic}: {msg.payload.decode()} eceived:\n{json.dumps(data, indent=2)}")

        if data.get("flag") != "request":
            print("[Agent] Ignoring non-request message")
            return       
      
        if (
            data.get("flag") == "request" and
            data.get("assigned") == True and
            data.get("agent_id") == AGENT_ID
        ):
            task_id = data.get("task_id")
            endpoint = data.get("endpoint")

            # Step 1: Generate CSR
            generate_csr(AGENT_CN, KEY_PATH, CSR_PATH)

            # Step 2: Submit to Dogtag
            request_id = submit_csr(CSR_PATH)
            if not request_id:
                publish_reply(AGENT_ID, task_id, 500, "csr_submission_failed")
                return

            input("Press Enter after certificate is issued in Dogtag...")

            # Step 3: Retrieve certificate
            if not retrieve_cert(request_id, CERT_PATH):
                publish_reply(AGENT_ID, task_id, 500, "cert_retrieval_failed")
                return

            # Step 4: Acknowledge start
            publish_reply(AGENT_ID, task_id, 200, "in_progress")

            # Step 5: Push to router
            code, status = run_ansible(endpoint)
            publish_reply(AGENT_ID, task_id, code, status)
        else:
            print("[Agent] Ignoring message not assigned to this agent") 
                       
    except Exception as e:
        print(f"[Agent] Error: {e}")


if __name__ == "__main__":
    client = mqtt.Client(client_id=f"agent-{AGENT_ID}", transport="websockets",protocol=mqtt.MQTTv5)
    client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    client.ws_set_options(path=MQTT_PATH)
    client.tls_set(tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.on_connect = on_connect
    client.on_message = on_message

    print(f"[Agent {AGENT_ID}] Connecting to {MQTT_BROKER}:{MQTT_PORT} ...")
    client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
    client.loop_forever()
