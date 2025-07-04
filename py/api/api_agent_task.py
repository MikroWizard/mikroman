from flask import Blueprint, request, jsonify
from libs.mqtt_util import publish_task
from flask import Blueprint, request, jsonify
import uuid
import time
from libs.mqtt_util import publish_task


bp = Blueprint("agent_task_api", __name__, url_prefix="/api/agent/task")


@bp.route('/assign', methods=['POST'])
def assign_task():
    try:
        data = request.get_json(force=True)

        task_id = str(uuid.uuid4())
        timestamp = time.strftime("%d-%b-%Y-%H:%M:%S")

          # Validate required fields
        required = ["type", "service", "client_id", "agent_id", "endpoint"]
        for key in required:
            if key not in data:
                return jsonify({"error": f"Missing required field: {key}"}), 400

        payload = {
            "task_id": task_id,
            "type": data["type"],
            "service": data["service"],
            "client_id": data["client_id"],
            "git_auth": data.get("git_auth", "key"),
            "timestamp": timestamp,
            "endpoint": data["endpoint"],
            "agent_id": data["agent_id"],
            "assigned": True,
            "flag": "request"
        }

        publish_task(data["agent_id"], payload)
        return jsonify({"status": "task published", "task_id": task_id})

        # task_type = data.get("task_type")
        # payload = data.get("payload")
        # if not task_type or not isinstance(payload, dict):
        #     return jsonify({"error": "Missing or invalid task_type or payload"}), 400

        # topic = f"task/{task_type}"
        # publish_task(topic, payload)
        # return jsonify({"message": f"Task published to topic {topic}"}), 200

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500