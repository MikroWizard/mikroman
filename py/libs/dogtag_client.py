import requests
import base64

DOGTAG_URL = "https://ca.networklab.ca"
DOGTAG_USER = "caadmin"
DOGTAG_PASS = "password"

def submit_csr(csr_path: str):
    with open(csr_path, "rb") as f:
        csr_bytes = f.read()
        csr_b64 = base64.b64encode(csr_bytes).decode()

        payload = {
            "profileId": "caUserCert",
            "input": [
                {"name": "cert_request_type", "value": "crmf"},
                {"name": "cert_request", "value": csr_b64}
            ]
        }

        headers = {"Content-Type": "application/json"}

        response = requests.post(
            f"{DOGTAG_URL}/certrequests",
            json=payload,
            # auth=(DOGTAG_USER, DOGTAG_PASS),
            headers=headers,
            verify=False
        )

        if response.status_code == 200:
            data = response.json()
            request_id = data.get("requestId")
            print(f"[DOGTAG] Certificate request submitted, ID: {request_id}")
            return request_id
        else:
            print(f"[DOGTAG ERROR] {response.status_code}")
            print(response.text)
            return None
        

def retrieve_cert(request_id: str, output_path: str):
    cert_url = f"{DOGTAG_URL}/certrequests/{request_id}/certificate"
    response = requests.get(cert_url, auth=(DOGTAG_USER, DOGTAG_PASS), verify=False)

    if response.status_code == 200:
        cert_data = response.content
        with open(output_path, "wb") as f:
            f.write(cert_data)
        print(f"[DOGTAG] Certificate saved to {output_path}")
        return True
    else:
        print("[DOGTAG ERROR] Unable to fetch certificate")
        return False