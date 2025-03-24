import json
import requests

# VirusTotal API
VT_API_KEY = "your_api_key"

# Name of our JSON file
json_file = "alert_data.json"

with open(json_file, mode="r", encoding="utf-8") as read_file:
    # Getting dictionary from list
    dt = json.load(read_file)[0]

threat_data = {
    "date": dt['date'],
    "event_id": dt['event_type_id'],
    "severity": dt['severity'],
    "hostname": dt['computer']['hostname'],
    "destination_ip": dt['computer']['network_addresses'][0]['ip'],
    "user": dt['computer']['user'],
    "detection": dt['detection'],
    "file_name": dt['file']['file_name'],
    "file_path": dt['file']['file_path'],
    "sha256": dt['file']['identity']['sha256'],
}

def virustotal_analyze(sha):
    """
    Analyze on the VirusTotal API status of a file with provided hash

    Parameters: sha256 from JSON file

    Returns: Analzye of the hash from VirusTotal API

    """
    url = f"https://www.virustotal.com/api/v3/files/{sha}"
    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        return result['data']['attributes']['last_analysis_stats']
    else:
        return f"VirusTotal site can not be accessed."
    
threat_data['analyze_detection'] = virustotal_analyze(threat_data['sha256'])

print(json.dumps(threat_data, indent=4))