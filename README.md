# Alert Context Automation

This is a simple script that checks the hash of a file through the VirusTotal API.

## Overview
- The script reads file hash from a JSON file.
- It queries the VirusTotal API to check if the file is flagged as malicious.
- It retunrs the scan results.

## Requirements
- Python 3.x
- requests library (install via 'pip insatll requests'
- A valid **VirusTotal API key**
- A JSON file containing the hash
