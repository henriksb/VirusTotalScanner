import requests
import hashlib
from sys import argv, exit
from pymsgbox import alert, prompt
from os import path, getenv
from TrayMessage import WindowsBalloonTip


def balloon_tip(title, msg):
    w = WindowsBalloonTip(title, msg)


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def add_api_key(message, title):
    api_key_path = open(API_PATH, "w")
    alert(message, title)
    response = prompt('Public API key:')
    if len(response) != 64: add_api_key("Invalid key entered. Please re-enter public key", "Invalid key entered")

    api_key_path.write(response)
    api_key_path.close()


USERNAME = getenv('username')
API_PATH = r"C:\Users\{}\vt_public_api".format(USERNAME)  # put api in this path to prevent issues with permissions

if not path.exists(API_PATH): add_api_key("Please enter your public API key", "Public API key required")
elif len(open(API_PATH, "r").read()) != 64: add_api_key("API key found, but not valid. Please re-enter public key.", "Public API key required")

PUBLIC_API_KEY = open(API_PATH, "r").read()
CHECKSUM = md5(argv[1])  # "53a0a94fcd38c422caf334b44638c03d" (Mimikatz)

url = 'https://www.virustotal.com/vtapi/v2/file/report'
params = {'apikey': PUBLIC_API_KEY, 'resource': CHECKSUM}

response = requests.get(url, params=params)
try: response = response.json()
except ValueError:
    balloon_tip("No results", "There might be a problem with your API key or scanning frequency.")
    exit(0)

if not "scans" in response:
    balloon_tip("Checksum not in databse", response["verbose_msg"])
    exit(1)

with open("Scan report.txt", "a") as f:
    for scan in response["scans"]:
        f.write("%-20s" % scan + " - Detection: " + str(response["scans"][scan]["detected"]))
        if response["scans"][scan]["detected"]: f.write(" (%s)" % response["scans"][scan]["result"])
        f.write("\n")

    f.write("\nDetection ratio: " + str(response["positives"]) + "/" + str(response["total"]) + "\n\n-----------------------------------------------------")

balloon_tip("Scan finished", "Detection ratio: " + str(response["positives"]) + "/" + str(response["total"]))
