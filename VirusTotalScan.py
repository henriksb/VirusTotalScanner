import requests
import hashlib
from sys import argv, exit
from pymsgbox import alert, prompt
from os import path, getenv
from TrayMessage import WindowsBalloonTip


def balloon_tip(title, msg):
    """Pop-up messagebox"""
    w = WindowsBalloonTip(title, msg)


def md5(file_name):
    """Gets file checksum"""
    hash_md5 = hashlib.md5()
    with open(file_name, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def add_api_key(message, title):
    api_key_path = open(API_PATH, "w")
    alert(message, title)
    key = prompt('Public API key:')
    # re-prompt user until the key is valid (by checking length)
    if len(key) != 64: add_api_key("Invalid key entered. Please re-enter public key", "Invalid key entered")

    api_key_path.write(key)
    api_key_path.close()


if len(argv) != 2: exit(1)  # exits if it is not started from context menu

USERNAME = getenv('username')
API_PATH = r"C:\Users\{}\vt_public_api".format(USERNAME)  # put api in this folder to prevent issues with permissions

# if api key is not present on the computer, add it
if not path.exists(API_PATH):
    add_api_key("Please enter your public API key", "Public API key required")
elif len(open(API_PATH, "r").read()) != 64:
    add_api_key("API key found, but not valid. Please re-enter public key.", "Public API key required")

PUBLIC_API_KEY = open(API_PATH, "r").read()
CHECKSUM = md5(argv[1])  # "53a0a94fcd38c422caf334b44638c03d" (Mimikatz)

URL = 'https://www.virustotal.com/vtapi/v2/file/report'
PARAMS = {'apikey': PUBLIC_API_KEY, 'resource': CHECKSUM}

# try except to prevent generic error message and provide a more descriptive message
try:
    response = requests.get(URL, params=PARAMS)
except requests.RequestException:
    balloon_tip("No internet", "Internet is required to scan item!")
    exit(1)

# also replaces generic error message
try:
    response = response.json()
except ValueError:
    balloon_tip("No results", "There might be a problem with your API key or scanning frequency.")
    exit(1)

if "scans" not in response:
    balloon_tip("Checksum not in database", response["verbose_msg"])
    exit(1)

PROGRAM_NAME = argv[1].split("\\")[-1]
SCAN_REPORT = open(r"C:\Users\{}\Scan report of {}.txt".format(USERNAME, PROGRAM_NAME), "a")

for scan in response["scans"]:
    SCAN_REPORT.write("%-20s" % scan + " - Detection: " + str(response["scans"][scan]["detected"]))
    if response["scans"][scan]["detected"]: SCAN_REPORT.write(" (%s)" % response["scans"][scan]["result"])
    SCAN_REPORT.write("\n")

SCAN_REPORT.write("\nDetection ratio: " + str(response["positives"]) + "/" + str(response["total"]))
SCAN_REPORT.close()

balloon_tip("Scan finished", "Detection ratio: " + str(response["positives"]) + "/" + str(response["total"]) +
            "\nFull report written to C:\\Users\\{}\\Scan report of {}.txt".format(USERNAME, PROGRAM_NAME))
