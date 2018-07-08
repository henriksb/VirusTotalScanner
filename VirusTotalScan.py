"""
Simple script that utilizes VirusTotals API to scan local
files on your computer. There is an installer available for
this script that adds it to your context menu so that scanning
a program isn't harder than two clicks.

virustotal API refrence: https://developers.virustotal.com/v2.0/reference
author: henriksb
"""

import requests
import hashlib
from sys import exit, argv
from pymsgbox import alert, prompt
from os import path, getenv
from TrayMessage import WindowsBalloonTip


class Scan:
    def __init__(self, program):
        self.program_name = program.split("\\")[-1]
        self.checksum = md5(program)
        self.url = "https://www.virustotal.com/vtapi/v2/file/report"
        self.response = ""

        # if api key is not present on the computer, add it
        if not path.exists(API_PATH):
            self.api_key = add_api_key("Please enter your public API key", "Public API key required")
        elif len(open(API_PATH, "r").read()) != 64:
            self.api_key = add_api_key("API key found, but not valid. Please re-enter public key.",
                                       "Public API key required")
        else:
            self.api_key = open(API_PATH).read()

    def vp_scan(self):
        params = {'apikey': self.api_key, 'resource': self.checksum}

        # try except to prevent generic error message and provide a more descriptive message
        try:
            response = requests.get(self.url, params=params)
            self.response = response.json()
        except requests.RequestException:
            balloon_tip("No internet", "Internet is required to scan item!")
            exit(1)
        except ValueError:
            balloon_tip("No results", "There might be a problem with your API key or scanning frequency.")
            exit(1)

        if "scans" not in self.response:
            balloon_tip("Checksum not in database", self.response["verbose_msg"])
            exit(1)

        balloon_tip("Scan finished",
                    "Detection ratio: " + str(self.response["positives"]) + "/" + str(self.response["total"]) +
                    "\nFull report written to C:\\Users\\{}\\Scan report of {}.txt".format(USERNAME, self.program_name))

    def write_to_file(self):
        scan_report = open(r"C:\Users\{}\Scan report of {}.txt".format(USERNAME, self.program_name), "a")

        for scan in self.response["scans"]:
            scan_report.write("%-20s" % scan + " - Detection: " + str(self.response["scans"][scan]["detected"]))
            if self.response["scans"][scan]["detected"]: scan_report.write(" (%s)" % self.response["scans"][scan]["result"])
            scan_report.write("\n")

        scan_report.write("\nDetection ratio: " + str(self.response["positives"]) + "/" + str(self.response["total"]))
        scan_report.close()


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
    try:
        if len(key) != 64: add_api_key("Invalid key entered. Please re-enter public key", "Invalid key entered")
    except TypeError:
        exit(0)

    api_key_path.write(key)
    api_key_path.close()

    return key


if __name__ == "__main__":
    if len(argv) != 2: exit(1)  # exits if it is not started from context menu

    FILE = argv[1]
    USERNAME = getenv('username')
    API_PATH = r"C:\Users\{}\vt_public_api".format(USERNAME)  # put api in this folder to prevent issues with permissions

    VirusTotalScan = Scan(FILE)
    VirusTotalScan.vp_scan()
    VirusTotalScan.write_to_file()
