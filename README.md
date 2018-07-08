# VirusTotalScanner

VirusTotalScanner is a Python script that utilizes the VirusTotal API to scan local files for malware. The installer script will add a compiled version of VirusTotalScanner to your context menu, allowing you to scan any program with a mere two clicks!

After your scan you will get a pop-up message in your tray with the detection rate. It will also produce a more detailed text file where you can see which anti-virus detected your program and what it detected.

You will have to enter your VirusTotal public API key the first time you try to scan a program or if it is invalid. To get an API key, simply sign up to VirusTotal and find your key in the [settings](https://www.virustotal.com/#/settings/apikey).

To get started using VirusTotalScanner, simply download and execute the [installer](https://github.com/henriksb/VirusTotalScanner/releases/download/1/VirusTotalScanner_Installer.exe).

![GIF](https://raw.githubusercontent.com/henriksb/VirusTotalScanner/master/gif.gif)

## Releases

There are currently two different [releases](https://github.com/henriksb/VirusTotalScanner/releases) available.

[First release](https://github.com/henriksb/VirusTotalScanner/releases/download/6/VirusTotalScanner_Installer.exe) (Only scanning)
[Second release](https://github.com/henriksb/VirusTotalScanner/releases/download/14/VirusTotal_Installer.exe) (Scanning and upload)

## TODO:

- Add upload to VirusTotal feature (in case md5 checksum does not exist)
