#!/usr/bin/python3

import requests
import pandas as pd
from bs4 import BeautifulSoup
import subprocess

#remove old output file#
subprocess.call("rm -rf myfile.txt", shell=True)

os_versions = [ "12.3R12-S15", "20.2R3-S2" ]

for os_version in os_versions:
    r = requests.get('http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=junos+{}'.format(os_version))
    c = r.content

    soup = BeautifulSoup(c, "html.parser")

    main_content = soup.find('div', attrs = {'id': 'TableWithRules'})
    content = main_content.find('table').text
    file1 = open("myfile.txt", "a")
    file1.write("Printing CVE details for Junos version:"+ os_version + "\n")
    file1.write(content)
    file1.close()

subprocess.call("sed -i '/^.*CVE/{N;s/\\n */, /}' myfile.txt", shell=True)
subprocess.call("sed -i '/^.*Name/{N;s/\\n */, /}' myfile.txt", shell=True)
