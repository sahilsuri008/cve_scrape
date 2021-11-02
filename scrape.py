#!/usr/bin/python3

import requests
import pandas as pd
from bs4 import BeautifulSoup

r = requests.get('https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=junos+12.3R12-S15')

c = r.content

soup = BeautifulSoup(c, "html.parser")

main_content = soup.find('div', attrs = {'id': 'TableWithRules'})
content = main_content.find('table').text
print (content)
