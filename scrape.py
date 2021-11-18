#!/usr/bin/python3

import requests
import pandas as pd
from bs4 import BeautifulSoup
import subprocess
from atlassian import Confluence

#remove old output file#
subprocess.call("rm -rf myfile.txt results.txt page_data_open page_data_resolved", shell=True)

os_versions = [ "12.3R12-S15", "20.2R3-S2" ]

for os_version in os_versions:
    r = requests.get('http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=junos+{}'.format(os_version))
    c = r.content

    soup = BeautifulSoup(c, "html.parser")

    main_content = soup.find('div', attrs = {'id': 'TableWithRules'})
    content = main_content.find('table').text
    file1 = open("myfile.txt", "a")
    file1.write(content)
    file1.close()

subprocess.call("sed -i '/^.*CVE/{N;s/\\n */# /}' myfile.txt", shell=True)
subprocess.call("sed -i '/^.*Name/d' myfile.txt", shell=True)
subprocess.call("sed -i '/^.*Description/d' myfile.txt", shell=True)
subprocess.call("sed -i '/^$/d' myfile.txt", shell=True)
subprocess.call("sed -i 's/<<<//g' myfile.txt", shell=True)
subprocess.call("sed -i 's/<>//g' myfile.txt", shell=True)

def content_for_new_page():
        result_file = open ("myfile.txt","r")
        result_file_final = open ("results.txt","a")
        for result_line in result_file:
                fields = result_line.split("#")
                result_file_final.write("<tr><td>Junos "+os_version+"</td><td>"+fields[0]+"</td><td>"+fields[1].strip('\n')+"</td><td></td><td></td><td></td></tr>")

        f = open ("results.txt","r+")
        final_content1 = f.read()
        f.seek(0,0)
        f.write("<table><tr><td>Junos OS version</td><td>CVE No</td><td>CVE Desc</td><td>Resolution</td><td>Assigned Engineer</td><td>Status</td></tr>\n"+final_content1)
        f.close


        f1 = open ("results.txt","a")
        f1.write("</table>\n")
        f1.close()

        file_to_read = open('results.txt', "r")
        file_content = file_to_read.read()

def update_existing_page():
        input_file = open ("myfile.txt","r")
        result_file_final = open ("vul.txt","a")
        for result_line in input_file:
                fields = result_line.split("#")
                result_file_final.write("<tr><td>Junos "+os_version+"</td><td>"+fields[0]+"</td><td>"+fields[1].strip('\n')+"</td><td></td><td></td><td></td></tr>\n")



confluence = Confluence(
    url='http://192.168.122.133:8090',
    username='admin',
    password='Skyfall@007')


def create_page():
        status = confluence.create_page(
            space="NI",
            title='This '+' Title',
            body='<strong>Vulnerability Report</strong>')


def append_page():
        status = confluence.append_page(page_id=1703954,title='This '+'Title', append_body=file_content, parent_id=None, type='page', representation='storage', minor_edit=False)
        print(status)

def update_page_open():

        file_to_read = open('page_data_open', "r")
        file_content = file_to_read.read()
        file_to_read.close()

        status = confluence.update_page(page_id=1703954,title='Vulnerability '+'Report', body=file_content, parent_id=None, type='page', representation='storage', minor_edit=False)
        print(status)


def update_page_resolved():

        file_to_read = open('page_data_resolved', "r")
        file_content = file_to_read.read()
        file_to_read.close()

        status = confluence.update_page(page_id=2162693,title='Resolved '+'vulnerabilities', body=file_content, parent_id=None, type='page', representation='storage', minor_edit=False)


def download_page_open():
        page_content = confluence.get_page_by_id(page_id=1703954,expand='body.storage').get('body').get('storage').get('value')
        f = open("page_data_open","w")
        f.write(page_content)
        f.close()
        subprocess.call("sed -i 's|</tr>|</tr>\\n|g' page_data_open", shell=True)

def download_page_resolved():
        page_content = confluence.get_page_by_id(page_id=2162693,expand='body.storage').get('body').get('storage').get('value')
        f = open("page_data_resolved","w")
        f.write(page_content)
        f.close()
        subprocess.call("sed -i 's|</tr>|</tr>\\n|g' page_data_resolved", shell=True)


update_existing_page()
#create_page()
#append_page()
#download_page()

download_page_open()
download_page_resolved()

subprocess.run("./page_format.bash")

update_page_open()
update_page_resolved()
