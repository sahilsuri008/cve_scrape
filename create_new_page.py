#!/usr/bin/python3

import requests
import pandas as pd
from bs4 import BeautifulSoup
import subprocess
from atlassian import Confluence

#remove old output file#
subprocess.call("rm -rf myfile.txt results_cisco.txt myfile_cisco.txt page_data_open page_data_resolved myfile_cisco_update_use.txt page_data_open_cisco page_data_resolved_cisco myfile_f5.txt  myfile_f5_update_use.txt  results_f5.txt", shell=True)

#Get OS versions for venodrs#
os_versions = [ "12.3R12-S15", "20.2R3-S2" ]
os_version_cisco_nexus = [ "7.3(5)D1(1)" ]
os_versions_f5 = [ "14.1.4.1", "15.0.1" ]

#Create file for Cisco Nexus#
def download_cve_info_cisco():
        for os_version_cisco in os_version_cisco_nexus:
                r = requests.get('http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=cisco+nexus-os+{}'.format(os_version_cisco))
                c = r.content

                soup = BeautifulSoup(c, "html.parser")

                main_content = soup.find('div', attrs = {'id': 'TableWithRules'})
                content = main_content.find('table').text
                file1 = open("myfile_cisco.txt", "a")
                file1.write(content)
                file1.close()

                subprocess.call("sed -i '/^.*CVE/{N;s/\\n */# /}' myfile_cisco.txt", shell=True)
                subprocess.call("sed -i '/^.*Name/d' myfile_cisco.txt", shell=True)
                subprocess.call("sed -i '/^.*Description/d' myfile_cisco.txt", shell=True)
                subprocess.call("sed -i '/^$/d' myfile_cisco.txt", shell=True)
                subprocess.call("sed -i 's/<<<//g' myfile_cisco.txt", shell=True)
                subprocess.call("sed -i 's/<>//g' myfile_cisco.txt", shell=True)

                result_file = open ("myfile_cisco.txt","r")
                result_file_final = open ("results_cisco.txt","a")
                for result_line in result_file:
                        fields = result_line.split("#")
                        result_file_final.write("<tr><td>NX-OS "+os_version_cisco+"</td><td>"+fields[0]+"</td><td>"+fields[1].strip('\n')+"</td><td></td><td></td><td></td></tr>")

        subprocess.call("cp -rp results_cisco.txt myfile_cisco_update_use.txt", shell=True)
        subprocess.call("sed -i 's|</tr>|</tr>\\n|g' myfile_cisco_update_use.txt", shell=True)
        f = open ("results_cisco.txt","r+")
        final_content1 = f.read()
        f.seek(0,0)
        f.write("<table><tr><td>Nexus OS version</td><td>CVE No</td><td>CVE Desc</td><td>Resolution</td><td>Assigned Engineer</td><td>Status</td></tr>\n"+final_content1)
        f.close

        f1 = open ("results_cisco.txt","a")
        f1.write("</table>")
        f1.close()

################################################

#Create file for F5 Big IP#
def download_cve_info_f5():
        for os_version_f5 in os_versions_f5:
                r = requests.get('http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=big+ip+{}'.format(os_version_f5))
                c = r.content

                soup = BeautifulSoup(c, "html.parser")

                main_content = soup.find('div', attrs = {'id': 'TableWithRules'})
                content = main_content.find('table').text
                file1 = open("myfile_f5.txt", "a")
                file1.write(content)
                file1.close()

                subprocess.call("sed -i '/^.*CVE/{N;s/\\n */# /}' myfile_f5.txt", shell=True)
                subprocess.call("sed -i '/^.*Name/d' myfile_f5.txt", shell=True)
                subprocess.call("sed -i '/^.*Description/d' myfile_f5.txt", shell=True)
                subprocess.call("sed -i '/^$/d' myfile_f5.txt", shell=True)
                subprocess.call("sed -i 's/<<<//g' myfile_f5.txt", shell=True)
                subprocess.call("sed -i 's/<>//g' myfile_f5.txt", shell=True)

                result_file = open ("myfile_f5.txt","r")
                result_file_final = open ("results_f5.txt","a")
                for result_line in result_file:
                        fields = result_line.split("#")
                        result_file_final.write("<tr><td>F5 Big IP OS "+os_version_f5+"</td><td>"+fields[0]+"</td><td>"+fields[1].strip('\n')+"</td><td></td><td></td><td></td></tr>")

        subprocess.call("cp -rp results_f5.txt myfile_f5_update_use.txt", shell=True)
        subprocess.call("sed -i 's|</tr>|</tr>\\n|g' myfile_f5_update_use.txt", shell=True)
        f = open ("results_f5.txt","r+")
        final_content1 = f.read()
        f.seek(0,0)
        f.write("<table><tr><td>F5 Big IP OS version</td><td>CVE No</td><td>CVE Desc</td><td>Resolution</td><td>Assigned Engineer</td><td>Status</td></tr>\n"+final_content1)

        f2 = open ("results_f5.txt","r+")
        f2.write("</table>")
        f2.close()

#############################################


confluence = Confluence(
    url='http://192.168.122.133:8090',
    username='admin',
    password='Skyfall@007')

#Cisco Confluence setup#

def create_page_cisco():

        file_to_read = open('results_cisco.txt', "r")
        file_content = file_to_read.read()
        file_to_read.close()

        status = confluence.create_page(
            space="NI",
            title='Vulnerability_Report_for_CiscoNexus',
            body=file_content)

def download_page_open_cisco():
        page_content = confluence.get_page_by_id(page_id=2457620,expand='body.storage').get('body').get('storage').get('value')
        f = open("page_data_open_cisco","w")
        f.write(page_content)
        f.close()
        subprocess.call("sed -i 's|</tr>|</tr>\\n|g' page_data_open_cisco", shell=True)


def download_page_resolved_cisco():
        page_content = confluence.get_page_by_id(page_id=2457614,expand='body.storage').get('body').get('storage').get('value')
        f = open("page_data_resolved_cisco","w")
        f.write(page_content)
        f.close()
        subprocess.call("sed -i 's|</tr>|</tr>\\n|g' page_data_resolved_cisco", shell=True)

def update_page_open_cisco():

        file_to_read = open('page_data_open_cisco', "r")
        file_content = file_to_read.read()
        file_to_read.close()
        status = confluence.update_page(page_id=2457620,title='Vulnerability_Report_for_CiscoNexus', body=file_content, parent_id=None, type='page', representation='storage', minor_edit=False)
        print(status)


def update_page_resolved_cisco():

        file_to_read = open('page_data_resolved_cisco', "r")
        file_content = file_to_read.read()
        file_to_read.close()
        status = confluence.update_page(page_id=2457614,title='resolved_cisco '+'vulnerabilities', body=file_content, parent_id=None, type='page', representation='storage', minor_edit=False)

####################################################

#F5 Confluence setup#
def create_page_f5():

        file_to_read = open('results_f5.txt', "r")
        file_content = file_to_read.read()
        file_to_read.close()

        status = confluence.create_page(
            space="NI",
            title='Vulnerability_Report_for_f5',
            body=file_content)

###################################################



download_cve_info_cisco()
#create_page_cisco()
download_page_open_cisco()
download_page_resolved_cisco()
subprocess.run("./page_format.bash")
update_page_open_cisco()
update_page_resolved_cisco()
download_cve_info_f5()
create_page_f5()
