#!/bin/bash

##Store CVE numbers from Active CVE page##


awk -F '<td>' '{print $3}' page_data_open | tr -d '</td>' | grep CVE- >> active_cve.txt
awk -F '<td>' '{print $3}' page_data_resolved | tr -d '</td>' | grep CVE- >> resolved_cve.txt

cat active_cve.txt resolved_cve.txt >> overall_cve.txt
sort -u overall_cve.txt >> unique_cve.txt

#Remove CVEs already on the page#
for vul in $(<unique_cve.txt); do
 sed -i "/$vul/d" vul.txt
done

#Remove resolved CVEs from open CVE report page#
grep -i resolved page_data_open >> resolved_page.txt

#Remove Resolved CVEs from Open CVE page#
sed -i "/resolved/Id" page_data_open

## Input into page_data file##

sed -i '$e cat vul.txt' page_data_open
sed -i '$e cat resolved_page.txt' page_data_resolved

rm -rf active_cve.txt resolved_cve.txt overall_cve.txt unique_cve.txt resolved_page.txt

#Separate active and resovled CVEs for Cisco#
awk -F '<td>' '{print $3}' page_data_open_cisco | tr -d '</td>' | grep CVE- >> active_cve_cisco.txt
awk -F '<td>' '{print $3}' page_data_resolved_cisco | tr -d '</td>' | grep CVE- >> resolved_cve_cisco.txt

cat active_cve_cisco.txt resolved_cve_cisco.txt >> overall_cve_cisco.txt
sort -u overall_cve_cisco.txt >> unique_cve_cisco.txt

#Remove CVEs already on the page#
for vul in $(<unique_cve_cisco.txt); do
 sed -i "/$vul/d" results_cisco.txt
done

#Remove resolved CVEs from open CVE report page#
grep -i resolved page_data_open_cisco >> resolved_page_cisco.txt

#Remove Resolved CVEs from Open CVE page#
sed -i "/resolved/Id" page_data_open_cisco

## Input into page_data file##

sed -i '$e cat results_cisco.txt' page_data_open_cisco
sed -i '$e cat resolved_page_cisco.txt' page_data_resolved_cisco

rm -rf active_cve_cisco.txt resolved_cve_cisco.txt overall_cve_cisco.txt unique_cve_cisco.txt resolved_page_cisco.txt

#Separate active and resovled CVEs for F5#
awk -F '<td>' '{print $3}' page_data_open_f5 | tr -d '</td>' | grep CVE- >> active_cve_f5.txt
awk -F '<td>' '{print $3}' page_data_resolved_f5 | tr -d '</td>' | grep CVE- >> resolved_cve_f5.txt

cat active_cve_f5.txt resolved_cve_f5.txt >> overall_cve_f5.txt
sort -u overall_cve_f5.txt >> unique_cve_f5.txt

#Remove CVEs already on the page#
for vul in $(<unique_cve_f5.txt); do
 sed -i "/$vul/d" results_f5.txt
done

#Remove resolved CVEs from open CVE report page#
grep -i resolved page_data_open_f5 >> resolved_page_f5.txt

#Remove Resolved CVEs from Open CVE page#
sed -i "/resolved/Id" page_data_open_f5

## Input into page_data file##

sed -i '$e cat results_f5.txt' page_data_open_f5
sed -i '$e cat resolved_page_f5.txt' page_data_resolved_f5

rm -rf active_cve_f5.txt resolved_cve_f5.txt overall_cve_f5.txt unique_cve_f5.txt resolved_page_f5.txt

#Separate active and resovled CVEs for fortinet#
awk -F '<td>' '{print $3}' page_data_open_fortinet | tr -d '</td>' | grep CVE- >> active_cve_fortinet.txt
awk -F '<td>' '{print $3}' page_data_resolved_fortinet | tr -d '</td>' | grep CVE- >> resolved_cve_fortinet.txt

cat active_cve_fortinet.txt resolved_cve_fortinet.txt >> overall_cve_fortinet.txt
sort -u overall_cve_fortinet.txt | grep "CVE-202" >> unique_cve_fortinet.txt

#Remove CVEs already on the page#
for vul in $(<unique_cve_fortinet.txt); do
 sed -i "/$vul/d" results_fortinet.txt
done

#Remove resolved CVEs from open CVE report page#
grep -i resolved page_data_open_fortinet >> resolved_page_fortinet.txt

#Remove Resolved CVEs from Open CVE page#
sed -i "/resolved/Id" page_data_open_fortinet

## Input into page_data file##

sed -i '$e cat results_fortinet.txt' page_data_open_fortinet
sed -i '$e cat resolved_page_fortinet.txt' page_data_resolved_fortinet

rm -rf active_cve_fortinet.txt resolved_cve_fortinet.txt overall_cve_fortinet.txt unique_cve_fortinet.txt resolved_page_fortinet.txt

#Separate active and resovled CVEs for paloalto#
awk -F '<td>' '{print $3}' page_data_open_paloalto | tr -d '</td>' | grep CVE- >> active_cve_paloalto.txt
awk -F '<td>' '{print $3}' page_data_resolved_paloalto | tr -d '</td>' | grep CVE- >> resolved_cve_paloalto.txt

cat active_cve_paloalto.txt resolved_cve_paloalto.txt >> overall_cve_paloalto.txt
sort -u overall_cve_paloalto.txt >> unique_cve_paloalto.txt

#Remove CVEs already on the page#
for vul in $(<unique_cve_paloalto.txt); do
 sed -i "/$vul/d" results_paloalto.txt
done

#Remove resolved CVEs from open CVE report page#
grep -i resolved page_data_open_paloalto >> resolved_page_paloalto.txt

#Remove Resolved CVEs from Open CVE page#
sed -i "/resolved/Id" page_data_open_paloalto

## Input into page_data file##

sed -i '$e cat results_paloalto.txt' page_data_open_paloalto
sed -i '$e cat resolved_page_paloalto.txt' page_data_resolved_paloalto

rm -rf active_cve_paloalto.txt resolved_cve_paloalto.txt overall_cve_paloalto.txt unique_cve_paloalto.txt resolved_page_paloalto.txt

