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
