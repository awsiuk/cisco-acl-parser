import re
import sys
import copy
import csv
import argparse
import os

#data structures
#Elements of this list will be based on 'policy' data strcuture (dictionary)
policies_set=[]
services_set=[]
hosts_set=[]

#define header for CVS, not used in any other purpose
policy_description=['VSYS','from-zone','to-zone',"policy-name", 'source-address','destination-address','application','source-identity',"global-from-zone","global-to-zone","action","application-name","category","description","tag"]

#fields mapping from SRX data strcutre SRX | PAOALTO (SRX parser project)
#source-identity from SRX = source-user
#application = service
#CISCO ASA/IOS do not use security zones thus it will be empty
#or it will be translated (in some version) to the interface name ifname (ifname should be used to refer to a security zone)
policy = {
"VSYS": "GLOBAL",
"from-zone": [],
"to-zone": [],
"policy-name": "",
"source-address": [],
"destination-address": [],
"application": [],
"source-identity": [],
"global-from-zone": [],
"global-to-zone": [],
"action": [],
"application-name": [],
"category": [],
"description": [],
"tag": []
}

service = {
    "name": "",
    "service": []
}

host = {
    "name": "",
    "address": []
}

#not yet used
acl_remark = (
    r'^access-list\s(?P<policy_name>[A-Za-z0-9\-\_]+)'
    r'\s+'
    r'remark\s+(?P<remark>.+)'
)


regex_ip_address = ( 
    r'([0-9]{1,3}\.){3}[0-9]{1,3}'
)

#when creating regex using {} then any regex expressions containing {} needs to be moved to variable
#otherwise when using .format it will through out an error while compliling the code
acl_general_structure = (
    r'access-list\s+(?P<policy_name>[\w\-]+)\s+extended\s+(?P<action>permit|deny)'
    r'\s'
    r'(?P<protocol>(\w+)|object-group\s[\w]+)'
    r'\s'
    r'(?P<source>(?:host\s({ipaddr}))|(?:object-group\s[\w\-]+)|(?:{ipaddr}\s{ipaddr})|any)'
    r'\s'
    r'(?P<destination>(?:host\s({ipaddr}))|(?:object-group\s[\w\-]+)|(?:{ipaddr}\s{ipaddr})|any)'
    r'(?:\s|$)'
    r'(?:(?P<service>echo|(?:object-group\s[\w\-]+)|(?:eq\s[\w]+)))?'.format(ipaddr=regex_ip_address)
)

#main script
#Ensuring that there are arguments provided to the scrip and not let run without it
parser = argparse.ArgumentParser(prog='cisco-acl-policy-parser',description='Script takes 1 argument of a config file (typically .conf) and outputs CSV file with ".csv" extension with the same name as orginal file.',epilog='by Lukasz Awsiukiewicz, biuro@la-tech.pl')
parser.add_argument('-f', '--file', help='%(prog)s --filein=<CISCO IOS format conf file - typically it contain ! in content of a file >', required=True)
a1 = parser.parse_args()

#test out if provided file exist
f_in_name=vars(a1)["file"]
if not(os.path.exists(f_in_name)):
    print("file not found!")
    exit()
f_out_name=f_in_name + ".csv"

with open(f_in_name, "r", encoding="utf8") as f:
    previous_policy_name=""
    for line in f.readlines():
        #pattern=re.compile(acl_general_structure, re.I)
        #result=re.match(acl_general_structure,line.lower())
        result=re.match(acl_general_structure,line)
        if result:
            temp_data=result.groupdict()
            temp_policy=copy.deepcopy(policy)
            if previous_policy_name!=temp_data["policy_name"]:
                rule_count=1
            temp_policy["policy-name"]=temp_data["policy_name"]+"#"+str(rule_count)
            temp_policy["source-address"]=temp_data["source"]
            temp_policy["destination-address"]=temp_data["destination"]
            temp_policy["action"]=temp_data["action"]
            previous_policy_name=temp_data["policy_name"]
            if temp_data["service"]:
                temp_service=temp_data["service"].split(" ")
                if temp_service[0]=='eq':
                    temp_policy["application"]=temp_data["protocol"]+"/"+temp_service[1]
                else:
                    temp_policy["application"]=temp_data["protocol"]+"/"+temp_data["service"]
            else:
                temp_policy["application"]="any"
            policies_set.append(temp_policy)
            rule_count+=1

with open(f_out_name,"w",newline='') as f:
    csv_writer = csv.DictWriter(f,fieldnames=policy_description,delimiter=';')
    csv_writer.writeheader()
    csv_writer.writerows(policies_set)

