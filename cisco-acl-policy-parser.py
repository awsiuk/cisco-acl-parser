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
zones_set=[]

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

#this is to grap "access-group" output and use to translate into proper security zone
zones = {
    "policy": "",
    "direction": "",
    "zone": ""
}

#not yet used
acl_remark = (
    r'^access-list\s(?P<policy_name>[A-Za-z0-9\-\_]+)'
    r'\s+'
    r'remark\s+(?P<remark>.+)'
)

regex_ip_address = ( 
    r'([\d]{1,3}\.){3}[\d]{1,3}'
)

#IP subnet mask
regex_mask = (
    r'(255\.255\.255\.[\d]{1,3})|(255\.255\.[\d]{1,3}\.0)|(255\.[\d]{1,3}\.0\.0)|([\d]{1,3}\.0\.0\.0)'
)

#when creating regex using {} then any regex expressions containing {} needs to be moved to variable
#otherwise when using .format it will through out an error while compliling the code
acl_general_structure = (
    r'access-list\s+(?P<policy_name>[\w-]+)\s+extended\s+(?P<action>permit|deny)'
    r'\s'
    r'(?:object-group\s|object\s)?(?P<protocol>[\w-]+)'
    r'\s'
    r'((host\s)|(object-group\s)|(object\s))?(?P<source>((?<=host\s){ipaddr})|({ipaddr}\s({mask}))|any|[\w\.-]+)'
    r'\s'
    r'((host\s)|(object-group\s)|(object\s))?(?P<destination>((?<=host\s){ipaddr})|({ipaddr}\s({mask}))|any|[\w\.-]+)'
    r'(?:\s|$)'
    r'(?:(?:object-group\s|eq\s|range\s)?(?P<service>(?<=eq\s)[\w-]+|(?<=object-group\s)[\w-]+|(?<=range\s)(?:[\d]+\s[\d]+)))?'.format(ipaddr=regex_ip_address,mask=regex_mask)
)

acl_apply_to = (
    r'^access-group\s(?P<policy>[\w\-]+)\s(?P<direction>in|out)\sinterface\s(?P<zone>[\w\-]+)'
)

#converts the network mask into prefix. Takes argument as string and returns string
def mask_convert(subnet_mask: str) -> str:
    mask_obj=subnet_mask.split(".")
    mask_bin=int(mask_obj[0])<<24
    mask_bin|=(int(mask_obj[1])<<16)
    mask_bin|=(int(mask_obj[2])<<8)
    mask_bin|=(int(mask_obj[3]))
    prefix="/"+str(str(bin(mask_bin)).count("1"))
    return prefix

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
            #Below line add to the policy name a rule number since cisco has different approach for traffic filtering
            #there are 2 approaches:
            #1. create 1 policy per exact ACL name but keep adding into that policy a rules. Please note that cisco 
            #   adds action after each rule
            #2. create new policy per each ACL --> this is the approach teken here. it migbt be important for asset
            #    management where tere mighe be multiple ownere for the rules.            
            temp_policy["policy-name"]=temp_data["policy_name"]+"#"+str(rule_count)
            if ' ' in temp_data["source"]:
                temp_policy["source-address"].append( temp_data["source"].split(" ")[0] + mask_convert(temp_data["source"].split(" ")[1]) )
            else:
                temp_policy["source-address"].append(temp_data["source"])
            if ' ' in temp_data["destination"]:
                temp_policy["destination-address"].append(temp_data["destination"].split(" ")[0]+ mask_convert(temp_data["destination"].split(" ")[1]) )
            else:
                temp_policy["destination-address"].append(temp_data["destination"])
            temp_policy["action"]=temp_data["action"]
            previous_policy_name=temp_data["policy_name"]
            if temp_data["service"]:
                temp_service=temp_data["service"].split(" ")
                if temp_service[0]=='eq':
                    temp_policy["application"].append(temp_data["protocol"]+"/"+temp_service[1])
                else:
                    temp_policy["application"].append(temp_data["protocol"]+"/"+temp_data["service"])
            else:
                temp_policy["application"].append("any")
            policies_set.append(temp_policy)
            rule_count+=1
        result=re.match(acl_apply_to,line)
        if result: 
            temp_apply=result.groupdict()
            temp_zone=copy.deepcopy(zones)
            temp_zone["policy"]=temp_apply["policy"]
            temp_zone["direction"]=temp_apply["direction"]
            temp_zone["zone"]=temp_apply["zone"]
            zones_set.append(temp_zone)

for entry in policies_set:
    for zone_obj in zones_set:
        if zone_obj["policy"] == (entry["policy-name"].split('#')[0]) and zone_obj["direction"]=="in":
            entry["from-zone"].append(zone_obj["zone"])
        if zone_obj["policy"] == (entry["policy-name"].split('#')[0]) and zone_obj["direction"]=="out":
            entry["to-zone"].append(zone_obj["zone"])

with open(f_out_name,"w",newline='') as f:
    csv_writer = csv.DictWriter(f,fieldnames=policy_description,delimiter=';')
    csv_writer.writeheader()
    csv_writer.writerows(policies_set)

