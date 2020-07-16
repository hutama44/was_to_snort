from tenable.io import TenableIO
import pprint
import sys
import json
import urllib
import re
import os

class color:
   PURPLE = '\033[1;35;48m'
   CYAN = '\033[1;36;48m'
   BOLD = '\033[1;37;48m'
   BLUE = '\033[1;34;48m'
   GREEN = '\033[1;32;48m'
   YELLOW = '\033[1;33;48m'
   RED = '\033[1;31;48m'
   BLACK = '\033[1;30;48m'
   UNDERLINE = '\033[4;37;48m'
   END = '\033[1;37;0m'

def snortrule(uri,field,payload,a):
    snort1 = "alert tcp any any -> $HOME_NET $HTTP_PORTS \n"
    snort1 = snort1 + "( \n"
    snort1 = snort1 + 'msg: "Temporary rule created from tenable WAS for app: ' + uri + '";\n'
    enc_payload = urllib.parse.quote(payload)
    enc_list = enc_payload.split('%')
    enc_list.pop(0)
    vector = "("
    for n in enc_list:
        vector1 = "\\%" + n + "|"
        vector = vector + vector1
    for n in payload:
        vector1 = "\\" + n + "|"
        vector = vector + vector1
    vector = vector[:-1]
    vector = vector + ")"
    urilist = uri.split("/")
    urif = urilist[-1]
    urif = urif.replace(".","\.").replace("/","\/")
    snort1 = snort1 + 'pcre:"/' + urif + "\?.*" + field + "=.*" + vector + '.*/ix";\n'
    snort1 = snort1 + "sid:1000001;\n"
    snort1 = snort1 + ") \n"
    if a == 1:
        txt = open("local.rules","a+")
        txt.write(snort1)
        txt.close
        print(color.BLUE + "Snort Signature - stored in local.rules file at local folder" + color.END)
        print(color.GREEN + snort1 + color.END)
    if a ==0:
        return(urif + "\?.*" + field + "=.*" + vector + '.*')

def findpattern(path,tring):
    if os.path.isfile(path):
        logs = open(path,"r")
        lines = logs.readlines()
        for i in lines:
            if re.search(tring, i):
                print(color.RED + "Possible attack in the past found:" + color.END)
                print(i)
    else:
        print(color.CYAN + "File not found, please check the path and permissions" + color.END)

tio = TenableIO('WRITE_ACCESS_KEY_HERE', 'WRITE_SECRET_KEY_HERE')
listt = []
listt2 = []
sl = []

def createlist(url,size):
    x = range(0, int(size/10), 1)
    listt = []
    for n in x:
        querystring = {"ordering":"asc","page":n,"size":"10"}
        headers = {'accept': 'application/json'}
        resp = tio.get(url, headers=headers, params=querystring)
        list1 = json.loads(resp.text)["data"]
        listt.extend(list1)
    return listt

def printvuln(list2):
    for vuln in list2:
        if vuln["plugin_id"]==98115:
            print(color.BLUE + "URI: " + color.END + vuln['uri'])
            print(color.BLUE + "Vulnerable Field: " + color.END + vuln['details']['inputName'])
            print(color.BLUE + "Payload: " + color.END + vuln['details']['payload'])
            for item in vuln['attachments']:
                if item['attachment_name']=='HTTP Request':
                    #print("Attachment ID: " + item['attachment_id'])
                    url3 = "was/v2/attachments/" + item['attachment_id']
                    response3 = tio.get(url3, headers=headers3)
                    print(color.BLUE + "Request: " + color.END)
                    print(response3.text)
            r = input(color.RED + "Do you want to create a snort rule for this vulnerability? y/n: " + color.END)
            if r =="y":
                snortrule(vuln['uri'],vuln['details']['inputName'],vuln['details']['payload'],1)
            if r =="k":
                break
            d = input(color.RED + "Do you want to check if this vuln was exploited in the past? y/n: " + color.END)
            if d =="y":
                path = input(color.CYAN + "Please enter the path for the server access logs: " + color.END)
                tring = snortrule(vuln['uri'],vuln['details']['inputName'],vuln['details']['payload'],0)
                findpattern(path,tring)
            c = input(color.PURPLE + "Continue? y/n :" + color.END)
            if c=="y":
                continue
            else:
                break
def printuri(list1):
    print(color.YELLOW + "Fetching list of Scans..." + color.END)
    i = 1 
    for scan in list1:
        print("(" + str(i) + ") Application_URI: " + scan["application_uri"])
        i = i + 1
        sl.append(scan["scan_id"])
    response1 = input(color.YELLOW + "Which scan do you want to analize?: " + color.END)
    response1 = int(response1) - 1
    id1 = sl[response1]
    return id1

url = "was/v2/scans"
querystring = {"ordering":"asc","page":"0","size":"10"}
headers = {'accept': 'application/json'}
resp = tio.get(url, headers=headers, params=querystring)
list1 = json.loads(resp.text)["data"]

if json.loads(resp.text)["total_size"] < 10:
    id1 = printuri(list1)
else:
    listt = createlist(url,list1,json.loads(resp.text)["total_size"])
    id1 = printuri(listt)
        
url2 = "was/v2/scans/" + id1 + "/vulnerabilities"
headers2 = {'accept': 'application/json'}
querystring2 = {"ordering":"asc","page":"0","size":"10"}
resp2 = tio.get(url2, headers=headers2, params=querystring2)
list2 = json.loads(resp2.text)["data"]

headers3 = {'accept': 'text/plain'}
print(color.YELLOW + "Total of vulnerabilities found: " + color.END + str(json.loads(resp2.text)["total_size"]))

if json.loads(resp2.text)["total_size"] < 10:
    print(color.YELLOW + "Fetching list of SQL Injection Vulnerabilities..." + color.END)
    printvuln(list2)
else:
    print(color.YELLOW + "Fetching list of SQL Injection Vulnerabilities..." + color.END)
    listt2 = createlist(url2,json.loads(resp2.text)["total_size"])
    printvuln(listt2)
