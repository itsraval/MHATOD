from datetime import datetime
import requests
import subprocess
from src.export import *
from src.settings import *

def AVclass(result, folderName, h):
    path = f"{folderName}\\VirusTotal\\{h}.json"
    exportJson(result, path, False)
    avclass = subprocess.run(["avclass", "-f", path, "-t"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    avclass_results = avclass.stdout.decode().split("\t")
    output = {}
    tags = []
    if len(avclass_results) > 1:
        for i in avclass_results[2].split(","):
            label = i.split("|")[0]
            if "FAM" in label:
                output["family"] = label[4:]

            else:
                tags.append(label)
        tags.sort()
        output["tags"] = tags
        if "family" not in output:
            output["family"] = ""
        return output
    return None


def getNames(names, h):
    new_names = []
    if len(names) == 0:
        return ["Name Missing"]
    for n in names:
        if "VirusShare_" not in n and h not in n.lower():
            new_names.append(n)
    return new_names

def getThreatNamesVT(*tn):
    threat_names = []
    for i in tn:
        if i != None:
            threat_names.append(i)
    return threat_names

def virusTotal(hash_list, folderName):
    api_url = "https://www.virustotal.com/api/v3/files/"
    headers = {"accept":"application/json","x-apikey":api_key_virustotal}
    metadata_list = []
    counter = 0
    num_lines = len(hash_list)

    print("Starting VirusTotal Scan...")

    for h in hash_list:
        counter += 1
        response = requests.get(api_url + h, headers=headers)
        result = response.json()

        avclass = AVclass(result, folderName, h)

        hash_metadata = {}
        hash_metadata['index'] = counter
        hash_metadata['sha256'] = h

        if response.status_code == 200:
            print(f"{counter}/{num_lines} - {h}")

            hash_metadata['names'] = getNames(result['data']['attributes']['names'], h)
            hash_metadata['file_type'] = result['data']['attributes']['type_description']
            hash_metadata['fs_date'] = datetime.fromtimestamp(result['data']['attributes']['first_submission_date']).strftime("%d/%m/%Y")
            hash_metadata['fs_time'] = datetime.fromtimestamp(result['data']['attributes']['first_submission_date']).strftime("%H:%M:%S")

            hash_metadata['threat_names'] = getThreatNamesVT(result['data']['attributes']['last_analysis_results']['TrendMicro']['result'], result['data']['attributes']['last_analysis_results']['Microsoft']['result'], result['data']['attributes']['last_analysis_results']['Kaspersky']['result'], result['data']['attributes']['last_analysis_results']['BitDefender']['result'])
            hash_metadata['error'] = "None"

            if avclass != None:
                hash_metadata['avclass_FAM'] = avclass["family"]
                hash_metadata['avclass_TAGS'] = avclass["tags"]
        else:
            if response.status_code == 429:
                print(f"Exiting VirusTotal scan because error: {result['error']['message']}")
                print()
                return metadata_list, counter
            else:
                print(f"{counter}/{num_lines} - {h} - Error: {result['error']['message']}")
                hash_metadata['error'] = result['error']['message']
        metadata_list.append(hash_metadata)   
    return metadata_list, counter


def getDateTimeMB(a, b):
    d1 = datetime.strptime(a, "%Y-%m-%d %H:%M:%S")
    d2 = datetime.strptime(b, "%Y-%m-%d %H:%M:%S")

    if d1 < d2:
        return d1.strftime("%d/%m/%Y"), d1.strftime("%H:%M:%S")
    else:
        return d2.strftime("%d/%m/%Y"), d2.strftime("%H:%M:%S")

def getThreatNamesMB(a, b):
    threat_names = []
    for i in a:
            threat_names.append(i)
    threat_names.append(b)
    return threat_names

def malwareBazaar(hash_list, folderName):
    api_url = "https://mb-api.abuse.ch/api/v1/"
    metadata_list = []
    counter = 0
    num_lines = len(hash_list)

    print("Starting Malware Bazaar Scan...")

    for h in hash_list:
        counter += 1
        data = {"query":"get_info","hash":h}
        response = requests.post(api_url, data=data)
        result = response.json()

        exportJson(result, f"{folderName}\\MalwareBazaar\\{h}.json", False)
        
        hash_metadata = {}
        hash_metadata['index'] = counter
        hash_metadata['sha256'] = h
        
        if result['query_status'] == "ok":
            print(f"{counter}/{num_lines} - {h}")

            hash_metadata['names'] = getNames([result['data'][0]['file_name']], h)
            hash_metadata['signature'] = result['data'][0]['signature']

            hash_metadata['file_type'] = result['data'][0]['file_type']
            hash_metadata['tags'] = result['data'][0]['tags']
            
            if "ReversingLabs" in result['data'][0]['vendor_intel']:
                hash_metadata['fs_date'], hash_metadata['fs_time'] = getDateTimeMB(result['data'][0]['first_seen'], result['data'][0]['vendor_intel']['ReversingLabs']['first_seen'])
            else:
                hash_metadata['fs_date'], hash_metadata['fs_time'] = getDateTimeMB(result['data'][0]['first_seen'], "2050-12-31 12:12:12")

            if result['data'][0]['intelligence']['clamav'] != None:
                if "ReversingLabs" in result['data'][0]['vendor_intel']:
                    hash_metadata['threat_names'] = getThreatNamesMB(result['data'][0]['intelligence']['clamav'], result['data'][0]['vendor_intel']['ReversingLabs']['threat_name'])
                else:
                    hash_metadata['threat_names'] = result['data'][0]['intelligence']['clamav']
            else:
                if "ReversingLabs" in result['data'][0]['vendor_intel']:
                    hash_metadata['threat_names'] = [result['data'][0]['vendor_intel']['ReversingLabs']['threat_name']]
                else:
                    hash_metadata['threat_names'] = []
            hash_metadata['error'] = "None"

        else:
            print(f"{counter}/{num_lines} - {h} - Error: {result['query_status']}")
            hash_metadata['error'] = result['query_status']
        
        metadata_list.append(hash_metadata)
    return metadata_list