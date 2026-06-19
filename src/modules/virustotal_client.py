import requests
import src.utils as utils
from pathlib import Path
from datetime import datetime
from types import SimpleNamespace

api_daily_requests = Path("tmp/cache/VirusTotal-api-requests.tmp")

def get_daily_api_requests():
	daily_requests = 0
	if api_daily_requests.is_file():
		with open(api_daily_requests, "r") as file:
			content = file.read()
			if content != "":
				content = content.strip().split("\t")
				last_api_request_date = datetime.strptime(content [0], "%d/%m/%Y").date()
				today_date = datetime.today().date()
				if last_api_request_date == today_date:
					daily_requests = int(content[1])
				else:
					set_daily_api_requests(0)
			else:
				set_daily_api_requests(0)
	else:
		api_daily_requests.parent.mkdir(parents=True, exist_ok=True)
		set_daily_api_requests(0)
	return daily_requests

def set_daily_api_requests(api_requests_number):
	today_date_str = datetime.today().strftime("%d/%m/%Y")
	api_daily_requests.parent.mkdir(parents=True, exist_ok=True)

	if api_daily_requests.is_file():
		with open(api_daily_requests, "r+") as file:
			content = file.read().strip()
			file.seek(0)
			if content:
				content = content.split("\t")
				last_api_request_date = datetime.strptime(content[0], "%d/%m/%Y").date()
				today_date = datetime.today().date()
			
				if last_api_request_date == today_date:
					new_count = int(content[1])+api_requests_number
				else:	
					new_count = api_requests_number
			else:
				new_count = 0
			file.write(f"{today_date_str}\t{new_count}")
			file.truncate()
	else:
		with open(api_daily_requests, "w") as file:
			file.write(f"{today_date_str}\t0")
	return


def get_data(hashes, api_key, output_dir, folder_first):
	api_url = "https://www.virustotal.com/api/v3/files/"
	headers = {"accept":"application/json", "x-apikey":api_key}
	metadata_list = []
	num_lines = len(hashes)

	print("Starting VirusTotal Scan...")

	for index, sha in enumerate(hashes):
		web_scan = True
		if folder_first:
			exists, path = utils.file_exists(output_dir, sha, ".json")
			if exists:
				result = utils.open_json(path)
				response = SimpleNamespace()
				response.status_code = 200	
				web_scan = False				
			else:
				response = requests.get(api_url + sha, headers=headers)
				result = response.json()
		else:
			response = requests.get(api_url + sha, headers=headers)
			result = response.json()

		hash_metadata = {
			"sha256": sha,
			"database": "VirusTotal",
			"error": None
		}
		
		if response.status_code == 200:
			if web_scan:
				utils.save_json(output_dir, sha, result)
			print(f"VT {index+1}/{num_lines} - {sha}")
			attributes = result.get("data", {}).get("attributes")

			if attributes:
				hash_metadata['file_type'] = attributes.get("type_description")

				submission_date = datetime.fromtimestamp(attributes.get("first_submission_date"))
				if submission_date:
					hash_metadata['fs_date'] = submission_date.strftime("%d/%m/%Y")
					hash_metadata['fs_time'] = submission_date.strftime("%H:%M:%S")

				threat_tags = {}

				for yara_results in attributes.get("crowdsourced_yara_results", {}):
					if "ruleset_name" in yara_results.keys():
						threat_tags = utils.extract_threat_metrics(yara_results.get("ruleset_name"), threat_tags)
					if "rule_name" in yara_results.keys():
						threat_tags = utils.extract_threat_metrics(yara_results.get("rule_name"), threat_tags)
					if "description" in yara_results.keys():
						threat_tags = utils.extract_threat_metrics(yara_results.get("description"), threat_tags)

				threat_classification = attributes.get("popular_threat_classification")
				if threat_classification:
					threat_tags = utils.extract_threat_metrics(threat_classification.get("suggested_threat_label"), threat_tags)

					for threat_category in threat_classification.get("popular_threat_category", {}):
						threat_tags = utils.extract_threat_metrics(threat_category.get("value"), threat_tags)

					for threat_name in threat_classification.get("popular_threat_name", {}):
						threat_tags = utils.extract_threat_metrics(threat_name.get("value"), threat_tags)

				for company in attributes.get("last_analysis_results", {}).keys():
					threat_tags = utils.extract_threat_metrics(attributes['last_analysis_results'][company].get("result"), threat_tags)

				hash_metadata['threat_tags'] = utils.filter_threat_tags(threat_tags)
		else:
			if response.status_code == 429:
				print(f"[!] Error: VirusTotal API request limit reached.\n")
				set_daily_api_requests(index)
				hash_metadata.pop("database")
				return metadata_list
			else:
				print(f"[!] Error VT: {response.status_code} - {index+1}/{num_lines} - {sha}")
				hash_metadata.pop("database")
				hash_metadata['error'] = f"VT {response.status_code}"
				utils.save_json(output_dir, sha, result)
		metadata_list.append(hash_metadata)   
	set_daily_api_requests(len(hashes))
	return metadata_list

