import requests
import src.utils as utils
from datetime import datetime

def get_data(hashes, api_key, output_dir):
	api_url = "https://www.virustotal.com/api/v3/files/"
	headers = {"accept":"application/json", "x-apikey":api_key}
	metadata_list = []
	num_lines = len(hashes)

	print("Starting VirusTotal Scan...")

	for index, sha in enumerate(hashes):
		response = requests.get(api_url + sha, headers=headers)
		result = response.json()

		hash_metadata = {
			"sha256": sha,
			"error": None
		}

		if response.status_code == 200:
			print(f"VT {index+1}/{num_lines} - {sha}")
			utils.save_json(output_dir, sha, result)

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
				return metadata_list, index
			else:
				print(f"[!] Error VT: {response.status_code} - {index+1}/{num_lines} - {sha}")
				hash_metadata['error'] = f"VT {response.status_code}"
		metadata_list.append(hash_metadata)   
	return metadata_list, None

