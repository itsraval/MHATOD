import re
import csv
import json
from pathlib import Path

def banner():
	print(":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::")
	print("::##::::'##:'##::::'##::::'###::::'########::'#######::'########:::")
	print("::###::'###: ##:::: ##:::'## ##:::... ##..::'##.... ##: ##.... ##::")
	print("::####'####: ##:::: ##::'##:. ##::::: ##:::: ##:::: ##: ##:::: ##::")
	print("::## ### ##: #########:'##:::. ##:::: ##:::: ##:::: ##: ##:::: ##::")
	print("::##. #: ##: ##.... ##: #########:::: ##:::: ##:::: ##: ##:::: ##::")
	print("::##:.:: ##: ##:::: ##: ##.... ##:::: ##:::: ##:::: ##: ##:::: ##::")
	print("::##:::: ##: ##:::: ##: ##:::: ##:::: ##::::. #######:: ########:::")
	print(":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::")
	print("\n\n")

	return

def info():
	print("This script has been developed by Alessandro Ravizzotti")
	print("GitHub: https://github.com/itsraval/MHATOD")
	print("Website: alessandro.ravizzotti.dev")
	print("Contact: alessandro@ravizzotti.dev")
	print("\n")
	return

def get_hashes_from_file(input_file):
	with open(input_file, "r") as file:
		hash_list = [line.strip() for line in file]
	return hash_list

def folder_setup(output_dir):
	main_dir = Path(output_dir)
	main_dir.mkdir(parents=True, exist_ok=True)
	vt_dir = main_dir / "VirusTotal"
	vt_dir.mkdir(parents=True, exist_ok=True)
	avc_dir = main_dir / "AvClass"
	avc_dir.mkdir(parents=True, exist_ok=True)
	mb_dir = main_dir / "MalwareBazaar"
	mb_dir.mkdir(parents=True, exist_ok=True)
	json_dir = main_dir / "json"
	json_dir.mkdir(parents=True, exist_ok=True)
	csv_dir = main_dir / "csv"
	csv_dir.mkdir(parents=True, exist_ok=True)
	return main_dir, vt_dir, avc_dir, mb_dir, json_dir, csv_dir

def save_json(path, filename, data):
	file_path = path / f"{filename}.json"
	if not Path(file_path).is_file():
		with open(file_path, "w") as json_file:
			json.dump(data, json_file)
	return

def open_json_to_continue(path, filename):
	file_path = path / f"{filename}.json"
	if file_path.is_file():
		with open(file_path, "r") as json_file:
			data = json.load(json_file)
		return data, filename
	else:
		files = [file.name.split('.')[0] for file in list(path.glob("*.json"))]
		for file in files:
			if filename in file:
				return open_json_to_continue(path, file)
	return {'data':[]}, filename

def save_csv(path, filename, data):
	file_path = path / f"{filename}.csv"

	preferred_order = [
		"sha256", 
		"fs_date", 
		"fs_time",
		"file_type", 
		"MHATOD_analysis",
		"signature", 
		"threat_tags", 
		"AV_family", 
		"AV_threat_tags", 
		"database",
		"error"
	]

	actual_keys_in_data = set()
	for item in data:
		actual_keys_in_data.update(item.keys())

	final_headers = [key for key in preferred_order if key in actual_keys_in_data]

	with open(file_path, 'w', newline="", encoding="utf-8") as csv_file:
		writer = csv.DictWriter(csv_file, fieldnames=final_headers, restval="")
		writer.writeheader()

		for row in data:
			processed_row = {}
			for key in final_headers:
				val = row.get(key, "")

				if key == "threat_tags" and isinstance(val, dict):
					processed_row[key] = "\n".join([f"{k}: {v}" for k, v in val.items()])
				elif key == "AV_threat_tags" and isinstance(val, list):
					processed_row[key] = "\n".join(val)
				elif isinstance(val, (list, dict)):
					processed_row[key] = json.dumps(val)
				else:
					processed_row[key] = val

			writer.writerow(processed_row)
	return


TAG_SPLIT_PATTERN = re.compile(r"[!\-_./: ]") 
def extract_threat_metrics(text, threat_tags):
	if text:
		results = TAG_SPLIT_PATTERN.split(text)
		for tag in results:
			tag = tag.lower().strip()
			if tag:
				threat_tags[tag] = threat_tags.get(tag, 0) + 1
	return threat_tags

def filter_threat_tags(threat_tags):
	all_sorted_tags = dict(sorted(
		threat_tags.items(), 
		key=lambda item: item[1], 
		reverse=True
	))

	filtered_threat_tags = {
		k: v for k, v in all_sorted_tags.items() 
		if v >= 5 and len(k) > 2
	}

	if not filtered_threat_tags:
		filtered_threat_tags = dict(list(all_sorted_tags.items())[:3])
	return filtered_threat_tags
