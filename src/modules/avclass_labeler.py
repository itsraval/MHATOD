import subprocess
import src.utils as utils

def get_data(path, hashes, output_dir):
	metadata_list = []
	num_lines = len(hashes)

	print("\nStarting AvClass Scan...")

	for index, sha in enumerate(hashes):
		print(f"AVC {index+1}/{num_lines} - {sha}")

		json_file = path / f"{sha}.json"
		avclass = subprocess.run(["avclass", "-f", json_file, "-t"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		avclass_results = avclass.stdout.decode().strip().split("\t")

		hash_metadata = {
			"sha256": sha,
			"error": None
		}
		tags = []
		if len(avclass_results) > 2:
			for i in avclass_results[2].split(","):
				label = i.split("|")[0]
				if "FAM" in label:
					hash_metadata['AV_family'] = label.split(":")[1]
				else:
					tags.append(label)
			tags.sort()
			hash_metadata['AV_threat_tags'] = tags
			if "family" not in hash_metadata:
				hash_metadata['family'] = ""
		else:
			hash_metadata['error'] = "No AvClass results found."
		utils.save_json(output_dir, sha, hash_metadata)
		metadata_list.append(hash_metadata) 
	return metadata_list, None
