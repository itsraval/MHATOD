from datetime import datetime

def list_to_dict(my_list):
	my_dict = {}
	for entry in my_list:
		sha = entry.get("sha256")
		my_dict[sha] = entry.copy()
	return my_dict

def change_date(date1, date2):
	dt_obj1 = datetime.strptime(f"{date1[0]} {date1[1]}", "%d/%m/%Y %H:%M:%S")
	dt_obj1 = datetime.strptime(f"{date2[0]} {date2[1]}", "%d/%m/%Y %H:%M:%S")

	if int(dt_obj1.timestamp()) < int(dt_obj1.timestamp()):
		return False
	return True

def merge_modules(vt_metadata, avc_metadata, mb_metadata, top_tags):
	merged = list_to_dict(vt_metadata)
	avc_dict = list_to_dict(avc_metadata)
	mb_dict = list_to_dict(mb_metadata)
		
	if mb_metadata != []:
		for sha in mb_dict.keys():
			current_merged_item = merged.get(sha)
			new_item = mb_dict[sha]

			if current_merged_item:
				current_merged_item['signature'] = new_item.get("signature", "")

				if current_merged_item.get("threat_tags"):
					for tag in new_item.get("threat_tags", {}).keys():
						if current_merged_item['threat_tags'].get(tag):
							current_merged_item['threat_tags'][tag] += new_item['threat_tags'][tag]
						else:
							current_merged_item['threat_tags'][tag] = new_item['threat_tags'][tag]

					if top_tags:
						top_tags = sorted(
							current_merged_item['threat_tags'].items(), 
							key=lambda x: x[1], 
							reverse=True
						)[:5]
						current_merged_item['threat_tags'] = dict(top_tags)

				if new_item.get("file_type"):
					if new_item['file_type'].lower() != "unknown" and new_item['file_type'].lower() not in current_merged_item.get("file_type", "").lower():
						current_merged_item['file_type'] = f"{current_merged_item.get("file_type", "")} - {new_item['file_type']}"

				if current_merged_item.get("fs_date") and current_merged_item.get("fs_time"):
					if new_item.get("fs_date") and new_item.get("fs_time"):
						if change_date((current_merged_item['fs_date'], current_merged_item['fs_time']),(new_item['fs_date'], new_item['fs_time'])):
							current_merged_item['fs_date'] = new_item['fs_date']
							current_merged_item['fs_time'] = new_item['fs_time']
				else:
					if new_item.get("fs_date") and new_item.get("fs_time"):
						current_merged_item['fs_date'] = new_item['fs_date']
						current_merged_item['fs_time'] = new_item['fs_time']

				if new_item['error']:
					if current_merged_item['error']:
						current_merged_item['error'] = f"{current_merged_item['error']}\n{new_item['error']}"
					else:
						current_merged_item['error'] = new_item['error']
			else:
				merged[sha] = new_item.copy()

	for sha in avc_dict.keys():
		current_merged_item = merged.get(sha)
		new_item = avc_dict[sha]

		if current_merged_item:
			current_merged_item['AV_family'] = new_item['family']
			current_merged_item['AV_threat_tags'] = new_item['AV_threat_tags']

			if new_item['error']:
				if current_merged_item['error']:
					current_merged_item['error'] = f"{current_merged_item['error']}\n{mb_dict['error']}"
				else:
					current_merged_item['error'] = new_item['error']
		else:
			merged[sha] = new_item.copy()
	return list(merged.values())

