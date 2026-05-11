import src.utils as utils
from src.cli import get_args

import src.modules.virustotal_client as vt
import src.modules.malwarebazaar_client as mb
import src.modules.avclass_labeler as avc
import src.modules.combine_modules as combine

import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

def multi_process(func, name, hashes, skip_lines, key, db_dir, json_dir, csv_dir):
	hashes_metadata = func(hashes[skip_lines:], key, db_dir)
	utils.save_json(json_dir, name, {'data':hashes_metadata})
	utils.save_csv(csv_dir, name, hashes_metadata)
	return hashes_metadata

def main():
	args = get_args()

	if args.banner:
		utils.banner()
	if args.info:
		utils.info()

	if not Path(args.input_file).is_file():
		print(f"[!] Error: File '{args.input_file}' not found.")
		sys.exit()
	hashes = utils.get_hashes_from_file(args.input_file)

	main_dir, vt_dir, avc_dir, mb_dir, json_dir, csv_dir = utils.folder_setup(args.output)

	with ThreadPoolExecutor() as executor:
		future_vt = None
		future_mb = None

		# VirusTotal
		if args.vtkey:
			future_vt = executor.submit(multi_process, vt.get_data, "VirusTotal", hashes, args.skip_lines, args.vtkey, vt_dir, json_dir, csv_dir)
		else:
			print("[!] Skipping VirusTotal: No API key provided.")

		# MalwareBazaar
		if args.mbkey:
			future_mb = executor.submit(multi_process, mb.get_data, "MalwareBazaar", hashes, args.skip_lines, args.mbkey, mb_dir, json_dir, csv_dir)
		else:
			print("[!] Skipping MalwareBazaar: No API key provided.")

		if future_vt:
			vt_hashes_metadata = future_vt.result()
		else:
			vt_hashes_metadata = []
		if future_mb:
			mb_hashes_metadata = future_mb.result()
		else:
			mb_hashes_metadata = []

	# AvClass
	avc_hashes_metadata = []
	if args.vtkey:
		avc_hashes_metadata = avc.get_data(vt_dir, hashes[args.skip_lines:], avc_dir)
		utils.save_json(json_dir, "AvClass", {'data':avc_hashes_metadata})
		utils.save_csv(csv_dir, "AvClass", avc_hashes_metadata)
	else:
		print("[!] Skipping AvClass: Depends on VirusTotal output.")

	# Combined
	if args.vtkey:
		combined_metadata = combine.merge_modules(vt_hashes_metadata, avc_hashes_metadata, mb_hashes_metadata, args.top_threat_tags)
		utils.save_json(json_dir, "Combined_metadata", {'data':combined_metadata})
		utils.save_csv(csv_dir, "Combined_metadata", combined_metadata)

	print("\nCompilation completed!")
	return

if __name__ == '__main__':
	main()