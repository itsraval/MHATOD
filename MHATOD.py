import src.utils as utils
from src.cli import get_args

import src.modules.virustotal_client as vt
import src.modules.malwarebazaar_client as mb
import src.modules.avclass_labeler as avc
import src.modules.combine_modules as combine

import sys
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

def continue_previous_scan_hashes_selection(vt_dir, avc_dir, mb_dir, hashes):
	hashes_to_scan = []
	vt_files = [file.name.split('.')[0] for file in list(vt_dir.glob("*.json"))]
	avc_files = [file.name.split('.')[0] for file in list(avc_dir.glob("*.json"))]
	mb_files = [file.name.split('.')[0] for file in list(mb_dir.glob("*.json"))]

	for sha in hashes:
		if not (sha in vt_files and sha in avc_files and sha in mb_files):
			hashes_to_scan.append(sha)
	return hashes_to_scan

def multi_process(func, name, hashes, skip_lines, analyse_lines, key, db_dir, json_dir, csv_dir, continue_previous_scan=False, folder_first=False):
	if analyse_lines != 0:
		hashes_metadata = func(hashes[skip_lines:skip_lines+analyse_lines], key, db_dir, folder_first)
	else:
		hashes_metadata = func(hashes[skip_lines:], key, db_dir, folder_first)

	output_file_name = name

	if continue_previous_scan:
		previous_hashes_metadata, output_file_name = utils.open_json_to_continue(json_dir, name)
		previous_hashes_metadata = previous_hashes_metadata['data']
		for sha_data in hashes_metadata:
			if sha_data in previous_hashes_metadata:
				hashes_metadata.remove(sha_data)
		hashes_metadata = previous_hashes_metadata + hashes_metadata 

		hashes_metadata = sorted(hashes_metadata, key=lambda x: x["sha256"])

		if skip_lines != 0:
			output_file_name = f"{output_file_name}-skip{skip_lines}"
		if analyse_lines != 0:
			output_file_name = f"{output_file_name}-analyse{analyse_lines}"
		
	else:	
		if skip_lines != 0:
			output_file_name = f"{output_file_name}-skip{skip_lines}"
		if analyse_lines != 0:
			output_file_name = f"{output_file_name}-analyse{analyse_lines}"

	utils.save_json(json_dir, output_file_name, {'data':hashes_metadata})
	utils.save_csv(csv_dir, output_file_name, hashes_metadata)
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

	if args.continue_previous_scan:
		hashes = continue_previous_scan_hashes_selection(vt_dir, avc_dir, mb_dir, hashes)

	analyse_lines = args.analyse_lines
	if args.vtkey and not args.skip_vt:
		analyse_lines_limit = 500 - vt.get_daily_api_requests()
		if analyse_lines_limit<args.analyse_lines:
			analyse_lines = analyse_lines_limit

	if analyse_lines<0:
		print("[!] VirusTotal API reached today's max requests: 500")
		return

	try:
		with ThreadPoolExecutor() as executor:
			future_vt = None
			future_mb = None

			# VirusTotal
			if args.vtkey and not args.skip_vt:
				future_vt = executor.submit(multi_process, vt.get_data, "VirusTotal", hashes, args.skip_lines, analyse_lines, args.vtkey, vt_dir, json_dir, csv_dir, args.continue_previous_scan, args.folder_first)
			else:
				print("[!] Skipping VirusTotal: No API key provided.")

			# MalwareBazaar
			if args.mbkey and not args.skip_mb:

				future_mb = executor.submit(multi_process, mb.get_data, "MalwareBazaar", hashes, args.skip_lines, analyse_lines, args.mbkey, mb_dir, json_dir, csv_dir, args.continue_previous_scan, args.folder_first)
			else:
				print("[!] Skipping MalwareBazaar: No API key provided.")

			vt_hashes_metadata = future_vt.result() if future_vt else []
			mb_hashes_metadata = future_mb.result() if future_mb else []
		
		# AvClass
		avc_hashes_metadata = []
		if args.vtkey and not args.skip_vt and vt_hashes_metadata and analyse_lines>=0:
			if args.analyse_lines != 0:
				avc_hashes_metadata = avc.get_data(vt_dir, hashes[args.skip_lines:args.skip_lines+analyse_lines], avc_dir)
			else:
				avc_hashes_metadata = avc.get_data(vt_dir, hashes[args.skip_lines:], avc_dir)
			
			output_file_name = "AvClass"
			
			if args.continue_previous_scan:
				previous_hashes_metadata, output_file_name = utils.open_json_to_continue(json_dir, output_file_name)
				previous_hashes_metadata = previous_hashes_metadata['data']
				for sha_data in avc_hashes_metadata:
					if sha_data in previous_hashes_metadata:
						avc_hashes_metadata.remove(sha_data)
				avc_hashes_metadata = previous_hashes_metadata + avc_hashes_metadata 
				avc_hashes_metadata = sorted(avc_hashes_metadata, key=lambda x: x["sha256"])

			if args.skip_lines != 0:
				output_file_name = f"{output_file_name}-skip{args.skip_lines}"
			if args.analyse_lines != 0:
				output_file_name = f"{output_file_name}-analyse{analyse_lines}"

			utils.save_json(json_dir, output_file_name, {'data':avc_hashes_metadata})
			utils.save_csv(csv_dir, output_file_name, avc_hashes_metadata)
		else:
			print("[!] Skipping AvClass: Depends on VirusTotal output.")

		# Combined
		if args.vtkey and vt_hashes_metadata and not args.skip_vt:
			combined_metadata = combine.merge_modules(vt_hashes_metadata, avc_hashes_metadata, mb_hashes_metadata, args.top_threat_tags)

			output_file_name = "Combined_metadata"
			if args.continue_previous_scan:
				output_file_name = f"{output_file_name}_continued"

			if args.skip_lines != 0:
				output_file_name = f"{output_file_name}-skip{args.skip_lines}"
			if args.analyse_lines != 0:
				output_file_name = f"{output_file_name}-analyse{analyse_lines}"

			utils.save_json(json_dir, output_file_name, {'data':combined_metadata})
			utils.save_csv(csv_dir, output_file_name, combined_metadata)

	except KeyboardInterrupt:
		print("\n[!] Execution interrupted by user. Exiting cleanly...")
		os._exit(1)

	print("\nCompilation completed!")
	return

if __name__ == '__main__':
	main()