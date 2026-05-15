import os
import sys
import argparse
from datetime import datetime
from dotenv import load_dotenv

def get_args():
	load_dotenv()
	vt_key = os.getenv("VIRUSTOTAL_API_KEY")
	mb_key = os.getenv("MALWAREBAZAAR_API_KEY")

	parser = argparse.ArgumentParser(
		description="Malware metadata scanner and classifier",
		epilog="Configuration: Store keys in a '.env' file as VIRUSTOTAL_API_KEY=key and MALWAREBAZAAR_API_KEY=key\nNote: The input file must contain exactly one SHA256 hash per line."
	)

	parser.add_argument("input_file", help="The path to the input file (Format: 1 SHA256 hash per line)")
	parser.add_argument("-b", "--banner", action="store_true", help="Display the banner")
	parser.add_argument("-i", "--info", action="store_true", help="Developer info")

	parser.add_argument("-o", "-d", "--output", "--destination", type=str, default=f"malware-metadata-{datetime.now().strftime('%Y.%m.%d-%H.%M.%S')}", help="Directory path where the scan results will be saved. (default: malware-metadata-TIMESTAMP)")

	parser.add_argument("-cps", "--continue-previous-scan", action="store_true", help="Continue previous scan. It needs same input file and outfile file to work. If these requirements are not meet, the scan would be a normal scan. (default: off)")

	parser.add_argument("--input-folder", type=str, default=None, help="Input folder with json response of the hashes. In the format of input-folder and VirusTotal, MalwareBazaar as subfolders.")

	# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

	parser.add_argument("--skip-lines", type=int, default=0, help="Number of lines to skip at the start of the input file. (default: 0)")

	parser.add_argument("--analyse-lines", type=int, default=0, help="Number of lines to analyse. (default: all the lines in the file)")

	parser.add_argument("--skip-vt", action="store_true", help="Skip VirusTotal analysis.")
	parser.add_argument("--skip-mb", action="store_true", help="Skip MalwareBazaar analysis")

	parser.add_argument("-ttt", "--top-threat-tags", action="store_true", help="Shows the only the top 5 threat tags.")

	parser.add_argument("--vtkey", type=str, default=vt_key, help="VirusTotal API Key (Overrides .env value).")

	parser.add_argument("--mbkey", type=str, default=mb_key, help="MalwareBazaar API Key (Overrides .env value).")

	args = parser.parse_args()

	missing_keys = []
	if not args.vtkey:
		missing_keys.append("VIRUSTOTAL_API_KEY")
	if not args.mbkey:
		missing_keys.append("MALWAREBAZAAR_API_KEY")

	if args.analyse_lines < 0:
		parser.error(
			f"\n\n[!] The number of lines to analyse has to be greater than 0."
		)

	if len(missing_keys) == 2:
		parser.error(
			f"\n\n[!] MISSING ALL API KEYS: {', '.join(missing_keys)}\n"
			"At least one API key is required to perform analysis.\n"
			"Please provide them via flags (--vtkey / --mbkey) or your .env file."
		)
	elif len(missing_keys) > 0:
		print(f"\n[!] WARNING: Missing API Key(s): {', '.join(missing_keys)}")
		print("[*] Analysis will be limited to the provided key(s).")
		
		choice = input("Do you want to proceed with reduced analysis? (y/n): ").lower().strip()
		if choice != 'y':
			print("[*] Operation cancelled by user.")
			sys.exit()
	return args