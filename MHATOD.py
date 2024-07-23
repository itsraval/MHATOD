from datetime import datetime
from pathlib import Path
import sys
from src.combine import *
from src.export import *
from src.gatheringDB import *
from src.menu import *
from src.settings import *
from src.utils import *


def main():
        banner()
        if (len(sys.argv) < 2):
                print("Please insert input_file or type -h for help")
                return
        else:
                if "-" in sys.argv[1][0]:
                        flagsEnable(sys.argv[1:])
                else:
                        input_file = open(sys.argv[1])

                        if len(sys.argv) > 2:
                                flagsEnable(sys.argv[2:])

                        if api_key_virustotal == "":
                                print("VirusTotal API-key needs to be set!\nSet the API-key in the settings.py file, located in the src folder.")
                                return


                        hash_list = generateHashList(input_file)

                        nameTime = datetime.now().strftime("%H.%M.%S-%d.%m.%Y")
                        if flags["folderName"] == "":
                                folderName = f"malware-metadata {nameTime}"
                        else:
                                folderName = flags["folderName"]
                        Path(folderName).mkdir(parents=True, exist_ok=True)
                        Path(f"{folderName}\\VirusTotal").mkdir(parents=True, exist_ok=True)
                        Path(f"{folderName}\\MalwareBazaar").mkdir(parents=True, exist_ok=True)
                        Path(f"{folderName}\\JSON").mkdir(parents=True, exist_ok=True)
                        
                        virusTotal_metadata, counterVT = virusTotal(hash_list[flags["startPosition"]:], folderName)
                        exportJson(virusTotal_metadata, f"{folderName}\\JSON\\VirusTotal.json", True)
                        output_file_nameVT = f"{folderName}\\malware-metadata-virusTotal-{nameTime}.csv"
                        exportMetadata(virusTotal_metadata, output_file_nameVT, False)

                        print("\n-----\n")

                        # counterVT = 2
                        malwareBazaar_metadata = malwareBazaar(hash_list[flags["startPosition"]:flags["startPosition"]+counterVT], folderName)        
                        exportJson(malwareBazaar_metadata, f"{folderName}\\JSON\\malwareBazaar.json", True)
                        output_file_nameMB = f"{folderName}\\malware-metadata-malwareBazaar-{nameTime}.csv"
                        exportMetadata(malwareBazaar_metadata, output_file_nameMB, False)

                        print("\n-----\n")
                        
                        combined_metadata = combineDatasets(virusTotal_metadata, malwareBazaar_metadata, folderName)
                        exportJson(combined_metadata, f"{folderName}\\JSON\\combined.json", True)
                        output_file_name = f"{folderName}\\malware-metadata-{nameTime}.csv"
                        exportMetadata(combined_metadata, output_file_name, True)
        

if __name__ == '__main__':
        main()