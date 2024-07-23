import collections.abc
import csv
import json
from pathlib import Path

def exportJson(metadata, filename, printY):
        if not Path(filename).is_file():
                with open(filename, 'w') as f:
                        json.dump(metadata, f)
                if printY:
                        print(f"Exported JSON {filename}")

def buildOutputString(m, isCombine):
        outputString = [m['index'], m['sha256']]
        outputString.append("\n".join(m['names']))

        if "signature" in m:
                outputString.append(m['signature'])

        if "tags" in m:
                if isinstance(m['tags'], collections.abc.Sequence):
                        outputString.append("\n".join(m['tags']))

        outputString.append(m['file_type'])
        outputString.append(m['fs_time'])
        outputString.append(m['fs_date'])
        
        tn = True
        if m['threat_names'] is not None:
                for i in m['threat_names']:
                        if i is None:
                                tn = False
                if tn == True:
                        outputString.append("\n".join(m['threat_names']))

        if tn == False:
                outputString.append(" ")

        if "avclass_FAM" in m:
                outputString.append(m['avclass_FAM'])
                outputString.append("\n".join(m['avclass_TAGS']))


        if isCombine:
                outputString.append("\n".join(m['db']))

        return outputString


def exportMetadata(metadata, filename, isCombine):
        if len(metadata) == 0:
                print("No data gathered")
                return

        with open(filename, 'w', newline='', encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)

                if "signature" in metadata[0]:
                        if isCombine:
                                writer.writerow(["Index", "SHA-256", "File Name", "Signature", "Tags", "File Type", "First Submission Time", "First Submission Date", "Threath Names", "AVclass Family", "AVclass Tags", "Databases"])
                        else:
                                writer.writerow(["Index", "SHA-256", "File Name", "Signature", "Tags", "File Type", "First Submission Time", "First Submission Date", "Threath Names"])
                else:
                        if isCombine:
                                writer.writerow(["Index", "SHA-256", "File Name", "Signature", "Tags", "File Type", "First Submission Time", "First Submission Date", "Threath Names", "AVclass Family", "AVclass Tags", "Databases"])
                        else:
                                writer.writerow(["Index", "SHA-256", "File Name", "File Type", "First Submission Time", "First Submission Date", "Threath Names", "AVclass Family", "AVclass Tags"])

                for m in metadata:
                        if m['error'] == "None":
                                writer.writerow(buildOutputString(m, isCombine))
                        else:
                                writer.writerow([m['index'], m['sha256'], m['error']])
        print(f"Exported file {filename}")