<img align="right" src="https://github.com/itsraval/MHATOD/blob/main/images/favicon.png" width="200" height="200">

# Malware Hash Analysis Through Online Databases (MHATOD)
descrizione

## Dependencies
### Internal
- requests
- sys
- datetime
- csv
- pathlib
- json
- subprocess
- collections

### External
The external dependencies are used by creating subprocess in the MHATOD script.
- avclass-malicialab [AVClass GitHub repository](https://github.com/malicialab/avclass/tree/master)

## API Requirements
Current API required to run the script:
- [VirusTotal](https://www.virustotal.com/gui/search/)

Future API required (it's reccomend to request the API key):
- [Triage](https://tria.ge/s)

## Example
```
python MHATOD.py hash-list.txt -nOutputFolder
```

### Input File
Text file which has an hash sha-256 per line, no comma or other characters needed.

### Output
All data gathered from the databases and information collected from the analysis
are saved inside a folder which is divided as follows:
- A "JSON" folder containing 3 .json files relating to the fields involved in
the total investigation into VirusTotal, Malware Bazaar and their results
combined together.
- A "MalwareBazaar" folder and a "VirusTotal" folder which contain a list of
.json files, one for each hash analysed, with the respective responses to the
requests made to the online databases.
- Three .csv files relating to the analysis carried out by the script, respectively
one for VirusTotal, one for Malware Bazaar and one with the combined
results of the two.

<p align="center"><img alt="Output folders" src="https://github.com/itsraval/MHATOD/blob/main/images/folder-struct.png"></p>

## Limitation
The main limitation of MHATOD is that its output depends on the information found on the databases and AVClass so it is not guaranteed that the output results will be right. If no data is found per hash on from the online sources, no data will be generate for that specific hash in the output.

It is possible to find discrepancies between the different sources which is why it is important to analyse more than one database from the creation of datasets.

### API Limitation
Based on the API-key the user has, you may be limitated on the daily number of requests.

## Help
Flags:
- ```-h```          help
- ```-l\[N\]```    starting at line \[N\] of the input sha256 file
- ```-n\[NAME\]```  \[NAME\] is going to be the folder's name

# Gather Hashes
To run the script you need to have a list of hashes you can check. If you are doing research and want to find lists of hashes you can use the following steps, which use semi-automatic tools: **retrive-hashes.js**, **clean.html** before executing **MHATOD.py** script.

1. Search on [Triage](https://tria.ge/s) or [Malware Bazaar](https://bazaar.abuse.ch/) for the category of malware you are looking for.
2. Paste **retrive-hashes.js** code into the browser's console.
3. Paste the output into **clean.html** inputbox.
4. Clean the text and save it into a file

## License
All tools listed below are released under the MIT license.
- MHATOD
- retrive-hashes.js
- clean.html

## Future Developements
Future developments concern the integration with [Triage](https://tria.ge/s) API for searching for information regarding malware. Other databases will be taken into consideration for the analysis and futher fields will be investigated. Furthermore, improvements regarding user usability will be made in the next version.

### TODO
- add description
- help menu
- flags settings
- requirements file
- new API
- add logo
- add logo to readme
- add logo to script
- divide script into files
- ...