# Malware Hash Analysis Through Online Databases (MHATOD)
descrizione

## Dependecies

## API Requirements
Current API required to run the script:
- [VirusTotal](https://www.virustotal.com/gui/search/)

Future API required (it's reccomend to request the API key):
- [Triage](https://tria.ge/s)



## Examples

### Input File

### Output
![Output folders](https://github.com/itsraval/MHATOD/blob/main/images/folder-struct.png)


## Limitation

## Help
Flags:
- -h          help
- -l\[N\]     starting at line \[N\] of the input sha256 file
- -n\[NAME\]  \[NAME\] is going to be the folder's name

# Gather Hashes
To run the script you need to have a list of hashes you can check. If you are doing research and want to find lists of hashes you can use the following steps, which use semi-automatic tools: **retrive-hashes.js**, **clean.html** before executing **MHATOD.py** script.

1. Search on [Triage](https://tria.ge/s) or [Malware Bazaar](https://bazaar.abuse.ch/) for the category of malware you are looking for.
2. Paste **retrive-hashes.js** code into the browser's console.
3. Paste the output into **clean.html** inputbox.
4. Clean the text and save it into a file

## License
All tools listed below are released under the MIT license.
- MHATOD.py
- retrive-hashes.js
- clean.html

## Future Developements
Future developments concern the integration with [Triage](https://tria.ge/s) API for searching for information regarding malware. Other databases will be taken into consideration for the analysis and futher fields will be investigated. Furthermore, improvements regarding user usability will be made in the next version.

### TODO
- help menu
- flags settings
- requirements file
- new API
- ...



[I'm an inline-style link](https://www.google.com)

IMMAGINI
![alt text](https://github.com/adam-p/markdown-here/raw/master/src/common/images/icon48.png "Logo Title Text 1")


per gli esempi
[VIDEO]
![](my_video.mov)

<video width="320" height="240" controls>
  <source src="video.mov" type="video/mp4">
</video>
