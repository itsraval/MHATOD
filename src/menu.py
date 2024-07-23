flags = {}
flags["startPosition"] = 0
flags["folderName"] = ""

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
	print("\n")
	return

def flagsEnable(flag):
    for f in flag:
        if "-b" in f:
        	banner()
        elif "-h" in f:
            # print help
            print("Help Menu")
            print("Description: The input file has to contain 1 sha256 per line of ransomware/malware.\nThe input file has to be the first argument.")
            print("Flags:\n-b\tshow banner\n-h\thelp\n-i\tdeveloper information\n-l[N]\tstarting at line [N] of the input sha256 file\n-n[NAME]\t[NAME] is going to be the folder's name")
        elif "-i" in f:
        	print("This script has been developed by Alessandro Ravizzotti")
        	print("GitHub: https://github.com/itsraval/MHATOD")
        	print("Website: alessandro.ravizzotti.dev")
        	print("Contact: alessandro@ravizzotti.dev")
        elif "-l" in f:
            # start position in file
            flags["startPosition"] = int(f[2:])
        elif "-n" in f:
            flags["folderName"] = f[2:]
        else:
            print("Flag not found! Please use -h to see the help menu.")
