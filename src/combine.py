from datetime import datetime

def combineLists(l1, l2):
        comb = l1
        for i in l2:
                if i not in comb:
                        comb.append(i)
        return comb

def combineFT(f1, f2):
        if (f1 == "Win32 EXE" or f2 == "Win32 EXE") and ((f1 == "exe" or f2 == "exe")):
                return "Win32 EXE"
        else:
                return f1 + " / " + f2

def combineDateTime(f1_date, f1_time, f2_date, f2_time):
        a = f1_time + " " + f1_date
        b = f2_time + " " + f2_date

        d1 = datetime.strptime(a, "%H:%M:%S %d/%m/%Y")
        d2 = datetime.strptime(b, "%H:%M:%S %d/%m/%Y")

        if d1 < d2:
                return d1.strftime("%d/%m/%Y"), d1.strftime("%H:%M:%S")
        else:
                return d2.strftime("%d/%m/%Y"), d2.strftime("%H:%M:%S")

def combineDatasets(vt, mb, folderName):
        dataset = []
        for i in range(len(vt)):
                metadata = {}
                metadata['index'] = vt[i]['index']
                metadata['sha256'] = vt[i]['sha256']

                if vt[i]['error'] != "None":
                        if mb[i]['error'] != "None":
                                metadata['error'] = "VirusTotal: " + vt[i]['error'] + " - MalwareBazaar: " + mb[i]['error']
                                metadata['db'] = []
                                metadata['avclass_FAM'] = ""
                                metadata['avclass_TAGS'] = []
                        else:
                                metadata = mb[i]
                                metadata['db'] = ["MalwareBazaar"]
                                metadata['avclass_FAM'] = ""
                                metadata['avclass_TAGS'] = []
                elif mb[i]['error'] != "None":
                        metadata = vt[i]
                        metadata['signature'] = ""
                        metadata['tags'] = []
                        metadata['db'] = ["VirusTotal"]
                        metadata['avclass_FAM'] = vt[i]['avclass_FAM']
                        metadata['avclass_TAGS'] = vt[i]['avclass_TAGS']
                else:
                        metadata['names'] = combineLists(vt[i]['names'], mb[i]['names'])
                        metadata['signature'] = mb[i]['signature']
                        metadata['file_type'] = combineFT(vt[i]['file_type'], mb[i]['file_type'])
                        metadata['tags'] = mb[i]['tags']
                        metadata['fs_date'], metadata['fs_time'] = combineDateTime(vt[i]['fs_date'], vt[i]['fs_time'], mb[i]['fs_date'], mb[i]['fs_time'])
                        metadata['threat_names'] = combineLists(vt[i]['threat_names'], mb[i]['threat_names'])
                        metadata['error'] = "None"
                        metadata['db'] = ["VirusTotal", "MalwareBazaar"]
                        metadata['avclass_FAM'] = vt[i]['avclass_FAM']
                        metadata['avclass_TAGS'] = vt[i]['avclass_TAGS']
                dataset.append(metadata)             
        return dataset
