def generateHashList(input_file):
    hash_list = []
    for line in input_file:
        hash_list.append(line.strip())
    return hash_list