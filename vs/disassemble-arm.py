# disassemble_arm.py
#
# Performs two functions:
# 1. Generates of list of ARM binary files for input to the second function.
# 2. Reads a list of ARM files and uses objdump to extract header 
#    information from each binary and to generate an assembly code
#    file of the binary.
#
# Input : arm_file_list.txt
#
# or
#
# Input : sorted-packer-id-features.csv
#         row format = [file_name, packer_name, packer_id, valid_pe, is_packed]
#
#         sorted-file-id-features.csv
#         row format = [file_name, file_type, file_id]
#
#         sorted-trid-id-features.csv
#         row format = [file_name, file_type, percentage, file_id]
#
# Output: assembler files [input_binary_filename.asm]
#         ARM header files [input_binary_filename.txt]
#
# or
#
# Output: arm_file_list.txt
#
# Author: Derek Chadwick
# Date  : 07/09/2016


import argparse
import subprocess as sub
import os
import sys
import pandas as pd


def get_arm_file_list(packer_id_feature_file, file_id_feature_file, trid_id_feature_file):
    # Load the malware packer id features and file id features from the sample set.
    packer_id_features = pd.read_csv(packer_id_feature_file)
    file_id_features = pd.read_csv(file_id_feature_file)
    trid_id_features = pd.read_csv(trid_id_feature_file)
    
    counter = 0

    file_names_list = file_id_features['file_name']
    file_list = []
    
    for idx, file_name in enumerate(file_names_list):
        trid_name = trid_id_features.iloc[idx, 1]
        fid_name = file_id_features.iloc[idx, 1]
        #trid_name = trid_name.lower()
        #fid_name = fid_name.lower()
        
        if trid_name.find('ARM') > -1 or fid_name.find('ARM') > -1:
            print('Found: {:s} - {:s}'.format(trid_name, fid_name))
            counter += 1
            full_name = "VirusShare_" + file_name + "\n"
            file_list.append(full_name)


        
    fop = open('data/arm-file-list.txt','w')
    fop.writelines(file_list)
    fop.close()
    
    print("Got {:d} ARM filenames.".format(counter))

    return file_list


def disassemble_arm_binaries(file_list):
    # Use the command "objdump -d file_name" to dump out all 
    # the code sections of the ARM binary.
    # Use the command "objdump -g -x file_name -o file_name.txt to dump out
    # all header sections.
    
    counter = 0
    disassed = 0
    error_count = 0
    
    print("Disassembling {:d} binary ARM files.".format(len(file_list)))
    
    for file_name in file_list:
        file_path = file_name.rstrip() # remove the newlines or else !!!
        asm_file_name = file_name + ".asm"
        hdr_file_name = file_name + ".txt"
            
        if (os.path.isfile(file_path)):
            
            # Dump the assembly code listing.
            fopasm = open(asm_file_name, "w")
            sub.call(["objdump", "-d", file_path], stdout=fopasm)
            fopasm.close()
            
            # Dump the ELF section headers and import tables.
            fophdr = open(hdr_file_name, "w")
            sub.call(["objdump", "-g", "-x", file_path], stdout=fophdr)
            fophdr.close()
            
            # now delete the binary, we do not need it anymore.
            # sub.call(["rm", file_path])
            
            disassed += 1

        else:
            #print("Error: file does not exist - {:s}".format(file_path))
            error_count += 1
           
        counter += 1
        if (counter % 1000) == 0: # print progress
            print('Disassembled: {:d} - {:s}'.format(counter, file_path))    
 

    print("Disassembled {:d} binaries with {:d} file path errors.".format(disassed, error_count))
    
    #sub.call(["mv", "*.asm", "/opt/vs/asm"])
    
    return


def run_processes(file_list):
    # Spawn worker processes.
    
    quart = len(file_list)//4
    train1 = file_list[:quart]
    train2 = file_list[quart:(2*quart)]
    train3 = file_list[(2*quart):(3*quart)]
    train4 = file_list[(3*quart):]

    print("Files: {:d} - {:d} - {:d}".format(len(file_list), quart, (len(train1)+len(train2)+len(train3)+len(train4))))

    trains = [train1, train2, train3, train4]
    p = Pool(4)
    p.map(disassemble_arm_binaries, trains)
    
    return


def print_help():
    print("disassemble_arm -efhiow [input_file_list.txt]")
    print("    -e /path/to/sample/binaries/")
    print("    -f /path/to/file/id/feature/file")
    
    return


# Start of Script


parser = argparse.ArgumentParser(description="Disassemble ARM binaries")
parser.add_argument("-w", "--writelist", action="store_true", dest="writefilelist", default=False)
parser.add_argument("-i", "--inputfile", dest="inputfilename")
parser.add_argument("-o", "--outputfile", dest="outputfilename")
parser.add_argument("-f", "--fileidfeature", dest="featurefilename")
parser.add_argument("-p", "--packeridfeature", dest="packerfilename")
parser.add_argument("-t", "--trididfeature", dest="tridfilname")
parser.add_argument("-e", "--extdrive", dest="externaldrive")

args = parser.parse_args()

# TODO: add code for options

# Load the malware packer id features sets.
ext_drive = args.externaldrive
feature_file = args.featurefilename
in_unpacked_file_list = args.inputfilename
out_unpacked_file_list = args.outputfilename
write_file_list = args.writefilelist

# Start of Script

# TODO: everything


# TEST

packer_id_file = 'data/sorted-packer-id-features-vs251.csv'
file_id_file = 'data/sorted-file-id-features-vs251.csv'
trid_id_file = 'data/sorted-trid-id-features-vs251.csv'
    
if os.path.isfile(packer_id_file) and os.path.isfile(file_id_file) and os.path.isfile(trid_id_file):
    unflist = get_arm_file_list(packer_id_file, file_id_file, trid_id_file)
    disassemble_arm_binaries(unflist)
else:
    print("Warning: Required data files not found. Skipping ARM disassembly.")
    
# END TEST

# End of Script