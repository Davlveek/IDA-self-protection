import glob 
import os 
import pefile

ida = 'ida64'
anti_debug_path = 'E:\\idaAnalysis\\scripts\\antiDebug1.py'
anti_VM_path = 'E:\\idaAnalysis\\scripts\\antiVM1.py'
path = 'E:\\idaAnalysis\\viruses\\zoo\\'

def main():
    pe_count = 0
    for filename in glob.glob(os.path.join(path, '*.*')):
        try:
            pe = pefile.PE(filename)
            os.system(ida + ' -B ' + filename)
            idb_filename = filename.replace('.exe', '.idb')
            os.system(ida + ' -A ' + '-S' + anti_debug_path + ' ' + idb_filename)
            os.system(ida + ' -A ' + '-S' + anti_VM_path + ' ' + idb_filename)
            pe_count += 1
        except pefile.PEFormatError:
            pass

    print("Count of PE-files - %d" % pe_count)

main()