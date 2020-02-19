import glob 
import os 

path = "E:\\idaAnalysis\\theZoo-master\\malwares\\Binaries\\"
unpack_path = "E:\\idaAnalysis\\viruses\\zoo\\"

def main():
    for root, dirs, files in os.walk(path):
        for dir in dirs:
            arc = path + dir + "\\*.zip"
            os.system("7z x -pinfected " + arc + " -o" + unpack_path)
main()