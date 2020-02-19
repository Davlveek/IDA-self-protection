import glob 
import os 

path = 'E:\\idaAnalysis\\zooStat1'

def anitVM_statistics():
    pills = hostnames = env = mal = proc = dll = wmi = fsa = mac = 0
    anal = ant = 0

    for filename in glob.glob(os.path.join(path, '*.txt')):
        if "[AntiVM]" in filename:
            f = open(filename, 'r')

            for line in f:
                if "[Anti-VM Detection]" in line:
                    continue
                elif "[Analysis Tools and Antiviruses]" in line:
                    continue
                elif "Checking Pills commands" in line:
                    if "BAD" in line:
                        pills += 1
                elif "Checking Hostnames" in line:
                    if "BAD" in line:
                        hostnames += 1
                elif "Checking Enviroment" in line:
                    if "BAD" in line:
                        env += 1
                elif "Checking Malicious commands" in line:
                    if "BAD" in line:
                        mal += 1
                elif "Checking Processes" in line:
                    if "BAD" in line:
                        proc += 1
                elif "Checking DLLs" in line:
                    if "BAD" in line:
                        dll += 1
                elif "Checking WMI requests" in line:
                    if "BAD" in line:
                        wmi += 1
                elif "Checking File System Artifacts" in line:
                    if "BAD" in line:
                        fsa += 1
                elif "Checking MAC-addresses" in line:
                    if "BAD" in line:
                        mac += 1
                elif "Analysis Tools" in line:
                    if "BAD" in line:
                        anal += 1
                elif "Antiviruses" in line:
                    if "BAD" in line:
                        ant += 1

            f.close() 

    print("Checking Pills commands - %d" % pills)
    print("Checking Hostnames - %d" % hostnames)
    print("Checking Enviroment - %d" % env)
    print("Checking Malicious commands - %d" % mal)
    print("Checking Processes - %d" % proc)
    print("Checking DLLs - %d" % dll)
    print("Checking WMI requests - %d" % wmi)
    print("Checking File System Artifacts - %d" % fsa)
    print("Checking MAC-addresses - %d" % mac)
    print("Analysis Tools - %d" % anal)
    print("Antiviruses - %d" % ant)

def antiDebug_statistics():
    IsDebuggerPresent = CheckRemoteDebuggerPresent = GetVersionExA = 0
    NtQueryInformationProcess = GetThreadContext = NtSetInformationThread = 0
    PEB = NtGlobalFlag = TrapFlag = HeapFlag = HB = SEH = VEH = 0
    NtCreateThreadEx = 0

    for filename in glob.glob(os.path.join(path, '*.txt')):
        if "[AntiDbg]" in filename:
            f = open(filename, 'r')

            for line in f:
                if "[Anti-Debugger Detection]" in line:
                    continue
                elif "-------------------------------------------------------------------------" in line:
                    break
                elif "IsDebuggerPresent" in line:
                    if "BAD" in line: 
                        IsDebuggerPresent += 1
                elif "CheckRemoteDebuggerPresent" in line:
                    if "BAD" in line: 
                        CheckRemoteDebuggerPresent += 1
                elif "GetVersionExA" in line:
                    if "BAD" in line: 
                        GetVersionExA += 1
                elif "NtQueryInformationProcess" in line:
                    if "BAD" in line:
                        NtQueryInformationProcess += 1
                elif "GetThreadContext" in line:
                    if "BAD" in line:
                        GetThreadContext += 1
                elif "NtSetInformationThread" in line:
                    if "BAD" in line:
                        NtSetInformationThread += 1
                elif "NtCreateThreadEx" in line:
                    if "BAD" in line:
                        NtCreateThreadEx += 1
                elif "Get PEB" in line:
                    if "BAD" in line:
                        PEB += 1
                elif "NtGlobalFlag" in line:
                    if "BAD" in line:
                        NtGlobalFlag += 1
                elif "TrapFlag" in line:
                    if "BAD" in line:
                        TrapFlag += 1
                elif "Heap Flags" in line:
                    if "BAD" in line:
                        HeapFlag += 1
                elif "Hardware Breakpoints" in line:
                    if "BAD" in line:
                        HB += 1
                elif "SEH" in line:
                    if "BAD" in line:
                        SEH += 1
                elif "VEH" in line:
                    if "BAD" in line:
                        VEH += 1

            f.close()

    print("-------------------------------Anti-Debug Statistics-------------------------------------")
    print("IsDebuggerPresent - %d" % IsDebuggerPresent)
    print("CheckRemoteDebuggerPresent - %d" % CheckRemoteDebuggerPresent)
    print("GetVersionExA - %d" % GetVersionExA)
    print("NtQueryInformationProcess - %d" % NtQueryInformationProcess)
    print("GetThreadContext - %d" % GetThreadContext)
    print("NtSetInformationThread - %d" % NtSetInformationThread)
    print("NtCreateThreadEx - %d" % NtCreateThreadEx)
    print("Get PEB - %d" % PEB)
    print("NtGlobalFlag - %d" % NtGlobalFlag)
    print("TrapFlag - %d" % TrapFlag)
    print("Heap Flags - %d" % HeapFlag)
    print("Hardware Breakpoints - %d" % HB)
    print("SEH - %d" % SEH)
    print("VEH - %d" % VEH)

def main():
    antiDebug_statistics()
    print("---------------------------------------------------------")
    anitVM_statistics()

main()