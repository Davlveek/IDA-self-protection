from idaapi import *
from idautils import *
from idc import *

antiVM = dict()
analysis = dict()

Hostnames = Pills = Env = Proc = MAC = DLL = Art = Mal = WMI = False
Tool = Antivirus = False

def good_bad(value):
    return "[BAD]" if value else "[GOOD]"

def trick_sort(trick):
    list_d = list(trick.items())
    list_d.sort(key=lambda i: i[1])

    return list_d

def print_inst():
    sorted_vm = trick_sort(antiVM)
    sorted_tools = trick_sort(analysis)

    filename = get_root_filename()
    filename = filename.replace('.exe', '')
    f = open("E:\\idaAnalysis\\" + filename + "[AntiVM]" + ".txt", 'w')
    
    f.write("------------------------[Anti-VM Detection]-------------------------\n")
    f.write("Checking Pills commands\t\t\t\t" + good_bad(Pills) + '\n')
    f.write("Checking Hostnames\t\t\t\t" + good_bad(Hostnames) + '\n')
    f.write("Checking Enviroment\t\t\t\t" + good_bad(Env) + '\n')
    f.write("Checking Malicious commands\t\t\t" + good_bad(Mal) + '\n')
    f.write("Checking Processes\t\t\t\t" + good_bad(Proc) + '\n')
    f.write("Checking DLLs\t\t\t\t\t" + good_bad(DLL) + '\n')
    f.write("Checking WMI requests\t\t\t\t" + good_bad(WMI) + '\n')
    f.write("Checking File System Artifacts\t\t\t" + good_bad(Art) + '\n')
    f.write("Checking MAC-addresses\t\t\t\t" + good_bad(MAC) + '\n')
    f.write("-------------------[Analysis Tools and Antiviruses]------------------\n")
    f.write("Analysis Tools\t\t\t\t\t" + good_bad(Tool) + '\n')
    f.write("Antiviruses\t\t\t\t\t" + good_bad(Antivirus) + '\n')
    f.write("--------------------------------------------------------------------\n")

    f.write("---------------------------------[Anti-VM]---------------------------------\n")
    for i in sorted_vm:
        disasmStr = GetDisasm(i[0])
        f.write("0x%08x [%s]" % (i[0], disasmStr))
        f.write(' ' + i[1] + '\n')

    f.write("---------------------[Analysis Tools and Antiviruses]----------------------\n")
    for i in sorted_tools:
        disasmStr = GetDisasm(i[0])
        f.write("0x%08x [%s]" % (i[0], disasmStr))
        f.write(' ' + i[1] + '\n')

    f.close()


def check_ports():
   #heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))

    flag1 = False
    flag2 = False
    for seg in Segments():
        for x in Heads(seg, SegEnd(seg)):  
            if isCode(GetFlags(x)):
                if GetMnem(x) == "mov" and "eax" in GetOpnd(x, 0) and "564D5868h" in GetOpnd(x, 1):
                    flag1 = True
                    continue
                if flag1:
                    if GetMnem(x) == "mov" and "edx" in GetOpnd(x, 0) and "5658h" in GetOpnd(x, 1):
                        flag1 = False
                        flag2 = True
                        continue
                if flag2:
                    if GetMnem(x) == "in" and "eax" in GetOpnd(x, 0) and "dx" in GetOpnd(x, 1):
                        flag2 = False
                        antiVM[x] = "I/O Ports"
                        continue

                elif GetMnem(x) == "call" and "RtlGetNativeSystemInformation" in GetOpnd(x, 0):
                    antiVM[x] = "I/O Ports: RtlGetNativeSystemInformation"

                if "564D5868h" in GetOpnd(x, 1) or "5658h" in GetOpnd(x, 1):
                   antiVM[x] = "I/O Ports"

def global_check():
    global Hostnames, Pills, Env, Proc, MAC, DLL, Art, Mal, WMI
    global Tool, Antivirus

    pill_check = ['sidt', 'sgdt', 'sldt', 'smsw', 'str', 'in']
    hostname_check = ['brbrb-d8fb22af1','KVMKVMKVM', 'prl hyperv', 'Microsoft Hv', 'XenVMMXenVMM']
    malicious_check = ['cmd', 'cpuid', 'autorun', 'autorunsc']
    env_check = ['dmesg', 'kmods', 'pcidevs', 'dmidecode', 'sysfs', 'procfs', 'dashXmstdout']
    proc_check = ['vboxservice.exe', 'vboxtray.exe', 'vmtoolsd.exe', 'vmwaretray.exe', 'VGAuthService.exe', 
        'vmacthlp.exe', 'vmsrvc.exe', 'vmusrvc.exe', 'prl_cc.exe', 'prl_tools.exe', 'xenservice.exe', 'qemu-ga.exe']
    dll_check = ['avghookx.dll', 'avghooka.dll', 'snxhk.dll', 'sbiedll.dll', 'dbghelp.dll', 'api_log.dll', 'dir_watch.dll', 
        'pstorec.dll', 'vmcheck.dll', 'wpespy.dll', 'cmdvrt32.dll', 'cmdvrt64.dll']
    wmi_check = ['SELECT * FROM Win32_Bios', 'SELECT * FROM Win32_PnPEntity', ' SELECT * FROM Win32_NetworkAdapterConfiguration', 
        'SELECT * FROM Win32_NTEventlogFile', 'SELECT * FROM Win32_Processor', 'SELECT * FROM Win32_LogicalDisk', 'SELECT * FROM Win32_ComputerSystem',
        'SELECT * FROM MSAcpi_ThermalZoneTemperature', 'SELECT * FROM Win32_Fan']
    fs_artifact_check = ['VBoxMouse.sys', 'VBoxGuest.sys', 'VBoxSF.sys', 'VBoxVideo.sys', 'vboxdisp.dll', 'vboxhook.dll',
        'vboxmrxnp.dll', 'vboxogl.dll', 'vboxoglarrayspu.dll', 'vboxoglcrutil.dll', 'vboxoglerrorspu.dll', 'vboxoglfeedbackspu.dll',
        'vboxoglpackspu.dll', 'vboxoglpassthroughspu.dll', 'vboxservice.exe', 'vboxtray.exe', 'VBoxControl.exe', 'vmmouse.sys', 
        'vmhgfs.sys', 'vm3dmp.sys', 'vmci.sys', 'vmhgfs.sys', 'vmmemctl.sys', 'vmmouse.sys', 'vmrawdsk.sys', 'vmusbmouse.sys']
    mac_check = [r'\x08\x00\x27', r'\x00\x05\x69', r'\x00\x0C\x29', r'\x00\x1C\x14', r'\x00\x50\x56', r'\x00\x1C\x42', r'\x00\x16\x3E', r'\x0A\x00\x27']

    tools = ['Procmon.exe', 'procexp.exe', 'procexp64.exe', 'ProcessHacker.exe', 'Wireshark.exe', 'SystemExplorer.exe', 'Speccy.exe', 'Speccy64.exe',
        'spyxx.exe', 'tcpdump.exe']
    antiviruses = ['msmpeng.exe', 'navapsvc.exe', 'avkwctl.exe', 'fsav32.exe', 'mcshield.exe', 'ntrtscan.exe', 'avguard.exe', 'ashServ.exe', 
        'AVENGINE.EXE', 'avgemc.exe', 'tmntsrv.exe', 'drweb.exe', 'AVP.EXE', 'egui.exe', 'ekrn.exe', 'ffavg.exe', 'alg.exe', 'avgnt.exe',
        'avfwsvc.exe', 'avmailc.exe', 'avwebgrd.exe', 'sched.exe', 'ashDisp.exe', 'ashWebSv.exe', 'ashMailSv.exe', 'aswUpdSv.exe', 
        'NortonAntiBot.exe', 'NABAgent.exe', 'NABWatcher.exe', 'NABMonitor.exe', 'Mcshield.exe', 'Vshwin32.exe', 'Avconsol.exe', 'Avsynmgr.exe' 
        'cfp.exe', 'cmdagent.exe']

    #heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))

    for seg in Segments():
        for x in Heads(seg, SegEnd(seg)):  
            if isCode(GetFlags(x)):
                if isCode(GetFlags(x)):
                    # Check pills
                    for pill in pill_check:
                        if GetMnem(x) == pill:
                            antiVM[x] = "Pill"
                            Pills = True

                    # Check hostnames
                    for hostname in hostname_check:
                        if hostname in GetDisasm(x):
                            antiVM[x] = "Hostname"
                            Hostnames = True

                    # Check malicious
                    for mal in malicious_check:
                        if GetMnem(x) == mal:
                            antiVM[x] = "Malicious"
                            Mal = True

                    # Check enviroments
                    for env in env_check:
                        if env in GetDisasm(x):
                            antiVM[x] = "Enviroment"
                            Env = True

                    # Check processes
                    for proc in proc_check:
                        if proc in GetDisasm(x):
                            antiVM[x] = "Process"
                            Proc = True
            
                    # Check DLLs
                    for dll in dll_check:
                        if dll in GetDisasm(x):
                            antiVM[x] = "DLL"
                            DLL = True
        
                    # Check WMI 
                    for wmi in wmi_check:
                        if wmi in GetDisasm(x):
                            antiVM[x] = "WMI"
                            WMI = True
        
                    # Check file system arifacts
                    for art in fs_artifact_check:
                        if art in GetDisasm(x):
                            antiVM[x] = "File System Arcifact"
                            Art = True
        
                    # Check MAC-Addresses
                    for mac in mac_check:
                        if mac in GetDisasm(x):
                            antiVM[x] = "MAC"
                            MAC = True
        
                    # Check Ananlysis Toools
                    for tool in tools:
                        if tool in GetDisasm(x):
                            analysis[x] = "Analysis Tool"
                            Tool = True
        
                    # Check Antiviruses
                    for ant in antiviruses:
                        if ant in GetDisasm(x):
                            analysis[x] = "Antivirus"     
                            Antivirus = True   

def main():
    check_ports()
    global_check()
    print_inst()

    print "------------------------[Anti-VM Detection]-------------------------"
    print "Checking Pills commands\t\t\t", good_bad(Pills) 
    print "Checking Hostnames\t\t\t\t", good_bad(Hostnames)
    print "Checking Enviroment\t\t\t\t", good_bad(Env)
    print "Checking Malicious commands\t\t\t", good_bad(Mal)
    print "Checking Processes\t\t\t\t", good_bad(Proc)
    print "Checking DLLs\t\t\t\t", good_bad(DLL)
    print "Checking WMI requests\t\t\t\t", good_bad(WMI)
    print "Checking File System Artifacts\t\t\t", good_bad(Art)
    print "Checking MAC-addresses\t\t\t\t", good_bad(MAC)
    print "-------------------[Analysis Tools and Antiviruses]------------------"
    print "Analysis Tools\t\t\t\t", good_bad(Tool)
    print "Antiviruses\t\t\t\t\t", good_bad(Antivirus)
    print "--------------------------------------------------------------------"

main()