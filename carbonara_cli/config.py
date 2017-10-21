import os
import glob
import json

radare2 = None
idacmd = None
ida64cmd = None

def populateConfig_radare():
    def inPath(cmd):
        return any(os.access(os.path.join(path, cmd), os.X_OK) for path in os.environ["PATH"].split(os.pathsep))
    global radare2
    rad = "radare2"
    if os.name == "nt":
        rad += ".exe"
    if not inPath(rad):
        print "!!! RADARE2 NOT FOUND IN PATH !!!"
        rad = raw_input("Specify the radare2 binary path manually: ")
        if not os.access(rad, os.X_OK):
            print "The file is not accessible. Abort."
            print
            exit(1)
    radare2 = rad

def populateConfig_idacmd():
    global idacmd
    global ida64cmd
    if os.name == 'nt': #Windows
        #get an array of directories in the ProgramFiles(x86) folder which the name starts with 'IDA'
        ida_dirs = glob.glob(os.environ["ProgramFiles(x86)"] + "\\IDA*\\")
        if len(ida_dirs) > 0:
            for d in ida_dirs:
                if os.path.isfile(d + "\\idat.exe"):
                    idacmd = d + "\\idat.exe"
                    ida64cmd = d + "\\idat64.exe"
                    return
                elif os.path.isfile(d + "\\idaw.exe"):
                    idacmd = d + "\\idaw.exe"
                    ida64cmd = d + "\\idaw64.exe"
                    return
                elif os.path.isfile(d + "\\ida.exe"):
                    idacmd = d + "\\ida.exe"
                    ida64cmd = d + "\\ida64.exe"
                    return
                elif os.path.isfile(d + "\\idaq.exe"):
                    idacmd = d + "\\idaq.exe"
                    ida64cmd = d + "\\idaq64.exe"
                    return
        #get an array of directories in the ProgramFiles folder which the name starts with 'IDA'
        ida_dirs = glob.glob(os.environ["ProgramW6432"] + "\\IDA*\\")
        if len(ida_dirs) > 0:
            for d in ida_dirs:
                if os.path.isfile(d + "\\idat.exe"):
                    idacmd = d + "\\idat.exe"
                    ida64cmd = d + "\\idat64.exe"
                    return
                elif os.path.isfile(d + "\\idaw.exe"):
                    idacmd = d + "\\idaw.exe"
                    ida64cmd = d + "\\idaw64.exe"
                    return
                elif os.path.isfile(d + "\\ida.exe"):
                    idacmd = d + "\\ida.exe"
                    ida64cmd = d + "\\ida64.exe"
                    return
                elif os.path.isfile(d + "\\idaq.exe"):
                    idacmd = d + "\\idaq.exe"
                    ida64cmd = d + "\\idaq64.exe"
                    return
    if os.name == "posix": #Linux or macOS, IDA Pro don't run on other posix systems
        import subprocess
        
        #TODO add native macOS and Linux support

        #get wine full path
        winepath = subprocess.check_output("which wine", shell=True).rstrip()
        if len(winepath) > 0: #wine is in PATH
            prefix = "~/.wine"
            try:
                prefix = os.environ["WINEPREFIX"]
            except: pass
            prefix = os.path.expanduser(prefix) #change ~ to /home/username
            #get ProgramFiles(x86) from wine
            program_files = subprocess.check_output("wine cmd /c 'echo %ProgramFiles%'", shell=True).rstrip()
            if program_files != "":
                #get an array of directories in the ProgramFiles(x86) folder (relative to posix not wine) which the name starts with 'IDA'
                ida_dirs = glob.glob(prefix + "/drive_c/" + program_files[2:].replace("\\", "/") + "/IDA*/")
                if len(ida_dirs) > 0:
                    for d in ida_dirs:
                        if os.path.isfile(d + "/idat.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idat.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idat64.exe'"
                            return
                        elif os.path.isfile(d + "/idaw.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaw.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaw64.exe'"
                            return
                        elif os.path.isfile(d + "/ida.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/ida.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/ida64.exe'"
                            return
                        elif os.path.isfile(d + "/idaq.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaq.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaq64.exe'"
                            return
            #get ProgramFiles from wine
            program_files = subprocess.check_output("wine cmd /c 'echo %ProgramW6432%'", shell=True).rstrip()
            if program_files != "":
                #get an array of directories in the ProgramFiles folder (relative to posix not wine) wich the name starts with 'IDA'
                ida_dirs = glob.glob(prefix + "/drive_c/" + program_files[2:].replace("\\", "/") + "/IDA*/")
                if len(ida_dirs) > 0:
                    for d in ida_dirs:
                        if os.path.isfile(d + "/idat.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idat.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idat64.exe'"
                            return
                        elif os.path.isfile(d + "/idaw.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaw.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaw64.exe'"
                            return
                        elif os.path.isfile(d + "/ida.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/ida.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/ida64.exe'"
                            return
                        elif os.path.isfile(d + "/idaq.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaq.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaq64.exe'"
                            return
    #IDA pro not found
    idacmd = None
    ida64cmd = None


def writeConfig():
    global radare2
    global idacmd
    global ida64cmd
    data = {
        "radare2": radare2,
        "idacmd": idacmd,
        "ida64cmd": ida64cmd
    }
    config_file = open(os.path.join(os.path.dirname(__file__), "carbonara_bininfo.config.json"), "w")
    json.dump(data, config_file, indent=4)
    config_file.close()

def generateConfig():
    global radare2
    global idacmd
    global ida64cmd
    print "Generating config file..."
    populateConfig_radare()
    populateConfig_idacmd()
    writeConfig()

def populate():
    global radare2
    global idacmd
    global ida64cmd
    
    #read config file
    try:
        config_file = open(os.path.join(os.path.dirname(__file__), "carbonara_bininfo.config.json"))
        config_json = json.load(config_file)
        config_file.close()
        if "radare2" in config_json:
            radare2 = config_json["radare2"]
        else:
            populateConfig_radare()
        if "idacmd" in config_json and "ida64cmd" in config_json:
            idacmd = config_json["idacmd"]
            idacmd = config_json["ida64cmd"]
        else:
            populateConfig_idacmd()
    except Exception:
        generateConfig()

populate()

