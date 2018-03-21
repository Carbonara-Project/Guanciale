#!/usr/bin/env python

__author__ = "Andrea Fioraldi, Luigi Paolo Pileggi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com, rop2bash@gmail.com"

import os
import glob
import json
import requests
import platform
import shutil
import sys
import guanciale
import appdirs
from distutils.dir_util import mkpath

dirs = appdirs.AppDirs("guanciale")

idacmd = None
ida64cmd = None
usewine = False
radare2 = None

def _downloadRadare():
    url = "https://carbonara-project.github.io/Carbonara-Downloads/" + platform.system() + "/" + platform.machine() + "/files.txt"
    try:
        r = requests.get(url)
    except:
        return None
    files = r.text.split("\n")
    
    r2folder = os.path.join(dirs.user_data_dir, "guanciale_radare2")
    mkpath(r2folder)
    
    r2 = None
    for filename in files:
        if filename.strip() == "":
            continue
        
        path = os.path.join(r2folder, filename)
        if "radare2" in filename:
            r2 = path
        url = "https://carbonara-project.github.io/Carbonara-Downloads/" + platform.system() + "/" + platform.machine() + "/" + filename
        
        try:
            out_file = open(path, "wb")
        except IOError as err:
            if err.errno == 13: #permission denied
                guanciale.printerr("Permission denied to download radare2 files in the user data folder, try to run me as root.")
                exit(1)
            raise err

        print(" >> Downloading %s..." % filename)
        r = requests.get(url, stream=True)
        size = r.headers.get('content-length')

        if size is None:
            out_file.write(r.content)
        else:
            progress = 0
            size = int(size)
            for data in r.iter_content(chunk_size=4096):
                progress += len(data)
                out_file.write(data)
                perc = str(int(float(progress) / size * 100))
                sys.stdout.write("\r %s%%%s     %d / %d" % (perc, " "*(3-len(perc)), progress, size))    
                sys.stdout.flush()
        
        out_file.close()
        print
        
    if os.name == "posix":
        os.chmod(r2, 0755)
    return r2folder


def populateConfig_radare():
    def inPath(cmd):
        return any(os.access(os.path.join(path, cmd), os.X_OK) for path in os.environ["PATH"].split(os.pathsep))
    
    global radare2
    rad = "radare2"
    if os.name == "nt":
        rad += ".exe"
    raddir = ""
    if not inPath(rad):
        print("!!! RADARE2 NOT FOUND IN PATH !!!")
        sel = None
        while True:
            print
            print(" 1. Download precompiled binary")
            print(" 2. Specify the radare2 binary path manually")
            sel = raw_input("> ")
            if sel == "1":
                raddir = _downloadRadare()
                if raddir != None:
                    break
                guanciale.printerr("Precompiled radare2 for your system and/or machine is not avaiable.")
            elif sel == "2":
                raddir = raw_input("Insert radare2 folder path: ")
                if os.path.isdir(raddir):
                    break
                print(" >> The folder is not accessible. Retry.")
                continue
    radare2 = raddir
    

def populateConfig_idacmd():
    global idacmd
    global ida64cmd
    global usewine
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
        winepath = ""
        try:
            winepath = subprocess.check_output("which wine", shell=True).rstrip()
        except:
            pass
        if len(winepath) > 0: #wine is in PATH
            prefix = "~/.wine"
            try:
                prefix = os.environ["WINEPREFIX"]
            except: pass
            prefix = os.path.expanduser(prefix) #change ~ to /home/username
            #get ProgramFiles(x86) from wine
            try:
                program_files = subprocess.check_output("wine cmd /c 'echo %ProgramFiles%'", shell=True).rstrip()
            except subprocess.CalledProcessError:
                idacmd = None
                ida64cmd = None
                return
            if program_files != "":
                #get an array of directories in the ProgramFiles(x86) folder (relative to posix not wine) which the name starts with 'IDA'
                ida_dirs = glob.glob(prefix + "/drive_c/" + program_files[2:].replace("\\", "/") + "/IDA*/")
                if len(ida_dirs) > 0:
                    for d in ida_dirs:
                        if os.path.isfile(d + "/idat.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idat.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idat64.exe'"
                            usewine = True
                            return
                        elif os.path.isfile(d + "/idaw.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaw.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaw64.exe'"
                            usewine = True
                            return
                        elif os.path.isfile(d + "/ida.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/ida.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/ida64.exe'"
                            usewine = True
                            return
                        elif os.path.isfile(d + "/idaq.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaq.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaq64.exe'"
                            usewine = True
                            return
            #get ProgramFiles from wine
            try:
                program_files = subprocess.check_output("wine cmd /c 'echo %ProgramW6432%'", shell=True).rstrip()
            except subprocess.CalledProcessError:
                idacmd = None
                ida64cmd = None
                return
            if program_files != "":
                #get an array of directories in the ProgramFiles folder (relative to posix not wine) wich the name starts with 'IDA'
                ida_dirs = glob.glob(prefix + "/drive_c/" + program_files[2:].replace("\\", "/") + "/IDA*/")
                if len(ida_dirs) > 0:
                    for d in ida_dirs:
                        if os.path.isfile(d + "/idat.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idat.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idat64.exe'"
                            usewine = True
                            return
                        elif os.path.isfile(d + "/idaw.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaw.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaw64.exe'"
                            usewine = True
                            return
                        elif os.path.isfile(d + "/ida.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/ida.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/ida64.exe'"
                            usewine = True
                            return
                        elif os.path.isfile(d + "/idaq.exe"):
                            idacmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaq.exe'"
                            ida64cmd = "env WINEPREFIX='" + prefix + "' " + winepath + " '" + d + "/idaq64.exe'"
                            usewine = True
                            return
    #IDA pro not found
    idacmd = None
    ida64cmd = None


def writeConfig():
    global radare2
    global idacmd
    global ida64cmd
    global usewine
    data = {
        "radare2": radare2,
        "idacmd": idacmd,
        "ida64cmd": ida64cmd,
        "usewine": usewine
    }
    try:
        mkpath(os.path.dirname(dirs.user_config_dir))
        config_file = open(os.path.join(os.path.dirname(dirs.user_config_dir), "carbonara_guanciale.config.json"), "w")
    except IOError as err:
        if err.errno == 13: #permission denied
            guanciale.printerr("Permission denied to write to the config file, try to run me as root.")
            exit(1)
        raise err
    json.dump(data, config_file, indent=4)
    config_file.close()

def generateConfig():
    print(" >> Generating config file...")
    populateConfig_radare()
    populateConfig_idacmd()
    writeConfig()

def populate():
    global radare2
    global idacmd
    global ida64cmd
    global usewine
    
    #read config file
    try:
        config_file = open(os.path.join(os.path.dirname(dirs.user_config_dir), "carbonara_guanciale.config.json"))
        config_json = json.load(config_file)
        config_file.close()
        if "radare2" in config_json:
            radare2 = config_json["radare2"]
        else:
            populateConfig_radare()
        if "idacmd" in config_json and "ida64cmd" in config_json and "usewine" in config_json:
            idacmd = config_json["idacmd"]
            ida64cmd = config_json["ida64cmd"]
            usewine = config_json["usewine"]
        else:
            populateConfig_idacmd()
    except Exception:
        generateConfig()
    if len(radare2) != 0: #=0 is already in path
        os.environ["PATH"] = radare2 + os.pathsep + os.environ["PATH"]


#populate()

