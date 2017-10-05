#!/usr/bin/env python

"""r2pipe

This module provides an API to interact with the radare2
commandline interface from Python using a pipe.

Some r2 commands display the information in JSON, that's
why r2pipe provides `-j` methods to directly parse it
and return a native Python object.

Example:
  $ python
  > import r2pipe
  > r = r2pipe.open("/bin/ls")
  > print(r.cmd("pd 10"))
  > print(r.cmdj("aoj")[0]['size'])
  > r.quit()
"""

import os
import sys
import time
import json
import fcntl
from subprocess import Popen, PIPE

class open:
    """Class representing an r2pipe connection with a running radare2 instance
    """
    def __init__(self, filename='', flags=[]):
        """Open a new r2 pipe
        Args:
            filename (str): path to filename
            flags (list of str): arguments, either in comapct form
                ("-wdn") or sepparated by commas ("-w","-d","-n")
        Returns:
            Returns an object with methods to interact with r2 via commands
        """

        cmd = ["radare2", "-q0", filename]
        cmd = cmd[:1] + flags + cmd[1:]
        try:
            self.process = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        except:
            raise Exception("ERROR: Cannot find radare2 in PATH")
        self.process.stdout.read(1) # Reads initial \x00
        # make it non-blocking to speedup reading
        self.nonblocking = True
        if self.nonblocking:
            fd = self.process.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    def _cmd(self, cmd):
        cmd = cmd.strip().replace("\n", ";")
        if sys.version_info >= (3,0):
            self.process.stdin.write(bytes(cmd+'\n'))
        else:
            self.process.stdin.write(cmd+'\n')
        self.process.stdin.flush()
        out = b''
        while True:
            if self.nonblocking:
                try:
                    foo = self.process.stdout.read(4096)
                except:
                    continue
            else:
                foo = self.process.stdout.read(1)
            if foo[-1] == b'\x00':
                out += foo[0:-1]
                break
            out += foo
        return out

    def quit(self):
        """Quit current r2pipe session and kill
        """
        self.cmd("q")
        if hasattr(self, 'process'):
            self.process.stdin.flush()
            self.process.terminate()
            self.process.wait()

    # r2 commands
    def cmd(self, cmd):
        """Run an r2 command return string with result
        Args:
            cmd (str): r2 command
        Returns:
            Returns an string with the results of the command
        """
        res = self._cmd(cmd)
        if res is not None:
            return res.strip()
        return None

    def cmdj(self, cmd):
        """Same as cmd() but evaluates JSONs and returns an object
        Args:
            cmd (str): r2 command
        Returns:
            Returns a Python object respresenting the parsed JSON
        """
        c = self.cmd(cmd)
        try:
            data = json.loads(self.cmd(cmd))
        except (ValueError, KeyError, TypeError) as e:
            sys.stderr.write ("r2pipe.cmdj.Error: %s\n"%(e))
            data = None
        return data

    def syscmd(self, cmd):
        """Executes a program and returns the output (stdout only)
        Args:
            cmd (str): commandline shell command
        Returns:
            Returns a string with the output
        """
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE)
        out, err = p.communicate()
        return out

    def syscmdj(self, cmd):
        """Executes a program and returns an object representing the parsed JSON of the output
        Args:
            cmd (str): commandline shell command
        Returns:
            Returns an object constructed by parsing the JSON returned by the command
        """
        try:
            data = json.loads(self.syscmd(cmd))
        except (ValueError, KeyError, TypeError) as e:
            sys.stderr.write ("r2pipe.syscmdj.Error %s\n"%(e))
            data = None
        return data
