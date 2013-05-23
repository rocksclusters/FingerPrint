#!/usr/bin/env python
#
#
# LC
#
# this file is used to trace a process and to see what are the 
# libraries it depends on
#

import FingerPrint.blotter
import FingerPrint.utils
import FingerPrint.sergeant

import tempfile
import os, signal, re
#TODO add logger
from logging import (getLogger, DEBUG, INFO, WARNING, ERROR)




class SyscallTracer:
    """this class can spawn a process and trace its' execution to record 
    what are its dynamic dependency requirements

    Usage:

        tracer = SyscallTracer()
        execcmd = shlex.split(execcmd)
        tracer.main(execcmd)
        # output will in the TracerControlBlock static variables
        TracerControlBlock.[files|dependencies|env|cmdline]
    """

    def main(self, command): 
        """start the trace with the given command

        The input parameters are:
            `command' command line to trace passed through shlex.split

        return false if something went wrong
        """

        import ctypes
        from FingerPrint.ptrace import func as ptrace_func
        import FingerPrint.ptrace.cpu_info
        import FingerPrint.ptrace.signames
        files={}
        #
        # main function to launch a process and trace it
        #
        returnValue = False
        self.program = command
        # this is to check if we are entering or returning from a system call
        processesStatus = dict()
        options =  ptrace_func.PTRACE_O_TRACEFORK | ptrace_func.PTRACE_O_TRACEVFORK \
                | ptrace_func.PTRACE_O_TRACECLONE | ptrace_func.PTRACE_O_TRACEEXIT \
                | ptrace_func.PTRACE_O_TRACEEXEC | ptrace_func.PTRACE_O_TRACESYSGOOD;
        #TODO add the logger
        #logger = getLogger()
        #logger.setLevel(DEBUG)
        # creating the debugger and setting it up
        child = os.fork()
        if child == 0:
            # we are in the child or traced process
            # traceme and execv
            ptrace_func.ptrace_traceme()
            os.execl(FingerPrint.utils.which(self.program[0]), *self.program)
        else:
            # father or tracer process
            # we trace the execution here
            print "The fingerprint process %d going to trace %d" % (os.getpid(), child)
            pid, status = os.waitpid(-1, 0)
            if pid != child :
                print("The process tracer could not bootstrap.")
                return False
            
            ptrace_func.ptrace_setoptions(child, options);
            ptrace_func.ptrace_syscall(child);
            files = TracerControlBlock.files
            TracerControlBlock.set_trace_function()
            while True: 
                # main loop tracer
                # 1. wait for syscall from the children
                # 2. analyze what happen, if mmap syscall scan /proc/PID/maps
                # 3. get ready to  wait for the next syscall
                try:
                    # wait for all cloned children __WALL = 0x40000000
                    (pid, status) = os.waitpid(-1, 0x40000000 )
                except OSError:
                    print "Tracing terminated successfully"
                    return True
                if not pid > 0:
                    print "Catastrofic failure"
                    return False

                event = status >> 16;
                signalValue = os.WSTOPSIG(status)
                deliverSignal = 0
                if os.WIFEXITED(status):
                    # a process died, report it and go back to wait for syscall
                    print "The process ", pid, " exited"
                    processesStatus.pop(pid)
                    continue

                if os.WIFSTOPPED(status) and signalValue == (signal.SIGTRAP | 0x80 ):
                    #
                    # we have a syscall
                    # orig_rax or orig_eax contains the syscall number 
                    # taken from linux src arch/x86/syscalls/syscall_[32|64].tbl
                    # switch on the syscal number to intercept mmap and open
                    regs = ptrace_func.ptrace_getregs(pid)
                    if pid not in processesStatus :
                        #new pid
                        tcb = TracerControlBlock( pid )
                        processesStatus[pid] = tcb
                    if (FingerPrint.ptrace.cpu_info.CPU_X86_64 and regs.orig_rax == 2):# or regs.orig_rax == 257):
                        #
                        # handle open (orig_rax == 2 on 64bit)
                        #
                        if processesStatus[pid].enterCall :
                            # we are entering open, regs.rsi contains the first arguments
                            # https://github.com/torvalds/linux/blob/master/arch/x86/kernel/entry_64.S#L585
                            processesStatus[pid].firstArg = regs.rdi
                            processesStatus[pid].enterCall = False
                        else:
                            # we are exiting from a open
                            processesStatus[pid].enterCall = True
                            # cast from c_ulong to c_long
                            returnValue = ctypes.c_long(regs.rax).value
                            if returnValue >= 0:
                                openPath = self.readCString(regs.rdi, pid)
                                if openPath[0] != '/':
                                    #relative path we need to get the pwd
                                    openPath = "$" + processesStatus[pid].getProcessCWD() + "$" + openPath
                                libName = processesStatus[pid].getFileOpener()
                                if libName not in files:
                                    files[libName] = {}
                                if processesStatus[pid].getProcessName() not in files[libName]:
                                    files[libName][processesStatus[pid].getProcessName()] = set()
                                files[libName][processesStatus[pid].getProcessName()].add(openPath)

                            # else don't do anything
                            # TODO use close to check for used files (easier to trace full path)

                    elif (FingerPrint.ptrace.cpu_info.CPU_X86_64 and regs.orig_rax == 9)\
                            or (FingerPrint.ptrace.cpu_info.CPU_I386 and \
                            (regs.orig_eax == 90 or regs.orig_eax == 192 ) ):
                        #
                        # handle mmap (orig_rax == 9 64bit or orig_eax == 90 or 192 on 32bit)
                        #
                        if processesStatus[pid].enterCall :
                            # we are entering mmap
                            processesStatus[pid].enterCall = False
                            #print "the process %d enter mmap" % pid
                        else:
                            # we are returning from mmap
                            processesStatus[pid].enterCall = True
                            processesStatus[pid].updateSharedLibraries()
                elif os.WIFSTOPPED(status) and (signalValue == signal.SIGTRAP) and event != 0:
                    # this is just to print some output to the users
                    subChild = ptrace_func.ptrace_geteventmsg(pid)
                    if event == ptrace_func.PTRACE_EVENT_FORK:
                        print "The process %d forked a new process %d" % (pid, subChild)
                    elif event == ptrace_func.PTRACE_EVENT_VFORK:
                        print "The process %d vforked a new process %d" % (pid, subChild)
                    elif event == ptrace_func.PTRACE_EVENT_CLONE :
                        print "The process %d cloned a new process %d" % (pid, subChild)
                    elif event == ptrace_func.PTRACE_EVENT_EXEC :
                        print "The process %d run exec" % (pid)
                        processesStatus[pid].updateProcessInfo()
                    elif event == ptrace_func.PTRACE_EVENT_EXIT:
                        pass
                        #print "the process %d is in a event exit %d" % (pid, subChild)
                else:
                    # when a signal is delivered to one of the child and we get notified
                    # we need to relay it properly to the child
                    # (in particular SIGCHLD must be rerouted to the parents if not mpirun
                    # will never end)
                    print "Signal %s(%d) delivered to %d " % \
                        (FingerPrint.ptrace.signames.signalName(signalValue), signalValue, pid)
                    deliverSignal = signalValue

                # set the ptrace option and wait for the next syscall notification
                ptrace_func.ptrace_setoptions(pid, options);
                ptrace_func.ptrace_syscall(pid, deliverSignal);



    def readCString(self, address, pid):
        data = []
        mem = open("/proc/" + str(pid) + "/mem", 'rb')
        mem.seek(address)
        while True:
            b = mem.read(1)
            if b == '\0':
                break
            data.append(b)
        mem.close()
        return ''.join(data)


    def test(self):
        a = {}
        self.main(["bash", "-c", "sleep 5 > /dev/null & find /tmp > /dev/null &"], a)
        print "dict: ", a



class TracerControlBlock:
    """This class hold data needed for tracing a processes

    Insiperd by strace code (strct tcb)).
    """

    """
    `env' dictionary that keeps track of process environment variables
    `cmdline' dictionary that keeps track of the executed cmdline
    `dynamicDependencies' is a dictionary of shared libraries used by the various
       processes e.g.: { 'binarypath' : [list of file it depends to],
       '/bin/bash' : ['/lib/x86_64-linux-gnu/libnss_files-2.15.so',
       '/lib/x86_64-linux-gnu/libnss_nis-2.15.so']}
    `files' is a dictionary of dictionary of opened files by the various processes
       for example files[libraryA][executableB] and files[libraryA][executableC]
       return respectively the list of opened file by the libraryA when run under
       executableB and when run under executable

    PS: I don't really like this solution of static variable but for the moment ti does its job
    """
    dependencies = {}
    files = {}
    env = {}
    cmdline = {}


    def __init__(self, pid):
        self.pid = pid
        self.enterCall = True
        self.firstArg = None
        self.updateProcessInfo()


    def updateProcessInfo(self):
        processName = self.getProcessName()
        #read the cmdline
        f = open('/proc/' + str(self.pid) + '/cmdline')
        TracerControlBlock.cmdline[processName] = f.read().split('\x00')
        f.close()
        #read the env
        f = open('/proc/' + str(self.pid) + '/environ')
        TracerControlBlock.env[processName] = f.read().split('\x00')
        f.close()

    def updateSharedLibraries(self):
        """ it scans the procfs to find the process loaded shared libraries

        results are stored in the class variable called dependencies"""
        binaryFile = self.getProcessName()
        if binaryFile not in TracerControlBlock.dependencies:
            # new binary file let's add it to the dyctionary
            TracerControlBlock.dependencies[binaryFile] = []
        f=open('/proc/' + str(self.pid) + '/maps')
        maps = f.read()
        f.close()
        for i in maps.split('\n'):
            tokens = i.split()
            if len(tokens) > 5 and 'x' in tokens[1] and os.path.isfile(tokens[5]):
                # assumption: if we have a memory mapped area to a file and it is
                # executable then it is a shared library
                libPath = tokens[5].strip()
                if libPath not in TracerControlBlock.dependencies[binaryFile] and libPath != binaryFile:
                    TracerControlBlock.dependencies[binaryFile].append( libPath )

    @classmethod
    def set_trace_function(cls):
        """method function need to set up the trace function which needs C binding"""
        try:
            from FingerPrint.stacktracer import trace
            cls.trace = trace
            cls.tracing = True
        except :
            # no tracer compiled fall back to binary name
            print " - Unable to load stacktracer - "
            cls.tracing = False

    def getProcessName(self):
        return os.readlink('/proc/' + str(self.pid) + '/exe')

    def getProcessCWD(self):
        return os.readlink('/proc/' + str(self.pid) + '/cwd')

    def getFileOpener(self):
        """ return the path to the object who initiate the current open syscall

        if FingerPrint is compiled with the stacktracer module it will find the
        file object who contains the code which instantiate the open if not it will
        return the path to the current process """
        if not self.tracing:
            return self.getProcessName()
        libname = self.trace(self.pid)
        prev_lib = ""
        for line in libname.split('\n'):
            splitline = line.split(':')
            if len(splitline) != 3:
                continue
            current_lib = splitline[0]
            if not prev_lib:
                #fisrt line in the stack
                prev_lib = current_lib
            else:
                if current_lib == prev_lib:
                    #we are still in the first library probaly libc
                    prev_lib = current_lib
                    continue
                else:
                    # that's it, we just got out of first lib in the stack, lets
                    # see if we have a open or not
                    if current_lib not in objectFiles:
                        objectFiles[current_lib] = ObjectFile(current_lib)
                    if self._isOpen(objectFiles[current_lib], splitline[1], splitline[2]) :
                        return current_lib
                    else :
                        return prev_lib
        #hmm probably we are in the loader
        return current_lib


    def _isOpen(self, objectFile, offset, ip):
        """return true if ip/offset are pointing to a open syscall for this 
        objectfile
        """
        if objectFile.isDynamic():
            # offset and ip are in the form of 0x45a3f2
            vma=offset[2:]
        else:
            vma=ip[2:]
        instruction = objectFile.getPrevInstruction(vma)
        #print "instruction ", instruction, " file ", objectFile.filename, " ", offset, ip
        if len(instruction[2]) == 0:
            # we don't know how to decode this situation
            return False
        if '@' in instruction[2]:
            #it's point to the plt just remove the @plt
            callname = instruction[2].split('@')[0]
        else :
            #we have a function call but it's not pointing to the plt table yet
            #so let's try to follow the code flow to see where it leads
            called_instruction = objectFile.getInstruction(instruction[1])
            if 'jmp' in called_instruction[0]:
                # we have a jump let's hope it goes to the plt
                if '@' in called_instruction[2]:
                    callname = called_instruction[2].split('@')[0]
                else:
                    return False
            else:
                return False
        # these are the system call that we trace for the moment
        if callname in ['fopen', '_IO_fopen', 'fopen64', 'open64', 'open', '__open', 'open64', '__open64']:
            return True
        else:
            return False



objectFiles = {}

class ObjectFile:
    """class that wrap an elf object file and its assembler code""" 

    def __init__(self, filename):
        """ """
        self.filename = filename
        if FingerPrint.sergeant.prelink :
            # we need to undo the prelink
            # we could use also the IP instead of the offset in the _isOpen function
            # instead of undoing the prelinking but then it would not work with prelinked
            # and it would fail with non prelinked libraries (this way always works but is slower)
            (fd, filename) = tempfile.mkstemp()
            returncode = FingerPrint.utils.getOutputAsList(["prelink", "-u", "-o", \
                                                              filename, self.filename])[1]
            if returncode != 0 :
                raise RuntimeError("unable to undo the prelink on " + self.filename)
        (outputs, returncode) = FingerPrint.utils.getOutputAsList(["objdump", "-x", "-D", filename])
        if returncode != 0 :
            raise RuntimeError("objdump failed for file " + self.filename)
        if FingerPrint.sergeant.prelink :
            os.close(fd)
            os.remove(filename)
        self.assembler = outputs

    def isDynamic(self):
        """ return true if this is a dynamic object aka shared library """
        #we just check the first lines no need to scan the whole thing
        for line in self.assembler[0:10]:
            if "EXEC_P" in line:
                return False
            if "DYNAMIC" in line:
                return True
        raise RuntimeError("Unable to determine VMA for file " + self.filename)


    def getInstruction(self, vma):
        for line in self.assembler:
            if re.match(" *" + vma + ":", line):
                return self._decodeLine(line)
        raise RuntimeError("Unable to determine VMA for file " + self.filename)


    def getPrevInstruction(self, vma):
        """ """
        for line in self.assembler:
            if re.match(" *" + vma + ":", line):
                return self._decodeLine(prevLine)
            prevLine = line
        raise RuntimeError("Unable to determine VMA for file " + self.filename)


    def _decodeLine(self, line):
        # take out the address part
        line = line[line.find(':') + 1:].lstrip()
        while True:
            if not re.match("[a-z0-9][a-z0-9] ", line[0:3]):
                break
            line = line[3:]
        #we removed all the hex opcodes
        line = line.lstrip()
        tokens = line.split()
        istr = tokens[0]
        if len(tokens) > 1:
            # we have an address
            addr = tokens[1]
        else:
            addr = ""
        if len(tokens) > 2:
            # we have a symbol
            sym = tokens[2]
            sym = sym.rstrip('>')
            sym = sym.lstrip('<')
        else:
            sym = ""
        return (istr, addr, sym)




