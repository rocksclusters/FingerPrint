#!/usr/bin/env python
#
#
# LC
#
# this file is used to trace a process and to see what are the 
# libraries it depends on
#

from FingerPrint.ptrace import func as ptrace_func
import FingerPrint.ptrace.cpu_info
import FingerPrint.ptrace.signames

from logging import (getLogger, DEBUG, INFO, WARNING, ERROR)

import FingerPrint.blotter
import FingerPrint.utils

import os, signal, ctypes



try:
    from FingerPrint.stacktracer import tracer
except :
    # no tracer compiled fall back to binary name
    def tracer(self):
        return self.getProcessName()


class SyscallTracer:
    """this class can spawn a process and trace its' execution to check 
    what are its dynamic dependency requirements

    Usage:

        file = {}
        dynamicDependecies = {}
        tracer = SyscallTracer()
        execcmd = shlex.split(execcmd)
        tracer.main(execcmd, dynamicDependecies, files)


    """


    def main(self, command, dependencies, files):
        """start the trace

        The input parameters are:
            `command' command line to trace passed through shlex.split
            `dynamicDependencies' is a dictionary of shared libraries used by the various 
            processes e.g.: { 'binarypath' : [list of file it depends to],
            '/bin/bash' : ['/lib/x86_64-linux-gnu/libnss_files-2.15.so',
            '/lib/x86_64-linux-gnu/libnss_nis-2.15.so']}
            `files' is a dictionary of opened files by the various processes

        return false if something went wrong
        """
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
                #print "the child process %d stops. status: %d, signal? %d, exit? %d, continue? %d, stop? %d\n" % \
                #    (child, status , os.WIFSIGNALED(status) ,
                #    os.WIFEXITED(status), os.WIFCONTINUED(status), os.WIFSTOPPED(status))
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
                        processesStatus[pid] = TracerControlBlock( pid )
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
                                    print "relative path"
                                    openPath = processesStatus[pid].getProcessCWD() + openPath
                                procName = processesStatus[pid].getFileOpener()
                                if procName not in files:
                                    files[procName] = set()
                                files[procName].add(openPath)

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
                            FingerPrint.blotter.getDependecyFromPID(str(pid), dependencies)
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
    """hold data needed for tracing a processes

    Insiperd by strace code (strct tcb)). This structure hold the data we need to trace
    the status of a proce with the SyscallTracer """

    def __init__(self, pid):
        self.pid = pid
        self.enterCall = True
        self.firstArg = None

    def getProcessName(self):
        return os.readlink('/proc/' + str(self.pid) + '/exe')

    def getProcessCWD(self):
        return os.readlink('/proc/' + str(self.pid) + '/cwd')

    def getFileOpener(self):
        """ return the path to the object who initiate the current open syscall

        if FingerPrint is compiled with the stacktracer module it will find the
        file object who contains the code which instantiate the open if not it will
        return the path to the current process """
        return tracer(self)

        #if libunwind :
        #    if not hasattr(self, 'unw_addr_space_ptr') :
        #        #we need to create an address space
        #        self.unw_addr_space_ptr = libunwind._UPT_create(self.pid);

        #    # libunwind-x86_64.h size(unw_cursor_t) = 8 * 127 = 1016
        #    cursor = ctypes.byref(  ctypes.create_string_buffer(1016) )

        #    libunwind.unw_init_remote(cursor, libunwind_as, self.unw_addr_space_ptr)



        #  unw_word_t ip;
        #  int n = 0, ret;
        #  unw_cursor_t c;
        #
        #  extern unw_addr_space_t libunwind_as;
        #  EXITIF(unw_init_remote(&c, libunwind_as, tcp->libunwind_ui) < 0);
        #  do {
        #    EXITIF(unw_get_reg(&c, UNW_REG_IP, &ip) < 0);
        #
        #    print_normalized_addr(tcp, ip);
        #
        #    ret = unw_step(&c);
        #
        #    if (++n > 255) {
        #      /* guard against bad unwind info in old libraries... */
        #      fprintf(stderr, "libunwind warning: too deeply nested---assuming bogus unwind\n");
        #      break;
        #    }
        #  } while (ret > 0);
        #}

        #return None




if __name__ == "__main__":
    SyscallTracer().test()

