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

import os, signal

class SyscallTracer:
    """this class can spawn a process and trace its' execution to check 
    what are its dynamic dependency requirements

    Usage:

        tracer = SyscallTracer()
        execcmd = shlex.split(execcmd)
        tracer.main(execcmd, dynamicDependecies)

    dynamicDependencies is a dictionary of 
    { 'binarypath' : [list of file it depends to],
    '/bin/bash' : ['/lib/x86_64-linux-gnu/libnss_files-2.15.so',
    '/lib/x86_64-linux-gnu/libnss_nis-2.15.so']}

    """

    def main(self, command, dependencies):
        #
        # main function to launch a process and trace it
        #
        self.dependencies = dependencies
        returnValue = False
        self.program = command
        # this is to check if we are entering or returning from a system call
        syscallEnter = dict()
        options =  ptrace_func.PTRACE_O_TRACEFORK | ptrace_func.PTRACE_O_TRACEVFORK \
                | ptrace_func.PTRACE_O_TRACECLONE | ptrace_func.PTRACE_O_TRACEEXIT \
                | ptrace_func.PTRACE_O_TRACEEXEC | ptrace_func.PTRACE_O_TRACESYSGOOD;
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
            #print("ptracing %d entrering the loop.\n" % child);
            
            while True: 
                # main loop tracer
                # 1. wait for syscall from the children
                # 2. analyze what happen, if mmap syscall scan /proc/PID/maps
                # 3. get ready to  wait for the next syscall
                try:
                    # wait for all cloned children __WALL = 0x40000000
                    (child, status) = os.waitpid(-1, 0x40000000 )
                except OSError:
                    print "Tracing terminated successfully"
                    return True
                if not child > 0:
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
                    print "The process ", child, " exited"
                    continue

                if os.WIFSTOPPED(status) and signalValue == (signal.SIGTRAP | 0x80 ):
                    regs = ptrace_func.ptrace_getregs(child)
                    # mmap on x86_64 is orig_rax == 9
                    # mmap on 32bit is orig_eax == 90 or 120
                    # taken from linux src arch/x86/syscalls/syscall_[32|64].tbl
                    if (FingerPrint.ptrace.cpu_info.CPU_X86_64 and regs.orig_rax == 9)\
                            or (FingerPrint.ptrace.cpu_info.CPU_I386 and \
                            (regs.orig_eax == 90 or regs.orig_eax == 192 ) ):
                        #we are inside a mmap function
                        if child not in syscallEnter.keys() :
                            #new pid
                            syscallEnter[child] = True
                        if syscallEnter[child] :
                            # we are entering mmap
                            syscallEnter[child] = False
                            #print "the process %d enter mmap" % child
                        else:
                            # we are returning from mmap
                            syscallEnter[child] = True
                            FingerPrint.blotter.getDependecyFromPID(str(child), self.dependencies)
                elif os.WIFSTOPPED(status) and (signalValue == signal.SIGTRAP) and event != 0:
                    # this is just to print some output to the users
                    subChild = ptrace_func.ptrace_geteventmsg(child)
                    if event == ptrace_func.PTRACE_EVENT_FORK:
                        print "The process %d forked a new process %d" % (child, subChild)
                    elif event == ptrace_func.PTRACE_EVENT_VFORK:
                        print "The process %d vforked a new process %d" % (child, subChild)
                    elif event == ptrace_func.PTRACE_EVENT_CLONE :
                        print "The child process %d cloned a new process %d" % (child, subChild)
                    elif event == ptrace_func.PTRACE_EVENT_EXEC :
                        print "The child process %d run exec" % (child)
                    elif event == ptrace_func.PTRACE_EVENT_EXIT:
                        pass
                        #print "the process %d is in a event exit %d" % (child, subChild)
                else:
                    # when a signal is delivered to one of the child and we get notified
                    # we need to relay it properly to the child
                    # (in particular SIGCHLD must be rerouted to the parents if not mpirun
                    # will never end)
                    print "Signal %s(%d) delivered to %d " % \
                        (FingerPrint.ptrace.signames.signalName(signalValue), signalValue, child)
                    deliverSignal = signalValue

                # set the ptrace option and wait for the next syscall notification
                ptrace_func.ptrace_setoptions(child, options);
                ptrace_func.ptrace_syscall(child, deliverSignal);


    def test(self):
        a = {}
        self.main(["bash", "-c", "sleep 5 > /dev/null & find /tmp > /dev/null &"], a)
        print "dict: ", a

if __name__ == "__main__":
    SyscallTracer().test()

