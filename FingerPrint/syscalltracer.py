#!/usr/bin/env python
#
#
# LC
#
# this file is used to trace a process and to see what are the 
# libraries it depends on
#

from ptrace import PtraceError
from ptrace.debugger import (PtraceDebugger, 
    ProcessExit, ProcessSignal, NewProcessEvent, ProcessExecution)
import ptrace.tools 
import ptrace.debugger.child

from logging import (getLogger, DEBUG, INFO, WARNING, ERROR)

import FingerPrint

class SyscallTracer():
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
        self.program[0] = ptrace.tools.locateProgram(self.program[0])
        #logger = getLogger()
        #logger.setLevel(DEBUG)
        # creating the debugger and setting it up
        self.debugger = PtraceDebugger()
        try:
            self.debugger.traceFork()
            self.debugger.traceExec()
            self.debugger.traceClone()
            process = None
            pid = ptrace.debugger.child.createChild(self.program, False, None)
            try:
                process = self.debugger.addProcess(pid, True)
            except (ProcessExit, PtraceError), err:
                if isinstance(err, PtraceError) and err.errno == EPERM:
                    print("ERROR: You are not allowed to trace process %s (permission"
                        "denied or process already traced)" % pid)
                else:
                    print("ERROR: Process can no be attached! %s" % err)
            if not process:
                return reutrnValue

            self.syscall_options = ptrace.func_call.FunctionCallOptions()
            self.syscallTrace(process)
        except ProcessExit, event:
            returnValue = True
        except PtraceError, err:
            print("ptrace() error: %s" % err)
        except KeyboardInterrupt:
            print("Interrupted.")
        returnValue = True
        self.debugger.quit()
        return returnValue


    def prepareProcess(self, process):
        process.syscall()
        process.syscall_state.ignore_callback = self.ignoreSyscall


    def ignoreSyscall(self, syscall):
        """ we want to trace only the mmap syscall"""
        if syscall.name.startswith('mmap') :
            return False
        else:
            return True


    def syscallTrace(self, process):
        # First query to break at next syscall
        self.prepareProcess(process)

        while True:
            # No more process? Exit
            if not self.debugger:
                break

            # Wait until next syscall enter
            try:
                event = self.debugger.waitSyscall()
                process = event.process
            except ProcessExit, event:
                # some subprocess terminated
                continue
            except ProcessSignal, event:
                #event.display()
                #print "display signals"
                process.syscall(event.signum)
                continue
            except NewProcessEvent, event:
                # newProcess (event)
                process2 = event.process
                #print("*** New process %s ***" % process2.pid)
                self.prepareProcess(process2)
                process2.parent.syscall()
                continue
            except ProcessExecution, event:
                #execv
                process3 = event.process
                #print("*** Process %s execution ***" % process3.pid)
                process3.syscall()
                continue

            # Process syscall enter or exit
            self.syscall(process)

    def syscall(self, process):
        state = process.syscall_state
        syscall = state.event(self.syscall_options)
        # we have a syscall but we also want to be sure 
        # it's the return of a syscall aka syscall.result is not None
        if syscall and syscall.result is not None :
            # ok we have to scan for new dependencies
            FingerPrint.blotter.getDependecyFromPID(str(syscall.process.pid), self.dependencies)
            #name = syscall.name
            #text = syscall.format()
            #result = syscall.result_text
            #print "", syscall.process.pid, "\t", syscall.name, "\t", syscall.result


        # Break at next syscall
        process.syscall()


if __name__ == "__main__":
    pass

