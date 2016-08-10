#!/usr/bin/env python
#
# Forked and turned into a plugin by @tylerhalfpop
# Code from setcolorsiko added as well
# https://practicalmalwareanalysis.com/setcolorssiko-py/
#
#
# ============================================================================
# Copyright (c) 2012, Sebastian Eschweiler <advanced(dot)malware<dot>analyst[at]gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# =============================================================================

import idaapi
import idautils
import idc

DEFCOLOR = 0xffffffff
COLOR_CRYPTO = 0xffd2f8
COLOR_CALL = 0xffffd0


class InitialAnalysis_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Wow, such comment."
    help = "Wow, much help."
    wanted_name = "InitialAnalysis"
    wanted_hotkey = "F3"

    def init(self):
        print "Initial Analysis Plugin Loaded"
        return idaapi.PLUGIN_OK

    def run(self, arg):
        InitialAnalysis_main()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return InitialAnalysis_t()


def findUnidentifiedFunctions():
    # just get all not-function code and convert it to functions
    next = idaapi.cvar.inf.minEA
    while next != idaapi.BADADDR:
        next = idaapi.find_not_func(next, SEARCH_DOWN)
        flags = idaapi.getFlags(next)
        if idaapi.isCode(flags):
            idc.MakeFunction(next)


def colorize(addr, color):
    idaapi.set_item_color(addr, color)


def revokeAnalysis():
    n = idaapi.netnode("$ initialAnalysis", 0, False)

    if (n == idaapi.BADNODE):
        return

    idx = n.alt1st()
    while idx != idaapi.BADNODE:
        colorize(idx, DEFCOLOR)
        idx = n.altnxt(idx)

    n.kill()

    idaapi.refresh_idaview_anyway()


def setEaInfo(ea, info=""):
    n = idaapi.netnode("$ initialAnalysis", 0, True)
    n.set(info)


def setFunctionInfo(ea, color, info=""):
    f = idaapi.get_func(ea)
    if not f:
        return
    setEaInfo(f.startEA, info)


def setInfo(ea, color, info=""):
    colorize(ea, color)
    setEaInfo(ea, info)
    setFunctionInfo(ea, info)


class CryptoTester(object):
    def __init__(self):
        self.xor_instructions = [
            idaapi.NN_xor, idaapi.NN_pxor, idaapi.NN_xorps, idaapi.NN_xorpd]
        self.other_crypto = [idaapi.NN_ror, idaapi.NN_rol, idaapi.NN_not]

    def instruction(self, cmd):

        colorize = False

        if cmd.itype in self.xor_instructions:
            # check if different operands
            if cmd.Op1.type != cmd.Op2.type or cmd.Op1.reg != cmd.Op2.reg or cmd.Op1.value != cmd.Op2.value:
                colorize = True

        elif cmd.itype in self.other_crypto:
            colorize = True

        if colorize:
            setInfo(cmd.ea, COLOR_CRYPTO, "crypto")


class CallTester(object):
    def __init__(self):
        self.call_instructions = [idaapi.NN_call,
                                  idaapi.NN_callfi, idaapi.NN_callni]

    def instruction(self, cmd):
        if cmd.itype in self.call_instructions:
            setInfo(cmd.ea, COLOR_CALL)


def iterateInstructions():
    next = 0
    while next != idaapi.BADADDR:

        # get next instruction
        next = idc.NextHead(next)

        idaapi.decode_insn(next)
        for handlers in InstructionCallbacks:
            handlers.instruction(idaapi.cmd)


def setcolorsiko():
    '''
    #Color the Calls off-white
    heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
    funcCalls = []
    for i in heads:
            if GetMnem(i) == "call":
                    funcCalls.append(i)
    print "Number of calls: %d" % (len(funcCalls))
    for i in funcCalls:
            SetColor(i, CIC_ITEM, 0xc7fdff)
    '''
    # Color Anti-VM instructions Red and print their location
    heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
    antiVM = []
    for i in heads:
        if (GetMnem(i) == "sidt" or GetMnem(i) == "sgdt" or GetMnem(i) == "sldt" or GetMnem(i) == "smsw" or GetMnem(i) == "str" or GetMnem(i) == "in" or GetMnem(i) == "cpuid"):
            antiVM.append(i)
    print "Number of potential Anti-VM instructions: %d" % (len(antiVM))
    for i in antiVM:
        print "Anti-VM potential at %x" % i
        SetColor(i, CIC_ITEM, 0x0000ff)
    # Color non-zeroing out xor instructions Orange
    heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
    xor = []
    for i in heads:
        if GetMnem(i) == "xor":
            if (GetOpnd(i, 0) != GetOpnd(i, 1)):
                xor.append(i)
    print "Number of xor: %d" % (len(xor))
    for i in xor:
        SetColor(i, CIC_ITEM, 0x00a5ff)

def InitialAnalysis_main():
    revokeAnalysis()

    # find unidentified functions
    findUnidentifiedFunctions()

    global InstructionCallbacks
    InstructionCallbacks = []
    InstructionCallbacks.append(CryptoTester())
    InstructionCallbacks.append(CallTester())

    iterateInstructions()

    # refresh ida view to display our results
    idaapi.refresh_idaview_anyway()
    setcolorsiko()
    print "InitialAnalysis completed"

if __name__ == '__main__':
    # InitialAnalysis_main()
    pass
