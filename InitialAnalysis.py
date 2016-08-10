#!/usr/bin/env python
#
# Forked and turned into a plugin by @tylerhalfpop
#
# SetColorSiko by Mike Sikorski
# https://practicalmalwareanalysis.com/setcolorssiko-py/
#
# Func-renamer by Alexander Hanel
# https://bitbucket.org/Alexander_Hanel/func-renamer
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

# SetColorSiko 
# Mike Sikorski
# https://practicalmalwareanalysis.com/setcolorssiko-py/

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

# func-rename
# alexander<dot>hanel<at>gmail<dot>com
# https://bitbucket.org/Alexander_Hanel/func-renamer

class GENAPI:
    def __init__(self):
        self.rename = False
        self.comment = False
        self.reg = [ 'Reg', 'RegCloseKey' ,'RegConnectRegistryA' ,'RegConnectRegistryW' ,'RegCreateKeyA' ,'RegCreateKeyExA' ,'RegCreateKeyExW',\
        'RegCreateKeyW' ,'RegDeleteKeyA' ,'RegDeleteKeyW' ,'RegDeleteValueA' ,'RegDeleteValueW' ,'RegDisablePredefinedCache' ,\
        'RegDisablePredefinedCacheEx' ,'RegEnumKeyA' ,'RegEnumKeyExA' ,'RegEnumKeyExW' ,'RegEnumKeyW' ,'RegEnumValueA' ,\
        'RegEnumValueW' ,'RegFlushKey' ,'RegGetKeySecurity' ,'RegLoadKeyA' ,'RegLoadKeyW' ,'RegNotifyChangeKeyValue' ,\
        'RegOpenCurrentUser' ,'RegOpenKeyA' ,'RegOpenKeyExA' ,'RegOpenKeyExW' ,'RegOpenKeyW' ,'RegOpenUserClassesRoot' ,\
        'RegOverridePredefKey' ,'RegQueryInfoKeyA' ,'RegQueryInfoKeyW' ,'RegQueryMultipleValuesA' ,'RegQueryMultipleValuesW' ,\
        'RegQueryValueA' ,'RegQueryValueExA' ,'RegQueryValueExW' ,'RegQueryValueW' ,'RegReplaceKeyA' ,'RegReplaceKeyW' ,\
        'RegRestoreKeyA' ,'RegRestoreKeyW' ,'RegSaveKeyA' ,'RegSaveKeyExA' ,'RegSaveKeyExW' ,'RegSaveKeyW' ,'RegSetKeySecurity' ,\
        'RegSetValueA' ,'RegSetValueExA' ,'RegSetValueExW' ,'RegSetValueW' ,'RegUnLoadKeyA' ,'RegUnLoadKeyW', 'SHDeleteEmptyKeyA' ,\
        'SHDeleteEmptyKeyW' ,'SHDeleteKeyA' ,'SHDeleteKeyW' ,'SHOpenRegStream2A' ,'SHOpenRegStream2W' ,'SHOpenRegStreamA' ,\
        'SHOpenRegStreamW' ,'SHQueryInfoKeyA' ,'SHQueryInfoKeyW' ,'SHQueryValueExA' ,'SHQueryValueExW' ,'SHRegCloseUSKey' ,\
        'SHRegCreateUSKeyA' ,'SHRegCreateUSKeyW' ,'SHRegDeleteEmptyUSKeyA' ,'SHRegDeleteEmptyUSKeyW' ,'SHRegDeleteUSValueA' ,\
        'SHRegDeleteUSValueW' ,'SHRegDuplicateHKey' ,'SHRegEnumUSKeyA' ,'SHRegEnumUSKeyW' ,'SHRegEnumUSValueA' ,'SHRegEnumUSValueW',\
        'SHRegGetBoolUSValueA' ,'SHRegGetBoolUSValueW' ,'SHRegGetPathA' ,'SHRegGetPathW' ,'SHRegGetUSValueA' ,'SHRegGetUSValueW' ,\
        'SHRegGetValueA' ,'SHRegGetValueW' ,'SHRegOpenUSKeyA' ,'SHRegOpenUSKeyW' ,'SHRegQueryInfoUSKeyA' ,'SHRegQueryInfoUSKeyW' ,\
        'SHRegQueryUSValueA' ,'SHRegQueryUSValueW' ,'SHRegSetPathA' ,'SHRegSetPathW' ,'SHRegSetUSValueA' ,'SHRegSetUSValueW' ,\
        'SHRegWriteUSValueA' ,'SHRegWriteUSValueW' ,'SHDeleteOrphanKeyA' ,'SHDeleteOrphanKeyW' ,'SHDeleteValueA' ,'SHDeleteValueW' ,\
        'SHEnumKeyExA' ,'SHEnumKeyExW' ,'SHEnumValueA' ,'SHEnumValueW' ,'SHGetValueA' ,'SHGetValueW' ,'SHOpenRegStream2A' ,\
        'SHOpenRegStream2W' ,'SHOpenRegStreamA' ,'SHOpenRegStreamW' ,'SHQueryInfoKeyA' ,'SHQueryInfoKeyW' ,'SHQueryValueExA' ,\
        'SHQueryValueExW' ,'SHRegCloseUSKey' ,'SHRegCreateUSKeyA' ,'SHRegCreateUSKeyW' ,'SHRegDeleteEmptyUSKeyA' ,\
        'SHRegDeleteEmptyUSKeyW' ,'SHRegDeleteUSValueA' ,'SHRegDeleteUSValueW' ,'SHRegDuplicateHKey' ,'SHRegEnumUSKeyA' ,\
        'SHRegEnumUSKeyW' ,'SHRegEnumUSValueA' ,'SHRegEnumUSValueW' ,'SHRegGetBoolUSValueA' ,'SHRegGetBoolUSValueW' ,'SHRegGetPathA' ,\
        'SHRegGetPathW' ,'SHRegGetUSValueA' ,'SHRegGetUSValueW' ,'SHRegGetValueA' ,'SHRegGetValueW' ,'SHRegOpenUSKeyA' ,'SHRegOpenUSKeyW' ,\
        'SHRegQueryInfoUSKeyA' ,'SHRegQueryInfoUSKeyW' ,'SHRegQueryUSValueA' ,'SHRegQueryUSValueW' ,'SHRegSetPathA' ,'SHRegSetPathW' ,\
        'SHRegSetUSValueA' ,'SHRegSetUSValueW' ,'SHRegWriteUSValueA' ,'SHRegWriteUSValueW']

        self.winsock = [ 'Ws2', 'FreeAddrInfoW', 'GetAddrInfoW', 'GetNameInfoW', 'WEP', 'WPUCompleteOverlappedRequest', 'WSAAccept', \
        'WSAAddressToStringA', 'WSAAddressToStringW', 'WSAAsyncGetHostByAddr', 'WSAAsyncGetHostByName', 'WSAAsyncGetProtoByName',\
        'WSAAsyncGetProtoByNumber', 'WSAAsyncGetServByName', 'WSAAsyncGetServByPort', 'WSAAsyncSelect', 'WSACancelAsyncRequest',\
        'WSACancelBlockingCall', 'WSACleanup', 'WSACloseEvent', 'WSAConnect', 'WSACreateEvent', 'WSADuplicateSocketA',\
        'WSADuplicateSocketW', 'WSAEnumNameSpaceProvidersA', 'WSAEnumNameSpaceProvidersW', 'WSAEnumNetworkEvents', 'WSAEnumProtocolsA',\
        'WSAEnumProtocolsW', 'WSAEventSelect', 'WSAGetLastError', 'WSAGetOverlappedResult', 'WSAGetQOSByName', \
        'WSAGetServiceClassInfoA', 'WSAGetServiceClassInfoW', 'WSAGetServiceClassNameByClassIdA', 'WSAGetServiceClassNameByClassIdW',\
        'WSAHtonl', 'WSAHtons', 'WSAInstallServiceClassA', 'WSAInstallServiceClassW', 'WSAIoctl', 'WSAIsBlocking', 'WSAJoinLeaf', \
        'WSALookupServiceBeginA', 'WSALookupServiceBeginW', 'WSALookupServiceEnd', 'WSALookupServiceNextA', 'WSALookupServiceNextW', \
        'WSANSPIoctl', 'WSANtohl', 'WSANtohs', 'WSAProviderConfigChange', 'WSARecv', 'WSARecvDisconnect', 'WSARecvFrom', \
        'WSARemoveServiceClass', 'WSAResetEvent', 'WSASend', 'WSASendDisconnect', 'WSASendTo', 'WSASetBlockingHook', 'WSASetEvent',\
        'WSASetLastError', 'WSASetServiceA', 'WSASetServiceW', 'WSASocketA', 'WSASocketW', 'WSAStartup', 'WSAStringToAddressA', \
        'WSAStringToAddressW', 'WSAUnhookBlockingHook', 'WSAWaitForMultipleEvents', 'WSApSetPostRoutine', 'WSCDeinstallProvider', \
        'WSCEnableNSProvider', 'WSCEnumProtocols', 'WSCGetProviderPath', 'WSCInstallNameSpace', 'WSCInstallProvider', 'WSCUnInstallNameSpace',\
        'WSCUpdateProvider', 'WSCWriteNameSpaceOrder', 'WSCWriteProviderOrder', '__WSAFDIsSet', 'accept', 'bind', 'closesocket', 'connect', \
        'freeaddrinfo', 'getaddrinfo', 'gethostbyaddr', 'gethostbyname', 'gethostname', 'getnameinfo', 'getpeername', 'getprotobyname', \
        'getprotobynumber', 'getservbyname', 'getservbyport', 'getsockname', 'getsockopt', 'htonl', 'htons', 'inet_addr', 'inet_ntoa', \
        'ioctlsocket', 'listen', 'ntohl', 'ntohs', 'recv', 'recvfrom', 'select', 'send', 'sendto', 'setsockopt', 'shutdown', 'socket']

        self.WinINet = [ 'WINet', 'CreateMD5SSOHash', 'DetectAutoProxyUrl', 'DllInstall', 'ForceNexusLookup', 'ForceNexusLookupExW', 'InternetAlgIdToStringA',\
        'InternetAlgIdToStringW', 'InternetAttemptConnect', 'InternetAutodial', 'InternetAutodialCallback', 'InternetAutodialHangup',\
        'InternetCanonicalizeUrlA', 'InternetCanonicalizeUrlW', 'InternetCheckConnectionA', 'InternetCheckConnectionW', \
        'InternetClearAllPerSiteCookieDecisions', 'InternetCloseHandle', 'InternetCombineUrlA', 'InternetCombineUrlW', \
        'InternetConfirmZoneCrossing', 'InternetConfirmZoneCrossingA', 'InternetConfirmZoneCrossingW', 'InternetConnectA',\
        'InternetConnectW', 'InternetCrackUrlA', 'InternetCrackUrlW', 'InternetCreateUrlA', 'InternetCreateUrlW', 'InternetDial',\
        'InternetDialA', 'InternetDialW', 'InternetEnumPerSiteCookieDecisionA', 'InternetEnumPerSiteCookieDecisionW', 'InternetErrorDlg',\
        'InternetFindNextFileA', 'InternetFindNextFileW', 'InternetFortezzaCommand', 'InternetGetCertByURL', 'InternetGetCertByURLA',\
        'InternetGetConnectedState', 'InternetGetConnectedStateEx', 'InternetGetConnectedStateExA', 'InternetGetConnectedStateExW',\
        'InternetGetCookieA', 'InternetGetCookieExA', 'InternetGetCookieExW', 'InternetGetCookieW', 'InternetGetLastResponseInfoA', \
        'InternetGetLastResponseInfoW', 'InternetGetPerSiteCookieDecisionA', 'InternetGetPerSiteCookieDecisionW', 'InternetGoOnline',\
        'InternetGoOnlineA', 'InternetGoOnlineW', 'InternetHangUp', 'InternetInitializeAutoProxyDll', 'InternetLockRequestFile',\
        'InternetOpenA', 'InternetOpenUrlA', 'InternetOpenUrlW', 'InternetOpenW', 'InternetQueryDataAvailable', 'InternetQueryFortezzaStatus',\
        'InternetQueryOptionA', 'InternetQueryOptionW', 'InternetReadFile', 'InternetReadFileExA', 'InternetReadFileExW', \
        'InternetSecurityProtocolToStringA', 'InternetSecurityProtocolToStringW', 'InternetSetCookieA', 'InternetSetCookieExA', \
        'InternetSetCookieExW', 'InternetSetCookieW', 'InternetSetDialState', 'InternetSetDialStateA', 'InternetSetDialStateW',\
        'InternetSetFilePointer', 'InternetSetOptionA', 'InternetSetOptionExA', 'InternetSetOptionExW', 'InternetSetOptionW', \
        'InternetSetPerSiteCookieDecisionA', 'InternetSetPerSiteCookieDecisionW', 'InternetSetStatusCallback', 'InternetSetStatusCallbackA',\
        'InternetSetStatusCallbackW', 'InternetShowSecurityInfoByURL', 'InternetShowSecurityInfoByURLA', 'InternetShowSecurityInfoByURLW', \
        'InternetTimeFromSystemTime', 'InternetTimeFromSystemTimeA', 'InternetTimeFromSystemTimeW', 'InternetTimeToSystemTime',\
        'InternetTimeToSystemTimeA', 'InternetTimeToSystemTimeW', 'InternetUnlockRequestFile', 'InternetWriteFile', 'InternetWriteFileExA',\
        'InternetWriteFileExW', 'IsHostInProxyBypassList', 'ParseX509EncodedCertificateForListBoxEntry', 'PrivacyGetZonePreferenceW', \
        'PrivacySetZonePreferenceW', 'ResumeSuspendedDownload', 'ShowCertificate', 'ShowClientAuthCerts', 'ShowSecurityInfo', \
        'ShowX509EncodedCertificate','UrlZonesDetach', '_GetFileExtensionFromUrl']

        self.cache = [ 'Cach','CommitUrlCacheEntryA', 'CommitUrlCacheEntryW', 'CreateUrlCacheContainerA', 'CreateUrlCacheContainerW', 'CreateUrlCacheEntryA',\
        'CreateUrlCacheEntryW', 'CreateUrlCacheGroup', 'DeleteIE3Cache', 'DeleteUrlCacheContainerA', 'DeleteUrlCacheContainerW', \
        'DeleteUrlCacheEntry', 'DeleteUrlCacheEntryA', 'DeleteUrlCacheEntryW', 'DeleteUrlCacheGroup', 'FindCloseUrlCache', 'FindFirstUrlCacheContainerA',\
        'FindFirstUrlCacheContainerW', 'FindFirstUrlCacheEntryA', 'FindFirstUrlCacheEntryExA', 'FindFirstUrlCacheEntryExW', 'FindFirstUrlCacheEntryW', \
        'FindFirstUrlCacheGroup', 'FindNextUrlCacheContainerA', 'FindNextUrlCacheContainerW', 'FindNextUrlCacheEntryA', 'FindNextUrlCacheEntryExA',\
        'FindNextUrlCacheEntryExW', 'FindNextUrlCacheEntryW', 'FindNextUrlCacheGroup', 'FreeUrlCacheSpaceA', 'FreeUrlCacheSpaceW', 'GetUrlCacheConfigInfoA', \
        'GetUrlCacheConfigInfoW', 'GetUrlCacheEntryInfoA', 'GetUrlCacheEntryInfoExA', 'GetUrlCacheEntryInfoExW', 'GetUrlCacheEntryInfoW', \
        'GetUrlCacheGroupAttributeA', 'GetUrlCacheGroupAttributeW', 'GetUrlCacheHeaderData', 'IncrementUrlCacheHeaderData', 'IsUrlCacheEntryExpiredA',\
        'IsUrlCacheEntryExpiredW', 'LoadUrlCacheContent', 'ReadUrlCacheEntryStream', 'RegisterUrlCacheNotification', 'RetrieveUrlCacheEntryFileA', \
        'RetrieveUrlCacheEntryFileW', 'RetrieveUrlCacheEntryStreamA', 'RetrieveUrlCacheEntryStreamW', 'RunOnceUrlCache', 'SetUrlCacheConfigInfoA',\
        'SetUrlCacheConfigInfoW', 'SetUrlCacheEntryGroup', 'SetUrlCacheEntryGroupA', 'SetUrlCacheEntryGroupW', 'SetUrlCacheEntryInfoA', 'SetUrlCacheEntryInfoW',\
        'SetUrlCacheGroupAttributeA', 'SetUrlCacheGroupAttributeW', 'SetUrlCacheHeaderData', 'UnlockUrlCacheEntryFile', 'UnlockUrlCacheEntryFileA', \
        'UnlockUrlCacheEntryFileW', 'UnlockUrlCacheEntryStream', 'UpdateUrlCacheContentPath']

        self.ftp = [ 'Ftp','FtpCommandA' ,'FtpCommandW' ,'FtpCreateDirectoryA' ,'FtpCreateDirectoryW' ,'FtpDeleteFileA' ,'FtpDeleteFileW' ,'FtpFindFirstFileA' ,\
        'FtpFindFirstFileW' ,'FtpGetCurrentDirectoryA' ,'FtpGetCurrentDirectoryW' ,'FtpGetFileA' ,'FtpGetFileEx' ,'FtpGetFileSize' ,'FtpGetFileW' ,\
        'FtpOpenFileA' ,'FtpOpenFileW' ,'FtpPutFileA' ,'FtpPutFileEx' ,'FtpPutFileW' ,'FtpRemoveDirectoryA' ,'FtpRemoveDirectoryW' ,'FtpRenameFileA' ,\
        'FtpRenameFileW' ,'FtpSetCurrentDirectoryA' ,'FtpSetCurrentDirectoryW']

        self.gopher = [ 'Gopher', 'GopherCreateLocatorA', 'GopherCreateLocatorW', 'GopherFindFirstFileA', 'GopherFindFirstFileW', 'GopherGetAttributeA', \
        'GopherGetAttributeW', 'GopherGetLocatorTypeA', 'GopherGetLocatorTypeW', 'GopherOpenFileA', 'GopherOpenFileW']

        self.url = ['Url', 'UrlApplySchemeA' ,'UrlApplySchemeW' ,'UrlCanonicalizeA' ,'UrlCanonicalizeW' ,'UrlCombineA' ,'UrlCombineW' ,'UrlCompareA' ,\
        'UrlCompareW' ,'UrlCreateFromPathA' ,'UrlCreateFromPathW' ,'UrlEscapeA' ,'UrlEscapeW' ,'UrlGetLocationA' ,'UrlGetLocationW' ,'UrlGetPartA'\
        ,'UrlGetPartW' ,'UrlHashA' ,'UrlHashW' ,'UrlIsA' ,'UrlIsNoHistoryA' ,'UrlIsNoHistoryW' ,'UrlIsOpaqueA' ,'UrlIsOpaqueW' ,'UrlIsW' ,'UrlUnescapeA' ,'UrlUnescapeW']

        self.dir = ['Dir','CreateDirectoryA', 'CreateDirectoryExA', 'CreateDirectoryExW', 'CreateDirectoryW', 'GetCurrentDirectoryA', 'GetCurrentDirectoryW',\
        'GetDllDirectoryA', 'GetDllDirectoryW', 'GetSystemDirectoryA', 'GetSystemDirectoryW', 'GetSystemWindowsDirectoryA', 'GetSystemWindowsDirectoryW',\
        'GetSystemWow64DirectoryA', 'GetSystemWow64DirectoryW', 'GetVDMCurrentDirectories', 'GetWindowsDirectoryA', 'GetWindowsDirectoryW', \
        'ReadDirectoryChangesW', 'RemoveDirectoryA', 'RemoveDirectoryW', 'SetCurrentDirectoryA', 'SetCurrentDirectoryW', 'SetDllDirectoryA',\
        'SetDllDirectoryW', 'SetVDMCurrentDirectories', 'SHCreateDirectory', 'SHCreateDirectoryExA', 'SHCreateDirectoryExW']

        # Mutex
        self.mutex = ['Mutx','CreateMutexA', 'CreateMutexW', 'OpenMutexA', 'OpenMutexW', 'ReleaseMutex']

        # Pipe
        self.pipe = [ 'Pipe', 'CallNamedPipeA', 'CallNamedPipeW', 'ConnectNamedPipe', 'CreateNamedPipeA', 'CreateNamedPipeW', 'CreatePipe', 'DisconnectNamedPipe',\
        'GetNamedPipeHandleStateA', 'GetNamedPipeHandleStateW', 'GetNamedPipeInfo', 'PeekNamedPipe', 'SetNamedPipeHandleState', 'TransactNamedPipe',\
        'WaitNamedPipeA', 'WaitNamedPipeW']

        # List of APIs related to HTTP from WinINet
        self.http = [ 'Http', 'HttpAddRequestHeadersA', 'HttpAddRequestHeadersW', 'HttpCheckDavCompliance', 'HttpEndRequestA', 'HttpEndRequestW',\
        'HttpOpenRequestA', 'HttpOpenRequestW', 'HttpQueryInfoA', 'HttpQueryInfoW', 'HttpSendRequestA', 'HttpSendRequestExA', \
        'HttpSendRequestExW', 'HttpSendRequestW' ]

        # enum process
        self.enum = [ 'Enum', 'CreateToolhelp32Snapshot', 'Process32First' ,'Process32FirstW' ,'Process32Next' ,'Process32NextW']

        # List of APIs related to hashing files
        self.hash = ['Hash', 'CryptCreateHash' ,'CryptDestroyHash' ,'CryptDuplicateHash' ,'CryptGetHashParam' ,'CryptHashData' ,'CryptHashSessionKey' ,\
        'CryptSetHashParam' ,'CryptSignHashA' ,'CryptSignHashW', 'FreeEncryptionCertificateHashList']

        # List of APIs related to Cryptograpy files
        self.crypt = ['Crypt', 'CryptAcquireContextA' ,'CryptAcquireContextW' ,'CryptContextAddRef' ,'CryptDecrypt' ,'CryptDeriveKey' ,'CryptDestroyKey' ,\
        'CryptDuplicateKey' ,'CryptEncrypt' ,'CryptEnumProviderTypesA' ,'CryptEnumProviderTypesW' ,'CryptEnumProvidersA' ,'CryptEnumProvidersW'\
        ,'CryptExportKey' ,'CryptGenKey' ,'CryptGenRandom' ,'CryptGetDefaultProviderA' ,'CryptGetDefaultProviderW' ,'CryptGetKeyParam' ,\
        'CryptGetProvParam' ,'CryptGetUserKey' ,'CryptImportKey' ,'CryptReleaseContext' ,'CryptSetKeyParam' ,'CryptSetProvParam' ,\
        'CryptSetProviderA' ,'CryptSetProviderExA' ,'CryptSetProviderExW' ,'CryptSetProviderW' ,'CryptVerifySignatureA' ,'CryptVerifySignatureW' ,\
        'DecryptFileA' ,'DecryptFileW', 'EncryptFileA' ,'EncryptFileW' ,'EncryptedFileKeyInfo' ,'EncryptionDisable', 'WriteEncryptedFileRaw', \
        'OpenEncryptedFileRawA' ,'OpenEncryptedFileRawW', 'DuplicateEncryptionInfoFile', 'SetUserFileEncryptionKey', 'ReadEncryptedFileRaw', \
        'RemoveUsersFromEncryptedFile', 'FileEncryptionStatusA', 'FileEncryptionStatusW', 'FreeEncryptedFileKeyInfo', 'CloseEncryptedFileRaw', \
        'AddUsersToEncryptedFile', 'QueryRecoveryAgentsOnEncryptedFile', 'QueryUsersOnEncryptedFile', 'ChainWlxLogoffEvent' ,'CryptAcquireContextU' ,\
        'CryptBinaryToStringA' ,'CryptBinaryToStringW' ,'CryptCloseAsyncHandle' ,'CryptCreateAsyncHandle' ,'CryptDecodeMessage' ,'CryptDecodeObject' ,\
        'CryptDecodeObjectEx' ,'CryptDecryptAndVerifyMessageSignature' ,'CryptDecryptMessage' ,'CryptEncodeObject' ,'CryptEncodeObjectEx' ,\
        'CryptEncryptMessage' ,'CryptEnumKeyIdentifierProperties' ,'CryptEnumOIDFunction' ,'CryptEnumOIDInfo' ,'CryptEnumProvidersU' ,'CryptExportPKCS8' ,\
        'CryptExportPublicKeyInfo' ,'CryptExportPublicKeyInfoEx' ,'CryptFindLocalizedName' ,'CryptFindOIDInfo' ,'CryptFormatObject' ,\
        'CryptFreeOIDFunctionAddress' ,'CryptGetAsyncParam' ,'CryptGetDefaultOIDDllList' ,'CryptGetDefaultOIDFunctionAddress' ,\
        'CryptGetKeyIdentifierProperty' ,'CryptGetMessageCertificates' ,'CryptGetMessageSignerCount' ,'CryptGetOIDFunctionAddress' ,\
        'CryptGetOIDFunctionValue' ,'CryptHashCertificate' ,'CryptHashMessage' ,'CryptHashPublicKeyInfo' ,'CryptHashToBeSigned' ,\
        'CryptImportPKCS8' ,'CryptImportPublicKeyInfo' ,'CryptImportPublicKeyInfoEx' ,'CryptInitOIDFunctionSet' ,'CryptInstallDefaultContext' ,\
        'CryptInstallOIDFunctionAddress' ,'CryptLoadSip' ,'CryptMemAlloc' ,'CryptMemFree' ,'CryptMemRealloc' ,'CryptMsgCalculateEncodedLength' ,\
        'CryptMsgClose' ,'CryptMsgControl' ,'CryptMsgCountersign' ,'CryptMsgCountersignEncoded' ,'CryptMsgDuplicate' ,'CryptMsgEncodeAndSignCTL' ,\
        'CryptMsgGetAndVerifySigner' ,'CryptMsgGetParam' ,'CryptMsgOpenToDecode' ,'CryptMsgOpenToEncode' ,'CryptMsgSignCTL' ,'CryptMsgUpdate' ,\
        'CryptMsgVerifyCountersignatureEncoded' ,'CryptMsgVerifyCountersignatureEncodedEx' ,'CryptProtectData' ,'CryptQueryObject' ,\
        'CryptRegisterDefaultOIDFunction' ,'CryptRegisterOIDFunction' ,'CryptRegisterOIDInfo' ,'CryptSIPAddProvider' ,\
        'CryptSIPCreateIndirectData' ,'CryptSIPGetSignedDataMsg' ,'CryptSIPLoad' ,'CryptSIPPutSignedDataMsg' ,'CryptSIPRemoveProvider' ,\
        'CryptSIPRemoveSignedDataMsg' ,'CryptSIPRetrieveSubjectGuid' ,'CryptSIPRetrieveSubjectGuidForCatalogFile' ,'CryptSIPVerifyIndirectData' ,\
        'CryptSetAsyncParam' ,'CryptSetKeyIdentifierProperty' ,'CryptSetOIDFunctionValue' ,'CryptSetProviderU' ,'CryptSignAndEncodeCertificate' ,\
        'CryptSignAndEncryptMessage' ,'CryptSignCertificate' ,'CryptSignHashU' ,'CryptSignMessage' ,'CryptSignMessageWithKey' ,\
        'CryptStringToBinaryA' ,'CryptStringToBinaryW' ,'CryptUninstallDefaultContext' ,'CryptUnprotectData' ,'CryptUnregisterDefaultOIDFunction' ,\
        'CryptUnregisterOIDFunction' ,'CryptUnregisterOIDInfo' ,'CryptVerifyCertificateSignature' ,'CryptVerifyCertificateSignatureEx' ,\
        'CryptVerifyDetachedMessageHash' ,'CryptVerifyDetachedMessageSignature' ,'CryptVerifyMessageHash' ,'CryptVerifyMessageSignature' ,\
        'CryptVerifyMessageSignatureWithKey' ,'CryptVerifySignatureU' ,'I_CertProtectFunction' ,'I_CertSrvProtectFunction' ,'I_CertSyncStore' ,\
        'I_CertUpdateStore' ,'I_CryptAddRefLruEntry' ,'I_CryptAddSmartCardCertToStore' ,'I_CryptAllocTls' ,'I_CryptCreateLruCache' ,\
        'I_CryptCreateLruEntry' ,'I_CryptDetachTls' ,'I_CryptDisableLruOfEntries' ,'I_CryptEnableLruOfEntries' ,'I_CryptEnumMatchingLruEntries' ,\
        'I_CryptFindLruEntry' ,'I_CryptFindLruEntryData' ,'I_CryptFindSmartCardCertInStore' ,'I_CryptFlushLruCache' ,'I_CryptFreeLruCache' ,\
        'I_CryptFreeTls' ,'I_CryptGetAsn1Decoder' ,'I_CryptGetAsn1Encoder' ,'I_CryptGetDefaultCryptProv' ,'I_CryptGetDefaultCryptProvForEncrypt' ,\
        'I_CryptGetFileVersion' ,'I_CryptGetLruEntryData' ,'I_CryptGetLruEntryIdentifier' ,'I_CryptGetOssGlobal' ,'I_CryptGetTls' ,'I_CryptInsertLruEntry' ,\
        'I_CryptInstallAsn1Module' ,'I_CryptInstallOssGlobal' ,'I_CryptReadTrustedPublisherDWORDValueFromRegistry' ,'I_CryptRegisterSmartCardStore' ,\
        'I_CryptReleaseLruEntry' ,'I_CryptRemoveLruEntry' ,'I_CryptSetTls' ,'I_CryptTouchLruEntry' ,'I_CryptUninstallAsn1Module' ,\
        'I_CryptUninstallOssGlobal' ,'I_CryptUnregisterSmartCardStore' ,'I_CryptWalkAllLruCacheEntries']

        # Look up there has to be more
        self.service = ['Serv', 'ChangeServiceConfig2A' ,'ChangeServiceConfig2W' ,'ChangeServiceConfigA' ,'ChangeServiceConfigW' ,'CloseServiceHandle' ,\
        'ControlService' ,'CreateServiceA' ,'CreateServiceW' ,'DeleteService' ,'EnumDependentServicesA' ,'EnumDependentServicesW' ,\
        'EnumServiceGroupW' ,'EnumServicesStatusA' ,'EnumServicesStatusExA' ,'EnumServicesStatusExW' ,'EnumServicesStatusW' ,\
        'GetServiceDisplayNameA' ,'GetServiceDisplayNameW' ,'GetServiceKeyNameA' ,'GetServiceKeyNameW' ,'I_ScPnPGetServiceName' ,\
        'I_ScSetServiceBitsA' ,'I_ScSetServiceBitsW' ,'LockServiceDatabase' ,'OpenServiceA' ,'OpenServiceW' ,'PrivilegedServiceAuditAlarmA' ,\
        'PrivilegedServiceAuditAlarmW' ,'QueryServiceConfig2A' ,'QueryServiceConfig2W' ,'QueryServiceConfigA' ,'QueryServiceConfigW' ,\
        'QueryServiceLockStatusA' ,'QueryServiceLockStatusW' ,'QueryServiceObjectSecurity' ,'QueryServiceStatus' ,'QueryServiceStatusEx' ,\
        'RegisterServiceCtrlHandlerA' ,'RegisterServiceCtrlHandlerExA' ,'RegisterServiceCtrlHandlerExW' ,'RegisterServiceCtrlHandlerW' ,\
        'SetServiceBits' ,'SetServiceObjectSecurity' ,'SetServiceStatus' ,'StartServiceA' ,'StartServiceCtrlDispatcherA' ,'StartServiceCtrlDispatcherW' ,\
        'StartServiceW' ,'UnlockServiceDatabase' ,'WdmWmiServiceMain']

        # Generic File Operations
        self.file = ['File', 'CompareFileTime' ,'CopyFileA' ,'CopyFileExA' ,'CopyFileExW' ,'CopyFileW' ,'CopyLZFile' ,'CreateFileA' ,'CreateFileMappingA' ,\
        'CreateFileMappingW' ,'CreateFileW' ,'DeleteFileA' ,'DeleteFileW' ,'DosDateTimeToFileTime' ,'FileTimeToDosDateTime' ,\
        'FileTimeToLocalFileTime' ,'FileTimeToLocalFileTime' ,'FileTimeToSystemTime' ,'FlushFileBuffers' ,'FlushViewOfFile' ,\
        'GetCPFileNameFromRegistry' ,'GetCompressedFileSizeA' ,'GetCompressedFileSizeW' ,'GetFileAttributesA' ,'GetFileAttributesExA' ,\
        'GetFileAttributesExW' ,'GetFileAttributesW' ,'GetFileInformationByHandle' ,'GetFileSize' ,'GetFileSizeEx' ,'GetFileTime' ,\
        'GetFileType' ,'GetSystemTimeAsFileTime' ,'GetTempFileNameA' ,'GetTempFileNameW' ,'LZCloseFile' ,'LZCreateFileW' ,'LZOpenFileA',\
        'LZOpenFileW' ,'LocalFileTimeToFileTime' ,'LocalFileTimeToFileTime' ,'LockFile' ,'LockFileEx' ,'MapViewOfFile' ,'MapViewOfFileEx' ,\
        'MoveFileA' ,'MoveFileExA' ,'MoveFileExW' ,'MoveFileW' ,'MoveFileWithProgressA' ,'MoveFileWithProgressW' ,'OpenDataFile' ,'OpenFile' ,\
        'OpenFileMappingA' ,'OpenFileMappingW' ,'OpenProfileUserMapping' ,'PrivCopyFileExW' ,'PrivMoveFileIdentityW' ,'ReadFile' ,'ReadFileEx' ,\
        'ReplaceFile' ,'ReplaceFileA' ,'ReplaceFileW' ,'SetEndOfFile' ,'SetFileAttributesA' ,'SetFileAttributesW' ,'SetFilePointer' ,\
        'SetFilePointerEx' ,'SetFileShortNameA' ,'SetFileShortNameW' ,'SetFileTime' ,'SetFileValidData' ,'SystemTimeToFileTime' ,\
        'UnlockFile' ,'UnlockFileEx' ,'UnmapViewOfFile' ,'WriteFile' ,'WriteFileEx' ,'WriteFileGather' ,'GetFileSecurityA' ,\
        'GetFileSecurityW' ,'SetFileSecurityA' ,'SetFileSecurityW', 'CreateFileU']

        # APIs related to Collecting information about the host OS
        self.os_info = [ 'Info', 'GetComputerNameA' ,'GetComputerNameExA' ,'GetComputerNameExW' ,'GetComputerNameW' ,'GetDiskFreeSpaceA' ,\
        'GetDiskFreeSpaceExA' ,'GetDiskFreeSpaceExW' ,'GetDiskFreeSpaceW' ,'GetDriveTypeA' ,'GetDriveTypeW', 'GetVersion' ,\
        'GetVersionExA' ,'GetVersionExW', 'GetSystemInfo', 'GetSystemMetrics', 'CheckTokenMembership']

        # List of APIs related to hashing files
        self.cert = ['Cert','CertAddCRLContextToStore' ,'CertAddCRLLinkToStore' ,'CertAddCTLContextToStore' ,'CertAddCTLLinkToStore' ,\
        'CertAddCertificateContextToStore' ,'CertAddCertificateLinkToStore' ,'CertAddEncodedCRLToStore' ,'CertAddEncodedCertificateToStore' ,\
        'CertAddEncodedCertificateToSystemStoreA' ,'CertAddEncodedCertificateToSystemStoreW' ,'CertAddEnhancedKeyUsageIdentifier' ,\
        'CertAddSerializedElementToStore' ,'CertAddStoreToCollection' ,'CertAlgIdToOID' ,'CertCloseStore' ,'CertCompareCertificate' ,\
        'CertCompareCertificateName' ,'CertCompareIntegerBlob' ,'CertComparePublicKeyInfo' ,'CertControlStore' ,'CertCreateCTLContext' ,\
        'CertCreateCTLEntryFromCertificateContextProperties' ,'CertCreateCertificateChainEngine' ,'CertCreateCertificateContext' ,'CertCreateContext',\
        'CertCreateSelfSignCertificate' ,'CertDeleteCTLFromStore' ,'CertDeleteCertificateFromStore' ,'CertDuplicateCTLContext' ,\
        'CertDuplicateCertificateChain' ,'CertDuplicateCertificateContext' ,'CertDuplicateStore' ,'CertEnumCRLContextProperties' ,\
        'CertEnumCRLsInStore' ,'CertEnumCTLContextProperties' ,'CertEnumCTLsInStore' ,'CertEnumCertificateContextProperties' ,\
        'CertEnumCertificatesInStore' ,'CertEnumPhysicalStore' ,'CertEnumSubjectInSortedCTL' ,'CertEnumSystemStore' ,\
        'CertEnumSystemStoreLocation' ,'CertFindAttribute' ,'CertFindCRLInStore' ,'CertFindCertificateInCRL' ,'CertFindCertificateInStore',\
        'CertFindChainInStore' ,'CertFindExtension' ,'CertFindRDNAttr' ,'CertFindSubjectInCTL' ,'CertFindSubjectInSortedCTL' ,\
        'CertFreeCRLContext' ,'CertFreeCertificateChain' ,'CertFreeCertificateChainEngine' ,'CertFreeCertificateContext' ,'CertGetCRLContextProperty' ,\
        'CertGetCRLFromStore' ,'CertGetCTLContextProperty' ,'CertGetCertificateChain' ,'CertGetCertificateContextProperty' ,'CertGetEnhancedKeyUsage' ,\
        'CertGetIssuerCertificateFromStore' ,'CertGetNameStringA' ,'CertGetNameStringW' ,'CertGetPublicKeyLength' ,'CertGetStoreProperty' ,\
        'CertGetSubjectCertificateFromStore' ,'CertGetValidUsages' ,'CertIsRDNAttrsInCertificateName' ,'CertIsValidCRLForCertificate' ,\
        'CertNameToStrA' ,'CertNameToStrW' ,'CertOIDToAlgId' ,'CertOpenStore' ,'CertOpenSystemStoreA' ,'CertOpenSystemStoreW' ,'CertRDNValueToStrA',\
        'CertRDNValueToStrW' ,'CertRegisterPhysicalStore' ,'CertRegisterSystemStore' ,'CertRemoveEnhancedKeyUsageIdentifier' ,\
        'CertRemoveStoreFromCollection' ,'CertResyncCertificateChainEngine' ,'CertSaveStore' ,'CertSerializeCRLStoreElement' ,\
        'CertSerializeCertificateStoreElement' ,'CertSetCRLContextProperty' ,'CertSetCertificateContextPropertiesFromCTLEntry' ,\
        'CertSetCertificateContextProperty' ,'CertSetEnhancedKeyUsage' ,'CertSetStoreProperty' ,'CertStrToNameA' ,'CertStrToNameW' ,\
        'CertUnregisterPhysicalStore' ,'CertUnregisterSystemStore' ,'CertVerifyCRLRevocation' ,'CertVerifyCRLTimeValidity' ,\
        'CertVerifyCTLUsage' ,'CertVerifyCertificateChainPolicy' ,'CertVerifyCertificateChainPolicy' ,'CertVerifyRevocation' ,\
        'CertVerifySubjectCertificateContext','CertVerifyTimeValidity' ,'CertVerifyValidityNesting' ,'CloseCertPerformanceData' ,\
        'CollectCertPerformanceData' ,'CryptAcquireCertificatePrivateKey' ,'CryptFindCertificateKeyProvInfo' ,'CryptGetMessageCertificates' ,\
        'CryptHashCertificate' ,'CryptSignAndEncodeCertificate' ,'CryptSignCertificate' ,'CryptVerifyCertificateSignature' ,\
        'CryptVerifyCertificateSignatureEx' ,'I_CertProtectFunction' ,'I_CertSrvProtectFunction' ,'I_CertSyncStore' ,'I_CertUpdateStore' ,\
        'I_CryptAddSmartCardCertToStore' ,'I_CryptFindSmartCardCertInStore' ,'OpenCertPerformanceData' ,'PFXExportCertStore' ,'PFXExportCertStoreEx' ,'PFXImportCertStore']

        # APIs realted to searching
        self.file_s = ['FSear', 'FindFirstFileW', 'FindNextFileW', 'FindClose']

        # Possible Hook or Injection functions
        self.modify = ['Mod', 'WriteProcessMemory', 'ReadProcessMemory']    

        self.virtual = ['Virt', 'VirtualAlloc' ,'VirtualAllocEx' ,'VirtualBufferExceptionHandler' ,'VirtualFree' ,'VirtualFreeEx' ,'VirtualLock' ,
        'VirtualProtect' ,'VirtualProtectEx' ,'VirtualQuery' ,'VirtualQueryEx' ,'VirtualUnlock']

        self.critical_section = [ 'CrSec', 'DeleteCriticalSection' ,'EnterCriticalSection' ,'InitializeCriticalSection' ,
        'InitializeCriticalSectionAndSpinCount' ,'LeaveCriticalSection' ,'SetCriticalSectionSpinCount' ,'TryEnterCriticalSection']

        #the list are appended to make a matrix. Removes the problem of tracking each list of apis names in the code. Hopefully makes it easier to update.
        self.api_matrix = [ self.reg, self.winsock, self.WinINet, self.cache, self.ftp, self.gopher, self.dir, self.mutex, self.pipe, self.http, self.enum, self.hash, self.crypt, self.service, self.file, self.cert, self.os_info, self.file_s, self.modify, self.virtual, self.critical_section ]

    def generic(self):
        for api_row in self.api_matrix:
            l = api_row[0]
            apis = api_row[1:]
            for api in apis:
                ref_addrs = CodeRefsTo(LocByName(api),0)
                for ref in ref_addrs:
                    func_addr = LocByName(GetFunctionName(ref))
                    func_name = GetFunctionName(ref)
                    if self.rename == True:
                        if l not in func_name:
                            MakeNameEx(func_addr , l + '_' + func_name , SN_NOWARN)
                    if self.comment == True:
                        cmt = ''
                        cmt = GetFunctionCmt(func_addr,1)
                        if l not in cmt:
                            cmt = cmt + ' ' + l 
                            SetFunctionCmt(func_addr, cmt, 1)

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

    #SetColorSiko
    setcolorsiko()

    #FuncRename
    ah = GENAPI()
    # To disable comments assign to False
    ah.comment = True
    # To disable renaming of functions to False
    ah.rename = True    
    ah.generic()

    print "InitialAnalysis completed"

if __name__ == '__main__':
    # InitialAnalysis_main()
    pass
