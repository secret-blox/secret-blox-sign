#!/usr/bin/env python3
# LICENSE: BSD-3
# Copyright: Josh Pitts @midnite_runr

import sys
import struct
import shutil
import io
import os
from optparse import OptionParser


def gather_file_info_win(binary):
        flItms = {}
        binary = open(binary, 'rb')
        binary.seek(int('3C', 16))
        flItms['buffer'] = 0
        flItms['JMPtoCodeAddress'] = 0
        flItms['dis_frm_pehdrs_sectble'] = 248
        flItms['pe_header_location'] = struct.unpack('<i', binary.read(4))[0]
        # Start of COFF
        flItms['COFF_Start'] = flItms['pe_header_location'] + 4
        binary.seek(flItms['COFF_Start'])
        flItms['MachineType'] = struct.unpack('<H', binary.read(2))[0]
        binary.seek(flItms['COFF_Start'] + 2, 0)
        flItms['NumberOfSections'] = struct.unpack('<H', binary.read(2))[0]
        flItms['TimeDateStamp'] = struct.unpack('<I', binary.read(4))[0]
        binary.seek(flItms['COFF_Start'] + 16, 0)
        flItms['SizeOfOptionalHeader'] = struct.unpack('<H', binary.read(2))[0]
        flItms['Characteristics'] = struct.unpack('<H', binary.read(2))[0]
        #End of COFF
        flItms['OptionalHeader_start'] = flItms['COFF_Start'] + 20

        #if flItms['SizeOfOptionalHeader']:
            #Begin Standard Fields section of Optional Header
        binary.seek(flItms['OptionalHeader_start'])
        flItms['Magic'] = struct.unpack('<H', binary.read(2))[0]
        flItms['MajorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
        flItms['MinorLinkerVersion'] = struct.unpack("!B", binary.read(1))[0]
        flItms['SizeOfCode'] = struct.unpack("<I", binary.read(4))[0]
        flItms['SizeOfInitializedData'] = struct.unpack("<I", binary.read(4))[0]
        flItms['SizeOfUninitializedData'] = struct.unpack("<I",
                                                               binary.read(4))[0]
        flItms['AddressOfEntryPoint'] = struct.unpack('<I', binary.read(4))[0]
        flItms['PatchLocation'] = flItms['AddressOfEntryPoint']
        flItms['BaseOfCode'] = struct.unpack('<I', binary.read(4))[0]
        if flItms['Magic'] != 0x20B:
            flItms['BaseOfData'] = struct.unpack('<I', binary.read(4))[0]
        # End Standard Fields section of Optional Header
        # Begin Windows-Specific Fields of Optional Header
        if flItms['Magic'] == 0x20B:
            flItms['ImageBase'] = struct.unpack('<Q', binary.read(8))[0]
        else:
            flItms['ImageBase'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SectionAlignment'] = struct.unpack('<I', binary.read(4))[0]
        flItms['FileAlignment'] = struct.unpack('<I', binary.read(4))[0]
        flItms['MajorOperatingSystemVersion'] = struct.unpack('<H',
                                                                   binary.read(2))[0]
        flItms['MinorOperatingSystemVersion'] = struct.unpack('<H',
                                                                   binary.read(2))[0]
        flItms['MajorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
        flItms['MinorImageVersion'] = struct.unpack('<H', binary.read(2))[0]
        flItms['MajorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
        flItms['MinorSubsystemVersion'] = struct.unpack('<H', binary.read(2))[0]
        flItms['Win32VersionValue'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfImageLoc'] = binary.tell()
        flItms['SizeOfImage'] = struct.unpack('<I', binary.read(4))[0]
        flItms['SizeOfHeaders'] = struct.unpack('<I', binary.read(4))[0]
        flItms['CheckSum'] = struct.unpack('<I', binary.read(4))[0]
        flItms['Subsystem'] = struct.unpack('<H', binary.read(2))[0]
        flItms['DllCharacteristics'] = struct.unpack('<H', binary.read(2))[0]
        if flItms['Magic'] == 0x20B:
            flItms['SizeOfStackReserve'] = struct.unpack('<Q', binary.read(8))[0]
            flItms['SizeOfStackCommit'] = struct.unpack('<Q', binary.read(8))[0]
            flItms['SizeOfHeapReserve'] = struct.unpack('<Q', binary.read(8))[0]
            flItms['SizeOfHeapCommit'] = struct.unpack('<Q', binary.read(8))[0]

        else:
            flItms['SizeOfStackReserve'] = struct.unpack('<I', binary.read(4))[0]
            flItms['SizeOfStackCommit'] = struct.unpack('<I', binary.read(4))[0]
            flItms['SizeOfHeapReserve'] = struct.unpack('<I', binary.read(4))[0]
            flItms['SizeOfHeapCommit'] = struct.unpack('<I', binary.read(4))[0]
        flItms['LoaderFlags'] = struct.unpack('<I', binary.read(4))[0]  # zero
        flItms['NumberofRvaAndSizes'] = struct.unpack('<I', binary.read(4))[0]
        # End Windows-Specific Fields of Optional Header
        # Begin Data Directories of Optional Header
        flItms['ExportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
        flItms['ExportTableSize'] = struct.unpack('<I', binary.read(4))[0]
        flItms['ImportTableLOCInPEOptHdrs'] = binary.tell()
        #ImportTable SIZE|LOC
        flItms['ImportTableRVA'] = struct.unpack('<I', binary.read(4))[0]
        flItms['ImportTableSize'] = struct.unpack('<I', binary.read(4))[0]
        flItms['ResourceTable'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['ExceptionTable'] = struct.unpack('<Q', binary.read(8))[0]
        flItms['CertTableLOC'] = binary.tell()
        flItms['CertLOC'] = struct.unpack("<I", binary.read(4))[0]
        flItms['CertSize'] = struct.unpack("<I", binary.read(4))[0]
        binary.close()
        return flItms


def copyCert(exe):
    flItms = gather_file_info_win(exe)

    if flItms['CertLOC'] == 0 or flItms['CertSize'] == 0:
        # not signed
        sys.exit(-1)

    with open(exe, 'rb') as f:
        f.seek(flItms['CertLOC'], 0)
        cert = f.read(flItms['CertSize'])
    return cert


def writeCert(cert, exe, output):
    flItms = gather_file_info_win(exe)
    
    if not output: 
        output = output = str(exe) + "_signed"

    shutil.copy2(exe, output)

    with open(exe, 'rb') as g:
        with open(output, 'wb') as f:
            f.write(g.read())
            f.seek(0)
            f.seek(flItms['CertTableLOC'], 0)
            f.write(struct.pack("<I", len(open(exe, 'rb').read())))
            f.write(struct.pack("<I", len(cert)))
            f.seek(0, io.SEEK_END)
            f.write(cert)

    return True


def outputCert(exe, output):
    cert = copyCert(exe)
    if not output:
        output = str(exe) + "_sig"

    open(output, 'wb').write(cert)

    return True

def check_sig(exe):
    flItms = gather_file_info_win(exe)
 
    if flItms['CertLOC'] == 0 or flItms['CertSize'] == 0:
        return False
    else:
        return True


def truncate(exe, output):
    flItms = gather_file_info_win(exe)
 
    if flItms['CertLOC'] == 0 or flItms['CertSize'] == 0:
        sys.exit(-1)
    else:
        pass

    if not output:
        output = str(exe) + "_nosig"

    shutil.copy2(exe, output)

    with open(output, "r+b") as binary:
        binary.seek(-flItms['CertSize'], io.SEEK_END)
        binary.truncate()
        binary.seek(flItms['CertTableLOC'], 0)
        binary.write(b"\x00\x00\x00\x00\x00\x00\x00\x00")

    return True


def signfile(exe, sigfile, output):
    flItms = gather_file_info_win(exe)
    
    cert = open(sigfile, 'rb').read()

    if not output: 
        output = output = str(exe) + "_signed"

    shutil.copy2(exe, output)
    
    with open(exe, 'rb') as g:
        with open(output, 'wb') as f:
            f.write(g.read())
            f.seek(0)
            f.seek(flItms['CertTableLOC'], 0)
            f.write(struct.pack("<I", len(open(exe, 'rb').read())))
            f.write(struct.pack("<I", len(cert)))
            f.seek(0, io.SEEK_END)
            f.write(cert)
    
    return True

if __name__ == "__main__":
    certificate = "roblox.cer"

    cert = copyCert(signed_dll)

    to_sign = {
        "hookloader.exe" : "Injector.exe",
        "unsigned.dll" : "test.dll"
    }

    for k, v in to_sign.items():
        if not os.path.exists(k):
            print("File not found: {0}".format(k))
            continue
        
        signfile(k, certificate, v)

    print("Signing complete.")
    os.system("pause")