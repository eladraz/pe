/*
 * Copyright (c) 2008-2016, Integrity Project Ltd. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the Integrity Project nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE
 */

/*
 * dumpPE.cpp
 *
 * The main entry point of the application
 *
 * Author: Elad Raz <e@eladraz.com>
 */
#include "xStl/types.h"
#include "xStl/remoteAddress.h"
#include "xStl/data/char.h"
#include "xStl/data/string.h"
#include "xStl/data/list.h"
#include "xStl/data/datastream.h"
#include "xStl/except/trace.h"
#include "xStl/except/exception.h"
#include "xStl/stream/traceStream.h"
#include "xStl/stream/fileStream.h"
#include "xStl/stream/ioStream.h"
#include "xStl/os/virtualMemoryAccesser.h"
#include "xStl/os/threadUnsafeMemoryAccesser.h"
#include "xStl/stream/memoryAccesserStream.h"
#include "pe/peFile.h"
#include "pe/dosheader.h"
#include "pe/ntheader.h"
#include "pe/ntDirExport.h"
#include "pe/ntDirImport.h"

/*
 * Returns the human readable name of an IMAGE_FILE_MACHINE_* value.
 */
static const char* getMachineName(uint16 machine)
{
    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:    return "Intel 32 bit";
    case IMAGE_FILE_MACHINE_AMD64:   return "AMD64 (x64)";
    case IMAGE_FILE_MACHINE_ARM64:   return "ARM 64 bit";
    case IMAGE_FILE_MACHINE_RISCV32: return "RISC-V 32";
    case IMAGE_FILE_MACHINE_RISCV64: return "RISC-V 64";
    case IMAGE_FILE_MACHINE_RISCV128: return "RISC-V 128";
    default:                         return "Unknown";
    }
}

/*
 * The main entry point. Captures all unexpected exceptions and make sure
 * that the application will notify the programmer.
 *
 * Invoke a call to the following modules:
 *   1.
 *
 */
int main(const int argc, const char** argv)
{
    XSTL_TRY
    {
        if (argc != 2)
        {
            cout << "Usage: dumpPE <filename>" << endl;
            return RC_ERROR;
        }

        // Load a file
        cFileStream peFileStream(argv[1]);

        // Load from memory
        /*
        addressNumericValue lib =
            getNumeric(LoadLibrary(XSTL_STRING("KERNEL32.DLL")));
        cVirtualMemoryAccesserPtr currentMap(new cThreadUnsafeMemoryAccesser());
        uint size = cPeFile::getImageSize(currentMap, lib);
        cMemoryAccesserStream peFileStream(currentMap, lib, lib + size);
        */

        // Read the PE
        cDosHeader dosFile(peFileStream, false);
        XSTL_TRY
        {
            uint32 id;
            peFileStream.seek(dosFile.e_lfanew, basicInput::IO_SEEK_SET);
            peFileStream.pipeRead(&id ,sizeof(id));
            CHECK(id == IMAGE_NT_SIGNATURE);
            peFileStream.seek(dosFile.e_lfanew, basicInput::IO_SEEK_SET);
        } XSTL_CATCH_ALL
        {
            cout << "No PE file!" << endl;
            return RC_ERROR;
        }
        cNtHeader ntFile(peFileStream);

        cout << "Machine: " << getMachineName(ntFile.FileHeader.Machine)
             << " (" << HEXWORD(ntFile.FileHeader.Machine) << ")" << endl;

        // Read the export-table, if the image has one
        cNtDirExport export_dir;
        if (ntFile.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0)
            export_dir.readDirectory(ntFile);
        //cout << export_dir;

        /**/
        addressNumericValue lib = 0x400000;
        for (uint i = 0; i < export_dir.getExportArray().getSize(); i++)
        {
            cout << "  "    << HEXADDRESS(NR_ADDRESS(export_dir.getExportArray()[i].m_address) + lib)
                 << "     " << HEXWORD (export_dir.getExportArray()[i].m_ordinal)
                 << "  ";

            if (export_dir.getExportArray()[i].m_isName)
                cout << export_dir.getExportArray()[i].m_name;

            cout << endl;
        }

        #ifdef XSTL_WINDOWS
        uint32 addr = getNumeric(&ReadFileEx);
        cout << "7C8384C5 ReadFileEx -   " << HEXDWORD(addr) << endl;
        #endif
        /**/

        // Read the import-table
        cNtDirImport import_dir(ntFile);
        uint64 imageBase = ntFile.getImageBase();
        cout << "Imports:" << endl;
        const cList<cNtDirImport::Module>& modules = import_dir.getModules();
        cList<cNtDirImport::Module>::iterator module = modules.begin();
        for (; module != modules.end(); ++module)
        {
            const cList<cNtDirImport::Entry>& entries = (*module).entries;
            cList<cNtDirImport::Entry>::iterator entry = entries.begin();
            for (; entry != entries.end(); ++entry)
            {
                cout << "  " << (*module).name << "!";
                if ((*entry).byOrdinal)
                    cout << "#" << (uint)(*entry).ordinal;
                else
                    cout << (*entry).name;
                cout << " iat=" << HEXQWORD(imageBase + (*entry).iatRva) << endl;
            }
        }

        return RC_OK;
    }
    XSTL_CATCH(cException& e)
    {
        // Print the exception
        e.print();
        return RC_ERROR;
    }
    XSTL_CATCH_ALL
    {
        TRACE(TRACE_VERY_HIGH,
                XSTL_STRING("Unknwon exceptions caught at main()..."));
        return RC_ERROR;
    }
}
