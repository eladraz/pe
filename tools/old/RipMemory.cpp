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
 * RipMemory.cpp
 *
 * Store an open executable from the disk.
 */


/* Windows version */
#include "windows.h"


/* We are in DEBUG mode */
#define _DBG


/* xSTL helpers */
#include "xStl/types.h"
#include "xStl/array.h"
#include "xStl/stream/file.h"
#include "xStl/stream/iostream.h"
#include "xStl/PE/pe.h"


#define SOURCE_FILENAME "d:\\utils\\re\\phasma5\\rip.dat"
#define DEST_FILENAME "d:\\utils\\re\\phasma5\\rip.exe"

#define STARTADDR (0x00402844)

int main(int argc, char **argv)
{
    XSTL_TRY
    {
        cFile rip_data(SOURCE_FILENAME);
        cFile newEXE  (DEST_FILENAME, cFile::cFile_CREATE | cFile::cFile_WRITE);
        cPE   pe;

        // Read the old executable
        pe.Read(rip_data, PE_FILE_MEMORY_DUMP);

        // Change the start address
        pe.get_nt_header().OptionalHeader.AddressOfEntryPoint = STARTADDR - pe.get_nt_header().OptionalHeader.ImageBase;

        // Write the new executable
        pe.Write(newEXE, PE_FILE_MEMORY_DUMP);
    }
    XSTL_CATCH(cException e)
    {
        e.print();
        return RC_ERROR;
    }
    XSTL_CATCH(...)
    {
        cout << "Unknown exception has sent" << endl;
        return RC_ERROR;
    }
    return RC_OK;
}