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
 * print_import.cpp
 *
 * Print the import table of PE file.
 *
 * Author: Elad Raz <e@eladraz.com>
 */

#include "windows.h"


/*
 * This program will be compiled as a debug program
 * if the following line will be unmarked.
 *
 * If you are using the Visual C++ and you compile
 * your code in debug mode, then the _DEBUG macro
 * will be defined normally.
 */
#ifndef _DEBUG
    #define _DEBUG
#endif

#define TRACE_LEVEL (0)


/*
 * Test PE file
 *
 * Equal to the DumpBIN program but with additional support
 */

#include <iostream.h>

#include <xStl/PE/pe.h>
#include <xStl/PE/nt_dir_resource.h>
#include <xStl/PE/nt_dir_resource_entry.h>
#include <xStl/PE/nt_dir_export.h>
#include <xStl/PE/nt_dir_import.h>
#include <xStl/types.h>
#include <xStl/stream/memorystream.h>
#include <xStl/stream/file.h>


/*
 * main()
 *
 * The main program that test the array class.
 */
int main(const int argc, const char **argv)
{
    _TRY
    {
        /*
         * First step
         *
         * Open an executable file and read it
         * After it transfer the file into
         * textuale viewer and print it to the screen.
         *
         */
        if (argc < 1)
        {
            cout << "Usage:" << endl;
            cout << "  print_import.exe <pe filename>" << endl;
            return RC_ERROR;
        }

        cFile file(argv[1]);
        cPE pe;
        pe.Read(file);

        /* Get the import table from the file */
        cNtDirImport idata(pe.get_nt_header());
        cout << idata;
        /**/


        // End of program.
        return RC_OK;
    }
    _CATCH (cException e)
    {
        e.print();
        return RC_ERROR;
    }
    _CATCH (...)
    {
        cout << "Unknown expception (...) was thrown" << endl;
        return RC_ERROR;
    }
}

