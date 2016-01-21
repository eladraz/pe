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

#ifndef __TBA_PE_PE_H
#define __TBA_PE_PE_H

/*
 * pe.h
 *
 * The global interface for the PE file header.
 *
 * Author: Elad Raz <e@eladraz.com>
 */
#include "pe_datastruct.h"
#include "dosheader.h"
#include "ntheader.h"
#include "../array.h"
#include "../list.h"
#include "../hash.h"
#include "../string.h"
#include "../stream/basic_io.h"
#include "../exception.h"

/*
 * The PE library is very flexable
 * and contain many modes of reading
 * or writing
 */
static const unsigned int PE_FILE_NORMAL      = 0;  /* File normal EXE storage            */
static const unsigned int PE_FILE_MEMORY_DUMP = 1;  /* Memory represintation of EXE files */

/*
 * class cPE
 *
 * Warpper class for the PE file format
 * Use this class with the Read function
 * to read any kind of PE file format
 *
 * IMPORTANT NOTICE:
 *   all the stream shows here must support reading / writting
 *   depending to the operation and to be able the IO_SEEK_SET
 *   seeking method.
 *   In order of usage of non seeking set streams you must write
 *   the pe image into cMemoryStream and than transmmit them.
 *
 *
 * The class throws exceptions.
 */
class cPE
{
public:
    // Constructors
    cPE();
    cPE(basic_io &stream);
    ~cPE();

    // Stream operation
    void Read (basic_io &stream, unsigned int flags = PE_FILE_NORMAL);
    void Write(basic_io &stream, unsigned int flags = PE_FILE_NORMAL);

    friend basic_io& operator >> (basic_io &stream, cPE & pe_data);
    friend basic_io& operator << (basic_io &stream, cPE & pe_data);

    // PE functions
    void init();
    cDosHeader & get_dos_header() { return dosHeader; }
    cNtHeader  & get_nt_header () { return ntHeader;  }

private:
    // Members
    cDosHeader dosHeader;
    cNtHeader  ntHeader;

    // Private functions and utils functions

    // Prevent copy-constructors
    cPE(const cPE &other);
    cPE & operator = (const cPE &other);
};

/*
 * cPE::cPE
 *
 * Create an empty PE format
 */
cPE::cPE()
{
    init();
}

/*
 * cPE::cPE(basic_io &stream)
 *
 * Create an empty PE object
 * and start reading the file
 */
cPE::cPE(basic_io &stream)
{
    init();
    Read(stream);
}

/*
 * cPE::init()
 *
 * Free all the information allocated
 * for the PE object
 */
void cPE::init()
{
    dosHeader.init();
    ntHeader.init();
}

/*
 * cPE::~cPE
 *
 * Destructor of the class free all memory
 * that are in used.
 */
cPE::~cPE()
{
    init();
}

/*
 * basic_io, expand operators
 * operator >> (cPE &)  - Read  operation
 * operator << (cPE &)  - Write operation
 *
 * Read a PE file or Write the PE file
 * Try to read/write all the section
 * and sub-data struct of the file.
 */
basic_io& operator >> (basic_io &stream, cPE & pe_data)
{
    // Call to the class function, and retrun
    pe_data.Read(stream);
    return stream;
}

basic_io& operator << (basic_io &stream, cPE & pe_data)
{
    // Call to the class functoin, and return
    pe_data.Write(stream);
    return stream;
}

/*
 * cPE::Read(basic_io &stream)
 *
 * Read a PE file from a stream,
 * read the DOSHEADER struct and
 * if the file is WINDOWS PE file
 * try to read it's seciton.
 */
void cPE::Read(basic_io &stream, unsigned int flags /* = PE_FILE_NORMAL*/)
{
    // Free all previous data of the PE object
    init();


    dosHeader.Read(stream, TRUE);

    // Checking PE exsistence
    if (dosHeader.e_lfanew != 0)
    {
        // Start reading PE file
        try
        {
            stream.seek(dosHeader.e_lfanew, IO_SEEK_SET);
            ntHeader.Read(stream, TRUE, flags == PE_FILE_MEMORY_DUMP);
        }
        catch (cException e)
        {
            /* NT Image is invalid, ignore */
        }
    }
}

/*
 * cPE::Write(basic_io &stream)
 *
 * Preform a full write of the executable
 * contect which found in the memory into
 * a stream.
 *
 * Meanwhile 'flags' can only be PE_FILE_NORMAL
 */
void cPE::Write(basic_io &stream, unsigned int flags /* = PE_FILE_NORMAL*/)
{
    // Try to write all the executable information
    dosHeader.Write(stream, TRUE);
    if (dosHeader.e_lfanew != 0)
    {
            stream.seek(dosHeader.e_lfanew, IO_SEEK_SET);
            ntHeader.Write(stream, TRUE, flags == PE_FILE_MEMORY_DUMP);
    }
}

#endif
