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

#ifndef __TBA_STL_PE_NT_DIRRCTORY_IMPORT_H
#define __TBA_STL_PE_NT_DIRECTORY_IMPORT_H


/*
 * nt_dir_import.h
 *
 * Define the class cNtDirImport which operate
 * the ".idata" section.
 *
 * Author: Elad Raz <e@eladraz.com>
 */

#include "../types.h"
#include "../array.h"
#include "../datastream.h"
#include "../list.h"
#include "../stream/basic_io.h"
#include "pe_datastruct.h"
#include "ntheader.h"

/*
 * cNtImportEntry
 *
 * Single entry of function name (from a module)
 */
class cNtImportEntry
{
public:
    WORD    hint;
    cString name;
};

/*
 * class cNtImportModule
 *
 * Helper data-struct class, store
 * the information of the import table
 * for a single module (DLL file).
 */
class cNtImportModule
{
public:
    // Members
    cList<cNtImportEntry>   m_proc;       // List of all the functions
    cString                 m_moduleName; // The module name, "Filename.exe"
    DWORD                   m_firstThunk; // The start location of the IAT for this module
};

/*
 * class cNtDirImport
 *
 * Declare the data-struct needed for storing
 * and editing the import table (.idata) with
 * all it's complex components.
 */
class cNtDirImport
{
public:
    /* Constructors */
    cNtDirImport();
    cNtDirImport(basic_io &stream, DWORD imageBase = 0);    /* Stream constructor  */
    cNtDirImport(cNtHeader& header);                        /* Directory analayzer */
    ~cNtDirImport();

    // cNtDirImport(const cNtDirImport& other);                /* Copy constructor    */


    /* Functions */
    void ReadFromStream1(basic_io &stream, DWORD imageBase = 0);
    void ReadFromStream2(basic_io &stream, DWORD imageBase = 0);
    void WriteToStream  (basic_io &stream, DWORD imageBase = 0) const;

    template <class OSTREAM>
    friend OSTREAM & operator << (OSTREAM &out, cNtDirImport &idata);

private:
    /* Private members */
    cList<cNtImportModule>         m_idata;
    cList<IMAGE_IMPORT_DESCRIPTOR> m_import_directory;
};

/*
 * cNtDirImport::cNtDirImport()
 * cNtDirImport::~cNtDirImport()
 *
 * Main constructor, create empty import table.
 */
cNtDirImport::cNtDirImport()
{
}
cNtDirImport::~cNtDirImport()
{
}

/*
 * cNtDirImport::cNtDirImport(basic_io &stream)
 *
 * Main constructor, create import table
 * from a stream.
 *  See ReadFromStream
 */
cNtDirImport::cNtDirImport(basic_io &stream, DWORD imageBase /* = 0 */)
{
    ReadFromStream1(stream, imageBase);
}

/*
 * cNtDirImport::cNtDirImport()
 *
 * Main constructor, create import table
 * from PE file. Seek to the import directory
 * and read the '.idata' section.
 */
cNtDirImport::cNtDirImport(cNtHeader& header)
{
    DWORD size    = header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    DWORD address = header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (size == 0)
    {
        /* No resource directory */
        _THROW cException("idata cannot be founded!!!");
    }

    /* Create a memory stream of the resource section */
    cStream idata;

    header.get_virtual_copy(address, address + size, idata);

    /* Call the reading to fill the datastruct */
    ReadFromStream1(cMemoryStream(idata), address);

    /* Fill the names into the binaries */
    /* Find the section of the names    */
    DWORD name_location = (*m_import_directory.Begin()).Name;
    cList<cNtSectionHeader>::iterator section = header.get_sections().Begin();

    for (cList<cNtSectionHeader>::iterator i  = header.get_sections().Begin();
                                           i != header.get_sections().End();
                                           i++)
    {
        /* Find the section */
        if ((*i).get_base() < (name_location + header.OptionalHeader.ImageBase))
        {
            if ((*i).get_base() > (*section).get_base())
                section = i;
        }
    }

    /* Fill the names into the binaries */
    ReadFromStream2(cMemoryStream((*section).get_data()), (*section).get_base() - header.OptionalHeader.ImageBase);
}

/*
 * cNtDirImport::ReadFromStream1(basic_io &stream)
 *
 * Get a stream located to the beginning of the
 * 'idata' and read the import table from it.
 *
 * This functions loaded only the import table
 * as defined in the import directory.
 * After this function called you must call the
 * "ReadFromStream2" with the ".text" or the ".rdata"
 * section (depending where the names are stored)
 * to read the reset of the names
 *
 * The stream must provide seeking from the
 * begining and get the position of the stream.
 */
void cNtDirImport::ReadFromStream1(basic_io &stream, DWORD imageBase /* = 0 */)
{
    IMAGE_IMPORT_DESCRIPTOR importDescriptor;
    cStream temp;

    m_import_directory.remove_all();

    do
    {
        stream >> importDescriptor.Characteristics;
        stream >> importDescriptor.TimeDateStamp;
        stream >> importDescriptor.ForwarderChain;
        stream >> importDescriptor.Name;
        stream >> importDescriptor.FirstThunk;

        if (importDescriptor.Characteristics != 0)
            m_import_directory.append(importDescriptor);
    } while(importDescriptor.Characteristics != 0);
}

/*
 * cNtDirImport::ReadFromStream1(basic_io &stream)
 *
 * Read the names from the image.
 * AFTER the ReadFromStream1() function had being called and
 * all the offsets filled, this function read the names for
 * the loaded binaries...
 */
void cNtDirImport::ReadFromStream2(basic_io &stream, DWORD imageBase /* = 0 */)
{
    unsigned int mpos = stream.get_pointer();


    /* Remove the old setting of the idata */
    m_idata.remove_all();

    /* Scan all the import section and read their names */
    for (cList<IMAGE_IMPORT_DESCRIPTOR>::iterator i = m_import_directory.Begin();
         i != m_import_directory.End();
         i++)
    {
        IMAGE_IMPORT_DESCRIPTOR node = (*i); // Get the correct module
        cNtImportModule iModule;             // Create new module struct

        /* Read the name of the module */
        stream.seek(mpos + (node.Name - imageBase), IO_SEEK_SET);
        iModule.m_moduleName = basic_io::read_null_string(stream);

        /* Change the Thunk location */
        iModule.m_firstThunk = node.FirstThunk;

        /* Read all the functions and thier thunk location */
        stream.seek((node.OriginalFirstThunk - imageBase), IO_SEEK_SET);
        DWORD index;
        stream >> index;

        iModule.m_proc.remove_all();

        while (index != 0)
        {
            cNtImportEntry entry; // Create new entry

            // Store the position of the Table
            DWORD last = stream.get_pointer();
            stream.seek(index - imageBase, IO_SEEK_SET);

            // Read the procedure import
            stream >> entry.hint;
            entry.name = basic_io::read_null_string(stream);

            iModule.m_proc.append(entry);

            // Read the next entry in the table
            stream.seek(last, IO_SEEK_SET);
            stream >> index;
        }

        m_idata.append(iModule);
    }
}

/*
 * operator << (OSTREAM &out, cNtDirImport &idata)
 *
 * Dump the contant of the import table into the OSTREAM
 * object.
 */
template <class OSTREAM>
OSTREAM & operator << (OSTREAM &out, cNtDirImport &idata)
{
    out << "Import Table\n";
    out << "============\n\n";

    /* Go over all the modules */
    for (cList<cNtImportModule>::iterator i  = idata.m_idata.Begin();
                                          i != idata.m_idata.End();
                                          i++)
    {
        cNtImportModule module = *i;
        out << "  " << module.m_moduleName << '\n';
        out << "  " << dup(cString("-"), module.m_moduleName.length()) << '\n';

        DWORD thunk = module.m_firstThunk;
        /* For each module print it's procedure table */
        for (cList<cNtImportEntry>::iterator j  = module.m_proc.Begin();
                                             j != module.m_proc.End();
                                             j++)
        {
            cNtImportEntry entry = *j;
            out << "      " << HEXDWORD(thunk) << "    " << entry.name << "\n";
            thunk = thunk + 4;
        }
    }

    out << "\n\n";

    return out;
}

#endif
