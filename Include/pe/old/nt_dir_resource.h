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

#ifndef __TBA_STL_PE_NT_DIRRCTORY_RESOURCE_H
#define __TBA_STL_PE_NT_DIRECTORY_RESOURCE_H


#include "../types.h"
#include "../array.h"
#include "../datastream.h"
#include "../list.h"
#include "../stream/basic_io.h"
#include "pe_datastruct.h"
#include "nt_dir_resource_entry.h"
#include "ntheader.h"

static const DWORD USER_CALL = 0xFFFFFFFF;

/*
 * nt_dir_resource.h
 *
 * Define the class cNtDirResource which operate
 * the ".res" section of the file.
 *
 * Author: Elad Raz <e@eladraz.com>
 */
class cNtDirResource
{
public:
    /* Constructors */
    cNtDirResource();
    cNtDirResource(basic_io &stream);            /* Stream constructor  */
    cNtDirResource(const cNtDirResource& other); /* Copy constructor    */
    cNtDirResource(const cNtHeader& header);     /* Directory analayzer */
    ~cNtDirResource();

    /* Functions */
    void ReadFromStream(basic_io &stream, DWORD RootDir = USER_CALL);
    void WriteToStream (basic_io &stream) const;

    IMAGE_RESOURCE_DIRECTORY   get_image_directory() { return m_resource_directory; }
    cList<cImageResourceEntry> get_image_entries()   { return m_resource_entries;   }

    /* Operators */
    // Use the default copy.
    // cNtDirResource & operator = (const cNtDirResource& other);
    //

private:
    /* Private members */
    IMAGE_RESOURCE_DIRECTORY    m_resource_directory;
    cList<cImageResourceEntry>  m_resource_entries;
};

/*
 * Normal constructor and destructors
 *
 * Do normal operation.
 */
cNtDirResource::cNtDirResource()
{
}
cNtDirResource::~cNtDirResource()
{
}

/*
 * cNtDirResource::cNtDirResource(basic_io &stream)
 *
 * Try to read from the stream the resource section
 * and instance a new class, represent the stream
 */
cNtDirResource::cNtDirResource(basic_io &stream)
{
    ReadFromStream(stream);
}

/*
 * cNtDirResource::cNtDirResource(const cNtDirResource& otrher)
 *
 * Copy constructor, use the operator =
 */
cNtDirResource::cNtDirResource(const cNtDirResource& other)
{
    *this = other;
}

/*
 * cNtDirResource::cNtDirResource(const cNtHeader& header)
 *
 * Get a filled section NT_HEADER, seek to the
 * resource directory and fill the class data.
 */
cNtDirResource::cNtDirResource(const cNtHeader& header)
{
    DWORD size    = header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
    DWORD address = header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;

    if (size == 0)
    {
        /* No resource directory */
        _THROW cException("Resource directory cannot be founded!!!");
    }

    /* Create a memory stream of the resource section */
    cStream resource_data;

    header.get_virtual_copy(address, address + size, resource_data);

    /* Call the reading to fill the datastruct */
    ReadFromStream(cMemoryStream(resource_data));
}

/*
 * void ReadFromStream(basic_io &stream);
 *
 * Retrive an open stream for reading which
 * locate at the resource section and read the entire
 * resource section.
 *
 * The stream must be at type
 *   canSeekAll
 *   canGetPointer.
 *
 * Which means other the stream is a file stream
 * or a memory stream.
 *
 * 'RoorDir' is inside variable which location the position
 * of the root directory inside the stream.
 */
void cNtDirResource::ReadFromStream(basic_io &stream, DWORD RootDir /* = 0xFFFFFFFF*/)
{
    IMAGE_RESOURCE_DIRECTORY_ENTRY item;
    unsigned int start_position;
    unsigned int i;
    unsigned int items;
    unsigned int pos;

    if (RootDir == USER_CALL)
    {
        start_position = stream.get_pointer();
    } else
    {
        start_position = RootDir;
    }

    m_resource_entries.remove_all();


    /* Read the IMAGE_RESOURCE_DIRECTORY */
    stream >> m_resource_directory.Characteristics;
    stream >> m_resource_directory.TimeDateStamp;
    stream >> m_resource_directory.MajorVersion;
    stream >> m_resource_directory.MinorVersion;
    stream >> m_resource_directory.NumberOfNamedEntries;
    stream >> m_resource_directory.NumberOfIdEntries;

    items = m_resource_directory.NumberOfNamedEntries + m_resource_directory.NumberOfIdEntries;

    /* Start reading the entries */
    for (i = 0; i < items; i++)
    {
        cString name;
        cStream data;

        /* Read an entry */
        stream >> item.Name;
        stream >> item.OffsetToData;

        /* If the item contain string name, read it */
        if (item.NameIsString)
        {
            /* Read the string */
            pos = stream.get_pointer();
            stream.seek(item.NameOffset + start_position, IO_SEEK_SET);
            name = basic_io::read_pascal16_string(stream);
            stream.seek(pos, IO_SEEK_SET);
        };

        if (item.DataIsDirectory)
        {
            /* Seek to the sub-directory and read the data */
            pos = stream.get_pointer();
            stream.seek(item.OffsetToDirectory + start_position, IO_SEEK_SET);

            cNtDirResource new_directory;
            new_directory.ReadFromStream(stream, start_position);

            stream.seek(pos, IO_SEEK_SET);
        } else
        {
            /* Read the data for the item */
            pos = stream.get_pointer();
            stream.seek(item.OffsetToData + start_position, IO_SEEK_SET);

            IMAGE_RESOURCE_DATA_ENTRY entry;
            stream >> entry.OffsetToData;
            stream >> entry.Size;
            stream >> entry.CodePage;
            stream >> entry.Reserved;

            stream.seek(entry.OffsetToData + start_position, IO_SEEK_SET);
            stream.read(data, entry.Size);

            stream.seek(pos, IO_SEEK_SET);
        }

    }
}

#endif
