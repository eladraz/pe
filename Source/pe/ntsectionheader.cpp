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

#include "pe/pePrecompiledHeaders.h"
/*
 * ntsectionheader.cpp
 *
 * Implementation file
 *
 * Author: Elad Raz <e@eladraz.com>
 */
#include "xStl/types.h"
#include "xStl/os/os.h"
#include "xStl/data/array.h"
#include "xStl/data/list.h"
#include "xStl/data/string.h"
#include "xStl/data/datastream.h"
#include "xStl/os/virtualMemoryAccesser.h"
#include "xStl/os/threadUnsafeMemoryAccesser.h"
#include "xStl/os/streamMemoryAccesser.h"
#include "xStl/stream/basicIO.h"
#include "xStl/stream/stringerStream.h"
#include "pe/datastruct.h"
#include "pe/section.h"
#include "pe/sectionTypes.h"
#include "pe/humanStringTranslation.h"
#include "pe/ntsectionheader.h"

cNtSectionHeader::cNtSectionHeader(const IMAGE_SECTION_HEADER& other) :
    cSection("", cForkStreamPtr(NULL)),
    m_relocations(NULL),
    m_linenumbers(NULL)
{
    // Change the header
    changeNtSection(other);
}

cNtSectionHeader::cNtSectionHeader(addressNumericValue imageBase,
                                   basicInput& stream,
                                   SectionType type,
                                   bool shouldReadData,
                                   bool isMemory) :
    cSection("", cForkStreamPtr(NULL)),
    m_relocations(NULL),
    m_linenumbers(NULL),
    m_imageBase(imageBase)
{
    read(stream, shouldReadData, isMemory);
    // Soft relocation
    m_base+= imageBase;
    // Change image type
    m_type = type;
}

cNtSectionHeader::cNtSectionHeader(addressNumericValue imageBase,
                                   cMemoryAccesserStream& stream,
                                   SectionType type,
                                   bool shouldReadData,
                                   bool isMemory) :
    cSection("", cForkStreamPtr(NULL)),
    m_relocations(NULL),
    m_linenumbers(NULL),
    m_imageBase(imageBase)
{
    read(stream, shouldReadData, isMemory);
    // Soft relocation
    m_base+= imageBase;
    // Change image type
    m_type = type;
}

bool cNtSectionHeader::canBeHandledByMe(SectionType type)
{
    bool ret = false;

    ret = ret | (type == SECTION_TYPE_WINDOWS_CODE);
    ret = ret | (type == SECTION_TYPE_WINDOWS_EXPORT);
    ret = ret | (type == SECTION_TYPE_WINDOWS_IMPORT);
    ret = ret | (type == SECTION_TYPE_WINDOWS_RESOURCE);
    ret = ret | (type == SECTION_TYPE_WINDOWS_EXCEPTION);
    ret = ret | (type == SECTION_TYPE_WINDOWS_SECURITY);
    ret = ret | (type == SECTION_TYPE_WINDOWS_BASERELOC);
    ret = ret | (type == SECTION_TYPE_WINDOWS_DEBUG);
    ret = ret | (type == SECTION_TYPE_WINDOWS_ARCHITECTURE);
    ret = ret | (type == SECTION_TYPE_WINDOWS_GLOBALPTR);
    ret = ret | (type == SECTION_TYPE_WINDOWS_TLS);
    ret = ret | (type == SECTION_TYPE_WINDOWS_LOAD_CONFIG);
    ret = ret | (type == SECTION_TYPE_WINDOWS_BOUND_IMPORT);
    ret = ret | (type == SECTION_TYPE_WINDOWS_IAT);
    ret = ret | (type == SECTION_TYPE_WINDOWS_DELAY_IMPORT);
    ret = ret | (type == SECTION_TYPE_WINDOWS_CLI_HEADER);

    return ret;
}

void cNtSectionHeader::changeNtSection(const IMAGE_SECTION_HEADER &other)
{
    // Copy the struct content
    cOS::memcpy(this->Name, other.Name, IMAGE_SIZEOF_SHORT_NAME);
    this->Misc                 = other.Misc;
    this->VirtualAddress       = other.VirtualAddress;
    this->SizeOfRawData        = other.SizeOfRawData;
    this->PointerToRawData     = other.PointerToRawData;
    this->PointerToRelocations = other.PointerToRelocations;
    this->PointerToLinenumbers = other.PointerToLinenumbers;
    this->NumberOfRelocations  = other.NumberOfRelocations;
    this->NumberOfLinenumbers  = other.NumberOfLinenumbers;
    this->Characteristics      = other.Characteristics;

    // Changes the name of the section
    m_name = "";
    if (this->Name[0] == '/')
    {
        // The name is pointer to a resource... TODO!
        m_name = ".RESNAME?00";
    } else
    {
        for (uint i = 0; ((i < IMAGE_SIZEOF_SHORT_NAME) && (this->Name[i])); i++)
        {
            m_name+= (char)(this->Name[i]);
        }
    }

    // Change the base address
    m_base = this->VirtualAddress;

    // Change the flags
    m_flags = 0;
    if ((this->Characteristics & 0x80000000) != 0)
    {
        m_flags|= SECTION_FLAG_WRITE;
    }
    if ((this->Characteristics & 0x40000000)  != 0)
    {
        m_flags|= SECTION_FLAG_READ;
    }
    if ((this->Characteristics & 0x20000000) != 0)
    {
        m_flags|= SECTION_FLAG_EXECUTABLE;
    }

    // The section type should be changed by the caller!
    m_type = SECTION_TYPE_WINDOWS_CODE;
}

cNtSectionHeader& cNtSectionHeader::operator = (const IMAGE_SECTION_HEADER& other)
{
    init();
    changeNtSection(other);
    return *this;
}

void cNtSectionHeader::init()
{
    m_data = cForkStreamPtr(NULL);
    m_relocations = cMemoryAccesserStreamPtr(NULL);
    m_linenumbers = cMemoryAccesserStreamPtr(NULL);
}

void cNtSectionHeader::read(basicInput& stream,
                            bool shouldReadData,
                            bool isMemory)
{
    init();
    // Reads the IMAGE_SECTION_HEADER
    IMAGE_SECTION_HEADER newHeader;
    memset(&newHeader, 0, sizeof(newHeader));
    stream.pipeRead(&newHeader, sizeof(newHeader));
    // Change it. and reset the content of the section
    changeNtSection(newHeader);

    if (shouldReadData)
    {
        uint oldPointer = stream.getPointer();

        // Snapshot the file image
        cBufferPtr data(new cBuffer());

        // Read section data
        if (!isMemory)
        {
            // Seek to the file postion
            stream.seek(this->PointerToRawData, basicInput::IO_SEEK_SET);
            data->changeSize(this->SizeOfRawData, false);
        } else
        {
            // Seek to memory location
            // Notice that the VirtualAddress is relative to the base... So the
            // calculation should be OK.
            stream.seek(this->VirtualAddress, basicInput::IO_SEEK_SET);
            data->changeSize(this->Misc.VirtualSize, false);

            // Relocate the section data. The section must be correct, so now
            // the physical contains a larger information.
            PointerToRawData = VirtualAddress;
            SizeOfRawData = Misc.VirtualSize;
        }

        // Read the data
        stream.pipeRead(data->getBuffer(), data->getSize());

        // Change the m_data
        cVirtualMemoryAccesserPtr memory(new cStreamMemoryAccesser(data));
        m_data = cForkStreamPtr(new cMemoryAccesserStream(
            memory,
            0,
            data->getSize()));

        // Read relocation table if needed
        if (this->PointerToRelocations != 0)
        {
            stream.seek(this->PointerToRelocations - m_imageBase, basicInput::IO_SEEK_SET);
            cBufferPtr relocationData(new cBuffer());
            stream.pipeRead(*relocationData,
                this->NumberOfRelocations * sizeof(IMAGE_RELOCATION));

            // Creates the relocation snapshot
            cVirtualMemoryAccesserPtr memory(new
                cStreamMemoryAccesser(relocationData));
            m_relocations = cMemoryAccesserStreamPtr(new cMemoryAccesserStream(
                memory, 0, relocationData->getSize()));
        }

        // Read linenumber table if needed
        if (this->PointerToLinenumbers != 0)
        {
            stream.seek(this->PointerToLinenumbers, basicInput::IO_SEEK_SET);
            cBufferPtr linenumberData(new cBuffer());
            stream.pipeRead(*linenumberData,
                this->NumberOfLinenumbers * sizeof(IMAGE_LINENUMBER));

            // Creates the relocation snapshot
            cVirtualMemoryAccesserPtr memory(new
                cStreamMemoryAccesser(linenumberData));
            m_linenumbers = cMemoryAccesserStreamPtr(new cMemoryAccesserStream(
                memory, 0, linenumberData->getSize()));
        }

        stream.seek(oldPointer, basicInput::IO_SEEK_SET);
    }
}

void cNtSectionHeader::read(cMemoryAccesserStream& stream,
                            bool shouldReadData,
                            bool isMemory)
{
    // Read only the header
    read((basicInput&)stream, false, isMemory);

    if (shouldReadData)
    {
        // Read the reset of the stream
        if (!isMemory)
        {
            // Use the PointerToRawData..+SizeOfRawData
            m_data = stream.forkRegion(
                this->PointerToRawData,
                this->PointerToRawData + this->SizeOfRawData)->fork();
        } else
        {
            // Use the VirtualAddress..+VirtualSize
            m_data = stream.forkRegion(
                this->VirtualAddress,
                this->VirtualAddress + this->Misc.VirtualSize)->fork();
        }

        // Read relocation table if needed
        if (this->PointerToRelocations != 0)
        {
            m_relocations = stream.forkRegion(
                this->PointerToRelocations,
                this->PointerToRelocations +
                this->NumberOfRelocations * sizeof(IMAGE_RELOCATION));
        }

        // Read linenumber table if needed
        if (this->PointerToLinenumbers != 0)
        {
            m_linenumbers = stream.forkRegion(
                this->PointerToLinenumbers,
                this->PointerToLinenumbers +
                this->NumberOfLinenumbers * sizeof(IMAGE_LINENUMBER));
        }
    }
}

void cNtSectionHeader::write(basicIO& stream,
                             bool shouldWriteData,
                             bool isMemory) const
{
    // Start writing the IMAGE_SECTION_HEADER
    IMAGE_SECTION_HEADER* imageSectionHeader = (IMAGE_SECTION_HEADER*)(&Name);
    stream.pipeWrite(imageSectionHeader, sizeof(IMAGE_SECTION_HEADER));

    if (shouldWriteData)
    {
        // Seek to the position of the start writing data
        uint m_pos = stream.getPointer();

        // Write all the section data
        stream.seek(this->PointerToRawData, basicInput::IO_SEEK_SET);

        if (!isMemory)
        {
            // Seek to the file postion
            stream.seek(this->PointerToRawData, basicInput::IO_SEEK_SET);
        } else
        {
            // Seek to memory location
            stream.seek(this->VirtualAddress, basicInput::IO_SEEK_SET);
        }

        basicIO::copyStream(stream, (basicInput&)*m_data);

        if (this->PointerToRelocations != 0)
        {
            stream.seek(this->PointerToRelocations, basicInput::IO_SEEK_SET);
            basicIO::copyStream(stream, (basicInput&)*m_relocations);
        }


        /* Write linenumber table if needed */
        if (this->PointerToRelocations != 0)
        {
            stream.seek(this->PointerToLinenumbers, basicInput::IO_SEEK_SET);
            basicIO::copyStream(stream, (basicInput&)*m_linenumbers);
        }

        // Go back to the start
        stream.seek(m_pos, basicInput::IO_SEEK_SET);
    }
}

#ifdef PE_TRACE
cStringerStream& operator << (cStringerStream& out,
                              const cNtSectionHeader& object)
{
    // Start with dumping to the section type,
    // name and location
    // Dump the normal cSection fields.
    out << "NT Section '" << object.m_name << "'" << endl;
    out << "-------------" << cString::dup(cString("-"), object.m_name.length()) << endl;
    out << "Type:  " << cHumanStringTranslation::getSectionTypeName(object.m_type) << endl;
    out << "Base:  " << HEXDWORD(object.m_base)  << endl;
    out << "Flags: " << HEXDWORD(object.m_flags) << endl;

    // Dump the cNtSectionHeader
    out << endl;
    out << "Virtual Address:  " << HEXDWORD(object.VirtualAddress)       << endl;
    out << "Virtual Size:     " << HEXDWORD(object.Misc.VirtualSize)     << endl;
    out << "Size of Raw data: " << HEXDWORD(object.SizeOfRawData)        << endl;
    out << "Pointer to raw:   " << HEXDWORD(object.PointerToRawData)     << endl;
    out << "Pointer to reloc: " << HEXDWORD(object.PointerToRelocations) << "       Number of relocations: " << object.NumberOfRelocations << endl;
    out << "Pointer line num: " << HEXDWORD(object.PointerToLinenumbers) << "       NUmber of linenumbers: " << object.NumberOfLinenumbers << endl;
    out << "Characteristics:  " << HEXDWORD(object.Characteristics)      << endl;
    out << endl;
    out << endl;

    // Print the content of the class
    if (!object.m_data.isEmpty())
    {
        cBuffer data;
        object.snapshotGetSectionContentCopy(data);
        out << DATA(data.begin(),
                    data.end(),
                    DATA::DATA_USE_ADDRESS,
                    object.m_base,
                    object.m_name.getBuffer()) << endl << endl;
    } else
        out << "There aren't any content to the section" << endl;

    // Print relocations
    if (!object.m_relocations.isEmpty())
    {
        cBuffer data;
        cForkStreamPtr access = object.m_relocations->fork();
        access->seek(0, basicInput::IO_SEEK_SET);
        access->readAllStream(data);

        out << DATA(data.begin(), data.end()) << endl;
    } else {
        out << "NO RELOCATIONS." << endl;
    }
    out << endl;

    // Print linenumber
    if (!object.m_linenumbers.isEmpty())
    {
        cBuffer data;
        cForkStreamPtr access = object.m_linenumbers->fork();
        access->seek(0, basicInput::IO_SEEK_SET);
        access->readAllStream(data);

        out << DATA(data.begin(), data.end()) << endl;
    } else {
        out << "NO LINENUMBER." << endl;
    }
    out << endl;

    return out;
}
#endif // PE_TRACE

