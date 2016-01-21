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
 * ntheader.cpp
 *
 * Implementation file
 *
 * Author: Elad Raz <e@eladraz.com>
 */
#include "xStl/types.h"
#include "xStl/data/list.h"
#include "xStl/data/array.h"
#include "xStl/data/string.h"
#include "xStl/data/datastream.h"
#include "xStl/except/trace.h"
#include "xStl/except/exception.h"
#include "pe/section.h"
#include "pe/datastruct.h"
#include "pe/sectionTypes.h"
#include "pe/ntheader.h"
#include "pe/ntsectionheader.h"
#include "pe/humanStringTranslation.h"

cNtHeader::cNtHeader(basicInput& stream,
                     addressNumericValue trueImageBase,
                     bool shouldReadSections,
                     bool isMemory) :
    m_shouldReadSections(shouldReadSections),
    m_fastImportDll(NULL),
    m_memoryImage(NULL),
    m_trueImageBase(trueImageBase)
{
    read(stream, shouldReadSections, isMemory);
}

cNtHeader::cNtHeader(cMemoryAccesserStream& stream,
                     addressNumericValue trueImageBase,
                     bool shouldReadSections,
                     bool isMemory) :
    m_shouldReadSections(shouldReadSections),
    m_fastImportDll(NULL),
    m_memoryImage(NULL),
    m_trueImageBase(trueImageBase)
{
    read(stream, shouldReadSections, isMemory);
}

cNtHeader::cNtHeader(const IMAGE_NT_HEADERS32& other) :
    m_fastImportDll(NULL),
    m_memoryImage(NULL)
{
    changeNtHeader(other);
}

void cNtHeader::changeNtHeader(const IMAGE_NT_HEADERS32& other)
{
    this->Signature                       = other.Signature;
    this->FileHeader.Machine              = other.FileHeader.Machine;
    this->FileHeader.NumberOfSections     = other.FileHeader.NumberOfSections;
    this->FileHeader.TimeDateStamp        = other.FileHeader.TimeDateStamp;
    this->FileHeader.PointerToSymbolTable = other.FileHeader.PointerToSymbolTable;
    this->FileHeader.NumberOfSymbols      = other.FileHeader.NumberOfSymbols;
    this->FileHeader.SizeOfOptionalHeader = other.FileHeader.SizeOfOptionalHeader;
    this->FileHeader.Characteristics      = other.FileHeader.Characteristics;
    this->OptionalHeader.Magic                        = other.OptionalHeader.Magic;
    this->OptionalHeader.MajorLinkerVersion           = other.OptionalHeader.MajorLinkerVersion;
    this->OptionalHeader.MinorLinkerVersion           = other.OptionalHeader.MinorLinkerVersion;
    this->OptionalHeader.SizeOfCode                   = other.OptionalHeader.SizeOfCode;
    this->OptionalHeader.SizeOfInitializedData        = other.OptionalHeader.SizeOfInitializedData;
    this->OptionalHeader.SizeOfUninitializedData      = other.OptionalHeader.SizeOfUninitializedData;
    this->OptionalHeader.AddressOfEntryPoint          = other.OptionalHeader.AddressOfEntryPoint;
    this->OptionalHeader.BaseOfCode                   = other.OptionalHeader.BaseOfCode;
    this->OptionalHeader.BaseOfData                   = other.OptionalHeader.BaseOfData;
    this->OptionalHeader.ImageBase                    = other.OptionalHeader.ImageBase;
    this->OptionalHeader.SectionAlignment             = other.OptionalHeader.SectionAlignment;
    this->OptionalHeader.FileAlignment                = other.OptionalHeader.FileAlignment;
    this->OptionalHeader.MajorOperatingSystemVersion  = other.OptionalHeader.MajorOperatingSystemVersion;
    this->OptionalHeader.MinorOperatingSystemVersion  = other.OptionalHeader.MinorOperatingSystemVersion;
    this->OptionalHeader.MajorImageVersion            = other.OptionalHeader.MajorImageVersion;
    this->OptionalHeader.MinorImageVersion            = other.OptionalHeader.MinorImageVersion;
    this->OptionalHeader.MajorSubsystemVersion        = other.OptionalHeader.MajorSubsystemVersion;
    this->OptionalHeader.MinorSubsystemVersion        = other.OptionalHeader.MinorSubsystemVersion;
    this->OptionalHeader.Win32VersionValue            = other.OptionalHeader.Win32VersionValue;
    this->OptionalHeader.SizeOfImage                  = other.OptionalHeader.SizeOfImage;
    this->OptionalHeader.SizeOfHeaders                = other.OptionalHeader.SizeOfHeaders;
    this->OptionalHeader.CheckSum                     = other.OptionalHeader.CheckSum;
    this->OptionalHeader.Subsystem                    = other.OptionalHeader.Subsystem;
    this->OptionalHeader.DllCharacteristics           = other.OptionalHeader.DllCharacteristics;
    this->OptionalHeader.SizeOfStackReserve           = other.OptionalHeader.SizeOfStackReserve;
    this->OptionalHeader.SizeOfStackCommit            = other.OptionalHeader.SizeOfStackCommit;
    this->OptionalHeader.SizeOfHeapReserve            = other.OptionalHeader.SizeOfHeapReserve;
    this->OptionalHeader.SizeOfHeapCommit             = other.OptionalHeader.SizeOfHeapCommit;
    this->OptionalHeader.LoaderFlags                  = other.OptionalHeader.LoaderFlags;
    this->OptionalHeader.NumberOfRvaAndSizes          = other.OptionalHeader.NumberOfRvaAndSizes;

    /* Copy the directories entries */
    for (uint i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
    {
        this->OptionalHeader.DataDirectory[i].Size           = other.OptionalHeader.DataDirectory[i].Size;
        this->OptionalHeader.DataDirectory[i].VirtualAddress = other.OptionalHeader.DataDirectory[i].VirtualAddress;
    }
}

cNtHeader& cNtHeader::operator = (const IMAGE_NT_HEADERS32& other)
{
    m_sections.removeAll();
    changeNtHeader(other);

    return *this;
}

void cNtHeader::read(basicInput& stream,
                     bool shouldReadSections,
                     bool isMemory)
{
    // Remove all old componentes
    m_memoryImage = cForkStreamPtr(NULL);
    m_fastImportDll = cForkStreamPtr(NULL);

    IMAGE_NT_HEADERS32 newHeader;
    memset(&newHeader, 0, sizeof(newHeader));
    // Read all header, except RVA
    stream.pipeRead(&newHeader,
                    sizeof(newHeader) -
                        (IMAGE_NUMBEROF_DIRECTORY_ENTRIES *
                        sizeof(IMAGE_DATA_DIRECTORY)));

    CHECK(newHeader.Signature == IMAGE_NT_SIGNATURE);
    changeNtHeader(newHeader);

    // Read DATA_DIRCTORIES. Limited by the number of RVA
    uint i;
    for (i = 0; i < this->OptionalHeader.NumberOfRvaAndSizes; i++)
        stream.pipeRead(&this->OptionalHeader.DataDirectory[i],
                        sizeof(IMAGE_DATA_DIRECTORY));

    // Test whether we should read sections
    if (!shouldReadSections)
        return;

    // Start reading sections
    for (i = 0; i < this->FileHeader.NumberOfSections; i++)
    {
        // Read section
        cNtSectionHeader* appenedSection = new cNtSectionHeader(
                            // If we wanted to specifiy the image base for ourselves, use it
                            m_trueImageBase ? m_trueImageBase : this->OptionalHeader.ImageBase,
                            stream,
                            SECTION_TYPE_WINDOWS_CODE,
                            true,
                            isMemory);
        cSectionPtr newSection(appenedSection);

        // Test whether we know what is the type of the section...
        for (uint j = 0; j < this->OptionalHeader.NumberOfRvaAndSizes; j++)
        {
            if ((this->OptionalHeader.DataDirectory[j].VirtualAddress ==
                    appenedSection->VirtualAddress) &&
                (this->OptionalHeader.DataDirectory[j].Size ==
                    appenedSection->SizeOfRawData))
            {
                appenedSection->setSectionType((SectionType)j);
            }
        }

        m_sections.append(newSection);
    }

    // TODO! readPrivate
}

void cNtHeader::read(cMemoryAccesserStream& stream,
                     bool shouldReadSections,
                     bool isMemory)
{
    // Read the header
    read((basicInput&)(stream), false, isMemory);

    // Test whether we should read sections
    if (!shouldReadSections)
        return;

    // TODO!
    CHECK(isMemory);

    // Start reading sections
    for (uint i = 0; i < this->FileHeader.NumberOfSections; i++)
    {
        // Read section
        cNtSectionHeader* appenedSection = new cNtSectionHeader(
            this->OptionalHeader.ImageBase,
            stream,
            SECTION_TYPE_WINDOWS_CODE,
            true,
            isMemory);
        cSectionPtr newSection(appenedSection);

        // Test whether we know what is the type of the section...
        for (uint j = 0; j < this->OptionalHeader.NumberOfRvaAndSizes; j++)
        {
            if ((this->OptionalHeader.DataDirectory[j].VirtualAddress ==
                appenedSection->VirtualAddress) &&
                (this->OptionalHeader.DataDirectory[j].Size ==
                appenedSection->SizeOfRawData))
            {
                appenedSection->setSectionType((SectionType)j);
            }
        }

        m_sections.append(newSection);
    }

    // Get a fast source
    m_memoryImage = stream.fork();

    // And read the private dll sections.
    // TODO! readPrivate(stream);
}

void cNtHeader::readPrivate(cMemoryAccesserStream& stream)
{
    /*
    // TODO! Maybe there are some more unreaded sections.
    DWORD length = stream.getPointer();
    addressNumericValue firstSegment = MAX_PHYSICAL_ADDRESS;
    cList<cSectionPtr>::iterator j  = m_sections.begin();
    for (; j != m_sections.end(); ++j)
    {
        cNtSectionHeader* section = (cNtSectionHeader*)((*j).getPointer());
        firstSegment = t_min((addressNumericValue)section->PointerToRawData,
                             firstSegment);
    }

    // Protect against corrupt PE files
    if (firstSegment > length)
    {
        length = firstSegment - length;
        stream.pipeRead(m_fastImportDll, length);
    }
    */
}

void cNtHeader::write(basicIO& stream,
                      bool shouldWriteSections,
                      bool isMemory)
{
    // Start writing all the fields of the IMAGE_NT_HEADERS struct
    IMAGE_NT_HEADERS* imageNtHeaders = (IMAGE_NT_HEADERS*)(&this->Signature);
    stream.pipeWrite(imageNtHeaders,
                     sizeof(IMAGE_NT_HEADERS) -
                        ((IMAGE_NUMBEROF_DIRECTORY_ENTRIES - this->OptionalHeader.NumberOfRvaAndSizes) *
                         sizeof(IMAGE_DATA_DIRECTORY)));

    // Test for section storage
    if (!shouldWriteSections)
        return;

    /* Start reading sections */
    cList<cSectionPtr>::iterator i = m_sections.begin();
    for (; i != m_sections.end(); ++i)
    {
        cNtSectionHeader* section = (cNtSectionHeader*)((*i).getPointer());
        section->write(stream, true, isMemory);
    }

    // Write the fucking fast-DLL loading
    // TODO!
    /*
    stream.pipeWrite(m_fastImportDll,
                     m_fastImportDll.getSize());
    */
    CHECK_FAIL(); // NOT READY YET.
}

#ifdef PE_TRACE
cStringerStream& operator << (cStringerStream& out,
                              const cNtHeader& object)
{
    uint i;

    out << "cNtHeader memory dump" << endl;
    out << "=====================" << endl << endl;

    /* Start printing the content of the cNtHeaders */
    out << "FileHeader" << endl;
    out << "----------" << endl;
    out << "     Machine:              ";
    switch (object.FileHeader.Machine)
    {
    case IMAGE_FILE_MACHINE_I386:    out << "Intel 32 bit" << endl; break;
    case IMAGE_FILE_MACHINE_IA64:    out << "Intel 64 bit" << endl; break;
    case IMAGE_FILE_MACHINE_ALPHA:   out << "DEC Alpha "   << endl; break;
    case IMAGE_FILE_MACHINE_POWERPC: out << "Power PC"     << endl; break;
    default: out << "Unknown - " << HEXWORD(object.FileHeader.Machine) << endl; break;
    }

    out << "     NumberOfSections:     " << (uint)object.FileHeader.NumberOfSections << endl;
    out << "     TimeDateStamp:        " << HEXDWORD(object.FileHeader.TimeDateStamp) << endl;
    out << "     PointerToSymbolTable: " << HEXDWORD(object.FileHeader.PointerToSymbolTable) << endl;
    out << "     NumberOfSymbols:      " << (uint)object.FileHeader.NumberOfSymbols << endl;
    out << "     SizeOfOptionalHeader: " << (uint)object.FileHeader.SizeOfOptionalHeader << endl;

    /* Print a list of all the flags avaliable */
    out << "     Characteristics:      " << HEXWORD(object.FileHeader.Characteristics) << endl;
    for (i = 0; i < 16; i++)
    {
        if ((object.FileHeader.Characteristics & (1 << i)) != 0)
        {
            out << "                           ";
            out << cHumanStringTranslation::getWindowsImageFileCharacter(1 << i) << endl;
        }
    }

    out << endl;
    out << "OptionalHeader" << endl;
    out << "--------------" << endl;
    out << "     Magic:               " << HEXWORD(object.OptionalHeader.Magic) << endl;
    out << "     Linker version:      " << HEXBYTE(object.OptionalHeader.MajorLinkerVersion) <<  ":" << HEXBYTE(object.OptionalHeader.MinorLinkerVersion) << endl;
    out << "     Size of code:        " << (uint)object.OptionalHeader.SizeOfCode << endl;
    out << "     SzInitializedData:   " << (uint)object.OptionalHeader.SizeOfInitializedData << endl;
    out << "     SzUninitialiezdData: " << (uint)object.OptionalHeader.SizeOfUninitializedData << endl;
    out << "     AddressOfEntryPoint: " << HEXDWORD(object.OptionalHeader.AddressOfEntryPoint + object.OptionalHeader.ImageBase) << endl;
    out << "     BaseOfCode:          " << HEXDWORD(object.OptionalHeader.BaseOfCode          + object.OptionalHeader.ImageBase) << endl;
    out << "     BaseOfData:          " << HEXDWORD(object.OptionalHeader.BaseOfData          + object.OptionalHeader.ImageBase) << endl;
    out << "     ImageBase:           " << HEXDWORD(object.OptionalHeader.ImageBase) << endl;
    out << "     SectionAlignment:    " << (uint)object.OptionalHeader.SectionAlignment  << endl;
    out << "     FileAlignment:       " << (uint)object.OptionalHeader.FileAlignment << endl;
    out << "     OS version:          " << (uint)object.OptionalHeader.MajorOperatingSystemVersion << "." << (uint)object.OptionalHeader.MinorOperatingSystemVersion << endl;
    out << "     Image version:       " << (uint)object.OptionalHeader.MajorImageVersion << "." << (uint)object.OptionalHeader.MinorImageVersion << endl;
    out << "     Sunsystem version:   " << (uint)object.OptionalHeader.MajorSubsystemVersion << "." << (uint)object.OptionalHeader.MinorSubsystemVersion << endl;
    out << "     Win32VersionValue:   " << (uint)object.OptionalHeader.Win32VersionValue  <<endl;
    out << "     SizeOfImage:         " << HEXDWORD(object.OptionalHeader.SizeOfImage) << "  " << (uint)object.OptionalHeader.SizeOfImage << endl;
    out << "     SizeOfHeaders:       " << (uint)object.OptionalHeader.SizeOfHeaders << endl;
    out << "     CheckSum:            " << HEXDWORD(object.OptionalHeader.CheckSum) << endl;
    out << "     Subsystem:           ";
    switch (object.OptionalHeader.Subsystem)
    {
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:    out << "Windows GUI"; break;
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:    out << "Windows CUI"; break;
    case IMAGE_SUBSYSTEM_POSIX_CUI:      out << "Posix CUI"; break;
    case IMAGE_SUBSYSTEM_NATIVE:         out << "No subsystem"; break;
    case IMAGE_SUBSYSTEM_NATIVE_WINDOWS: out << "Native windows"; break;
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: out << "Windows CE GUI"; break;
    default: out << "Unkwon subsystem: " << HEXWORD(object.OptionalHeader.Subsystem);
    }
    out << endl;
    out << "     SizeOfStackReserve:  " << HEXDWORD(object.OptionalHeader.SizeOfStackReserve)  << endl;
    out << "     SizeOfStackCommit:   " << HEXDWORD(object.OptionalHeader.SizeOfStackCommit)   << endl;
    out << "     SizeOfHeapReserve:   " << HEXDWORD(object.OptionalHeader.SizeOfHeapReserve)   << endl;
    out << "     SizeOfHeapCommit:    " << HEXDWORD(object.OptionalHeader.SizeOfHeapCommit)    << endl;
    out << "     LoaderFlags:         " << (uint)object.OptionalHeader.LoaderFlags         << endl;
    out << "     NumberOfRvaAndSizes: " << (uint)object.OptionalHeader.NumberOfRvaAndSizes << endl;

    for (i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
    {
        if (object.OptionalHeader.DataDirectory[i].Size != 0)
        {
            /* Print only the active directories */
            out << "Dir#" << HEXBYTE(i) << " size: "<<
                HEXDWORD(object.OptionalHeader.DataDirectory[i].Size) <<
                " location: " << HEXDWORD(object.OptionalHeader.DataDirectory[i].VirtualAddress + object.OptionalHeader.ImageBase) <<
                " - " << cHumanStringTranslation::getWindowsDirectoryName(i) << endl;
        }
    }

    out << endl << endl;
    out << endl << endl;
    out << "Sections" << endl;
    out << "========" << endl << endl;
    cList<cSectionPtr>::iterator itr  = object.m_sections.begin();
    for (; itr != object.m_sections.end(); ++itr)
    {
        cNtSectionHeader* section = (cNtSectionHeader*)((*itr).getPointer());
        out << *section;
        out << endl;
    }

    return out;
}
#endif // PE_TRACE

cVirtualMemoryAccesserPtr cNtHeader::getPeMemory() const
{
    return cVirtualMemoryAccesserPtr(new cNtPeFileMapping(this));
}

uint cNtHeader::calculatePeLastVirtualAddress() const
{
    uint last = 0;
    for (uint i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
    {
        last = t_max((uint)(OptionalHeader.DataDirectory[i].Size +
                            OptionalHeader.DataDirectory[i].VirtualAddress),
                     last);
    }
    return last;
}

bool cNtHeader::getSections(cList<cSectionPtr>& sections) const
{
    if(!m_shouldReadSections)
        return false;
    sections = m_sections;
    return true;
}

//////////////////////////////////////////////////////////////////////////
// cNtHeader::cNtPeFileMapping

cNtHeader::cNtPeFileMapping::cNtPeFileMapping(const cNtHeader* parent) :
    m_parent(parent)
{
}

bool cNtHeader::cNtPeFileMapping::memread(addressNumericValue address,
                                    void* buffer,
                                    uint length,
                                    cFragmentsDescriptor*) const
{
    // TODO!
    // For now the fragmentation is ignore because it's irrelevant

    if (!m_parent->m_memoryImage.isEmpty())
    {
        cForkStreamPtr stream = m_parent->m_memoryImage->fork();

        stream->seek(address,
                     basicInput::IO_SEEK_SET);
        stream->pipeRead((uint8*)buffer, length);
        return true;
    }

    // Reset buffer
    memset(buffer, IMAGE_RDATA_CELL_CODE , length);

    cList<cSectionPtr>::iterator i = m_parent->m_sections.begin();
    for (; i != m_parent->m_sections.end(); ++i)
    {
        cNtSectionHeader& ntSection = *((cNtSectionHeader*)(*i).getPointer());
        // For each section check if we have data within the range
        addressNumericValue SectionAddress = ntSection.VirtualAddress;
        addressNumericValue SectionLength  = ntSection.SizeOfRawData;
        addressNumericValue SectionEnd     = SectionAddress + SectionLength;

        if ((SectionEnd > address) && (SectionAddress < (address + length)))
        {
            // There is some overlapped
            addressNumericValue cBegin = t_max(SectionAddress, address);
            addressNumericValue cEnd   = t_min(SectionEnd, (address + length));

            cForkStreamPtr stream =
                ntSection.getSectionContentAccesser()->fork();

            stream->seek(cBegin - SectionAddress, basicInput::IO_SEEK_SET);
            stream->pipeRead((uint8*)buffer + (cBegin - address), cEnd - cBegin);
        }
    }

    return true;
}

bool cNtHeader::cNtPeFileMapping::write(addressNumericValue,
                                        const void*,
                                        uint)
{
    CHECK_FAIL();
}

bool cNtHeader::cNtPeFileMapping::isWritableInterface() const
{
    return false;
}
