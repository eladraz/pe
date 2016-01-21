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
 * ntDirReloc.cpp
 *
 * Implementation file
 *
 * Author: Tal Harel, 2014
 */
#include "xStl/types.h"
#include "xStl/data/array.h"
#include "xStl/data/list.h"
#include "xStl/data/string.h"
#include "xStl/data/datastream.h"
#include "xStl/stream/basicIO.h"
#include "xStl/stream/stringerStream.h"
#include "pe/section.h"
#include "pe/datastruct.h"
#include "pe/ntheader.h"
#include "pe/ntDirReloc.h"

#include "xStl/stream/traceStream.h"

cNtDirReloc::cNtDirReloc()
{
}

cNtDirReloc::cNtDirReloc(cNtHeader& header)
{
    readDirectory(header);
}

bool cNtDirReloc::isMyDir(uint directoryTypeIndex)
{
    return directoryTypeIndex == IMAGE_DIRECTORY_ENTRY_BASERELOC;
}

void cNtDirReloc::readDirectory(const cNtHeader& header,
                                uint directoryTypeIndex)
{
    if (directoryTypeIndex == UNKNOWNDIR)
        directoryTypeIndex = IMAGE_DIRECTORY_ENTRY_BASERELOC;

    const IMAGE_DATA_DIRECTORY& relocDirectory =
        header.OptionalHeader.DataDirectory[directoryTypeIndex];
    uint size    = relocDirectory.Size;
    uint address = relocDirectory.VirtualAddress;
    CHECK_MSG(size != 0, ".reloc cannot be found!!!");

    cVirtualMemoryAccesserPtr mem = header.getPeMemory();
    cMemoryAccesserStream newStream(mem, address, address + size);
    read(newStream);
}

void cNtDirReloc::read(basicInput& stream)
{
    // Delete all the previous functions
    m_relocOffsets.changeSize(0);

    // Set the initial relocation table size
    m_relocOffsets.changeSize(stream.length() / 2);

    // Start reading the relocation blocks
    IMAGE_BASE_RELOCATION currReloc;
    WORD relocItem;
    int totalRelocs = 0;
    while(!stream.isEOS())
    {
        // Read the current block header
        stream.pipeRead(&currReloc, sizeof(currReloc));

        // Calculate the number of items in the block
        DWORD numItems = (currReloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (uint i = 0; i < numItems; i++)
        {
            // Read the current item
            stream.streamReadUint16(relocItem);

            switch (relocItem >> 12)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                // Calculate and set the offset address
                m_relocOffsets[totalRelocs].m_offsetAddress = currReloc.VirtualAddress + (relocItem & 0xFFF);
                totalRelocs++;
                break;
            default:
                CHECK_MSG(false, "bad relocation table");
            }
        }
    }

    // Set the final relocation table size
    m_relocOffsets.changeSize(totalRelocs);
}

const cNtDirReloc::RelocTable& cNtDirReloc::getRelocArray() const
{
    return m_relocOffsets;
}

bool cNtDirReloc::cRelocEntry::isValid() const
{
    return true;
}

void cNtDirReloc::cRelocEntry::serialize(basicOutput& stream) const
{
    // TODO
    /*
    stream.streamWriteRemoteAddress(m_address);
    if (m_isName)
    {
        // isname = true
        stream.streamWriteUint8(1);
        stream.writeAsciiNullString(m_name);
    } else
        // isname = false
        stream.streamWriteUint8(0);

    // Encode the oridinal number
    stream.streamWriteUint16(m_ordinal);
    */
}

void cNtDirReloc::cRelocEntry::deserialize(basicInput& stream)
{
    // TODO
    /*
    m_address = stream.streamReadRemoteAddress();
    uint8 isName;
    stream.streamReadUint8(isName);
    m_isName = (isName == 1);
    if (m_isName)
    {
        // Read a string
        m_name = stream.readAsciiNullString();
    } else
        // Remove the old name
        m_name = cString();

    // Decode the oridinal
    stream.streamReadUint16(m_ordinal);
    */
}

bool cNtDirReloc::cRelocEntry::operator > (const cNtDirReloc::cRelocEntry &other) const
{
    //return (this->m_contentAddress > other.m_contentAddress);
    return (this->m_offsetAddress > other.m_offsetAddress);
}

/*
#ifdef PE_TRACE
cStringerStream& operator << (cStringerStream& out,
                              const cNtDirExport& _export)
{
    out << "_export table for " << _export.m_moduleName << endl;
    out << "=================" << cString::dup(cString("="), _export.m_moduleName.length())
        << endl << endl;

    out << "Characteristics:       " << HEXDWORD(_export.m_exportDirectory.Characteristics) << endl;
    out << "TimeDateStamp:         " << HEXDWORD(_export.m_exportDirectory.TimeDateStamp)   << endl;
    out << "Version:               " << (uint)_export.m_exportDirectory.MajorVersion << '.' << (uint)_export.m_exportDirectory.MinorVersion << endl;
    out << "Name:                  " << HEXDWORD(_export.m_exportDirectory.Name) << endl;
    out << "Base:                  " << HEXDWORD(_export.m_exportDirectory.Base) << endl;
    out << "NumberOfFunctions:     " << (uint)_export.m_exportDirectory.NumberOfFunctions << endl;
    out << "NumberOfNames:         " << (uint)_export.m_exportDirectory.NumberOfNames << endl;
    out << "AddressOfFunctions:    " << HEXDWORD(_export.m_exportDirectory.AddressOfFunctions)    << endl;
    out << "AddressOfNames:        " << HEXDWORD(_export.m_exportDirectory.AddressOfNames)        << endl;
    out << "AddressOfNameOrdinals: " << HEXDWORD(_export.m_exportDirectory.AddressOfNameOrdinals) << endl;

    out << endl << endl;

    //Print all the functions at the _export directory
    for (uint i = 0; i < _export.m_exportFunctions.getSize(); i++)
    {
        out << "  "    << HEXREMOTEADDRESS(_export.m_exportFunctions[i].m_address)
            << "     " << HEXWORD (_export.m_exportFunctions[i].m_ordinal)
            << "  ";

        if (_export.m_exportFunctions[i].m_isName)
            out << _export.m_exportFunctions[i].m_name;

        out << endl;
    }

    return out;
}
#endif
*/
