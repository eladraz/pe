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
 * ntDirExport.cpp
 *
 * Implementation file
 *
 * Author: Elad Raz <e@eladraz.com>
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
#include "pe/ntDirExport.h"

cNtDirExport::cNtDirExport()
{
}

cNtDirExport::cNtDirExport(const cNtHeader& header)
{
    readDirectory(header);
}

bool cNtDirExport::isMyDir(uint directoryTypeIndex)
{
    return directoryTypeIndex == IMAGE_DIRECTORY_ENTRY_EXPORT;
}

void cNtDirExport::readDirectory(const cNtHeader& header,
                                 uint directoryTypeIndex)
{
    if (directoryTypeIndex == UNKNOWNDIR)
        directoryTypeIndex = IMAGE_DIRECTORY_ENTRY_EXPORT;

    const IMAGE_DATA_DIRECTORY& exportDirectory =
        header.OptionalHeader.DataDirectory[directoryTypeIndex];
    uint size    = exportDirectory.Size;
    uint address = exportDirectory.VirtualAddress;
    CHECK_MSG(size != 0, ".edata cannot be founded!!!");

    cVirtualMemoryAccesserPtr mem = header.getPeMemory();
    cMemoryAccesserStream newStream(mem, address, address + size);
    read(newStream, address, header.OptionalHeader.AddressOfEntryPoint);
}

void cNtDirExport::read(basicInput& stream,
                        addressNumericValue imageBase,
                        addressNumericValue entryPoint)
{
    // Save the root pointer
    uint mpos = stream.getPointer();

    // Delete all the previous functions
    m_exportFunctions.changeSize(0);

    // Read the IMAGE_EXPORT_DIRECTORY data
    stream.pipeRead(&m_exportDirectory, sizeof(m_exportDirectory));

    // Reading the module name
    stream.seek(mpos + (m_exportDirectory.Name - imageBase),
                basicInput::IO_SEEK_SET);
    m_moduleName = stream.readAsciiNullString();

    // There are 3 components for each export enrty: Name, address and ordinal
    // value.

    // Calculate the needed table size
    uint tableSize = t_max(m_exportDirectory.NumberOfFunctions,
                      m_exportDirectory.NumberOfNames);
    if (entryPoint)
        tableSize++;

    // Read the function table and their names
    m_exportFunctions.changeSize(tableSize);

    // Read the ordinal values
    stream.seek(mpos + (m_exportDirectory.AddressOfNameOrdinals - imageBase),
                basicInput::IO_SEEK_SET);
    uint i;
    for (i = 0; i < m_exportFunctions.getSize(); i++)
        stream.streamReadUint16((uint16&)m_exportFunctions[i].m_ordinal);


    // Read the name table
   cSArray<uint32> namePointers(m_exportDirectory.NumberOfNames);
   stream.seek(mpos + (m_exportDirectory.AddressOfNames - imageBase),
                basicInput::IO_SEEK_SET);

    for (i = 0; i < m_exportDirectory.NumberOfNames; ++i)
        stream.streamReadUint32(namePointers[i]);

    // Read the real names
    for (i = 0; i < m_exportDirectory.NumberOfNames; ++i)
    {
        stream.seek(mpos + (namePointers[i] - imageBase),
                    basicInput::IO_SEEK_SET);

        uint oridinal = m_exportFunctions[i].m_ordinal;
        m_exportFunctions[oridinal].m_isName = true;
        m_exportFunctions[oridinal].m_name = stream.readAsciiNullString();
    }

    // Read the address for the functions
    stream.seek(mpos + (m_exportDirectory.AddressOfFunctions - imageBase),
                basicInput::IO_SEEK_SET);

    for (i = 0; i < m_exportDirectory.NumberOfFunctions; i++)
    {
        // TODO!
        // The export directory is set for 32bit files only!
        uint32 address = 0;
        stream.streamReadUint32(address);
        m_exportFunctions[i].m_address =
                       remoteAddressNumericValue(address, REMOTE_ADDRESS_32BIT);
    }

    // Add the entry point, if it exists
    if (entryPoint)
    {
        m_exportFunctions[tableSize - 1].m_isName = true;
        m_exportFunctions[tableSize - 1].m_name = ENTRYPOINT_NAME;
        m_exportFunctions[tableSize - 1].m_address = entryPoint;
    }
}

const cNtDirExport::ExportTable& cNtDirExport::getExportArray() const
{
    return m_exportFunctions;
}

bool cNtDirExport::cExportEntrie::isValid() const
{
    return true;
}

void cNtDirExport::cExportEntrie::serialize(basicOutput& stream) const
{
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
}

void cNtDirExport::cExportEntrie::deserialize(basicInput& stream)
{
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
}

bool cNtDirExport::cExportEntrie::operator > (const cNtDirExport::cExportEntrie &other) const
{
    return (this->m_address > other.m_address);
}

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

    /* Print all the functions at the _export directory */
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
