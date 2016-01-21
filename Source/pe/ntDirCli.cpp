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
 * ntDirCli.cpp
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
#include "pe/ntDirCli.h"

cNtDirCli::cNtDirCli()
{
    // Generate invalid core-header
    memset(&m_coreHeader, 0, sizeof(m_coreHeader));
}

cNtDirCli::cNtDirCli(const cNtHeader& header)
{
    readDirectory(header);
}

bool cNtDirCli::isMyDir(uint directoryTypeIndex)
{
    // The 14 directory which used to be COM descriptor (TLB) is the CLI
    // header at .NET PE header files.
    return directoryTypeIndex == IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR;
}

void cNtDirCli::readDirectory(const cNtHeader& header,
                              uint directoryTypeIndex)
{
    if (directoryTypeIndex == UNKNOWNDIR)
        directoryTypeIndex = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR;

    const IMAGE_DATA_DIRECTORY& cliDirectory =
        header.OptionalHeader.DataDirectory[directoryTypeIndex];

    uint size    = cliDirectory .Size;
    uint address = cliDirectory .VirtualAddress;

    CHECK_MSG(size != 0, ".NET CLI Header cannot be found!!!");

    m_data = cMemoryAccesserStreamPtr(new cMemoryAccesserStream(
        header.getPeMemory(),
        address,
        address + size));


    // Parse the information.
    // First of all read the size of the header
    uint32 cliHeaderSize;
    m_data->streamReadUint32(cliHeaderSize);

    // Unknown framework-file cannot be loaded using the CLI header
    // TODO! When the CLI changes remember to support backward compatability.
    CHECK(cliHeaderSize == sizeof(IMAGE_COR20_HEADER));

    // Write the size of the header.
    m_coreHeader.cb = cliHeaderSize;

    // Read the rest of the header.
    // NOTE: The struct IMAGE_COR20_HEADER declared as "pack 1 byte"
    m_data->pipeRead((void*)&m_coreHeader.MajorRuntimeVersion,
                     cliHeaderSize - sizeof(cliHeaderSize)); // We read 4 bytes!

    // Return the pointer back to it's original state.
    m_data->seek(0, basicInput::IO_SEEK_SET);
}

const cMemoryAccesserStreamPtr& cNtDirCli::getData() const
{
    return m_data;
}

const IMAGE_COR20_HEADER& cNtDirCli::getCoreHeader() const
{
    return m_coreHeader;
}

#ifdef PE_TRACE
cStringerStream& operator << (cStringerStream& out,
                              const cNtDirCli& object)
{
    out << "CLI header" << endl;
    out << "==========" << endl;
    out << "Size:         " << HEXNUMBER(object.m_coreHeader.cb) << endl;
    out << "Version:      " << (uint)(object.m_coreHeader.MajorRuntimeVersion)
                            << "."
                            << (uint)(object.m_coreHeader.MinorRuntimeVersion)
                            << endl;
    out << "Flags:        " << HEXDWORD(object.m_coreHeader.Flags) << endl;
    out << "Entry-point:  " << HEXDWORD(object.m_coreHeader.EntryPointToken)
        << endl;
    return out;
}
#endif // PE_TRACE
