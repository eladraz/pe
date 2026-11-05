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
 * ntDirImport.cpp
 *
 * Implementation file
 */
#include "xStl/types.h"
#include "xStl/data/list.h"
#include "xStl/data/string.h"
#include "xStl/data/datastream.h"
#include "xStl/except/exception.h"
#include "xStl/stream/basicIO.h"
#include "pe/section.h"
#include "pe/datastruct.h"
#include "pe/ntsectionheader.h"
#include "pe/ntheader.h"
#include "pe/ntDirImport.h"

/*
 * Locates the section which fully contains [rva, rva + length). Only the raw
 * data of a section is addressable. Returns NULL if no section contains the
 * range.
 */
static cNtSectionHeader* findSection(const cList<cSectionPtr>& sections,
                                     uint64 rva,
                                     uint64 length)
{
    cList<cSectionPtr>::iterator i = sections.begin();
    for (; i != sections.end(); ++i)
    {
        cNtSectionHeader* section = (cNtSectionHeader*)((*i).getPointer());
        uint64 start = section->VirtualAddress;
        uint64 end   = start + section->SizeOfRawData;
        if ((rva >= start) && (rva < end) && (length <= end - rva))
            return section;
    }
    return NULL;
}

/*
 * Reads 'length' bytes at the RVA 'rva'. Throw cException if the range is not
 * completely inside a section.
 */
static void readRva(const cList<cSectionPtr>& sections,
                    uint64 rva,
                    void* buffer,
                    uint length)
{
    cNtSectionHeader* section = findSection(sections, rva, length);
    CHECK_MSG(section != NULL, "import table: RVA out of section bounds");

    cForkStreamPtr stream = section->getSectionContentAccesser()->fork();
    stream->seek(rva - section->VirtualAddress, basicInput::IO_SEEK_SET);
    stream->pipeRead(buffer, length);
}

/*
 * Reads a null terminated ASCII string at the RVA 'rva'. The string must end
 * inside the section which contains its first byte.
 */
static cString readRvaString(const cList<cSectionPtr>& sections, uint64 rva)
{
    cString result;
    for (uint64 current = rva; ; current++)
    {
        char ch;
        readRva(sections, current, &ch, sizeof(ch));
        if (ch == 0)
            break;
        result += cString(ch);
    }
    return result;
}

/*
 * Reads one thunk (an entry of the ILT or the IAT) of PE32 (4 bytes) or
 * PE32+ (8 bytes) width.
 */
static uint64 readThunk(const cList<cSectionPtr>& sections,
                        uint64 rva,
                        bool is64bit)
{
    if (is64bit)
    {
        uint64 thunk = 0;
        readRva(sections, rva, &thunk, sizeof(thunk));
        return thunk;
    }

    uint32 thunk = 0;
    readRva(sections, rva, &thunk, sizeof(thunk));
    return thunk;
}

cNtDirImport::cNtDirImport()
{
}

cNtDirImport::cNtDirImport(const cNtHeader& header)
{
    readDirectory(header);
}

bool cNtDirImport::isMyDir(uint directoryTypeIndex)
{
    return directoryTypeIndex == IMAGE_DIRECTORY_ENTRY_IMPORT;
}

void cNtDirImport::readDirectory(const cNtHeader& header,
                                 uint directoryTypeIndex)
{
    if (directoryTypeIndex == UNKNOWNDIR)
        directoryTypeIndex = IMAGE_DIRECTORY_ENTRY_IMPORT;

    m_modules.removeAll();

    if (directoryTypeIndex >= header.OptionalHeader.NumberOfRvaAndSizes)
        return;

    const IMAGE_DATA_DIRECTORY& importDirectory =
        header.OptionalHeader.DataDirectory[directoryTypeIndex];
    uint64 address = importDirectory.VirtualAddress;
    uint64 size    = importDirectory.Size;
    if ((address == 0) || (size == 0))
        return;

    cList<cSectionPtr> sections;
    CHECK_MSG(header.getSections(sections),
              "import table: the NT header does not hold the sections");

    const bool is64bit = header.is64bit();
    const uint thunkSize = is64bit ? sizeof(uint64) : sizeof(uint32);

    // Walk the import descriptors until the all-zero terminator. The declared
    // directory size is not enforced: real linkers sometimes omit the
    // terminator from it, and the Windows loader ignores it. Every read is
    // bounded by the section holding the table instead.
    for (uint64 offset = 0; ; offset += sizeof(IMAGE_IMPORT_DESCRIPTOR))
    {

        IMAGE_IMPORT_DESCRIPTOR descriptor;
        readRva(sections, address + offset, &descriptor, sizeof(descriptor));

        if ((descriptor.OriginalFirstThunk == 0) &&
            (descriptor.TimeDateStamp == 0) &&
            (descriptor.ForwarderChain == 0) &&
            (descriptor.Name == 0) &&
            (descriptor.FirstThunk == 0))
        {
            break;
        }

        CHECK_MSG(descriptor.Name != 0, "import table: module without a name");
        CHECK_MSG(descriptor.FirstThunk != 0, "import table: module without an IAT");

        Module module;
        module.name = readRvaString(sections, descriptor.Name);

        // The ILT (OriginalFirstThunk) describes the imports. Some linkers
        // leave it empty, in which case the IAT is used as the lookup table.
        uint64 lookupRva = descriptor.OriginalFirstThunk;
        if (lookupRva == 0)
            lookupRva = descriptor.FirstThunk;

        for (uint64 index = 0; ; index++)
        {
            uint64 thunk = readThunk(sections,
                                     lookupRva + index * thunkSize,
                                     is64bit);
            if (thunk == 0)
                break;

            Entry entry;
            entry.iatRva = (uint32)(descriptor.FirstThunk + index * thunkSize);

            bool byOrdinal = is64bit ? (IMAGE_SNAP_BY_ORDINAL64(thunk) != 0) :
                                       (IMAGE_SNAP_BY_ORDINAL32(thunk) != 0);
            if (byOrdinal)
            {
                entry.byOrdinal = true;
                entry.ordinal   = (uint16)(thunk & 0xFFFF);
                entry.hint      = 0;
            } else
            {
                // A by-name thunk is an RVA to IMAGE_IMPORT_BY_NAME, which
                // must fit in 32 bits.
                CHECK_MSG(thunk <= 0xFFFFFFFFULL,
                          "import table: name RVA out of range");
                uint32 nameRva = (uint32)thunk;

                entry.byOrdinal = false;
                entry.ordinal  = 0;
                uint16 hint = 0;
                readRva(sections, nameRva, &hint, sizeof(hint));
                entry.hint = hint;
                entry.name = readRvaString(sections, (uint64)nameRva + sizeof(hint));
            }

            module.entries.append(entry);
        }

        m_modules.append(module);
    }
}

const cList<cNtDirImport::Module>& cNtDirImport::getModules() const
{
    return m_modules;
}
