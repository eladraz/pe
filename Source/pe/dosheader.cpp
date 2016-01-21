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
 * dosheader.cpp
 *
 * Implementation file
 *
 * Author: Elad Raz <e@eladraz.com>
 */
#include "xStl/types.h"
#include "xStl/os/os.h"
#include "xStl/os/streamMemoryAccesser.h"
#include "xStl/data/datastream.h"
#include "xStl/except/exception.h"
#include "xStl/stream/memoryAccesserStream.h"
#include "pe/dosheader.h"

cDosHeader::cDosHeader(const IMAGE_DOS_HEADER& other)
{
    *this = other;
}

cDosHeader::cDosHeader(basicInput& stream,
                       bool shouldReadSections)
{
    read(stream, shouldReadSections);
}

void cDosHeader::init()
{
    m_relocations.changeSize(0);
    m_sections.removeAll();
}

cDosHeader& cDosHeader::operator = (const IMAGE_DOS_HEADER& other)
{
    init();
    changeDosHeader(other);

    return *this;
}

void cDosHeader::changeDosHeader(const IMAGE_DOS_HEADER& other)
{
    // Copy the IMAGE_DOS_HEADER struct
    this->e_magic    = other.e_magic;
    this->e_cblp     = other.e_cblp;
    this->e_cp       = other.e_cp;
    this->e_crlc     = other.e_crlc;
    this->e_cparhdr  = other.e_cparhdr;
    this->e_minalloc = other.e_minalloc;
    this->e_maxalloc = other.e_maxalloc;
    this->e_ss       = other.e_ss;
    this->e_sp       = other.e_sp;
    this->e_csum     = other.e_csum;
    this->e_ip       = other.e_ip;
    this->e_cs       = other.e_cs;
    this->e_lfarlc   = other.e_lfarlc;
    this->e_ovno     = other.e_ovno;
    this->e_oemid    = other.e_oemid;
    this->e_oeminfo  = other.e_oeminfo;
    this->e_lfanew   = other.e_lfanew;

    cOS::memcpy(this->e_res , other.e_res, 4);
    cOS::memcpy(this->e_res2, other.e_res, 10);
}

void cDosHeader::generateNewHeader(uint16 cs,
                                   uint16 ip,
                                   uint16 ss,
                                   uint16 sp)
{
    uint totalSize = 0;

    // Calculates the size of the headers
    cList<cSectionPtr>::iterator i = m_sections.begin();
    for (; i != m_sections.end(); ++i)
    {
        totalSize+= (*i)->getSectionContentSize();
    }

    this->e_magic    = IMAGE_DOS_SIGNATURE;
    this->e_crlc     = m_relocations.getSize();
    this->e_lfarlc   = ((sizeof(IMAGE_DOS_HEADER) + 30) / 0x10) * 0x10;
    this->e_cparhdr  = ((this->e_lfarlc + m_relocations.getSize() * 4) / 0x10) + 1;
    this->e_minalloc = 0;
    this->e_maxalloc = 0xFFFF;
    this->e_ss       = ss;
    this->e_sp       = sp;
    this->e_csum     = 0;   // Should change this!!!
    this->e_cs       = cs;
    this->e_ip       = ip;
    this->e_ovno     = 0;
    this->e_oemid    = 0;
    this->e_oeminfo  = 0;
    this->e_lfanew   = 0;

    totalSize+= e_cparhdr * 0x10 + 0x200;
    this->e_cblp     = totalSize % 512;
    this->e_cp       = totalSize / 512;

    memset(this->e_res,  0,  8);
    memset(this->e_res2, 0, 20);
}

void cDosHeader::read(basicInput& stream,
                      bool shouldReadSections)
{
    init();

    // NOTE: The numbering of the
    IMAGE_DOS_HEADER* thisHeader = (IMAGE_DOS_HEADER*)&e_magic;
    stream.pipeRead(thisHeader, sizeof(IMAGE_DOS_HEADER));

    // Checking the DOS_HEADER
    CHECK(e_magic == IMAGE_DOS_SIGNATURE);

    if (shouldReadSections)
    {
        // Take a snapshot, Read the entire executable in one chunk. That is
        // the way that EXE loader works.
        cBufferPtr peFileSnapshot(new cBuffer());
        stream.seek(0, basicInput::IO_SEEK_SET);
        stream.pipeRead(*peFileSnapshot, getRealExecutableLength(stream));
        cVirtualMemoryAccesserPtr newSnapshot(
            new cStreamMemoryAccesser(peFileSnapshot));
        cForkStreamPtr snapshotStream(new cMemoryAccesserStream(newSnapshot,
            0,
            peFileSnapshot->getSize()));
        // Perform the read
        internalReadSections((cMemoryAccesserStream&)(*snapshotStream));
    }
}

uint cDosHeader::getRealExecutableLength(basicInput& stream)
{
    // Computing the size of the executable length
    uint executableLength = t_min((uint)(e_cblp + (e_cp * 512)),
                                  stream.length());

    // Test whether PE file is attached
    uint position = stream.getPointer();
    XSTL_TRY
    {
        if (e_lfanew != 0)
        {
            uint32 id;
            stream.seek(e_lfanew, basicInput::IO_SEEK_SET);
            stream.pipeRead(&id ,sizeof(id));
            if (id == IMAGE_NT_SIGNATURE)
            {
                executableLength = t_min(executableLength, (uint)e_lfanew);
            }
        }
    }
    XSTL_CATCH_ALL
    {
        // No PE File
    }
    stream.seek(position, basicInput::IO_SEEK_SET);
    return executableLength;
}

void cDosHeader::read(const cMemoryAccesserStream& stream)
{
    // Perform a normal read
    read((basicInput&)(stream), false);
    // And complex read
    internalReadSections((cMemoryAccesserStream&)(*stream.fork()));
}

void cDosHeader::internalReadSections(cMemoryAccesserStream& stream)
{
    // Calculate the size of the header
    uint headerSize = e_cparhdr * 0x10;

    // Start reading sections.
    // Start with the relocation table
    if (e_crlc > 0)
    {
        stream.seek(e_lfarlc, basicInput::IO_SEEK_SET);
        m_relocations.changeSize(e_crlc); // Prepare the array
        stream.pipeRead(m_relocations.getBuffer(), sizeof(uint32) * e_crlc);
    }

    // Start analyzing the sections according to the relocation table
    cList<uint16> segmentsInUsed;

    // The entry point e_cs:e_ip will be the first function and will be first
    // code segment
    segmentsInUsed.append(e_cs * 0x10);

    // Start with the STACK section
    cSection::SectionFlag stackFlag = cSection::SECTION_FLAG_NORMAL;

    cForkStreamPtr newStackSegment(NULL);
    // Test whether the stack exist in this stream or not.
    if ((((e_ss * 0x10) + headerSize) > stream.length()) ||
        (((e_ss * 0x10) + headerSize + e_sp) > stream.length()))
    {
        // Create a dummy 0xCD stack
        cBufferPtr newStack(new cBuffer(e_sp));
        memset(newStack->getBuffer(), 0xCD, e_sp);
        // Read the only information which can enter
        stackFlag|= cSection::SECTION_FLAG_UNKNOWN;
        if (stream.length() > ((e_ss * 0x10) + headerSize))
        {
            uint read = stream.length() - ((e_ss * 0x10) + headerSize);
            stream.seek(stream.length() - read, basicInput::IO_SEEK_SET);
            stream.pipeRead(newStack->getBuffer(), read);
        }
        cVirtualMemoryAccesserPtr newMemory(new cStreamMemoryAccesser(newStack));
        newStackSegment = cForkStreamPtr(new cMemoryAccesserStream(
            newMemory,
            0,
            e_sp));
    } else
    {
        newStackSegment = cForkStreamPtr(new cMemoryAccesserStream(
                                    stream.getMemoryAccesser(),
                                    (e_ss * 0x10) + headerSize,
                                    (e_ss * 0x10) + headerSize + e_sp));
    }

    m_sections.append(cSectionPtr(new cDosSection(
        newStackSegment,
        SECTION_TYPE_DOS_STACK,
        e_ss,
        stackFlag)));


    // Scan the relocation table in order to find new sections.
    cArray<uint32>::iterator i = m_relocations.begin();
    for (; i != m_relocations.end(); ++i)
    {
        // Ignore the offset
        uint16 segment = (WORD)(*i >> 16);

        // Test whether the segment is in the table
        if (find(segmentsInUsed.begin(),
                 segmentsInUsed.end(),
                 segment) == segmentsInUsed.end())
        {
            // Else append the new segment
            segmentsInUsed.append(segment);
        }

        // Put the call segment
        // The pointers for the relocation are 16 bits which describes only
        // the segments number
        DWORD rlLocation = (segment * 0x10) + (WORD)(*i & 0xFFFF);

        stream.seek(rlLocation + headerSize,
                    basicInput::IO_SEEK_SET);
        ((basicInput&)stream).streamReadUint16(segment);

        // Test whether the segment is in the table
        if (find(segmentsInUsed.begin(),
                 segmentsInUsed.end(),
                 segment) == segmentsInUsed.end())
        {
            // Else append the new segment
            segmentsInUsed.append(segment);
        }
    }

    /* Rearrange the new segments */
    boubbleSort(segmentsInUsed.begin(), segmentsInUsed.end());

    // Start scan all the segments and add them as new sections
    uint executableLengthWithoutHeader = stream.length() - headerSize;
    cList<WORD>::iterator index = segmentsInUsed.begin();
    for (; index != segmentsInUsed.end(); index++)
    {
        // Add the bytes [*i : *(i + 1)] as new section
        // Note that the i is in paragraph size, which is 16 bytes.
        uint startLocation = ((*index) * 0x10);
        uint endLocation;

        if ((index + 1) != segmentsInUsed.end())
        {
            endLocation = (*(index + 1) * 0x10);
        } else
        {
            endLocation = executableLengthWithoutHeader;
        }

        // Since we took care to the STACK segment before we will have to
        // ignore it now (if the stack is not on the code segment)
        if ((startLocation != (DWORD)(e_ss * 0x10)) ||
            (startLocation == (DWORD)(e_cs * 10)))
        {
            if ((startLocation <= (DWORD) (e_ss * 0x10)) &&
                (endLocation   >= (DWORD)((e_ss * 0x10) + e_sp)))
            {
                // The process recognize this section and unit it with the
                // STACK segment
                endLocation = e_ss * 0x10;
            }


            // Protect against over-read
            if (endLocation > executableLengthWithoutHeader)
                endLocation = executableLengthWithoutHeader;

            // Protect against empty segments
            if (endLocation > startLocation)
            {
                cMemoryAccesserStreamPtr newSegment = stream.forkRegion(
                    startLocation + headerSize,
                    endLocation + headerSize);

                m_sections.append(cSectionPtr(new cDosSection(
                                              newSegment->fork(),
                                              SECTION_TYPE_DOS_CODE,
                                              *index)));
            }
        }
    }
}

void cDosHeader::write(basicOutput& stream) const
{
    IMAGE_DOS_HEADER* thisHeader = (IMAGE_DOS_HEADER*)&e_magic;
    stream.pipeWrite(thisHeader, sizeof(IMAGE_DOS_HEADER));
}

void cDosHeader::write(basicIO& stream,
                       bool shouldWriteSections) const
{
    basicOutput& outputStream = stream;
    write(outputStream);
    if (!shouldWriteSections)
        return;

    // Refill the reset of the file header with zeroes
    cBuffer zeros((e_cparhdr * 0x10) - sizeof(IMAGE_DOS_HEADER));
    fill(zeros.begin(), zeros.end(), 0);
    stream.pipeWrite(zeros.getBuffer(), zeros.getSize());

    // Start writing the relocation table
    stream.seek(e_lfarlc, basicInput::IO_SEEK_SET);
    stream.pipeWrite(m_relocations.getBuffer(), sizeof(DWORD) * e_crlc);

    // Start writing all dos section according to thier segment location.
    uint16 lastSegmentLocation = 0;
    for (uint seg = 0; seg < m_sections.length(); seg++)
    {
        cList<cSectionPtr>::iterator currectSectionPtr = m_sections.begin();
        // The section which will right to the disk
        cDosSection* currentWrittenSection = NULL;

        // For each section choose the right sorted section
        cList<cSectionPtr>::iterator i = m_sections.begin();
        for (; i != m_sections.end(); i++)
        {
            cDosSection* info = reinterpret_cast<cDosSection*>((*i).getPointer());

            // Test for errors (Empty section)
            if (info == NULL)
                XSTL_THROW(cException, EXCEPTION_FORMAT_ERROR);

            // Test whether the section had being written
            // Or the sections are overlapped (i.e. stack)
            if (info->getSegment() >= lastSegmentLocation)
            {
                // Check whether this section is next
                if (currentWrittenSection == NULL)
                {
                    currentWrittenSection = info;
                    currectSectionPtr = i;
                } else
                {
                    if (info->getSegment() <
                        currentWrittenSection->getSegment())
                    {
                        currentWrittenSection = info;
                        currectSectionPtr = i;
                    }
                }
            }
        }

        // Test for numbers confusions
        if (currentWrittenSection == NULL)
            XSTL_THROW(cException, EXCEPTION_FORMAT_ERROR);

        // I contain the pointer to the segment
        // Write down the segment to the disk
        stream.seek((currentWrittenSection->getSegment() + e_cparhdr) * 0x10,
                    basicInput::IO_SEEK_SET);

        // Snapshot the stream.
        cBuffer data;
        (*currectSectionPtr)->snapshotGetSectionContentCopy(data);
        stream.pipeWrite(data, data.getSize());

        lastSegmentLocation = currentWrittenSection->getSegment();
    }
}

#ifdef PE_TRACE
cStringerStream& operator << (cStringerStream& out, const cDosHeader& object)
{
    out << "cDosHeader memory dump" << endl;
    out << "======================" << endl << endl;

    out << "FILE mod 512:       " << HEXWORD(object.e_cblp)     << endl;
    out << "FILE div 512:       " << HEXWORD(object.e_cp)       << endl;
    out << "Size of .reloc      " << HEXWORD(object.e_crlc)     << endl;
    out << "Size of header>>4:  " << HEXWORD(object.e_cparhdr)  << endl;
    out << "Min alloc:          " << HEXWORD(object.e_minalloc) << endl;
    out << "Max alloc:          " << HEXWORD(object.e_maxalloc) << endl;
    out << "Stack Segment:      " << HEXWORD(object.e_ss)       << endl;
    out << "Stack size:         " << HEXWORD(object.e_sp)       << endl;
    out << "Checksum:           " << HEXWORD(object.e_csum)     << endl;
    out << "Start entry:        " << HEXWORD(object.e_ip)       << endl;
    out << "Code Segment:       " << HEXWORD(object.e_cs)       << endl;
    out << "Position of .reloc: " << HEXWORD(object.e_lfarlc)   << endl;
    out << "Overlay Number:     " << HEXWORD(object.e_ovno)     << endl;
    out << "OEMID:              " << HEXWORD(object.e_oemid)    << endl;
    out << "OEMINFO:            " << HEXWORD(object.e_oeminfo)  << endl;
    out << "PE Header location: " << HEXDWORD(object.e_lfanew)  << endl;

    out << endl << endl;

    out << "Relocation table" << endl;
    out << "================" << endl;

    for (cArray<uint32>::iterator i = object.m_relocations.begin(); i < object.m_relocations.end(); i++)
    {
        DWORD address = *i;
        out << "  " << HEXHIGH((uint8)((address >> 24) & 0xFF)) << HEXLOW((uint8)((address >> 24) & 0xFF))
            << HEXHIGH((uint8)((address >> 16) & 0xFF)) << HEXLOW((uint8)((address >> 16) & 0xFF)) << ":"
            << HEXHIGH((uint8)((address >>  8) & 0xFF)) << HEXLOW((uint8)((address >>  8) & 0xFF))
            << HEXHIGH((uint8)((address >>  0) & 0xFF)) << HEXLOW((uint8)((address >>  0) & 0xFF)) << endl;
    }

    out << endl << endl;

    cList<cSectionPtr>::iterator lSections = object.m_sections.begin();
    while (lSections != object.m_sections.end())
    {
        out << *(*lSections);
        out << endl << endl;

        lSections.next();
    }

    return out;
}
#endif // PE_TRACE
