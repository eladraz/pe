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
 * section.cpp
 *
 * Implementation file
 *
 * Author: Elad Raz <e@eladraz.com>
 */
#include "xStl/types.h"
#include "xStl/data/string.h"
#include "xStl/data/array.h"
#include "pe/section.h"
#include "pe/sectionTypes.h"
#include "pe/humanStringTranslation.h"

cSection::cSection(const cForkStreamPtr& data) :
    m_data(data),
    m_base(0),
    m_type(SECTION_TYPE_DUMP),
    m_flags(cSection::SECTION_FLAG_NORMAL)
{
}

cSection::cSection(const cString& name,
                   const cForkStreamPtr& data,
                   addressNumericValue base /* = 0 */,
                   SectionType type /* = SECTION_TYPE_DUMP */,
                   SectionFlag flags /* = SECTION_FLAG_ALL */) :
    m_data(data),
    m_name(name),
    m_base(base),
    m_type(type),
    m_flags(flags)
{
}

cForkStreamPtr cSection::getSectionContentAccesser() const
{
    return m_data->fork();
}

uint cSection::getSectionContentSize() const
{
    return m_data->length();
}

void cSection::snapshotGetSectionContentCopy(cBuffer& out) const
{
    out.changeSize(0);
    cForkStreamPtr access = getSectionContentAccesser();
    access->seek(0, basicInput::IO_SEEK_SET);
    access->readAllStream(out);
}

const cString& cSection::getSectionName()  const
{
    return m_name;
}

addressNumericValue cSection::getSectionBaseAddress() const
{
    return m_base;
}

SectionType cSection::getSectionType() const
{
    return m_type;
}

cSection::SectionFlag cSection::getSectionFlags() const
{
    return m_flags;
}

void cSection::setSectionName(const cString& name)
{
    m_name = name;
}

void cSection::setSectionBaseAddress(addressNumericValue base)
{
    m_base = base;
}

void cSection::setSectionFlags(SectionFlag flags)
{
    m_flags = flags;
}

void cSection::setSectionType(SectionType type)
{
    m_type = type;
}

#ifdef PE_TRACE
cStringerStream& operator << (cStringerStream& out, const cSection& object)
{
    // Start with dumping to the section type,
    // name and location
    out << "Section '" << object.m_name << "'" << endl;
    out << "----------" << cString::dup(cString("-"), object.m_name.length()) << endl;
    out << "Type:  " << cHumanStringTranslation::getSectionTypeName(object.m_type) << endl;
    out << "Base:  " << HEXDWORD(object.m_base)  << endl;
    out << "Flags: " << HEXDWORD(object.m_flags) << endl;
    out << endl << endl;

    // Get the content of the stream
    if (!object.m_data.isEmpty())
    {
        cBuffer content;
        object.snapshotGetSectionContentCopy(content);

        // Print the content of the class
        out << DATA(content.begin(),
                    content.end(),
                    DATA::DATA_USE_ADDRESS,
                    object.m_base,
                    object.m_name.getBuffer()) << endl << endl;
    }

    return out;
}
#endif // PE_TRACE
