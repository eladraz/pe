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

#ifndef __TBA_PE_SECTION_H
#define __TBA_PE_SECTION_H

/*
 * section.h
 *
 * The concept of "section" is an individual block of data which can be
 * loaded in a different space area and contains information.
 * The information can be CODE, DATA, RELOC, RES, EXPORT, IMPORT and so on.
 *
 * This section file contains generic, cross-platform elements. Each operating
 * system can be implemented with less/more elements.
 *
 * Author: Elad Raz <e@eladraz.com>
 */
#include "xStl/types.h"
#include "xStl/data/array.h"
#include "xStl/data/list.h"
#include "xStl/data/hash.h"
#include "xStl/data/string.h"
#include "xStl/data/smartptr.h"
#include "xStl/data/datastream.h"
#include "xStl/except/exception.h"
#include "xStl/stream/basicIO.h"
#include "xStl/stream/forkStream.h"
#include "xStl/stream/stringerStream.h"
#include "pe/datastruct.h"
#include "pe/sectionTypes.h"

// Forward decleretion
#ifdef PE_TRACE
class cSection;
cStringerStream& operator << (cStringerStream& out, const cSection& object);
#endif // PE_TRACE

/*
 * Store the information about the section. The information devided into these
 * parts:
 *   - Name
 *   - Type (Which can tell which sub-inherit class is responsible for the
 *           section)
 *   - Stream of information
 *   - Attributes (Read only/RW/Execute etc..)
 */
class cSection {
public:
    // Section's flag
    enum {
        // The section can be accessed with read operations.
        SECTION_FLAG_READ         = 0x00000001,
        // The section can be accessed with write operations
        SECTION_FLAG_WRITE        = 0x00000002,
        // The section can be accessed with executed operations
        SECTION_FLAG_EXECUTABLE   = 0x00000004,
        // When section is accessed by write it's duplicates.
        SECTION_FLAG_COPYONWRITE  = 0x00000008,
        // The content of the section if unknwon and init by memory value
        SECTION_FLAG_UNKNOWN      = 0x00000010,

        // The normal section properties.
        SECTION_FLAG_NORMAL = SECTION_FLAG_READ |
                              SECTION_FLAG_WRITE |
                              SECTION_FLAG_EXECUTABLE,
        // The protected section properties.
        SECTION_FLAG_PROTECTED = SECTION_FLAG_READ |
                                 SECTION_FLAG_EXECUTABLE
    };
    typedef uint SectionFlag;

    /*
     * Default constructor.
     *
     * name - The name of the section
     * data - The content of the data
     * base - The base-address of the section in the memory
     * type - The section type. See SectionType for more information
     * flags - The attributes of the section
     */
    cSection(const cString& name,
             const cForkStreamPtr& data,
             addressNumericValue base = 0,
             SectionType type = SECTION_TYPE_DUMP,
             SectionFlag flags = SECTION_FLAG_NORMAL);

    // Virtual constructor. You can inherit from me
    virtual ~cSection() {};

    /*
     * Return the size of the forkable stream, without creating new stream.
     */
    uint getSectionContentSize() const;

    /*
     * Return the content of the section, the return pointer is new stream
     * accessor.
     */
    cForkStreamPtr getSectionContentAccesser() const;

    /*
     * Return the content of entire section in a stream.
     */
    void snapshotGetSectionContentCopy(cBuffer& out) const;

    /*
     * Returns the name of the section
     */
    const cString& getSectionName() const;

    /*
     * Returns the base-address of the section
     */
    addressNumericValue getSectionBaseAddress() const;

    /*
     * Returns the section type. See SectionType
     */
    SectionType getSectionType() const;

    /*
     * Returns the section flags. See SectionFlag
     */
    SectionFlag getSectionFlags() const;

    // Set functions.

    /*
     * Changes the name of the section.
     *
     * name - The name of the section
     */
    void setSectionName(const cString& name);

    /*
     * Changes the section based address.
     *
     * base - The new based address.
     */
    void setSectionBaseAddress(addressNumericValue base);

    /*
     * Changes the section flags
     *
     * flags - New flags for the section
     */
    void setSectionFlags(SectionFlag flags);

    /*
     * Changes the section type
     *
     * type - New type for the section
     */
    void setSectionType(SectionType type);

    /*
     * Return true if the 'type' can be handled by the
     */
    virtual bool canBeHandledByMe(SectionType type) = 0;

protected:
    // Deny operator = and copy-constructor.
    // This class is an interface
    cSection(const cSection& other);
    cSection& operator = (const cSection& other);

    // Deny default constructor. Only the inherit class can initialized this
    // class.
    cSection(const cForkStreamPtr& data);

    // Private data members

    // The raw data of the section (The content of the section)
    cForkStreamPtr m_data;
    // A human description string of the section
    cString m_name;
    // The base address of the section
    addressNumericValue m_base;
    // The type of the section. See SectionType
    SectionType m_type;
    // The flag of the section. See SectionFlag
    SectionFlag m_flags;

    /*
     * OUTSTREAM operator <<.
     * Used to dump the content of the section into human readable string
     */
    #ifdef PE_TRACE
    friend cStringerStream& operator << (cStringerStream& out,
                                         const cSection& object);
    #endif // PE_TRACE
};

// The reference-countable section object
typedef cSmartPtr<cSection> cSectionPtr;

#endif // __TBA_PE_SECTION_H

