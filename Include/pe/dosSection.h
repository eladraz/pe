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

#ifndef __TBA_PE_DOS_SECTION_H
#define __TBA_PE_DOS_SECTION_H

/*
 * dosSection.h
 *
 * DOS binary files (.COM, .EXE) section definitions...
 * The problem with dos-section it's thier physical disk location. This section
 * append this information to the section descriptor...
 *
 * Author: Elad Raz <e@eladraz.com>
 */
#include "xStl/types.h"
#include "pe/section.h"

/*
 * Contains additional information for each dos-section: The position of the
 * section inside the binary file = Code segment.
 * In order to translates segment to disk-location, use the following:
 *      (SEGMENT + e_cparhdr) * 0x10
 */
class cDosSection : public cSection {
public:
    /*
     * Default constructor
     */
    cDosSection(const cForkStreamPtr& data,
                SectionType type,
                uint16 segment,
                SectionFlag flags = SECTION_FLAG_NORMAL);

    /*
     * Returns the starting segment of the section from the beginning of the
     * executable
     */
    uint16 getSegment() const;

    /*
     * Changes the section segment
     */
    void setSegment(uint16 newSegment);

    /*
     * Returns true for the following:
     *     SECTION_TYPE_DUMP
     *     SECTION_TYPE_DOS_CODE  - DOS CODE+DATA section
     *     SECTION_TYPE_DOS_DATA  - DOS DATA+CODE section section
     *     SECTION_TYPE_DOS_STACK - DOS STACK section.
     */
    virtual bool canBeHandledByMe(SectionType type);

private:
    // Stores the position inside the disk
    uint m_diskLocation;
    // Stores the segment
    uint16 m_segment;
};

#endif // __TBA_PE_DOS_SECTION_H
