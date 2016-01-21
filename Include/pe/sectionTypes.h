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

#ifndef __TBA_PE_SECTIONTYPES_H
#define __TBA_PE_SECTIONTYPES_H

/*
 * sectionTypes.h
 *
 * Contains a list of all possibles sections types and thier derived classes.
 *
 * Author: Elad Raz <e@eladraz.com>
 */
#include "xStl/types.h"

/*
 * See: cSection
 *      cDosSection
 *      cNtSection
 */
enum SectionType {
    // Unknown data. Managed by cSection class.
    SECTION_TYPE_DUMP      = 0x119,

    // DOS CODE+DATA section. Managed by cDosSection
    SECTION_TYPE_DOS_CODE  = 0x116,
    // DOS DATA+CODE section section. Managed by cDosSection
    SECTION_TYPE_DOS_DATA  = 0x117,
    // DOS STACK section. Managed by cDosSection
    SECTION_TYPE_DOS_STACK = 0x118,

    // Windows normal section code
    SECTION_TYPE_WINDOWS_CODE           = 0x115,

    // Windows PE - Export Directory
    SECTION_TYPE_WINDOWS_EXPORT         =  0,
    // Windows PE - Import Directory
    SECTION_TYPE_WINDOWS_IMPORT         =  1,
    // Windows PE - Resource Directory
    SECTION_TYPE_WINDOWS_RESOURCE       =  2,
    // Windows PE - Exception Directory
    SECTION_TYPE_WINDOWS_EXCEPTION      =  3,
    // Windows PE - Security Directory
    SECTION_TYPE_WINDOWS_SECURITY       =  4,
    // Windows PE - Base Relocation Table
    SECTION_TYPE_WINDOWS_BASERELOC      =  5,
    // Windows PE - Debug Directory
    SECTION_TYPE_WINDOWS_DEBUG          =  6,
    // Windows PE - Architecture Specific Data
    SECTION_TYPE_WINDOWS_ARCHITECTURE   =  7,
    // Windows PE - RVA of GP
    SECTION_TYPE_WINDOWS_GLOBALPTR      =  8,
    // Windows PE - TLS Directory
    SECTION_TYPE_WINDOWS_TLS            =  9,
    // Windows PE - Load Configuration Directory
    SECTION_TYPE_WINDOWS_LOAD_CONFIG    = 10,
    // Windows PE - Bound Import Directory in headers
    SECTION_TYPE_WINDOWS_BOUND_IMPORT   = 11,
    // Windows PE - Import Address Table
    SECTION_TYPE_WINDOWS_IAT            = 12,
    // Windows PE - Delay Load Import Descriptors
    SECTION_TYPE_WINDOWS_DELAY_IMPORT   = 13,
    // Windows PE - CLI Header with directories for runtime data (::COM)
    SECTION_TYPE_WINDOWS_CLI_HEADER     = 14,
    // Reserved
    SECTION_TYPE_WINDOWS_RESERVED       = 15
};

#endif // __TBA_PE_SECTIONTYPES_H
