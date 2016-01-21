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
 * humanStringTranslation.cpp
 *
 * Implementation file
 *
 * Author: Elad Raz <e@eladraz.com>
 */
#include "xStl/types.h"
#include "xStl/data/string.h"
#include "xStl/except/exception.h"
#include "xStl/except/trace.h"
#include "pe/datastruct.h"
#include "pe/humanStringTranslation.h"

#ifdef PE_TRACE
/*
 * An array of strings which describes each Data directory.
 */
const char* OPTINAL_HEADER_DATA_DIRECTORIES_NAME[] = {
    "IMAGE_DIRECTORY_ENTRY_EXPORT",
    "IMAGE_DIRECTORY_ENTRY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_RESOURCE",
    "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
    "IMAGE_DIRECTORY_ENTRY_SECURITY",
    "IMAGE_DIRECTORY_ENTRY_BASERELOC",
    "IMAGE_DIRECTORY_ENTRY_DEBUG",
    "IMAGE_DIRECTORY_ENTRY_COPYRIGHT",
    "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE",
    "IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
    "IMAGE_DIRECTORY_ENTRY_TLS",
    "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
    "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_IAT",
    "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_CLI_HEADER",
    "IMAGE_DIRECTORY_ENTRY_RESERVED"
};

// Description of the SECTION's type for debugging information
const char* SECTION_TYPE_STRINGS[] = {"Windows Export",
                                      "Windows Import",
                                      "Windows Resource",
                                      "Windows Exception",
                                      "Windows Security",
                                      "Windows Relocation Table",
                                      "Windows Debug information",
                                      "Windows architecture",
                                      "Windows Global Pointer",
                                      "Windows ThreadLocalStorage (TLS)",
                                      "Windows Load configuration Dir",
                                      "Windows Bound Import directory",
                                      "Windows Address Table (IAT)",
                                      "Windows Delay Import Table",
                                      "Windows CLI Header",
                                      "Windows reserved section",
                                      "Windows CODE",
                                      "DOS code section",
                                      "DOS data section",
                                      "DOS stack section",
                                      "Unknown"
};

cString cHumanStringTranslation::getSectionTypeName(const SectionType& type)
{
    if ((type < 0) || (type >= arraysize(SECTION_TYPE_STRINGS)))
        XSTL_THROW(cException, EXCEPTION_OUT_OF_RANGE);

    return cString(SECTION_TYPE_STRINGS[type]);
}

cString cHumanStringTranslation::getWindowsDirectoryName(uint dir)
{
    if (dir >= arraysize(OPTINAL_HEADER_DATA_DIRECTORIES_NAME))
        XSTL_THROW(cException, EXCEPTION_OUT_OF_RANGE);

    return cString(OPTINAL_HEADER_DATA_DIRECTORIES_NAME[dir]);
}

cString cHumanStringTranslation::getWindowsImageFileCharacter(uint bitwise)
{
    if (bitwise & IMAGE_FILE_RELOCS_STRIPPED)
        return "IMAGE_FILE_RELOCS_STRIPPED";

    if (bitwise & IMAGE_FILE_EXECUTABLE_IMAGE)
        return "IMAGE_FILE_EXECUTABLE_IMAGE";

    if (bitwise & IMAGE_FILE_LINE_NUMS_STRIPPED)
        return "IMAGE_FILE_LINE_NUMS_STRIPPED";

    if (bitwise & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
        return "IMAGE_FILE_LOCAL_SYMS_STRIPPED";

    if (bitwise & IMAGE_FILE_AGGRESIVE_WS_TRIM)
        return "IMAGE_FILE_AGGRESIVE_WS_TRIM";

    if (bitwise & IMAGE_FILE_LARGE_ADDRESS_AWARE)
        return "IMAGE_FILE_LARGE_ADDRESS_AWARE";

    if (bitwise & IMAGE_FILE_BYTES_REVERSED_LO)
        return "IMAGE_FILE_BYTES_REVERSED_LO";

    if (bitwise & IMAGE_FILE_32BIT_MACHINE)
        return "IMAGE_FILE_32BIT_MACHINE";

    if (bitwise & IMAGE_FILE_DEBUG_STRIPPED)
        return "IMAGE_FILE_DEBUG_STRIPPED";

    if (bitwise & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
        return "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP";

    if (bitwise & IMAGE_FILE_NET_RUN_FROM_SWAP)
        return "IMAGE_FILE_NET_RUN_FROM_SWAP";

    if (bitwise & IMAGE_FILE_SYSTEM)
        return "IMAGE_FILE_SYSTEM";

    if (bitwise & IMAGE_FILE_DLL)
        return "IMAGE_FILE_DLL";

    if (bitwise & IMAGE_FILE_UP_SYSTEM_ONLY)
        return "IMAGE_FILE_UP_SYSTEM_ONLY";

    if (bitwise & IMAGE_FILE_BYTES_REVERSED_HI)
        return "IMAGE_FILE_BYTES_REVERSED_HI";

    return "";
}

#else // PE_TRACE

    static const char gNotCompiledPeTraced[] = "INFORMATION WASN'T COMPILED";

    cString cHumanStringTranslation::getWindowsImageFileCharacter(uint bitwise)
    {
        return gNotCompiledPeTraced;
    }

    cString cHumanStringTranslation::getWindowsDirectoryName(uint dir)
    {
        return gNotCompiledPeTraced;
    }

    cString cHumanStringTranslation::getSectionTypeName(const SectionType& type)
    {
        return gNotCompiledPeTraced;
    }

#endif
