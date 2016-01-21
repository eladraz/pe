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

#ifndef __TBA_PE_HUMANSTRINGTRANSLATION_H
#define __TBA_PE_HUMANSTRINGTRANSLATION_H

/*
 * humanStringTranslation.h
 *
 * All the functions needed in order to translate an internal PE-LIB value into
 * a human readable string.
 *
 * Author: Elad Raz <e@eladraz.com>
 */
#include "xStl/types.h"
#include "xStl/data/string.h"
#include "pe/sectionTypes.h"

/*
 * All the functions needed in order to translate an internal PE-LIB value into
 * a human readable string.
 */
class cHumanStringTranslation {
public:
    /*
     * Return a string descriptor for the section-type object.
     *
     * type - The section's type
     */
    static cString getSectionTypeName(const SectionType& type);

    /*
     * Returns a string represents a character of a image-file.
     *
     * For example getWindowsImageFileCharacter(IMAGE_FILE_RELOCS_STRIPPED) will
     * returned IMAGE_FILE_RELOCS_STRIPPED.
     * Returns empty string for non-exist characters
     */
    static cString getWindowsImageFileCharacter(uint bitwise);

    /*
     * Returns the directory name.
     */
    static cString getWindowsDirectoryName(uint dir);
};

#endif // __TBA_PE_HUMANSTRINGTRANSLATION_H

