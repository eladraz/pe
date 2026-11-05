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

#ifndef __TBA_STL_PE_NT_DIRECTORY_IMPORT_H
#define __TBA_STL_PE_NT_DIRECTORY_IMPORT_H

/*
 * ntDirImport.h
 *
 * Operation over PE import table (IMAGE_DIRECTORY_ENTRY_IMPORT).
 *
 * The parser works for both PE32 (4 byte thunks) and PE32+ (8 byte thunks).
 * Every RVA is translated through the section table and bounds-checked; a
 * malformed import table throws cException.
 */
#include "xStl/types.h"
#include "xStl/data/list.h"
#include "xStl/data/string.h"
#include "pe/ntdir.h"
#include "pe/ntheader.h"

/*
 * Reads the import directory of a PE image.
 */
class cNtDirImport : public cNtDirectory {
public:
    /*
     * One imported symbol of a module.
     */
    struct Entry {
        // The name of the symbol. Empty when the symbol is imported by ordinal
        cString name;
        // The hint (name table index) of the symbol. 0 when imported by ordinal
        uint16 hint;
        // True if the symbol is imported by ordinal number
        bool byOrdinal;
        // The ordinal number. Valid only if byOrdinal is true
        uint16 ordinal;
        // The RVA of the IAT slot which receives the resolved address
        uint32 iatRva;
    };

    /*
     * One imported module (DLL) and the symbols imported from it.
     */
    struct Module {
        // The name of the DLL, e.g. "msvcrt.dll"
        cString name;
        // All the symbols imported from this module
        cList<Entry> entries;
    };

    /*
     * Default constructor. Creates an empty import table.
     */
    cNtDirImport();

    /*
     * Read the import directory from a PE image.
     *
     * header - The NT-header descriptor of the PE file.
     *
     * Throw cException if the import table is malformed.
     */
    cNtDirImport(const cNtHeader& header);

    /*
     * See cNtDirectory::isMyDir
     * Return true on the IMAGE_DIRECTORY_ENTRY_IMPORT
     */
    virtual bool isMyDir(uint directoryTypeIndex);

    /*
     * See cNtDirectory::readDirectory
     *
     * An image without an import directory yields an empty module list.
     */
    virtual void readDirectory(const cNtHeader& image,
                               uint directoryTypeIndex = UNKNOWNDIR);

    /*
     * Returns the imported modules, in the order of the import descriptors.
     */
    const cList<Module>& getModules() const;

private:
    // Deny copy-constructor and operator =
    cNtDirImport(const cNtDirImport& other);
    cNtDirImport& operator = (const cNtDirImport& other);

    // The imported modules
    cList<Module> m_modules;
};

#endif // __TBA_STL_PE_NT_DIRECTORY_IMPORT_H
