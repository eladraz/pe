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

#ifndef __TBA_STL_PE_NT_DIRECTORY_CLI_H
#define __TBA_STL_PE_NT_DIRECTORY_CLI_H

/*
 * ntDirCli.h
 *
 * Operation over PE common-language directory.
 *
 * Author: Elad Raz <e@eladraz.com>
 */
#include "xStl/types.h"
#include "xStl/data/array.h"
#include "xStl/data/list.h"
#include "xStl/data/string.h"
#include "xStl/stream/basicIO.h"
#include "xStl/stream/stringerStream.h"
#include "xStl/stream/memoryAccesserStream.h"
#include "pe/ntdir.h"
#include "pe/section.h"
#include "pe/datastruct.h"
#include "pe/ntheader.h"
#include "coreHeadersTypes.h"

/*
 * Forward deceleration for output streams
 */
#ifdef PE_TRACE
    class cNtDirCli;
    cStringerStream& operator << (cStringerStream& out,
                                  const cNtDirCli& object);
#endif // PE_TRACE

/*
 * Handles the .net section - The Common language header.
 */
class cNtDirCli : public cNtDirectory {
public:
    /*
     * Default constructor.
     */
    cNtDirCli();

    /*
     * Read the .net section from a PE image.
     *
     * header - The NT-header descriptor of the PE file.
     *
     * NOTE: This function extract from the NT-header the location of the CLI
     *       directory and use the auto-generated 'VirtualMemoryAccesser' in
     *       order to access the export directory and extract the information
     *       from
     *
     * Throw exception if the header doesn't contain a reference for the memory
     * of the PE file.
     */
    cNtDirCli(const cNtHeader& header);

    /*
     * See cNtDirectory::isMyDir
     * Return true on the SECTION_TYPE_WINDOWS_CLI_HEADER
     */
    virtual bool isMyDir(uint directoryTypeIndex);

    /*
     * See cNtDirectory::readDirectory
     * See cNtDirectory::cNtDirectory(const cNtHeader&)
     */
    virtual void readDirectory(const cNtHeader& image,
                               uint directoryTypeIndex = UNKNOWNDIR);

    /*
     * Return a pointer to the streamed CLI header memory
     */
    const cMemoryAccesserStreamPtr& getData() const;

    /*
     * Return the parsed core header.
     */
    const IMAGE_COR20_HEADER& getCoreHeader() const;

private:
    // Private members

    // Deny copy-constructor and operator =
    cNtDirCli(const cNtDirCli& other);
    cNtDirCli& operator = (const cNtDirCli& other);

    // The friendly trace
    #ifdef PE_TRACE
    friend cStringerStream& operator << (cStringerStream& out,
                                         const cNtDirCli& object);
    #endif // PE_TRACE

    // The stream pointer to the CLI header
    cMemoryAccesserStreamPtr m_data;

    // The parsed content of the memory.
    IMAGE_COR20_HEADER m_coreHeader;
};

#endif // __TBA_STL_PE_NT_DIRECTORY_CLI_H
