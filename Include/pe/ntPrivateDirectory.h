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

#ifndef __TBA_PE_NT_PRIVATEDITECTORY_H
#define __TBA_PE_NT_PRIVATEDITECTORY_H

/*
 * ntPrivateDirectory.h
 *
 * The NT private directory responsible to extract a single custom portion from
 * the PE file as give the user it's stream
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

/*
 * Forward deceleration for output streams
 */
#ifdef PE_TRACE
class cNtPrivateDirectory;
cStringerStream& operator << (cStringerStream& out,
                              const cNtPrivateDirectory& object);
#endif // PE_TRACE

/*
 * The NT-private directory takes a PE file and IMAGE_DATA_DIRECTORY struct
 * (which contains the virtual-start address and size of a directory) and
 * extract this information as cMemoryAccesserStreamPtr stream.
 */
class cNtPrivateDirectory {
public:
    /*
     * Read a custom directory from the PE file
     *
     * header - The PE file.
     * directory - The directory to be load
     */
    cNtPrivateDirectory(const cNtHeader& image,
                        const IMAGE_DATA_DIRECTORY& directory);

    /*
     * Return a pointer to the streamed memory
     */
    const cMemoryAccesserStreamPtr& getData() const;

    /*
     * Return the directory
     */
    const IMAGE_DATA_DIRECTORY& getDirectory() const;

private:
    // Private members

    // Deny copy-constructor and operator =
    cNtPrivateDirectory(const cNtPrivateDirectory& other);
    cNtPrivateDirectory& operator = (const cNtPrivateDirectory& other);

    // The friendly trace
    friend cStringerStream& operator << (cStringerStream& out,
                                         const cNtPrivateDirectory& object);

    // The stream pointer to the directory
    cMemoryAccesserStreamPtr m_data;

    // The cached directory
    IMAGE_DATA_DIRECTORY m_directory;
};

#endif // __TBA_PE_NT_PRIVATEDITECTORY_H
