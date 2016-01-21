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

#ifndef __TBA_PE_NT_DIR_H
#define __TBA_PE_NT_DIR_H

/*
 * ntdir.h
 *
 * Generic interface for PE image file directory parser.
 *
 * Author: Elad Raz <e@eladraz.com>
 */
#include "xStl/types.h"
#include "xStl/os/virtualMemoryAccesser.h"
#include "pe/ntheader.h"

/*
 * Generic interface for PE image file directory parser.
 *
 * Unlike section, which are fixed memory block inside the memory, the directory
 * object are quite differents. The directory can exist with one or more memory
 * region and can includes likes to other objects in the image. For that, this
 * interface require a complete cNtHeader inorder to parse the directory.
 */
class cNtDirectory {
public:
    /*
     * Default virtual destructor. You can inherit from me.
     */
    virtual ~cNtDirectory() {};

    /*
     * Used in 'readDirectory'. Mark that the default handling directory should
     * be read
     */
    enum { UNKNOWNDIR = 0xFFFFFFFF };

    /*
     * Read the directory from NT PE virtual memory map image
     *
     * image - The memory to read the image from.
     * directoryTypeIndex - The directory index to be accessed
     */
    virtual void readDirectory(const cNtHeader& image,
                               uint directoryTypeIndex = UNKNOWNDIR) = 0;

    /*
     * Return true is a directory at index X can be handle by this class.
     *
     * directoryTypeIndex - The directory index to be accessed
     */
    virtual bool isMyDir(uint directoryTypeIndex) = 0;

    // TODO! Incase of chain-of-responsibilities implementation. add clone() API
};

#endif // __TBA_PE_NT_DIR_H
