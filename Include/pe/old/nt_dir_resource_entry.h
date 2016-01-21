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

#ifndef __TBA_STL_RESOURCE_DIRECTORY_ENTRY_H
#define __TBA_STL_RESOURCE_DIRECTORY_ENTRY_H

/*
 * nt_dir_resource_entry.h
 *
 * Declare the class cImageResourceEntry
 * which store the information about the
 * resource.
 */

#include "../string.h"
#include "../types.h"
#include "../array.h"

/*
 * class cImageResourceEntry
 *
 * Store the name of the resource (ID, Text)
 * and also the data (cStream) of the code.
 *
 * Author: Elad Raz <e@eladraz.com>
 */
class cImageResourceEntry
{
public:
    cImageResourceEntry() { m_is_named = FALSE; m_id = 0; };
    cImageResourceEntry(cString name, cStream data) { m_text = name; m_data = data; m_is_named = TRUE;  };
    cImageResourceEntry(DWORD   id,   cStream data) { m_id = id;     m_data = data; m_is_named = FALSE; };
    ~cImageResourceEntry() {};


    /* Getting / Changing the content of the resource entity */
    BOOL isNamed()                    { return m_is_named;    }
    BOOL setName(BOOL isNamed = TRUE) { m_is_named = isNamed; }


    DWORD      get_id()   { return m_id;   }
    cString &  get_name() { return m_text; }
    cStream &  get_data() { return m_data; }

    void set_id  (DWORD   id)   { m_id = id;     }
    void set_name(cString text) { m_text = text; }
    void set_data(cStream data) { m_data = data; }

    /*
     * Copy constructor and operator = is the default:
     *   copy all the members at this class.
     */

private:
    DWORD    m_id;
    cString  m_text;

    BOOL     m_is_named;
    cStream  m_data;
};

#endif
