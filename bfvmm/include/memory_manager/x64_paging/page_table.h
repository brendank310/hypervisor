//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef PAGE_TABLE_H
#define PAGE_TABLE_H

#include <stdint.h>
#include <memory.h>

class page_table
{
public:

    /// Page Default Constructor
    ///
    /// Creates an empty, invalid page
    ///
    page_table();

    /// Valid Page Constructor
    ///
    /// If given the correct values, creates a valid page
    ///
    /// @param size the number of entries in the page table
    ///
    page_table(uint64_t size);

    /// Page Destructor
    ///
    virtual ~page_table();

    /// Add entry
    ///
    /// @return true if the entry could be added to the table
    ///
    virtual bool add_entry(void *physical_address, void *virtual_address);

    /// Remove entry
    ///
    /// @return true if the entry was in the table, and was removed
    ///
    virtual bool remove_entry(void *virtual_address);

    /// Allocate Page
    ///
    /// Changes the page's is_allocated() status to true
    ///
    virtual void allocate();

    /// size
    ///
    /// @return the number of entries in the page table
    ///
    virtual uint64_t size() const;

    /// Page Copy Constructor
    ///
    page_table(const page_table &other);

    /// Page Equal Operator
    ///
    void operator=(const page &other);

private:
    page m_mem;
    uint64_t m_size;

    uint64_t m_page_table_mask;

    bool m_allocated;
};

#endif
