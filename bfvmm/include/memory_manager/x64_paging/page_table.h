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

    /// size
    ///
    /// @return the number of entries in the page table
    ///
    virtual uint64_t size() const;

protected:

    /// The physical addresses of the tables themselves
    ///
    void *m_phys_table;

    /// The virtual address of the page table 
    /// 
    void *m_virt_table;

    /// Entry size
    ///
    uint64_t m_size;

    /// Address mask of this page table level
    ///
    uint64_t m_page_table_mask;

    /// Shift of the page table level
    ///
    uint32_t m_page_table_shift;
};

#endif
