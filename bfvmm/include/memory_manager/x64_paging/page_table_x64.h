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
#include <memory_manager/memory_manager.h>
#include <memory_manager/x64_paging/page_table.h>

#define PAGE_PRESET_FLAG            (1<<0)
#define PAGE_RW_FLAG                (1<<1)
#define PAGE_USERSPACE_FLAG         (1<<2)
#define PAGE_WRITE_THROUGH_FLAG     (1<<3)
#define PAGE_CACHE_DISABLED_FLAG    (1<<4)
#define PAGE_ACCESSED_FLAG          (1<<5)
#define PAGE_RESERVED_FLAG          (1<<6)
#define PAGE_SIZE_FLAG              (1<<7)

#define X64_PAGE_ENTRY_ORDER (9)
#define PAGE_X64_LIMIT (1<<X64_PAGE_ENTRY_ORDER)

#define PML4_MASK       (0xFF80000000000000)
#define PML4_SHIFT      (55)
#define PML4_OFFSET(x)     (((uint64_t)x & PML4_MASK) >> PML4_SHIFT)
#define PML4_RECURSIVE_ENTRY    (PAGE_X64_LIMIT - 1)

#define PDP_MASK        (PML4_MASK >> X64_PAGE_ENTRY_ORDER)
#define PDP_SHIFT       (PML4_SHIFT - X64_PAGE_ENTRY_ORDER)
#define PDP_OFFSET(x)   (((uint64_t)x&PDP_MASK)>>PDP_SHIFT)
#define PDP_RECURSIVE_ENTRY (PAGE_X64_LIMIT - 1)

#define PGD_MASK        (PDP_MASK >> X64_PAGE_ENTRY_ORDER)
#define PGD_SHIFT       (PDP_SHIFT - X64_PAGE_ENTRY_ORDER)
#define PGD_OFFSET(x)   (((uint64_t)x & PGD_MASK) >> PGD_SHIFT)
#define PGD_RECURSIVE_ENTRY (PAGE_X64_LIMIT - 1)

#define PT_MASK        (PGD_MASK >> X64_PAGE_ENTRY_ORDER)
#define PT_SHIFT       (PGD_SHIFT - X64_PAGE_ENTRY_ORDER)
#define PT_OFFSET(x)   (((uint64_t)x & PT_MASK) >> PT_SHIFT)
#define PT_RECURSIVE_ENTRY (PAGE_X64_LIMIT - 1)

#define PML4_PT_ORDER   0
#define PDP_PT_ORDER    1
#define PGD_PT_ORDER    2
#define PT_PT_ORDER     3

// Originally I was going to go down the route of having
// a different (albeit simple) class for each level of 
// 64bit x64 page tables, but having a class (with its storage)
// and the actual page table allocation was going to be excessive,
// not to mention redundant. So the control of each level of the
// page tables will be contained within this class, to minimize
// excess storage requirements. It may make sense in the future,
// when all the chicken and egg problems are sorted out to return
// to having each level having a class. There's a good chance that
// commonalities exist between the page tables for the VMM and 
// the mechanisms required for proper EPT support, but that can
// happen in a refactor when EPT support is added. Also of note,
// recursive page tables would likely be desirable, and the last
// page of the top level page table is reserved for such a purpose.

class page_table_x64
{

public:

    /// Page table x64 Constructor
    ///
    /// Creates an empty, invalid page
    ///
    page_table_x64(memory_manager *memory_manager);

    /// Page Destructor
    ///
    virtual ~page_table_x64();

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

private:

    bool add_pml4_entry(void *physical_address, void *virtual_address);

    bool add_pdp_entry(void *physical_address, void *virtual_address);

    bool add_pgd_entry(void *physical_address, void *virtual_address);

    bool add_pt_entry(void *physical_address, void *virtual_address);

    // Add an entry to the page table at level order
    // @param physical_address Address of the physical page that will be addressed
    // @param virtual_address Virtual address that will used to address the physical_page
    // @param order The level of page table to add the record to
    //              0 - Primary page table (x64 it's the pml4)
    //              1 - Secondary page table (x64 it's the page directory pointer (pdp))
    //              2 - Tertiary page table (x64 it's the page diretory (pgd))
    //              3 - Quaternary page table (x64 it's the page table (pt))
    bool add_entry_to_table(void *physical_address, void *virtual_address, uint8_t order);

    memory_manager *m_memory_manager;

    // This is the PML4 storage (Top level page table)
    page m_pml4;

    // These are sparse storage arrays to the actual
    // page tables for each level
    page m_pdp_ptrs;
    page m_pgd_ptrs;
    page m_pt_ptrs;
};

#endif
