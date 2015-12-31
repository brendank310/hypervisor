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

#include <memory_manager/x64_paging/page_table_x64.h>

page_table_x64::page_table_x64()
{
    uint16_t entry = 0;

    // Allocate the top level page table
    m_pml4 = (uint64_t*)mm()->malloc_aligned(4096, 4096);


    for(int entry = 0; entry < PAGE_X64_LIMIT; entry++)
    {
        m_pml4[entry] = 0x00;
    }
}

page_table_x64::~page_table_x64()
{
	// Cleanup the page tables? if this were a proper 
	// object I might be inclined to agree, but this is
	// a controller
}

bool page_table_x64::add_entry(void *physical_address, void *virtual_address)
{
    uint8_t order = 0;
    bool rc = true;

    rc = add_entry_to_table(physical_address, virtual_address, order);

    if(rc == false)
    {
        // Failed to add the page table entry for the pair,
        // likely because we're out of pages to complete the mapping
    }

    return rc;
}

bool page_table_x64::remove_entry(void *virtual_address)
{
	return false;
}

uint64_t *page_table_x64::pml4()
{
    return m_pml4;
}

uint64_t *page_table_x64::pdp(void *virtual_address)
{
    uint64_t pml4_entry = (uint64_t)pml4()[PML4_OFFSET(virtual_address)];

    pml4_entry &= PAGE_FLAG_MASK;

    return (uint64_t*)mm()->phys_to_virt((void*)pml4_entry);
}

uint64_t *page_table_x64::pgd(void *virtual_address)
{
    uint64_t pdp_entry = (uint64_t)pdp(virtual_address)[PDP_OFFSET(virtual_address)];

    pdp_entry &= PAGE_FLAG_MASK;

    return (uint64_t*)mm()->phys_to_virt((void*)pdp_entry);
}

uint64_t *page_table_x64::pt(void *virtual_address)
{
    uint64_t pgd_entry = (uint64_t)pgd(virtual_address)[PGD_OFFSET(virtual_address)];

    pgd_entry &= PAGE_FLAG_MASK;

    return (uint64_t*)mm()->phys_to_virt((void*)pgd_entry);
}

bool page_table_x64::add_table_entry_generic(uint64_t *table, void *phys_addr, void *virt_addr, uint16_t offset)
{
    if((table[offset] & PAGE_PRESET_FLAG) == 0)
    {
        uint64_t *new_table = (uint64_t*)mm()->malloc_aligned(4096, 4096);

        if(new_table == NULL)
        {
            return false;
        }

        table[offset] = (uint64_t)(uint64_t*)mm()->virt_to_phys(new_table);
        table[offset] |= PAGE_PRESET_FLAG;
    }

    return true;
}

bool page_table_x64::add_pml4_entry(void *physical_address, void *virtual_address)
{
    uint16_t pml4_offset = PML4_OFFSET(virtual_address);

    if(pml4_offset == PML4_RECURSIVE_ENTRY)
    {
        // Reserved for future recursive mapping implementation
        return false;
    }

    return add_table_entry_generic(pml4(), physical_address, virtual_address, pml4_offset);
}

bool page_table_x64::add_pdp_entry(void *physical_address, void *virtual_address)
{
    uint16_t pdp_offset = PDP_OFFSET(virtual_address);
    
    return add_table_entry_generic(pdp(virtual_address), physical_address, virtual_address, pdp_offset);
}

bool page_table_x64::add_pgd_entry(void *physical_address, void *virtual_address)
{
    uint16_t pgd_offset = PGD_OFFSET(virtual_address);

    return add_table_entry_generic(pgd(virtual_address), physical_address, virtual_address, pgd_offset);
}

bool page_table_x64::add_pt_entry(void *physical_address, void *virtual_address)
{
    uint16_t pt_offset = PT_OFFSET(virtual_address);

    return add_table_entry_generic(pt(virtual_address), physical_address, virtual_address, pt_offset);
}

bool page_table_x64::add_entry_to_table(void *physical_address, void *virtual_address, uint8_t order)
{
    bool rc = false;

    rc = add_pml4_entry(physical_address, virtual_address);
    rc &= add_pdp_entry(physical_address, virtual_address);
    rc &= add_pgd_entry(physical_address, virtual_address);
    rc &= add_pt_entry(physical_address, virtual_address);

    return rc;
}
