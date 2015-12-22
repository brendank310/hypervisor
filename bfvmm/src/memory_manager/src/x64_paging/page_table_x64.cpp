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

page_table_x64::page_table_x64(memory_manager *memory_manager) : m_memory_manager(memory_manager)
{
    uint16_t entry = 0;

    // Allocate the top level page table
    m_memory_manager->alloc_page(&m_pml4);

    // Allocate the sparse arrays for the 
    // next level page tables
    m_memory_manager->alloc_page(&m_pdp_ptrs);
    m_memory_manager->alloc_page(&m_pgd_ptrs);
    m_memory_manager->alloc_page(&m_pt_ptrs);

    uint64_t *pdp = (uint64_t *)(m_pdp_ptrs.virt_addr());
    uint64_t *pgd = (uint64_t *)(m_pgd_ptrs.virt_addr());
    uint64_t *pt = (uint64_t *)(m_pt_ptrs.virt_addr());

    for(entry = 0; entry < PAGE_X64_LIMIT; entry++)
    {
        pdp[entry] = 0x00;
        pgd[entry] = 0x00;
        pt[entry] = 0x00;
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

bool page_table_x64::add_pml4_entry(void *physical_address, void *virtual_address)
{
    uint16_t pml4_offset = PML4_OFFSET(virtual_address);
    uint64_t *pml4 = (uint64_t *)(m_pml4.virt_addr());
    
    if(pml4_offset == PML4_RECURSIVE_ENTRY)
    {
        // Reserved for future recursive mapping implementation
        return false;
    }

    if(pml4[pml4_offset] & PAGE_PRESET_FLAG)
    {
        // Okay we have a page already allocated for the page
        // directory pointer for this address, so just return 
        // true and let the next level handle the rest
        return true;
    }
    else
    {
        // No next page directory pointer (page? ugh) allocated
        // yet for this address, we need to add one from the 
        // page pool (non-continuous, because why waste those
        // precious continuous pages)

        page new_pdp;

        m_memory_manager->alloc_page(&new_pdp);
        pml4[pml4_offset] = (uint64_t)new_pdp.phys_addr();

        return true;            
    }

}

bool page_table_x64::add_pdp_entry(void *physical_address, void *virtual_address)
{
    uint16_t pml4_offset = PML4_OFFSET(virtual_address);
    uint16_t pdp_offset = PDP_OFFSET(virtual_address);
    
    // In order for this function to get called, the PML4
    // function must have passed, meaning the page for this
    // PDP to exist.
    uint64_t *pml4 = (uint64_t *)(m_pml4.virt_addr());
    uint64_t *pdp = (uint64_t *)(pml4[pml4_offset]);
    
    if(pdp_offset == PDP_RECURSIVE_ENTRY)
    {
        // Reserved for future recursive mapping implementation
        return false;
    }

    if(pdp[pdp_offset] & PAGE_PRESET_FLAG)
    {
        // Okay we have a page already allocated for the page
        // directory pointer for this address, so just return 
        // true and let the next level handle the rest
        return true;
    }
    else
    {
        // No next page directory (page? ugh again) allocated
        // yet for this address, we need to add one from the 
        // page pool (non-continuous, because why waste those
        // precious continuous pages)

        page new_pgd;

        m_memory_manager->alloc_page(&new_pgd);
        pdp[pdp_offset] = (uint64_t)new_pgd.phys_addr();

        return true;            
    }

}

bool page_table_x64::add_pgd_entry(void *physical_address, void *virtual_address)
{
    uint16_t pml4_offset = PML4_OFFSET(virtual_address);
    uint16_t pdp_offset = PDP_OFFSET(virtual_address);
    uint16_t pgd_offset = PGD_OFFSET(virtual_address);
    
    // In order for this function to get called, the PDP
    // function must have passed, meaning the page for this
    // PDP to exist.
    uint64_t *pml4 = (uint64_t *)(m_pml4.virt_addr());
    uint64_t *pdp = (uint64_t *)(pml4[pml4_offset]);
    uint64_t *pgd = (uint64_t *)(pdp[pdp_offset]);

    if(pgd_offset == PDP_RECURSIVE_ENTRY)
    {
        // Reserved for future recursive mapping implementation
        return false;
    }

    if(pgd[pgd_offset] & PAGE_PRESET_FLAG)
    {
        // Okay we have a page already allocated for the page
        // directory for this address, so just return 
        // true and let the next level handle the rest
        return true;
    }
    else
    {
        // No next page directory (page? ugh again) allocated
        // yet for this address, we need to add one from the 
        // page pool (non-continuous, because why waste those
        // precious continuous pages)

        page new_pt;

        m_memory_manager->alloc_page(&new_pt);
        pgd[pgd_offset] = (uint64_t)new_pt.phys_addr();

        return true;            
    }

}

bool page_table_x64::add_pt_entry(void *physical_address, void *virtual_address)
{
    uint16_t pml4_offset = PML4_OFFSET(virtual_address);
    uint16_t pdp_offset = PDP_OFFSET(virtual_address);
    uint16_t pgd_offset = PGD_OFFSET(virtual_address);
    uint16_t pt_offset = PT_OFFSET(virtual_address);
    
    // In order for this function to get called, the PDP
    // function must have passed, meaning the page for this
    // PDP to exist.
    uint64_t *pml4 = (uint64_t *)(m_pml4.virt_addr());
    uint64_t *pdp = (uint64_t *)(pml4[pml4_offset]);
    uint64_t *pgd = (uint64_t *)(pdp[pdp_offset]);
    uint64_t *pt = (uint64_t *)(pgd[pt_offset]);

    if(pt_offset == PDP_RECURSIVE_ENTRY)
    {
        // Reserved for future recursive mapping implementation
        return false;
    }

    if(pt[pt_offset] & PAGE_PRESET_FLAG)
    {
        // Okay we have a page already allocated for the page
        // table for this address, so we should mark the old
        // page as now free... where do we keep this bitmap?g
        pt[pt_offset] = (uint64_t)physical_address;

        return true;
    }
    else
    {
        pt[pt_offset] = (uint64_t)physical_address;
        return true;            
    }

}

bool page_table_x64::add_entry_to_table(void *physical_address, void *virtual_address, uint8_t order)
{
    bool rc = false;

    switch(order)
    {
        case PML4_PT_ORDER:
        {
            rc = add_pml4_entry(physical_address, virtual_address);
            // Intentional fallthrough
        }
        case PDP_PT_ORDER:
        {
            if(rc == false)
            {
                return rc;
            }

            rc = add_pdp_entry(physical_address, virtual_address);
            // Intentional fallthrough
        }
        case PGD_PT_ORDER:
        {
            if(rc == false)
            {
                return rc;
            }
            
            rc = add_pgd_entry(physical_address, virtual_address);
            // Intentional fallthrough
        }
        case PT_PT_ORDER:
        {
            if(rc == false)
            {
                return rc;
            }

            rc = add_pt_entry(physical_address, virtual_address);

            return rc;
            break;
        }
        default:
        {
            // What? only 0-3 are valid
            return false;
            break;
        }
    }
}
