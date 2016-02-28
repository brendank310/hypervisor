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

#include <memory_manager/memory_manager.h>
#include <memory_manager/x64_paging/page_table_x64.h>

page_table_x64::page_table_x64() : m_pml4(NULL)
{
}

page_table_x64::~page_table_x64()
{
    // Cleanup the page tables? if this were a proper 
    // object I might be inclined to agree, but this is
    // a controller
}

bool page_table_x64::add_entry(void *physical_address, void *virtual_address)
{
    bool rc = true;

    // Allocate the top level page table
    if(!m_pml4)
        {
            m_pml4 = (uint64_t*)memory_manager::instance()->malloc_aligned(4096, 4096);
            scrub_page_table(&m_pml4);
        }

    rc = add_entry_to_table(physical_address, virtual_address);

    if(rc == false)
    {
        // Failed to add the page table entry for the pair,
        // likely because we're out of pages to complete the mapping
    }

    return rc;
}

bool page_table_x64::remove_entry(void *virtual_address)
{
    (void)virtual_address;
    return false;
}

void page_table_x64::dump_page_table(void *virtual_address, uint8_t level)
{
    int entry = 0;
    uint64_t *table = NULL;

    switch(level)
    {
        case 3:
        {
            // pml4 (top level)
            table = pml4();
            break;
        }
        case 2:
        {
            // pml4 (top level)
            table = pdp(virtual_address, false);
            break;
        }
        case 1:
        {
            // pml4 (top level)
            table = pgd(virtual_address, false);
            break;
        }
        case 0:
        {
            // pml4 (top level)
            table = pt(virtual_address, false);
            break;
        }
        default:
        {
            std::cout << "Tried to dump invalid page table level... Bailing." << std::endl;
            return;
        }
    }

    if(table == NULL)
    {
        std::cout << "Couldn't locate page table to dump." << std::endl;
        return;
    }

    std::cout << std::hex; 
    for(entry = 0; entry < PAGE_X64_LIMIT; entry++)
    {
        if(table[entry] != 0)
        {
            switch(level)
            {
                case 3:
                    std::cout << std::endl << "+-----+--------------------+" << std::endl;
                    break;
                case 2:
                    std::cout << std::endl << "                           " << "+-----+--------------------+" << std::endl << "                           ";
                    break;
                case 1:
                    std::cout << std::endl << "                           " << "                           " << "+-----+--------------------+" << std::endl << "                           " << "                           ";
                    break;
                case 0:
                    std::cout << std::endl << "                           " << "                           " << "                           ";
                    break;
            }

            print_pte(entry, table[entry]);

            if((table[entry] & PAGE_PRESET_FLAG) && level != 0)
            {
                std::cout << std::endl;
                switch(level)
                {
                    case 3:
                        break;
                    case 2:
                        std::cout << "                           ";
                        break;
                    case 1:
                        std::cout << "                           " << "                           ";
                        break;
                    case 0:
                        std::cout << "                           " << "                           " << "                           ";
                        break;
                }

                std::cout << "+-----+--------------------+";
                dump_page_table(virtual_address, level-1);
            }
            else if(level != 0)
            {
                std::cout << std::endl;
            }

            switch(level)
            {
                case 3:
                    break;
                case 2:
                    std::cout << "                            ";
                    break;
                case 1:
                    std::cout  << "                            " << "                            ";
                    break;
                case 0:
                    break;
            }
        }
    }

    if(level == 0)
    {
        std::cout << std::dec << std::endl;
    }
}

void page_table_x64::print_pte(uint64_t index, uint64_t entry)
{
    std::cout << "|    ";
    if(index == 0) std::cout << '\b';
    for(int i = index; i != 0; i /= 10)
    {
        std::cout << '\b';
    }

    std::cout << std::dec;
    std::cout << index << " |                 ";
    std::cout << std::hex;

    for(uint64_t i = entry; i != 0; i /= 16)
    {
        std::cout << '\b';
    }

    std::cout << "0x" << entry << " |";
}

void page_table_x64::dump_page_tables(void *virt)
{
    this->dump_page_table(virt, 3);
}

void page_table_x64::scrub_page_table(uint64_t **page_table)
{
    uint64_t *pt = *page_table;

    for(int i = 0; i < 512; i++)
    {
        pt[i] = 0;
    }
}

uint64_t *page_table_x64::pml4()
{
    return m_pml4;
}

uint64_t page_table_x64::pml4_entry(void *virt_addr)
{
    uint64_t l_pml4_entry = pml4()[PML4_OFFSET(virt_addr)];

    return l_pml4_entry;
}

uint64_t *page_table_x64::pdp(void *virtual_address, bool alloc)
{
    uint64_t entry = pml4_entry(virtual_address);

    if((entry & PAGE_PRESET_FLAG) == 0 && alloc)
    {
        uint64_t *new_table = (uint64_t*)memory_manager::instance()->malloc_aligned(4096, 4096);

        if(new_table == NULL)
        {
            return NULL;
        }

        scrub_page_table(&new_table);

        pml4()[PML4_OFFSET(virtual_address)] = (uint64_t)memory_manager::instance()->virt_to_phys(new_table);
        pml4()[PML4_OFFSET(virtual_address)] |= PAGE_PRESET_FLAG;

        return new_table;
    }

    entry &= ~PAGE_PRESET_FLAG;

    return (uint64_t*)memory_manager::instance()->phys_to_virt((void*)entry);
}

uint64_t page_table_x64::pdp_entry(void* virt_addr)
{
    uint64_t l_pdp_entry = pdp(virt_addr)[PDP_OFFSET(virt_addr)];

    return l_pdp_entry;
}

uint64_t *page_table_x64::pgd(void *virtual_address, bool alloc)
{
    uint64_t entry = pdp_entry(virtual_address);

    if((entry & PAGE_PRESET_FLAG) == 0 && alloc)
    {
        uint64_t *new_table = (uint64_t*)memory_manager::instance()->malloc_aligned(4096, 4096);

        if(new_table == NULL)
        {
            return NULL;
        }

        scrub_page_table(&new_table);

        pdp(virtual_address)[PDP_OFFSET(virtual_address)] = (uint64_t)memory_manager::instance()->virt_to_phys(new_table);
        pdp(virtual_address)[PDP_OFFSET(virtual_address)] |= PAGE_PRESET_FLAG;

        return new_table;
    }

    entry &= ~PAGE_PRESET_FLAG;

    return (uint64_t*)memory_manager::instance()->phys_to_virt((void*)entry);
}

uint64_t page_table_x64::pgd_entry(void* virt_addr)
{
    uint64_t l_pgd_entry = pgd(virt_addr)[PGD_OFFSET(virt_addr)];

    return l_pgd_entry;
}

uint64_t *page_table_x64::pt(void *virtual_address, bool alloc)
{
    uint64_t pgd_entry = pgd(virtual_address)[PGD_OFFSET(virtual_address)];

    if((pgd_entry & PAGE_PRESET_FLAG) == 0 && alloc)
    {
        uint64_t *new_table = (uint64_t*)memory_manager::instance()->malloc_aligned(4096, 4096);

        if(new_table == NULL)
        {
            return NULL;
        }

        scrub_page_table(&new_table);

        pgd(virtual_address)[PGD_OFFSET(virtual_address)] = (uint64_t)memory_manager::instance()->virt_to_phys(new_table);
        pgd(virtual_address)[PGD_OFFSET(virtual_address)] |= PAGE_PRESET_FLAG;

        return new_table;
    }

    pgd_entry &= ~PAGE_PRESET_FLAG;

    return (uint64_t*)memory_manager::instance()->phys_to_virt((void*)pgd_entry);
}

bool page_table_x64::add_table_entry_generic(uint64_t *table, void *phys_addr, uint16_t offset)
{
    table[offset] = (uint64_t)phys_addr;
    table[offset] |= PAGE_PRESET_FLAG;;

    return true;
}

bool page_table_x64::add_pdp_entry(void *physical_address, void *virtual_address)
{
    uint16_t pdp_offset = PDP_OFFSET(virtual_address);

    return add_table_entry_generic(pdp(virtual_address), physical_address, pdp_offset);
}

bool page_table_x64::add_pgd_entry(void *physical_address, void *virtual_address)
{
    uint16_t pgd_offset = PGD_OFFSET(virtual_address);

    return add_table_entry_generic(pgd(virtual_address), physical_address, pgd_offset);
}

bool page_table_x64::add_pt_entry(void *physical_address, void *virtual_address)
{
    uint16_t pt_offset = PT_OFFSET(virtual_address);

    return add_table_entry_generic(pt(virtual_address), physical_address, pt_offset);
}

bool page_table_x64::add_entry_to_table(void *physical_address, void *virtual_address)
{
    bool rc = false;

    if(virtual_address == 0) std::cout << "Someone is trying to map provide a mapping to the NULL pointer" << std::endl;
    
    rc = add_pt_entry(physical_address, virtual_address);

    return rc;
}