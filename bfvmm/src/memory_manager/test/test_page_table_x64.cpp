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

#include <test_page_table_x64.h>

void page_table_x64_ut::test_add_non_canonical_address()
{
    page_table_x64 pager;

    void *virt_addr, *phys_addr;
    void *virt_addr_old = 0;

    for(int i = 0; i < 513; i++)
    {
        //virt_addr = phys_addr = g_mm->malloc_aligned(4096, 4096);

        //pager.add_entry(phys_addr, virt_addr);
        //if(virt_addr_old != 0 && pager.pgd_entry(virt_addr_old) != pager.pgd_entry(virt_addr))
        //{
        //    pager.dump_page_tables(virt_addr_old);
        //}

        //virt_addr_old = virt_addr;
        // g_mm->free(virt_addr);
    }

    //pager.dump_page_tables(virt_addr);
}

void page_table_x64_ut::test_add_canonical_address()
{

}

void page_table_x64_ut::test_add_address_pml4_alloc_fail()
{

}

void page_table_x64_ut::test_add_address_pml4_alloc_success()
{

}

void page_table_x64_ut::test_add_address_pml4_pdp_alloced()
{

}

void page_table_x64_ut::test_add_address_pml4_pdp_unalloced()
{

}


void page_table_x64_ut::test_add_address_pdp_alloc_fail()
{

}

void page_table_x64_ut::test_add_address_pdp_alloc_success()
{

}

void page_table_x64_ut::test_add_address_pdp_pgd_alloced()
{

}

void page_table_x64_ut::test_add_address_pdp_pgd_unalloced()
{

}


void page_table_x64_ut::test_add_address_pgd_alloc_fail()
{

}

void page_table_x64_ut::test_add_address_pgd_alloc_success()
{

}

void page_table_x64_ut::test_add_address_pgd_pt_alloced()
{

}

void page_table_x64_ut::test_add_address_pgd_pt_unalloced()
{

}


void page_table_x64_ut::test_add_address_pt_alloc_fail()
{

}

void page_table_x64_ut::test_add_address_pt_alloc_success()
{

}

void page_table_x64_ut::test_add_address_alloced()
{

}

void page_table_x64_ut::test_add_address_unalloced()
{

}
