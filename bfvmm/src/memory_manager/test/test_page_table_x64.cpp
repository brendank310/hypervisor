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
    memory_manager mm;
    void *p_pml4 = malloc(4096);
    void *p_pdp = malloc(4096);
    void *p_pgd = malloc(4096);
    void *p_pt = malloc(4096);

    void *p_page = malloc(4096);

    page pml4((void*)0xdeadbeef00, p_pml4, MAX_PAGES);
    page pdp((void*)0xdeadbeef01, p_pdp, MAX_PAGES);
    page pgd((void*)0xdeadbeef02, p_pgd, MAX_PAGES);
    page pt((void*)0xdeadbeef03, p_pt, MAX_PAGES);

    mm.add_page(pml4);
    mm.add_page(pdp);
    mm.add_page(pgd);
    mm.add_page(pt);

    uint16_t i = 0;

    for(i = 0; i < 32; i++)
    {
        void *p_tmp = malloc(4096);
    
        page tmp((void*)(0xdeadbeef06+i), p_tmp, MAX_PAGES);

        mm.add_page(tmp);
    }

    page_table_x64 *pager = new page_table_x64(&mm);

    pager->add_entry((void*)0xff8fdeadbeefdead, p_page);

    pager->dump_pml4_table();
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

void page_table_x64_ut::test_add_address_pdp_alloc_fail()
{

}

void page_table_x64_ut::test_add_address_pdp_alloc_success()
{

}

void page_table_x64_ut::test_add_address_pgd_alloc_fail()
{

}

void page_table_x64_ut::test_add_address_pgd_alloc_success()
{

}

void page_table_x64_ut::test_add_address_pt_alloc_fail()
{

}

void page_table_x64_ut::test_add_address_pt_alloc_success()
{

}

