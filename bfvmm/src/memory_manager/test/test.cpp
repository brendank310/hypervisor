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

#include <test.h>

memory_manager_ut::memory_manager_ut()
{
}

bool
memory_manager_ut::init()
{
    return true;
}

bool
memory_manager_ut::fini()
{
    return true;
}

bool
memory_manager_ut::list()
{
    this->test_memory_manager_malloc_zero();
    this->test_memory_manager_malloc_valid();
    this->test_memory_manager_multiple_malloc_should_be_contiguous();
    this->test_memory_manager_malloc_free_malloc();
    this->test_memory_manager_malloc_page_is_page_aligned();
    this->test_memory_manager_free_zero();
    this->test_memory_manager_free_random();
    this->test_memory_manager_free_twice();
    this->test_memory_manager_malloc_all_of_memory();
    this->test_memory_manager_malloc_all_of_memory_fragmented();
    this->test_memory_manager_malloc_aligned_ignored_alignment();
    this->test_memory_manager_malloc_aligned();
    this->test_memory_manager_malloc_alloc_fragment();

    return true;
}

#include <test_page_table_x64.h>

page_table_x64_ut::page_table_x64_ut()
{

}

bool
page_table_x64_ut::init()
{
   return true;
}

bool
page_table_x64_ut::fini()
{
   return true;
}

bool
page_table_x64_ut::list()
{
    this->test_add_non_canonical_address();
    this->test_add_canonical_address();

    this->test_add_address_pml4_alloc_fail();
    this->test_add_address_pml4_alloc_success();
    this->test_add_address_pml4_pdp_alloced();
    this->test_add_address_pml4_pdp_unalloced();

    this->test_add_address_pdp_alloc_fail();
    this->test_add_address_pdp_alloc_success();
    this->test_add_address_pdp_pgd_alloced();
    this->test_add_address_pdp_pgd_unalloced();

    this->test_add_address_pgd_alloc_fail();
    this->test_add_address_pgd_alloc_success();
    this->test_add_address_pgd_pt_alloced();
    this->test_add_address_pgd_pt_unalloced();

    this->test_add_address_pt_alloc_fail();
    this->test_add_address_pt_alloc_success();
    this->test_add_address_alloced();
    this->test_add_address_unalloced();
    
    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(page_table_x64_ut);
}
