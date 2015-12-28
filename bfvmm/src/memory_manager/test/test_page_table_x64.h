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

#ifndef PAGE_TABLE_X64_UT__H
#define PAGE_TABLE_X64_UT__H

#include <unittest.h>
#include <memory_manager/x64_paging/page_table_x64.h>

class page_table_x64_ut : public unittest
{
public:

    page_table_x64_ut();
    ~page_table_x64_ut() {}

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:
    void test_add_non_canonical_address();
    void test_add_canonical_address();

    void test_add_address_pml4_alloc_fail();
    void test_add_address_pml4_alloc_success();
    void test_add_address_pml4_pdp_alloced();
    void test_add_address_pml4_pdp_unalloced();

    void test_add_address_pdp_alloc_fail();
    void test_add_address_pdp_alloc_success();
    void test_add_address_pdp_pgd_alloced();
    void test_add_address_pdp_pgd_unalloced();

    void test_add_address_pgd_alloc_fail();
    void test_add_address_pgd_alloc_success();
    void test_add_address_pgd_pt_alloced();
    void test_add_address_pgd_pt_unalloced();

    void test_add_address_pt_alloc_fail();
    void test_add_address_pt_alloc_success();
    void test_add_address_alloced();
    void test_add_address_unalloced();
};

#endif
