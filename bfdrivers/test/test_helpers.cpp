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

#include <common.h>
#include <platform.h>
#include <constants.h>
#include <driver_entry_interface.h>

// -----------------------------------------------------------------------------
// Expose Private Functions
// -----------------------------------------------------------------------------

extern "C"
{
    struct module_t *get_module(uint64_t index);
    int64_t symbol_length(const char *sym);
    int64_t resolve_symbol(const char *name, void **sym, struct module_t *module);
    int64_t execute_symbol(const char *sym, int64_t arg);
    int64_t add_md_to_memory_manager(struct module_t *module);

    typedef int64_t (*get_misc_t)(void);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

void
driver_entry_ut::test_helper_common_vmm_status()
{
    EXPECT_TRUE(common_vmm_status() == VMM_UNLOADED);
    EXPECT_TRUE(common_add_module(m_dummy_init_vmm_success, m_dummy_init_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success, m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success, m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success, m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_LOADED);
    EXPECT_TRUE(common_start_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_RUNNING);
    EXPECT_TRUE(common_stop_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_LOADED);
    EXPECT_TRUE(common_unload_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_UNLOADED);
}

void
driver_entry_ut::test_helper_get_file_invalid_index()
{
    EXPECT_TRUE(get_module(10000) == 0);
}

void
driver_entry_ut::test_helper_get_file_success()
{
    EXPECT_TRUE(common_add_module(m_dummy_init_vmm_success, m_dummy_init_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(get_module(0) != 0);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_symbol_length_null_symbol()
{
    EXPECT_TRUE(symbol_length(NULL) == 0);
}

void
driver_entry_ut::test_helper_symbol_length_success()
{
    EXPECT_TRUE(symbol_length("hello world") == 11);
}

void
driver_entry_ut::test_helper_resolve_symbol_invalid_name()
{
    void *sym;

    EXPECT_TRUE(resolve_symbol(0, &sym, 0) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_resolve_symbol_invalid_sym()
{
    EXPECT_TRUE(resolve_symbol("sym", 0, 0) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_resolve_symbol_missing_symbol()
{
    void *sym;

    EXPECT_TRUE(common_add_module(m_dummy_init_vmm_success, m_dummy_init_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success, m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success, m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success, m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(resolve_symbol("invalid_symbol", &sym, 0) == BFELF_ERROR_NO_SUCH_SYMBOL);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_execute_symbol_invalid_arg()
{
    EXPECT_TRUE(execute_symbol(NULL, 0) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_helper_execute_symbol_missing_symbol()
{
    EXPECT_TRUE(common_add_module(m_dummy_init_vmm_success, m_dummy_init_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success, m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success, m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success, m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(execute_symbol("invalid_symbol", 0) == BFELF_ERROR_NO_SUCH_SYMBOL);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_execute_symbol_sym_failed()
{
    EXPECT_TRUE(common_add_module(m_dummy_init_vmm_success, m_dummy_init_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success, m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success, m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success, m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(execute_symbol("sym_that_returns_failure", 0) == -1);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_execute_symbol_sym_success()
{
    EXPECT_TRUE(common_add_module(m_dummy_init_vmm_success, m_dummy_init_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success, m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success, m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success, m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(execute_symbol("sym_that_returns_success", 0) == 0);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_helper_constructors_success()
{
    get_misc_t get_misc;

    EXPECT_TRUE(common_add_module(m_dummy_init_vmm_success, m_dummy_init_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success, m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success, m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success, m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    ASSERT_TRUE(resolve_symbol("get_misc", (void **)&get_misc, 0) == BF_SUCCESS);
    EXPECT_TRUE(get_misc() == 10);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}
