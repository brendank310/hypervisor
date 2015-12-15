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

#ifndef TEST_H
#define TEST_H

#include <unittest.h>

class vmcs_ut : public unittest
{
public:

    vmcs_ut();
    ~vmcs_ut() {}

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_check_host_cr0_for_unsupported_bits_missing_1s();
    void test_check_host_cr0_for_unsupported_bits_missing_0s();
    void test_check_host_cr0_for_unsupported_bits_valid();

    void test_check_host_cr4_for_unsupported_bits_missing_1s();
    void test_check_host_cr4_for_unsupported_bits_missing_0s();
    void test_check_host_cr4_for_unsupported_bits_valid();

    void test_check_host_cr3_for_unsupported_bits_invalid_width();
    void test_check_host_cr3_for_unsupported_bits_valid_width();

    void test_check_is_address_canonical_top_of_address_space();
    void test_check_is_address_canonical_bottom_of_address_space();
    void test_check_is_address_canonical_high_address_space_border();
    void test_check_is_address_canonical_low_address_space_border();

    void test_check_host_ia32_sysenter_esp_canonical_address_valid();
    void test_check_host_ia32_sysenter_esp_canonical_address_invalid();

    void test_check_host_ia32_sysenter_eip_canonical_address_valid();
    void test_check_host_ia32_sysenter_eip_canonical_address_invalid();

    void test_check_host_ia32_perf_global_ctrl_for_reserved_bits_valid();
    void test_check_host_ia32_perf_global_ctrl_for_reserved_bits_invalid();

    void test_check_host_ia32_pat_for_unsupported_bits_valid();
    void test_check_host_ia32_pat_for_unsupported_bits_invalid();

    void test_check_host_verify_load_ia32_efer_enabled_invalid();
    void test_check_host_verify_load_ia32_efer_enabled_valid();

    void test_check_host_ia32_efer_for_reserved_bits_invalid();
    void test_check_host_ia32_efer_for_reserved_bits_valid();

    void test_check_host_ia32_efer_set_invalid();
    void test_check_host_ia32_efer_set_valid();

    void test_check_host_es_selector_rpl_ti_equal_zero_invalid();
    void test_check_host_es_selector_rpl_ti_equal_zero_valid();

    void test_check_host_cs_selector_rpl_ti_equal_zero_invalid();
    void test_check_host_cs_selector_rpl_ti_equal_zero_valid();

    void test_check_host_ss_selector_rpl_ti_equal_zero_invalid();
    void test_check_host_ss_selector_rpl_ti_equal_zero_valid();

    void test_check_host_ds_selector_rpl_ti_equal_zero_invalid();
    void test_check_host_ds_selector_rpl_ti_equal_zero_valid();

    void test_check_host_fs_selector_rpl_ti_equal_zero_invalid();
    void test_check_host_fs_selector_rpl_ti_equal_zero_valid();

    void test_check_host_gs_selector_rpl_ti_equal_zero_invalid();
    void test_check_host_gs_selector_rpl_ti_equal_zero_valid();

    void test_check_host_tr_selector_rpl_ti_equal_zero_invalid();
    void test_check_host_tr_selector_rpl_ti_equal_zero_valid();

    void test_check_host_cs_not_equal_zero_invalid();
    void test_check_host_cs_not_equal_zero_valid();

    void test_check_host_tr_not_equal_zero_invalid();
    void test_check_host_tr_not_equal_zero_valid();

    void test_check_host_ss_not_equal_zero_invalid();
    void test_check_host_ss_not_equal_zero_valid_non_zero_selector();
    void test_check_host_ss_not_equal_zero_valid_zero_selector();

    void test_check_host_fs_canonical_base_address_invalid();
    void test_check_host_fs_canonical_base_address_valid();

    void test_check_host_gs_canonical_base_address_invalid();
    void test_check_host_gs_canonical_base_address_valid();

    void test_check_host_gdtr_canonical_base_address_invalid();
    void test_check_host_gdtr_canonical_base_address_valid();

    void test_check_host_idtr_canonical_base_address_invalid();
    void test_check_host_idtr_canonical_base_address_valid();

    void test_check_host_tr_canonical_base_address_invalid();
    void test_check_host_tr_canonical_base_address_valid();
};

#endif
