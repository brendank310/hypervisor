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
#include <vmcs/vmcs_intel_x64.h>

uint64_t fake_vmread_return;

bool
fake_vmread(uint64_t field, uint64_t *val)
{
    if (val == 0)
        return false;

    *val = fake_vmread_return;
    return true;
}

// CR0 checks
void
vmcs_ut::test_check_host_cr0_for_unsupported_bits_missing_1s()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    fake_vmread_return = 0x0;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0x0F0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFFF);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_cr0_for_unsupported_bits() == false);
    });
}

void
vmcs_ut::test_check_host_cr0_for_unsupported_bits_missing_0s()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    fake_vmread_return = 0xFFFFFFFFFFFFFFFF;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0x0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xFFFFFFFFFFFFF0FF);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_cr0_for_unsupported_bits() == false);
    });
}

void
vmcs_ut::test_check_host_cr0_for_unsupported_bits_valid()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    // The hardware apears to always return 0xFFFFFFFFFFFFFFFF for the fixed
    // 1 MSR, which means that it is always ok to turn on a bit. For this
    // reason we test this case specifically for valid as it's more likely to
    // occur on real hardware

    fake_vmread_return = 0x0FA;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED0_MSR).Return(0x0F0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR0_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFFF);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_cr0_for_unsupported_bits() == true);
    });
}

// CR4 checks
void
vmcs_ut::test_check_host_cr4_for_unsupported_bits_missing_1s()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    fake_vmread_return = 0x0;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED0_MSR).Return(0x0F0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFFF);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_cr4_for_unsupported_bits() == false);
    });
}

void
vmcs_ut::test_check_host_cr4_for_unsupported_bits_missing_0s()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    fake_vmread_return = 0xFFFFFFFFFFFFFFFF;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED0_MSR).Return(0x0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED1_MSR).Return(0xFFFFFFFFFFFFF0FF);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_cr4_for_unsupported_bits() == false);
    });
}

void
vmcs_ut::test_check_host_cr4_for_unsupported_bits_valid()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    // The hardware apears to always return 0xFFFFFFFFFFFFFFFF for the fixed
    // 1 MSR, which means that it is always ok to turn on a bit. For this
    // reason we test this case specifically for valid as it's more likely to
    // occur on real hardware

    fake_vmread_return = 0x0FA;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED0_MSR).Return(0x0F0);
    mocks.OnCall(intrinsics, intrinsics_intel_x64::read_msr).With(IA32_VMX_CR4_FIXED1_MSR).Return(0xFFFFFFFFFFFFFFFF);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_cr4_for_unsupported_bits() == true);
    });
}

// CR3 checks
void
vmcs_ut::test_check_host_cr3_for_unsupported_bits_invalid_width()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    fake_vmread_return = 0x3FFFFFFFFFF + 1;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_cr3_for_unsupported_bits() == false);
    });
}

void
vmcs_ut::test_check_host_cr3_for_unsupported_bits_valid_width()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    fake_vmread_return = 0x3FFFFFFFFFF;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_cr3_for_unsupported_bits() == true);
    });
}

// Canonical address checks
void
vmcs_ut::test_check_is_address_canonical_top_of_address_space()
{
    vmcs_intel_x64 vmcs;
    uint64_t top_addr = 0xFFFFFFFFFFFFFFFF;
    uint64_t below_top_addr = 0xFFFFFFFFFFFFFFFE;

    EXPECT_TRUE(vmcs.check_is_address_canonical(top_addr));
    EXPECT_TRUE(vmcs.check_is_address_canonical(below_top_addr));
}

void
vmcs_ut::test_check_is_address_canonical_bottom_of_address_space()
{
    vmcs_intel_x64 vmcs;
    uint64_t bottom_addr = 0x00;
    uint64_t above_bottom_addr = 0x01;

    EXPECT_TRUE(vmcs.check_is_address_canonical(bottom_addr));
    EXPECT_TRUE(vmcs.check_is_address_canonical(above_bottom_addr));
}

void
vmcs_ut::test_check_is_address_canonical_high_address_space_border()
{
    vmcs_intel_x64 vmcs;
    uint64_t below_high_border = 0xFFFF7FFFFFFFFFFF;;  // false
    uint64_t high_border = 0xFFFF800000000000; // true
    uint64_t above_high_border = 0xFFFF800000000001; // true

    EXPECT_TRUE(vmcs.check_is_address_canonical(below_high_border) == false);
    EXPECT_TRUE(vmcs.check_is_address_canonical(high_border) == true);
    EXPECT_TRUE(vmcs.check_is_address_canonical(above_high_border) == true);
}

void
vmcs_ut::test_check_is_address_canonical_low_address_space_border()
{
    vmcs_intel_x64 vmcs;
    uint64_t above_low_border = 0x0000800000000000;  // false
    uint64_t low_border = 0x00007FFFFFFFFFFF; // true
    uint64_t below_low_border = 0x00007FFFFFFFFFFE; // true

    EXPECT_TRUE(vmcs.check_is_address_canonical(above_low_border) == false);
    EXPECT_TRUE(vmcs.check_is_address_canonical(low_border) == true);
    EXPECT_TRUE(vmcs.check_is_address_canonical(below_low_border) == true);
}

void
vmcs_ut::test_check_host_ia32_sysenter_esp_canonical_address_valid()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    mocks.OnCall(&vmcs, vmcs_intel_x64::check_is_address_canonical).Return(true);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_ia32_sysenter_esp_canonical_address() == true);
    });
}

void
vmcs_ut::test_check_host_ia32_sysenter_esp_canonical_address_invalid()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    mocks.OnCall(&vmcs, vmcs_intel_x64::check_is_address_canonical).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_ia32_sysenter_esp_canonical_address() == false);
    });
}

// eip
void
vmcs_ut::test_check_host_ia32_sysenter_eip_canonical_address_valid()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    mocks.OnCall(&vmcs, vmcs_intel_x64::check_is_address_canonical).Return(true);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_ia32_sysenter_eip_canonical_address() == true);
    });
}

void
vmcs_ut::test_check_host_ia32_sysenter_eip_canonical_address_invalid()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    mocks.OnCall(&vmcs, vmcs_intel_x64::check_is_address_canonical).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_ia32_sysenter_eip_canonical_address() == false);
    });
}

// perf_global_ctrl
void
vmcs_ut::test_check_host_ia32_perf_global_ctrl_for_reserved_bits_invalid()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    fake_vmread_return = VM_EXIT_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_ia32_perf_global_ctrl_for_reserved_bits() == false);
    });

}

void
vmcs_ut::test_check_host_ia32_perf_global_ctrl_for_reserved_bits_valid()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    fake_vmread_return = 0;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_ia32_perf_global_ctrl_for_reserved_bits() == true);
    });
}

// perf_global_ctrl
void
vmcs_ut::test_check_host_ia32_pat_for_unsupported_bits_invalid()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    fake_vmread_return = VM_EXIT_CONTROL_LOAD_IA32_PAT;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_ia32_perf_global_ctrl_for_reserved_bits() == false);
    });

}

void
vmcs_ut::test_check_host_ia32_pat_for_unsupported_bits_valid()
{
    MockRepository mocks;
    memory_manager *mm = mocks.Mock<memory_manager>();
    intrinsics_intel_x64 *intrinsics = mocks.Mock<intrinsics_intel_x64>();

    vmcs_intel_x64 vmcs;
    vmcs.init(intrinsics, mm);

    fake_vmread_return = 0;
    mocks.OnCall(intrinsics, intrinsics_intel_x64::vmread).Do(fake_vmread);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        EXPECT_TRUE(vmcs.check_host_ia32_perf_global_ctrl_for_reserved_bits() == true);
    });
}


// REMOVE ME:
//
// Make sure you take a look at the following:
// http://hippomocks.com/Main_Page
//
// Remember that you should only use ExpectCall if you cannot observe the
// result your looking for because the function modifies a dependency. Which
// is the big difference between a Mock and a Stub. A mock "expects" a function
// to be called as it is the thing your checking. A stub simply provides
// fake stimulus to get a certain part of the code to execute.
//
// There is also, NeverCall which is great here too. For example, I used that
// for vmxon / vmxoff becuase if that code is called under certain conditions
// your looking at a segfault.
//
// Also notice how I have three tests for a single function. That's because
// there are three different code paths in this one function. The function
// name clearly states what I am trying to do test_<func>_<desc>
//

