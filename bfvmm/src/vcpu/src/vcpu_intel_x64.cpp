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

#include <vcpu/vcpu_intel_x64.h>

vcpu_intel_x64::vcpu_intel_x64(int64_t id) :
    vcpu(id),
    m_vmm(0),
    m_vmcs(0),
    m_intrinsics(0)
{
    m_intrinsics = new intrinsics_intel_x64();
    m_vmm = new vmm_intel_x64(m_intrinsics);
    m_vmcs = new vmcs_intel_x64(m_intrinsics);
    m_exit_handler = new exit_handler_dispatch(m_intrinsics);
}

vcpu_intel_x64::vcpu_intel_x64(int64_t id,
                               debug_ring *debug_ring,
                               vmm_intel_x64 *vmm,
                               vmcs_intel_x64 *vmcs,
                               intrinsics_intel_x64 *intrinsics) :
    vcpu(id, debug_ring),
    m_vmm(vmm),
    m_vmcs(vmcs),
    m_intrinsics(intrinsics)
{
    if (intrinsics == 0)
        m_intrinsics = new intrinsics_intel_x64();

    if (vmm == 0)
        m_vmm = new vmm_intel_x64(m_intrinsics);

    if (vmcs == 0)
        m_vmcs = new vmcs_intel_x64(intrinsics);
}

static void blah_fn(void)
{
    std::cout << __PRETTY_FUNCTION__ << std::endl;
}

vcpu_error::type
vcpu_intel_x64::start()
{
    std::cout << "About to start and launch the hypervisor" << std::endl;
    std::cout << "blah fn: " << reinterpret_cast<void *>(blah_fn) << std::endl;
    if (m_vmm->start() != vmm_error::success)
        return vcpu_error::failure;

    if (m_vmcs->launch() != vmcs_error::success)
        return vcpu_error::failure;

    return vcpu_error::success;
}

vcpu_error::type
vcpu_intel_x64::dispatch()
{
    m_exit_handler->dispatch();

    return vcpu_error::success;
}

vcpu_error::type
vcpu_intel_x64::stop()
{
    m_vmcs->clear_vmcs_region();

    if (m_vmm->stop() != vmm_error::success)
        return vcpu_error::failure;

    return vcpu_error::success;
}

void
vcpu_intel_x64::dump_cpu_state()
{
    gdt_t gdt = { 0 };
    idt_t idt = { 0 };
    m_intrinsics->read_idt(&idt);
    m_intrinsics->read_gdt(&gdt);

    std::cout << std::hex << "--------------------------------------------------------" << std::endl;
    std::cout << "RIP:        : 0x" << m_intrinsics->read_rip() << std::endl;
    std::cout << "IDT base    : 0x" << idt.base << " limit 0x" << idt.limit << std::endl;
    std::cout << "GDT base    : 0x" << gdt.base << " limit 0x" << gdt.limit << std::endl;
    std::cout << "TR Selector : 0x" << m_intrinsics->read_tr() << std::endl;
    std::cout << "Segment selectors: " << std::endl;
    std::cout << "ES:         : 0x" << m_intrinsics->read_es() << std::endl;
    std::cout << "CS:         : 0x" << m_intrinsics->read_cs() << std::endl;
    std::cout << "SS:         : 0x" << m_intrinsics->read_ss() << std::endl;
    std::cout << "DS:         : 0x" << m_intrinsics->read_ds() << std::endl;
    std::cout << "FS:         : 0x" << m_intrinsics->read_fs() << std::endl;
    std::cout << "GS:         : 0x" << m_intrinsics->read_gs() << std::endl;
    std::cout << std::dec << "--------------------------------------------------------" << std::endl;
}

vcpu_error::type
vcpu_intel_x64::promote_to_root()
{
    if(vcpu_error::success == m_intrinsics->vmcall(0xdeadbeef))
    {
        std::cout << "Promoted guest to VMX Root" << std::endl;
        return vcpu_error::success;
    }
    else
    {
        std::cout << "Invalid vmcall id" << std::endl;
        return vcpu_error::success;
    }

    return vcpu_error::failure;
}
