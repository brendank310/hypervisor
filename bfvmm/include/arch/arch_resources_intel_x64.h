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

#ifndef ARCH_RESOURCES_INTEL_X64__H
#define ARCH_RESOURCES_INTEL_X64__H

#include <stddef.h>
#include <stdint.h>
#include <memory.h>
#include <exception.h>

// -----------------------------------------------------------------------------
// Internal classes
// -----------------------------------------------------------------------------
class gdt {
public:
    /// Constructor
    /// @param size Number of entries for the GDT
    ///
    gdt(uint16_t size = 4);

    /// Destructor
    ///
    virtual ~gdt() {}

    /// Create GDT Entry
    ///
    /// @param index Index of the GDT to add the entry to
    /// @param base  Base address of the segment
    /// @param limit Size of the segment 
    /// @param type  Permissions on the segment
    ///
    void add_gdt_entry(uint16_t index, uint32_t base, uint32_t limit, uint8_t type);

    /// Remove GDT Entry
    ///
    /// @param index Index of the GDT entry to remove
    /// 
    void remove_gdt_entry(uint16_t index);

};

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

class arch_resources_intel_x64
{
public:

    /// Default Constructor
    ///
    arch_resources_intel_x64();

    /// Destructor
    ///
    virtual ~arch_resources_intel_x64() {}

    /// Add an entry to the IDT
    ///
    /// @param
    ///
    void add_idt_entry(void);

    /// Remove IDT Entry
    ///
    /// @param index Index of the IDT entry to remove
    /// 
    void remove_idt_entry(uint16_t index);

};

// -----------------------------------------------------------------------------
// Exceptions
// -----------------------------------------------------------------------------

namespace bfn
{

}

#endif
