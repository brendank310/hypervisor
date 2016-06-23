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

#include <memory_manager/page_table_entry_x64.h>

page_table_entry_x64::page_table_entry_x64(uintptr_t *entry) noexcept :
    m_entry(entry)
{
}

bool
page_table_entry_x64::present() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & (1ULL << 0));
}

void
page_table_entry_x64::set_present(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= (1ULL << 0) : *m_entry &= ~(1ULL << 0);
}

bool
page_table_entry_x64::rw() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & (1ULL << 1));
}

void
page_table_entry_x64::set_rw(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= (1ULL << 1) : *m_entry &= ~(1ULL << 1);
}

bool
page_table_entry_x64::us() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & (1ULL << 2));
}

void
page_table_entry_x64::set_us(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= (1ULL << 2) : *m_entry &= ~(1ULL << 2);
}

bool
page_table_entry_x64::pwt() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & (1ULL << 3));
}

void
page_table_entry_x64::set_pwt(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= (1ULL << 3) : *m_entry &= ~(1ULL << 3);
}

bool
page_table_entry_x64::pcd() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & (1ULL << 4));
}

void
page_table_entry_x64::set_pcd(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= (1ULL << 4) : *m_entry &= ~(1ULL << 4);
}

bool
page_table_entry_x64::accessed() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & (1ULL << 5));
}

void
page_table_entry_x64::set_accessed(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= (1ULL << 5) : *m_entry &= ~(1ULL << 5);
}

bool
page_table_entry_x64::dirty() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & (1ULL << 6));
}

void
page_table_entry_x64::set_dirty(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= (1ULL << 6) : *m_entry &= ~(1ULL << 6);
}

bool
page_table_entry_x64::pat() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & (1ULL << 7));
}

void
page_table_entry_x64::set_pat(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= (1ULL << 7) : *m_entry &= ~(1ULL << 7);
}

bool
page_table_entry_x64::global() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & (1ULL << 8));
}

void
page_table_entry_x64::set_global(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= (1ULL << 8) : *m_entry &= ~(1ULL << 8);
}

uintptr_t
page_table_entry_x64::phys_addr() const noexcept
{
    if (m_entry == nullptr)
        return 0;

    return (*m_entry & 0x000FFFFFFFFFF000);
}

void
page_table_entry_x64::set_phys_addr(uintptr_t addr) noexcept
{
    if (m_entry == nullptr)
        return;

    *m_entry = (*m_entry & 0xFFF0000000000FFF) | (addr & 0x000FFFFFFFFFF000);
}

bool
page_table_entry_x64::nx() const noexcept
{
    if (m_entry == nullptr)
        return false;

    return (*m_entry & (1ULL << 63));
}

void
page_table_entry_x64::set_nx(bool enabled) noexcept
{
    if (m_entry == nullptr)
        return;

    enabled ? *m_entry |= (1ULL << 63) : *m_entry &= ~(1ULL << 63);
}
