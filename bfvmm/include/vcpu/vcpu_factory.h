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

#ifndef VCPU_FACTORY_H
#define VCPU_FACTORY_H

#include <memory>
#include <vcpu/vcpu_intel_x64.h>

// TODO: Note that this is a placeholder. This class needs to be moved to
// it's own module, as this is what people will implement to create their
// own vCPUs. This way, they have a very simple means picking which portions
// of the system to change without having to re-write a lot of code.

class vcpu_factory
{
public:

    /// Default Constructor
    ///
    vcpu_factory() {}

    /// Destructor
    ///
    virtual ~vcpu_factory() {}

    /// Make vCPU
    ///
    /// @return returns a pointer to a newly created vCPU. Note that it is
    /// up to the caller to free this vCPU.
    ///
    std::shared_ptr<vcpu> make_vcpu(int64_t vcpuid)
        { return std::make_shared<vcpu_intel_x64>(vcpuid); }
};

#endif
