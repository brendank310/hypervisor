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

#include <exception.h>
#include <ioctl_private.h>

#include <driver_entry_interface.h>

#include <fcntl.h>
#include <SetupAPI.h>
#include <vector>
#include <iostream>

// -----------------------------------------------------------------------------
// Unit Test Seems
// -----------------------------------------------------------------------------

HANDLE
bf_ioctl_open()
{
	HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_bareflank, 0, 0, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
	if (hDevInfo == INVALID_HANDLE_VALUE)
	{
		return (HANDLE)0;
	}

	std::vector<SP_INTERFACE_DEVICE_DATA> interfaces;

	for (DWORD i = 0; true; ++i)
	{
		SP_DEVINFO_DATA devInfo;
		devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
		BOOL succ = SetupDiEnumDeviceInfo(hDevInfo, i, &devInfo);
		if (GetLastError() == ERROR_NO_MORE_ITEMS)
			break;
		if (!succ) continue;

		SP_INTERFACE_DEVICE_DATA ifInfo;
		ifInfo.cbSize = sizeof(SP_INTERFACE_DEVICE_DATA);
		if (TRUE != SetupDiEnumDeviceInterfaces(hDevInfo, &devInfo, &(GUID_DEVINTERFACE_bareflank), 0, &ifInfo))
		{
			if (GetLastError() != ERROR_NO_MORE_ITEMS)
				break;
		}
		interfaces.push_back(ifInfo);
	}

	std::vector<SP_INTERFACE_DEVICE_DETAIL_DATA*> devicePaths;
	SP_INTERFACE_DEVICE_DETAIL_DATA* devicePath = NULL;
	for (size_t i = 0; i < interfaces.size(); ++i)
	{
		DWORD requiredSize = 0;
		SetupDiGetDeviceInterfaceDetail(hDevInfo, &(interfaces.at(i)), NULL, NULL, &requiredSize, NULL);
		SP_INTERFACE_DEVICE_DETAIL_DATA* data = (SP_INTERFACE_DEVICE_DETAIL_DATA*)malloc(requiredSize);

		data->cbSize = sizeof(SP_INTERFACE_DEVICE_DETAIL_DATA);

		if (!SetupDiGetDeviceInterfaceDetail(hDevInfo, &(interfaces.at(i)), data, requiredSize, NULL, NULL))
		{
			continue;
		}
		devicePaths.push_back(data);
		if (i == 0) devicePath = data;
		std::cout << data->DevicePath << std::endl;
	}
    
	if (!devicePath) return (HANDLE)0;

	return CreateFile(devicePath->DevicePath,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
}

int64_t
bf_send_ioctl(HANDLE fd, unsigned long request)
{
	if (!DeviceIoControl(fd, request, NULL, 0, NULL, 0, NULL, NULL))
		return BF_IOCTL_FAILURE;

	return 0;
}

int64_t
bf_read_ioctl(HANDLE fd, unsigned long request, void *data, size_t sz)
{
	if (!DeviceIoControl(fd, request, NULL, 0, data, sz, NULL, NULL))
		return BF_IOCTL_FAILURE;

	return 0; // DeviceIoControl(fd, request, data);
}

int64_t
bf_write_ioctl(HANDLE fd, unsigned long request, const void *data, size_t sz)
{
	if (!DeviceIoControl(fd, request, (LPVOID)data, sz, NULL, 0, NULL, NULL))
		return BF_IOCTL_FAILURE;

	return 0;
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

ioctl_private::ioctl_private()
{
}

ioctl_private::~ioctl_private()
{
    //if (fd >= 0)
    //    close(fd);
}

void
ioctl_private::open()
{
    if ((fd = bf_ioctl_open()) < 0)
        throw driver_inaccessible();
}

int64_t g_module_length = 0;

void
ioctl_private::call_ioctl_add_module_length(int64_t len)
{
    if (len <= 0)
        throw std::invalid_argument("len <= 0");

	g_module_length = len;

	std::cout << "module length: " << g_module_length << std::endl;

    if (bf_write_ioctl(fd, IOCTL_ADD_MODULE_LENGTH, &len, sizeof(len)) < 0)
        throw ioctl_failed(IOCTL_ADD_MODULE_LENGTH);
}

void
ioctl_private::call_ioctl_add_module(const char *data)
{
	if (data == 0) 
	{
		g_module_length = 0;
		throw std::invalid_argument("data == NULL");
	}
    

	if (bf_write_ioctl(fd, IOCTL_ADD_MODULE, data, g_module_length) < 0)
	{
		g_module_length = 0;
		throw ioctl_failed(IOCTL_ADD_MODULE);
	}

	g_module_length = 0;
}

void
ioctl_private::call_ioctl_load_vmm()
{
    if (bf_send_ioctl(fd, IOCTL_LOAD_VMM) < 0)
        throw ioctl_failed(IOCTL_LOAD_VMM);
}

void
ioctl_private::call_ioctl_unload_vmm()
{
    if (bf_send_ioctl(fd, IOCTL_UNLOAD_VMM) < 0)
        throw ioctl_failed(IOCTL_UNLOAD_VMM);
}

void
ioctl_private::call_ioctl_start_vmm()
{
    if (bf_send_ioctl(fd, IOCTL_START_VMM) < 0)
        throw ioctl_failed(IOCTL_START_VMM);
}

void
ioctl_private::call_ioctl_stop_vmm()
{
    if (bf_send_ioctl(fd, IOCTL_STOP_VMM) < 0)
        throw ioctl_failed(IOCTL_STOP_VMM);
}

void
ioctl_private::call_ioctl_dump_vmm(debug_ring_resources_t *drr)
{
    if (drr == 0)
        throw std::invalid_argument("drr == NULL");

    if (bf_read_ioctl(fd, IOCTL_DUMP_VMM, drr, sizeof(*drr)) < 0)
        throw ioctl_failed(IOCTL_DUMP_VMM);
}

void
ioctl_private::call_ioctl_vmm_status(int64_t *status)
{
    if (status == 0)
        throw std::invalid_argument("status == NULL");

    if (bf_read_ioctl(fd, IOCTL_VMM_STATUS, status, sizeof(*status)) < 0)
        throw ioctl_failed(IOCTL_VMM_STATUS);

	std::cout << "bf-status: " << *status << std::endl;
}
