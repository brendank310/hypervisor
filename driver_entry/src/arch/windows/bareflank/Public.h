/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that app can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_bareflank,
    0x1d9c9218,0x3c88,0x4b81,0x8e,0x81,0xb4,0x62,0x2a,0x4d,0xcb,0x44);
// {1d9c9218-3c88-4b81-8e81-b4622a4dcb44}
