// libbfm.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "libbfm.h"


// This is an example of an exported variable
LIBBFM_API int nlibbfm=0;

// This is an example of an exported function.
LIBBFM_API int fnlibbfm(void)
{
    return 42;
}

// This is the constructor of a class that has been exported.
// see libbfm.h for the class definition
Clibbfm::Clibbfm()
{
    return;
}
