#ifndef __STDINT__H
#define __STDINT__H

typedef unsigned char uint8_t;
typedef char int8_t;

typedef unsigned short uint16_t;
typedef short int16_t;
typedef unsigned long uint32_t;
typedef long int32_t;
typedef unsigned long long uint64_t;
typedef long long int64_t;


/* This may not technically be correct, but because
   bareflank is only supporting 64bit architectures
   we shouldn't run into any trouble with this
*/
typedef unsigned long long uintptr_t;

#endif // __STDINT__H
