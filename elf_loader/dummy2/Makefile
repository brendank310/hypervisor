#
# Bareflank Hypervisor
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

################################################################################
# FLAGS
################################################################################

CROSS_CC=~/opt/cross/bin/x86_64-elf-gcc
CROSS_CXX=~/opt/cross/bin/x86_64-elf-g++
CROSS_ASM=~/opt/cross/bin/nasm
CROSS_LD=~/opt/cross/bin/x86_64-elf-ld

CC=$(CROSS_CC)
CXX=$(CROSS_CXX)
ASM=$(CROSS_ASM)
LD=$(CROSS_LD)
RM=rm -rf
MD=mkdir -p

CCFLAGS=
CXXFLAGS=
ASMFLAGS=-f elf64
LDFLAGS=

DEFINES=

################################################################################
# Sources
################################################################################

TARGET_NAME=dummy2
TARGET_TYPE=lib
TARGET_CROSS_COMPILED=true

OBJDIR=.build
OUTDIR=../bin

SOURCES=dummy2.cpp

INCLUDES=
LIBS=

INCLUDE_PATHS=./ ../include/
LIB_PATHS=

################################################################################
# Common
################################################################################

include ../../common/common_target.mk
