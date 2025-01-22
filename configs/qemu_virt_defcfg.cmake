#
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
#

#
# Set the RMM_PLATFORM variable to Cmake cache.
#
set(RMM_PLATFORM "arm" CACHE STRING "platform")
arm_config_option_override(NAME RMM_TOOLCHAIN DEFAULT "gnu")

#
# Set RMM_MAX_SIZE for this platform (40MB).  Needs to be kept in sync with
# TF-A's REALM_DRAM_SIZE in platform_def.h.
#
arm_config_option_override(NAME RMM_MAX_SIZE DEFAULT 0x02800000)

# Maximum number of translation tables allocated by the runtime context
# for the translation library.
#
arm_config_option_override(NAME PLAT_CMN_CTX_MAX_XLAT_TABLES DEFAULT 7)

#
# Maximum number of granules supported.  Needs to be kept in sync with
# TF-A's PLAT_QEMU_L1_GPT_SIZE in platform_def.h.
#
arm_config_option_override(NAME RMM_MAX_GRANULES DEFAULT 0x200000)

#
# TF-A sets a limit of 32 CPUs for the QEMU virt platform.
#
arm_config_option_override(NAME MAX_CPUS DEFAULT 32)
