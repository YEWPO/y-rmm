/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#ifndef SMC_RSI_H
#define SMC_RSI_H

#include <smc.h>

/*
 * This file describes the Realm Services Interface (RSI) Application Binary
 * Interface (ABI) for SMC calls made from within the Realm to the RMM and
 * serviced by the RMM.
 */

/*
 * The major version number of the RSI implementation.  Increase this whenever
 * the binary format or semantics of the SMC calls change.
 */
#define RSI_ABI_VERSION_MAJOR		UL(1)

/*
 * The minor version number of the RSI implementation.  Increase this when
 * a bug is fixed, or a feature is added without breaking binary compatibility.
 */
#ifdef RMM_V1_1
#define RSI_ABI_VERSION_MINOR		UL(1)
#else
#define RSI_ABI_VERSION_MINOR		UL(0)
#endif

#define RSI_ABI_VERSION			((RSI_ABI_VERSION_MAJOR << U(16)) | \
					  RSI_ABI_VERSION_MINOR)

#define RSI_ABI_VERSION_GET_MAJOR(_version) ((_version) >> U(16))
#define RSI_ABI_VERSION_GET_MINOR(_version) ((_version) & U(0xFFFF))

#define IS_SMC64_RSI_FID(_fid)		IS_SMC64_STD_FAST_IN_RANGE(RSI, _fid)

#define SMC64_RSI_FID(_offset)		SMC64_STD_FID(RSI, _offset)

/*
 * RsiCommandReturnCode enumeration
 * representing a return code from an RSI command.
 */
/* Command completed successfully */
#define RSI_SUCCESS		UL(0)

/* The value of a command input value caused the command to fail */
#define RSI_ERROR_INPUT		UL(1)

/*
 * The state of the current Realm or current REC
 * does not match the state expected by the command
 */
#define RSI_ERROR_STATE		UL(2)

/* The operation requested by the command is not complete */
#define RSI_INCOMPLETE		UL(3)

/* The operation requested by the command failed for an unknown reason */
#define RSI_ERROR_UNKNOWN	UL(4)

/*
 * The state of a Realm device does not match the state expected by the command.
 */
#define RSI_ERROR_DEVICE	UL(5)

#define RSI_ERROR_COUNT_MAX	UL(6)

/* RsiHashAlgorithm */
#define RSI_HASH_SHA_256	0U
#define RSI_HASH_SHA_512	1U

/*
 * RsiRipasChangeDestroyed:
 * RIPAS change from DESTROYED should not be permitted
 */
#define RSI_NO_CHANGE_DESTROYED	U(0)

/* A RIPAS change from DESTROYED should be permitted */
#define RSI_CHANGE_DESTROYED	U(1)

/*
 * RsiResponse enumeration represents whether Host accepted
 * or rejected a Realm request
 */
#define RSI_ACCEPT		U(0)
#define RSI_REJECT		U(1)

/* The number of GPRs (starting from X0) per voluntary exit context */
#define PLANE_EXIT_NR_GPRS  U(31)

/* Maximum number of Interrupt Controller List Registers */
#define PLANE_GIC_NUM_LRS    U(16)

/*
 * FID: 0xC4000190
 *
 * Returns RSI version.
 * arg1: Requested interface version
 * ret0: Status / error
 * ret1: Lower implemented interface revision
 * ret2: Higher implemented interface revision
 */
#define SMC_RSI_VERSION			SMC64_RSI_FID(U(0x0))

/*
 * FID: 0xC4000191
 *
 * Returns RSI Feature register requested by index.
 * arg1: Feature register index
 * ret0: Status / error
 * ret1: Feature register value
 */
#define SMC_RSI_FEATURES		SMC64_RSI_FID(U(0x1))

/*
 * FID: 0xC4000192
 *
 * Returns a measurement.
 * arg1: Measurement index (0..4), measurement (RIM or REM) to read
 * ret0: Status / error
 * ret1: Measurement value, bytes:  0 -  7
 * ret2: Measurement value, bytes:  8 - 15
 * ret3: Measurement value, bytes: 16 - 23
 * ret4: Measurement value, bytes: 24 - 31
 * ret5: Measurement value, bytes: 32 - 39
 * ret6: Measurement value, bytes: 40 - 47
 * ret7: Measurement value, bytes: 48 - 55
 * ret8: Measurement value, bytes: 56 - 63
 */
#define SMC_RSI_MEASUREMENT_READ	SMC64_RSI_FID(U(0x2))

/*
 * FID: 0xC4000193
 *
 * Extends a REM.
 * arg1:  Measurement index (1..4), measurement (REM) to extend
 * arg2:  Measurement size in bytes
 * arg3:  Challenge value, bytes:  0 -  7
 * arg4:  Challenge value, bytes:  8 - 15
 * arg5:  Challenge value, bytes: 16 - 23
 * arg6:  Challenge value, bytes: 24 - 31
 * arg7:  Challenge value, bytes: 32 - 39
 * arg8:  Challenge value, bytes: 40 - 47
 * arg9:  Challenge value, bytes: 48 - 55
 * arg10: Challenge value, bytes: 56 - 63
 * ret0:  Status / error
 */
#define SMC_RSI_MEASUREMENT_EXTEND	SMC64_RSI_FID(U(0x3))

/*
 * FID: 0xC4000194
 *
 * Initialize the operation to retrieve an attestation token.
 * arg1: Challenge value, bytes:  0 -  7
 * arg2: Challenge value, bytes:  8 - 15
 * arg3: Challenge value, bytes: 16 - 23
 * arg4: Challenge value, bytes: 24 - 31
 * arg5: Challenge value, bytes: 32 - 39
 * arg6: Challenge value, bytes: 40 - 47
 * arg7: Challenge value, bytes: 48 - 55
 * arg8: Challenge value, bytes: 56 - 63
 * ret0: Status / error
 * ret1: Upper bound on attestation token size in bytes
 */
#define SMC_RSI_ATTEST_TOKEN_INIT	SMC64_RSI_FID(U(0x4))

/*
 * FID: 0xC4000195
 *
 * Continue the operation to retrieve an attestation token.
 * arg1: IPA of the Granule to which the token will be written
 * arg2: Offset within Granule to start of buffer in bytes
 * arg3: Size of buffer in bytes
 * ret0: Status / error
 * ret1: Number of bytes written to buffer
 */
#define SMC_RSI_ATTEST_TOKEN_CONTINUE	SMC64_RSI_FID(U(0x5))

/*
 * FID: 0xC4000196
 *
 * Read configuration for the current Realm.
 * arg1 == IPA of the Granule to which the configuration data will be written
 * ret0 == Status / error
 */
#define SMC_RSI_REALM_CONFIG		SMC64_RSI_FID(U(0x6))

/*
 * FID: 0xC4000197
 *
 * arg1 == Base IPA address of target region
 * arg2 == Top address of target region
 * arg3 == RIPAS value
 * arg4 == flags
 * ret0 == Status / error
 * ret1 == Base of IPA region which was not modified by the command
 * ret2 == RSI response
 */
#define SMC_RSI_IPA_STATE_SET		SMC64_RSI_FID(U(0x7))

/*
 * FID: 0xC4000198
 *
 * arg1 == Base of target IPA region
 * arg2 == End of target IPA region
 * ret0 == Status / error
 * ret1 == Top of IPA region which has the reported RIPAS value
 * ret2 == RIPAS value
 */
#define SMC_RSI_IPA_STATE_GET		SMC64_RSI_FID(U(0x8))

/*
 * FID: 0xC4000199
 *
 * arg1 == IPA of the Host call data structure
 * ret0 == Status / error
 */
#define SMC_RSI_HOST_CALL		SMC64_RSI_FID(U(0x9))

/*
 * TODO: Update the documentation of new FIDs once the 1.1 spec has stabilized.
 */

/*
 * FID: 0xC40001A0
 */
#define SMC_RSI_MEM_GET_PERM_VALUE	SMC64_RSI_FID(U(0x10))

/*
 * FID: 0xC40001A1
 */
#define SMC_RSI_MEM_SET_PERM_INDEX	SMC64_RSI_FID(U(0x11))

/*
 * FID: 0xC40001A2
 */
#define SMC_RSI_MEM_SET_PERM_VALUE	SMC64_RSI_FID(U(0x12))

/*
 * FID: 0xC40001A3
 *
 * arg1: The number of the auxiliary plane to enter
 * arg2: IPA of the Granule where PlaneRun is
 * ret0: Status / error
 */
#define SMC_RSI_PLANE_ENTER		SMC64_RSI_FID(U(0x13))

/*
 * FID: 0xC40001A4
 */
#define SMC_RSI_RDEV_CONTINUE		SMC64_RSI_FID(U(0x14))

/*
 * FID: 0xC40001A5
 */
#define SMC_RSI_RDEV_GET_INFO		SMC64_RSI_FID(U(0x15))

/*
 * FID: 0xC40001A6
 */
#define SMC_RSI_RDEV_GET_INTERFACE_REPORT SMC64_RSI_FID(U(0x16))

/*
 * FID: 0xC40001A7
 */
#define SMC_RSI_RDEV_GET_MEASUREMENTS	SMC64_RSI_FID(U(0x17))

/*
 * FID: 0xC40001A8
 */
#define SMC_RSI_RDEV_GET_STATE		SMC64_RSI_FID(U(0x18))

/*
 * FID: 0xC40001A9
 */
#define SMC_RSI_RDEV_LOCK		SMC64_RSI_FID(U(0x19))

/*
 * FID: 0xC40001AA
 */
#define SMC_RSI_RDEV_START		SMC64_RSI_FID(U(0x1A))

/*
 * FID: 0xC40001AB
 */
#define SMC_RSI_RDEV_STOP		SMC64_RSI_FID(U(0x1B))

/*
 * FID: 0xC40001AC
 */
#define SMC_RSI_RDEV_VALIDATE_MAPPING	SMC64_RSI_FID(U(0x1C))

/*
 * FID: 0xC40001AE
 */
#define SMC_RSI_PLANE_SYSREG_READ		SMC64_RSI_FID(U(0x1E))

/*
 * FID: 0xC40001AF
 */
#define SMC_RSI_PLANE_SYSREG_WRITE		SMC64_RSI_FID(U(0x1F))

#ifndef __ASSEMBLER__
/*
 * Defines member of structure and reserves space
 * for the next member with specified offset.
 */
#define SET_MEMBER_RSI	SET_MEMBER

/* Size of Realm Personalization Value */
#ifndef CBMC
#define RSI_RPV_SIZE		64
#else
/*
 * Small RPV size so that RsiRealmConfig structure
 * fits in the reduced sized granule defined for CBMC
 */
#define RSI_RPV_SIZE		1
#endif

/* RsiRealmConfig structure containing realm configuration */
struct rsi_realm_config {
	/* IPA width in bits */
	SET_MEMBER_RSI(unsigned long ipa_width, 0x0, 0x8);		/* Offset 0 */
	/* Hash algorithm */
	SET_MEMBER_RSI(unsigned char algorithm, 0x8, 0x10);	/* Offset 8 */
  /* Number of auxiliary Planes */
  SET_MEMBER_RSI(unsigned long num_aux_planes, 0x10, 0x18); /* Offset 0x10 */
  /* GICv3 VGIC Type Register value */
  SET_MEMBER_RSI(unsigned long gicv3_vtr, 0x18, 0x20); /* Offset 0x18 */
  /* If ATS is enabled, determines the stage 2 translation used by devices assigned to the Realm */
  SET_MEMBER_RSI(unsigned long ats_plane, 0x20, 0x200); /* Offset 0x20 */

	/* Realm Personalization Value */
	SET_MEMBER_RSI(unsigned char rpv[RSI_RPV_SIZE], 0x200, 0x1000); /* Offset 0x200 */
};

#define RSI_HOST_CALL_NR_GPRS		U(31)

struct rsi_host_call {
	SET_MEMBER_RSI(struct {
		/* Immediate value */
		unsigned int imm;		/* Offset 0 */
		/* Registers */
		unsigned long gprs[RSI_HOST_CALL_NR_GPRS];
		}, 0, 0x100);
};

/*
 * RsiFeature
 * Represents whether a feature is enabled.
 * Width: 1 bit
 */
#define RSI_FEATURE_FALSE			U(0)
#define RSI_FEATURE_TRUE			U(1)

/*
 * RsiFeatureRegister0
 * Fieldset contains feature register 0
 * Width: 64 bits
 */
#define RSI_FEATURE_REGISTER_0_INDEX		UL(0)
#define RSI_FEATURE_REGISTER_0_DA_SHIFT		UL(0)
#define RMM_FEATURE_REGISTER_0_DA_WIDTH		UL(1)
#define RSI_FEATURE_REGISTER_0_MRO_SHIFT	UL(1)
#define RMM_FEATURE_REGISTER_0_MRO_WIDTH	UL(1)

/*
 * RsiDevMemShared
 * Represents whether an device memory mapping is shared.
 * Width: 1 bit
 */
#define RSI_DEV_MEM_MAPPING_PRIVATE		U(0)
#define RSI_DEV_MEM_MAPPING_SHARED		U(1)

/*
 * RsiDevMemCoherent
 * Represents whether a device memory location is within the system coherent
 * memory space.
 * Width: 1 bit
 */
#define RSI_DEV_MEM_NON_COHERENT		U(0)
#define RSI_DEV_MEM_COHERENT			U(1)

/*
 * RsiRdevValidateIoFlags
 * Fieldset contains flags provided when requesting validation of an IO mapping.
 * Width: 64 bits
 */
/* RsiDevMemShared: Bits 0 to 1 */
#define RSI_RDEV_VALIDATE_IO_FLAGS_SHARE_SHIFT	UL(0)
#define RSI_RDEV_VALIDATE_IO_FLAGS_SHARE_WIDTH	UL(1)
/* RsiDevMemCoherent: Bits 1 to 2 */
#define RSI_RDEV_VALIDATE_IO_FLAGS_COH_SHIFT	UL(1)
#define RSI_RDEV_VALIDATE_IO_FLAGS_COH_WIDTH	UL(1)

/*
 * RsiDeviceState
 * This enumeration represents state of an assigned Realm device.
 * Width: 64 bits.
 */
#define RSI_RDEV_STATE_NEW			U(0)
#define RSI_RDEV_STATE_NEW_BUSY			U(1)
#define RSI_RDEV_STATE_LOCKED			U(2)
#define RSI_RDEV_STATE_LOCKED_BUSY		U(3)
#define RSI_RDEV_STATE_STARTED			U(4)
#define RSI_RDEV_STATE_STARTED_BUSY		U(5)
#define RSI_RDEV_STATE_STOPPING			U(6)
#define RSI_RDEV_STATE_STOPPED			U(7)
#define RSI_RDEV_STATE_ERROR			U(8)

/*
 * RsiSysregAddress
 * Width: 64 bits
 */
#define RSI_SYSREG_D128_SHIFT   U(16)
#define RSI_SYSREG_D128_MASK    (U(0x1) << RSI_SYSREG_D128_SHIFT)
#define RSI_SYSREG_D128(sysreg_addr) \
  (((sysreg_addr) & RSI_SYSREG_D128_MASK) >> RSI_SYSREG_D128_SHIFT)

#define RSI_SYSREG_OP0_SHIFT    U(14)
#define RSI_SYSREG_OP0_MASK     (U(0x3) << RSI_SYSREG_OP0_SHIFT)
#define RSI_SYSREG_OP1_SHIFT    U(11)
#define RSI_SYSREG_OP1_MASK     (U(0x7) << RSI_SYSREG_OP1_SHIFT)
#define RSI_SYSREG_CRN_SHIFT    U(7)
#define RSI_SYSREG_CRN_MASK     (U(0xf) << RSI_SYSREG_CRN_SHIFT)
#define RSI_SYSREG_CRM_SHIFT    U(3)
#define RSI_SYSREG_CRM_MASK     (U(0xf) << RSI_SYSREG_CRM_SHIFT)
#define RSI_SYSREG_OP2_SHIFT    U(0)
#define RSI_SYSREG_OP2_MASK     (U(0x7) << RSI_SYSREG_OP2_SHIFT)
#define RSI_SYSREG_MASK         (RSI_SYSREG_OP0_MASK | \
                                 RSI_SYSREG_OP1_MASK | \
                                 RSI_SYSREG_CRN_MASK | \
                                 RSI_SYSREG_CRM_MASK | \
                                 RSI_SYSREG_OP2_MASK)
#define RSI_SYSREG_VAL(op0, op1, crn, crm, op2) \
  (((op0) << RSI_SYSREG_OP0_SHIFT) | \
   ((op1) << RSI_SYSREG_OP1_SHIFT) | \
   ((crn) << RSI_SYSREG_CRN_SHIFT) | \
   ((crm) << RSI_SYSREG_CRM_SHIFT) | \
   ((op2) << RSI_SYSREG_OP2_SHIFT))

struct rsi_sysreg_val {
  SET_MEMBER_RSI(unsigned long value_lower, 0, 0x8);
  SET_MEMBER_RSI(unsigned long value_upper, 0x8, 0x10);
};

/*
 * RsiExitReason
 * This enumeration represents the reason for a plane exit.
 * Width: 64 bits.
 */
#define RSI_EXIT_SYNC       U(0)
#define RSI_EXIT_IRQ        U(1)
#define RSI_EXIT_HOST       U(2)
#define RSI_EXIT_UNKNOWN    U(0xff)

/*
 * RsiPlaneEnterFlags
 * This enumeration represents the flags for a plane enter.
 * Width: 64 bits.
 */
#define PLANE_ENTER_FLAG_TRAP_WFI          U(1<<0)
#define PLANE_ENTER_FLAG_TRAP_WFE          U(1<<1)
#define PLANE_ENTER_FLAG_TRAP_HC           U(1<<2)
#define PLANE_ENTER_FLAG_GIC_OWNER         U(1<<3)
#define PLANE_ENTER_FLAG_TRAP_SIMD         U(1<<4)

struct rsi_plane_enter {
  /* Flags */
  SET_MEMBER_RSI(unsigned long flags, 0, 0x8); /* Offset 0 */
  /* Program counter */
  SET_MEMBER_RSI(unsigned long pc, 0x8, 0x100); /* Offset 0x8 */

  /* Registers */
  SET_MEMBER_RSI(unsigned long gprs[PLANE_EXIT_NR_GPRS], 0x100, 0x200); /* Offset 0x10 */

  /* GICv3 Hypervisor Control Register value */
  SET_MEMBER_RSI(unsigned long gicv3_hcr, 0x200, 0x208); /* Offset 0x200 */
  /* GICv3 List Registers values */
  SET_MEMBER_RSI(unsigned long gicv3_lrs[PLANE_GIC_NUM_LRS], 0x208, 0x300); /* Offset 0x208 */

  /* SPSR_EL2 value */
  SET_MEMBER_RSI(unsigned long spsr_el2, 0x300, 0x800); /* Offset 0x300 */
};

struct rsi_plane_exit {
  /* Exit reason */
  SET_MEMBER_RSI(unsigned long exit_reason, 0, 0x100); /* Offset 0 */

  /* Exception Link Register */
  SET_MEMBER_RSI(unsigned long elr_el2, 0x100, 0x108); /* Offset 0x100 */
  /* Exception Syndrome Register */
  SET_MEMBER_RSI(unsigned long esr_el2, 0x108, 0x110); /* Offset 0x108 */
  /* Fault Address Register */
  SET_MEMBER_RSI(unsigned long far_el2, 0x110, 0x118); /* Offset 0x110 */
  /* Hypervisor IPA Fault Address register */
  SET_MEMBER_RSI(unsigned long hpfar_el2, 0x118, 0x120); /* Offset 0x118 */
  /* SPSR_EL2 value */
  SET_MEMBER_RSI(unsigned long spsr_el2, 0x120, 0x200); /* Offset 0x120 */

  /* Registers */
  SET_MEMBER_RSI(unsigned long gprs[PLANE_EXIT_NR_GPRS], 0x200, 0x300); /* Offset 0x200 */

  /* GICv3 Hypervisor Control Register value */
  SET_MEMBER_RSI(unsigned long gicv3_hcr, 0x300, 0x308); /* Offset 0x300 */
  /* GICv3 List Registers values */
  SET_MEMBER_RSI(unsigned long gicv3_lrs[PLANE_GIC_NUM_LRS], 0x308, 0x388); /* Offset 0x308 */
  /* GICv3 Maintenance Interrupt State Register value */
  SET_MEMBER_RSI(unsigned long gicv3_misr, 0x388, 0x390); /* Offset 0x388 */
  /* GICv3 Virtual Machine Control Register value */
  SET_MEMBER_RSI(unsigned long gicv3_vmcr, 0x390, 0x400); /* Offset 0x390 */

  /* Counter-timer Physical Timer Control Register value */
  SET_MEMBER_RSI(unsigned long cntp_ctl, 0x400, 0x408); /* Offset 0x400 */
  /* Counter-timer Physical Timer CompareValue Register value */
  SET_MEMBER_RSI(unsigned long cntp_cval, 0x408, 0x410); /* Offset 0x408 */
  /* Counter-timer Virtual Timer Control Register value */
  SET_MEMBER_RSI(unsigned long cntv_ctl, 0x410, 0x418); /* Offset 0x410 */
  /* Counter-timer Virtual Timer CompareValue Register value */
  SET_MEMBER_RSI(unsigned long cntv_cval, 0x418, 0x800); /* Offset 0x418 */
};

struct rsi_plane_run {
  /* Plane entry information */
  SET_MEMBER_RSI(struct rsi_plane_enter enter, 0, 0x800); /* Offset 0 */
  /* Plane exit information */
  SET_MEMBER_RSI(struct rsi_plane_exit exit, 0x800, 0x1000); /* Offset 0x800 */
};

/*
 * RsiDeviceInfo
 * Contains device configuration information.
 * Width: 512 (0x200) bytes.
 */
struct rsi_device_info {
	/* UInt64: Instance identifier */
	SET_MEMBER_RSI(unsigned long inst_id, 0, 0x8);
	/* UInt64: Certificate identifier */
	SET_MEMBER_RSI(unsigned long cert_id, 0x8, 0x10);
	/* RsiHashAlgorithm: Algorithm used to generate device digests */
	SET_MEMBER_RSI(unsigned char hash_algo, 0x10, 0x40);

	/* Bits512: Certificate digest */
	SET_MEMBER_RSI(unsigned char cert_digest[64], 0x40, 0x80);
	/* Bits512: Device public key digest */
	SET_MEMBER_RSI(unsigned char key_digest[64], 0x80, 0xc0);
	/* Bits512: Measurement block digest */
	SET_MEMBER_RSI(unsigned char meas_digest[64], 0xc0, 0x100);
	/* Bits512: Interface report digest */
	SET_MEMBER_RSI(unsigned char report_digest[64], 0x100, 0x200);
};

/*
 * RsiDeviceMeasurementsParams
 * This structure contains parameters for retrieval of Realm device measurements.
 * Width: 64 (0x40) bytes.
 */
struct rsi_device_measurements_params {
	/* RsiBoolean[256]: Measurement indices */
	SET_MEMBER_RSI(unsigned char meas_ids[32], 0, 0x20);
	/* RsiBoolean[256]: Measurement parameters */
	SET_MEMBER_RSI(unsigned char meas_params[32], 0x20, 0x40);
};
#endif /* __ASSEMBLER__ */

#endif /* SMC_RSI_H */
