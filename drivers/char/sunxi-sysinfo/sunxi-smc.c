/*
 * Based on arch/arm64/kernel/chipid-sunxi.c
 *
 * Copyright (C) 2015 Allwinnertech Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/sunxi-smc.h>
#include <linux/sunxi-sid.h>

#ifdef CONFIG_ARM
/*cmd to call ATF service*/
#define ARM_SVC_EFUSE_PROBE_SECURE_ENABLE    (0x8000fe03)
#define ARM_SVC_READ_SEC_REG                 (0x8000ff05)
#define ARM_SVC_WRITE_SEC_REG                (0x8000ff06)
#endif

#ifdef CONFIG_ARM64
/*cmd to call ATF service*/
#define ARM_SVC_EFUSE_PROBE_SECURE_ENABLE    (0xc000fe03)
#define ARM_SVC_READ_SEC_REG                 (0xC000ff05)
#define ARM_SVC_WRITE_SEC_REG                (0xC000ff06)
#endif

/*interface for smc */
int sunxi_smc_readl(phys_addr_t addr)
{
	return invoke_smc_fn(ARM_SVC_READ_SEC_REG, addr, 0, 0);
}
EXPORT_SYMBOL_GPL(sunxi_smc_readl);

int sunxi_smc_writel(u32 value, phys_addr_t addr)
{
	return invoke_smc_fn(ARM_SVC_WRITE_SEC_REG, addr, value, 0);
}
EXPORT_SYMBOL_GPL(sunxi_smc_writel);

int sunxi_smc_probe_secure(void)
{
	return invoke_smc_fn(ARM_SVC_EFUSE_PROBE_SECURE_ENABLE,
			0, 0, 0);
}

/*called by DISP module when resume from standby*/

/*optee smc*/
#define ARM_SMCCC_STD_CALL		0
#define ARM_SMCCC_FAST_CALL		1
#define ARM_SMCCC_TYPE_SHIFT		31

#define ARM_SMCCC_SMC_32		0
#define ARM_SMCCC_SMC_64		1
#define ARM_SMCCC_CALL_CONV_SHIFT	30

#define ARM_SMCCC_OWNER_MASK		0x3F
#define ARM_SMCCC_OWNER_SHIFT		24

#define ARM_SMCCC_FUNC_MASK		0xFFFF
#define ARM_SMCCC_OWNER_TRUSTED_OS	50

#define ARM_SMCCC_IS_FAST_CALL(smc_val)	\
	((smc_val) & (ARM_SMCCC_FAST_CALL << ARM_SMCCC_TYPE_SHIFT))
#define ARM_SMCCC_IS_64(smc_val) \
	((smc_val) & (ARM_SMCCC_SMC_64 << ARM_SMCCC_CALL_CONV_SHIFT))
#define ARM_SMCCC_FUNC_NUM(smc_val)	((smc_val) & ARM_SMCCC_FUNC_MASK)
#define ARM_SMCCC_OWNER_NUM(smc_val) \
	(((smc_val) >> ARM_SMCCC_OWNER_SHIFT) & ARM_SMCCC_OWNER_MASK)

#define ARM_SMCCC_CALL_VAL(type, calling_convention, owner, func_num) \
	(((type) << ARM_SMCCC_TYPE_SHIFT) | \
	((calling_convention) << ARM_SMCCC_CALL_CONV_SHIFT) | \
	(((owner) & ARM_SMCCC_OWNER_MASK) << ARM_SMCCC_OWNER_SHIFT) | \
	((func_num) & ARM_SMCCC_FUNC_MASK))

#define OPTEE_SMC_FAST_CALL_VAL(func_num) \
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_32, \
			   ARM_SMCCC_OWNER_TRUSTED_OS, (func_num))

#define OPTEE_SMC_FUNCID_CRYPT  16
#define OPTEE_SMC_CRYPT \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_CRYPT)

#define TEESMC_RSSK_DECRYPT      5
int sunxi_smc_refresh_hdcp(void)
{
	return invoke_smc_fn(OPTEE_SMC_CRYPT, TEESMC_RSSK_DECRYPT, 0 , 0);
}
EXPORT_SYMBOL(sunxi_smc_refresh_hdcp);
