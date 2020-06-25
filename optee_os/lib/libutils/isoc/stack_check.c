// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifdef __KERNEL__
#include <kernel/panic.h>
#else
#include <tee_api.h>
#include <trace.h>

#define panic(m) \
	EMSG(m); \
	TEE_Panic(TEE_ERROR_OVERFLOW);
	
#endif

#include <compiler.h>
void *__stack_chk_guard __nex_data = (void *)0x00000aff;

void __attribute__((noreturn)) __stack_chk_fail(void);

void __stack_chk_fail(void)
{
	panic("Stack canary corrupted");
}

