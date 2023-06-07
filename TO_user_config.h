/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2023 Trusted Objects. All rights reserved.
 */

/**
 * @file TO_user_config.h
 * @brief Group all libTO custom configuration in this file
 * Requires -DTO_USER_CONFIG on the compiler command line
 */

#include "POC_settings.h"

#define TO_LOG_LEVEL_MAX 2

#define TO_DISABLE_TLS_FULL_DUPLEX
#define TOSE_HELPER_TLS_IO_BUFFER_SIZE 4096

#if POC_SECURE_ELEMENT_USED == POC_SE_TO136
	/* Specific to TO136 */

	/* Disable need for TO-Protect files */
#	define TODRV_SSE_DRIVER_DISABLE
	/* Arduino_TO136 power switch configuration */
#	define TO_POWER_PIN D3

	/* remove dependancy to TO_defs.h/TO_CERT_X509_MAXSIZE
	* This is only an HSE/SSE internal setting
	* libTO does not have to know this SE internal limit
	*/
#	define POC_CERT_X509_MAXSIZE	512

#elif POC_SECURE_ELEMENT_USED == POC_SE_TOPROTECT /* } POC_SECURE_ELEMENT_USED { */
	/* Specific to TO-Protect */

	/* remove dependancy to TO_defs.h/TO_CERT_X509_MAXSIZE
	* This is only an HSE/SSE internal setting
	* libTO does not have to know this SE internal limit
	*/
#	define POC_CERT_X509_MAXSIZE	1024

#	define TO_DISABLE_API_HELPER_TLS_HANDLE_SERVER_CERTIFICATE
#	define TO_DISABLE_API_HELPER_TLS_GET_CERTIFICATE
#	define TO_DISABLE_CAPI

	/* Disable need for TO136 files */
#	define TODRV_HSE_DRIVER_DISABLE
	/* TO-Protect.bin Flashing */
#	define TODRV_SSE_TOP_ADDRESS 0x08060000

	/* Secure Storage Flashing */
/* Storage placed in 0x080A0000, to allow room for TO-Protect.bin with TRACES */
/* Definition is made in hal_nvm_mbed.cpp */

#else
#error Project is not configured to use any Secure Element
#endif /* } POC_SECURE_ELEMENT_USED */

/* Driver SSE configuration */
#define TODRV_SSE_NVM_SECTOR_SIZE 2048
