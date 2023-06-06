
#define TO_LOG_LEVEL_MAX 2
#define TOSE_HELPER_TLS_IO_BUFFER_SIZE 8192
#define TOSE_HELPER_TLS_RX_BUFFER_SIZE 4096

	/* Specific to TO136 */

#define TO_POWER_PIN D3

	/* Specific to TO-Protect */

#define TODRV_SSE_TOP_ADDRESS 0x08060000

/* mandatory for TO-Protect */
#define TO_DISABLE_API_HELPER_TLS_HANDLE_SERVER_CERTIFICATE
#define TO_DISABLE_API_HELPER_TLS_GET_CERTIFICATE
#define TO_DISABLE_CAPI

	/* TO-Protect.bin Flashing */
#define TODRV_SSE_TOP_ADDRESS 0x08060000

	/* Secure Storage Flashing */
/* Storage placed in 0x080A0000, to allow room for TO-Protect.bin with TRACES */
/* Definition is made in hal_nvm_mbed.cpp */

	/* Driver SSE configuration */
#define TODRV_SSE_NVM_SECTOR_SIZE 2048

