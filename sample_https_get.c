/**
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTIONs OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright 2018-2019 Trusted Objects
 *
 * @file libTO_sample_https_get.c
 * @brief HTTPS get sample
 */

#include "wifi.h"

#include "TO.h"
#include "TO_helper.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sample_https.h"

/* Private defines -----------------------------------------------------------*/
#define WIFI_WRITE_TIMEOUT 10000
#define WIFI_READ_TIMEOUT 10000

#define CERT_IDX_MAX 3


static TOSE_ctx_t *to_se_ctx;  /* Trusted Objects' HSE / SSE context */
static TOSE_helper_tls_ctx_t *to_tls_ctx; /* Trusted Objects' Helper context */
#if POC_SECURE_ELEMENT_USED == POC_SE_TOPROTECT
static TO_log_ctx_t *to_log_ctx;
#endif

static uint8_t libTO_cert_slot = 0; // Default: Bootstrap certificate

static char response[2048];

TO_lib_ret_t TODRV_SSE_secure_storage_init(void); /* TODO: add to some include */

#if POC_SECURE_ELEMENT_USED == POC_SE_TOPROTECT
/* HAL NVM interface */
TO_lib_ret_t HAL_nvm_secure_storage_init(void);
TO_lib_ret_t HAL_nvm_secure_storage_deinit(void);
#endif

/**
 * Receive callback for libTO
 */

TO_lib_ret_t user_recv(void *ctx, uint8_t *buf, uint32_t len, uint32_t *read_len, int32_t timeout)
{
	int32_t _socket = *(int32_t*)(ctx);
	uint16_t Datalen;
	if (timeout == (int32_t)0xFFFFFFFF)
	{
		timeout = 0;
		TO_LOG_DBG("TCP RECVing(len=%d)", len);
	}
	else
	{
		TO_LOG_DBG("TCP RECVing(len=%d, timeout=%lu)", len, timeout);
	}

	// Truncate to WIFI maximum payload (else driver returns an error)
	len = (len > ES_WIFI_PAYLOAD_SIZE) ? ES_WIFI_PAYLOAD_SIZE : len;

	if (WIFI_ReceiveData(_socket, (uint8_t *)buf, len, &Datalen, timeout) == WIFI_STATUS_OK)
	{
		TO_LOG_DBG("TCP RECVed(len=%d)", Datalen);
		*read_len = Datalen;
		return TO_OK;
	}
	else
	{
		TO_LOG_ERR("ERROR : Failed to Receive Data (len=%d).", len);
		*read_len = 0;
		return TO_ERROR;
	}

	return TO_OK;
}

/**
 * Send callback for libTO
 */
TO_lib_ret_t user_send(void *ctx, const uint8_t *buf, const uint32_t len)
{
	int32_t _socket = *(int32_t*)(ctx);
	uint16_t Datalen;
	uint32_t tx_len = len;

	while (tx_len)
	{
		TO_LOG_DBG("TCP SEND(len=%lu)", tx_len);
		// Truncate to WIFI maximum payload (WiFi driver truncates, without returning an error)
		if (WIFI_SendData(_socket, (uint8_t *)buf, tx_len, &Datalen, WIFI_WRITE_TIMEOUT) != WIFI_STATUS_OK)
		{
			TO_LOG_ERR("ERROR: Failed to send Data.");
			return TO_OK;
		}
		else
		{
			TO_LOG_DBG("TCP SENT(len=%u)", Datalen);
		}

		tx_len -= Datalen;
		buf += Datalen;
	}

	return TO_OK;
}



int POC_init_se(void)
{
	int errTO;

#if POC_SECURE_ELEMENT_USED == POC_SE_TO136
	to_se_ctx = TODRV_HSE_get_ctx();
#elif POC_SECURE_ELEMENT_USED == POC_SE_TOPROTECT
	to_se_ctx = TODRV_SSE_get_ctx();
	to_log_ctx = TO_log_get_ctx();
#else
#error Project is not configured to use any Secure Element
#endif

#if 0 //POC_SECURE_ELEMENT_USED == POC_SE_TOPROTECT

	/*
	 * These tests are for INTEGRATION mode ONLY
	 * To be removed in PRODUCTION mode
	 */

	errTO = TODRV_SSE_top_self_test(to_log_ctx);
	if (errTO != TO_OK)
	{
		TO_LOG_ERR("TO_init() failed %d", errTO);
		return -1;
	}

	errTO = TODRV_SSE_nvm_self_test(to_log_ctx);
	if (errTO != TO_OK)
	{
		TO_LOG_ERR("TO_init() failed %d", errTO);
		return -1;
	}
#endif

#if POC_SECURE_ELEMENT_USED == POC_SE_TOPROTECT
	errTO = HAL_nvm_secure_storage_init();
	if (errTO != TO_OK) {
		TO_LOG_ERR("TODRV_SSE_secure_storage_init() failed %d", errTO);
		return -1;
	} else {
		TO_LOG_INF("TODRV_SSE_secure_storage_init() OK");
	}
#endif
	errTO = TOSE_init(to_se_ctx);
	if (errTO != TO_OK) {
		TO_LOG_ERR("TO_init() failed %d", errTO);
		return -1;
	} else {
		TO_LOG_DBG("TO_init() : OK");
	}

	return 0;
}

int POC_fini_se(void)
{
	int errTO;

	errTO = TOSE_fini(to_se_ctx);
	if (errTO != TO_OK) {
		TO_LOG_ERR("TO_fini() failed %d", errTO);
		return -1;
	}

#if POC_SECURE_ELEMENT_USED == POC_SE_TOPROTECT
	errTO = HAL_nvm_secure_storage_deinit();

	if (errTO != TO_OK) {
		TO_LOG_ERR("HAL_nvm_secure_storage_deinit() failed %d", errTO);
		return -1;
	} else {
		TO_LOG_INF("HAL_nvm_secure_storage_deinit() OK");
	}
#endif

	return 0;
}

int POC_display_se_infos(void)
{
	int errTO;

	// Display some useful versioning information

	uint8_t a, b, c;
	errTO = TOSE_get_software_version(to_se_ctx, &a, &b, &c);
	if (errTO != TORSP_SUCCESS)
	{
		TO_LOG_ERR("TO_KO: %d, %d", __LINE__, errTO);
		goto error_to;
	}
	else
	{
		TO_LOG_INF("SE version: %d.%d.%d", a, b, c);
	}

	uint8_t serial[8];
	uint16_t serial_length;

	serial_length = sizeof(serial);
 	errTO = TOSE_get_serial_number(to_se_ctx, serial, &serial_length);
	if (errTO != TORSP_SUCCESS)
	{
		TO_LOG_ERR("TO_KO: %d, %d", __LINE__, errTO);
		goto error_to;
	}
	else
	{
		TO_LOG_DBG("SE serial: %02X%02X%02X%02X%02X%02X%02X%02X", serial[0], serial[1], serial[2], serial[3], serial[4], serial[5], serial[6], serial[7]);
	}

	return 0;

error_to:
	return -1;
}

int POC_set_certificate_slot(uint8_t cert_slot)
{
	if (cert_slot > CERT_IDX_MAX)
	{
		TO_LOG_ERR("Invalid slot; must be in range [0,%d]", CERT_IDX_MAX);
		return -1;
	}

	TO_LOG_DBG("TO_OK: Using Certificate Slot [%d]", cert_slot);
	libTO_cert_slot = cert_slot;
	return 0;
}

int POC_connect_tls_server(void *socket, int reset_tls, char *remote_hostname)
{
	int errTO;

	TO_LOG_DBG("TO_helper_tls_handshake...");

	if (reset_tls)
	{
		TO_LOG_DBG("Resetting TLS");
		errTO = TOSE_tls_reset(to_se_ctx);
		if (errTO != TORSP_SUCCESS)
		{
			TO_LOG_ERR("TO_KO: %d, %d", __LINE__, errTO);
			goto error_to;
		}
		else
		{
			TO_LOG_DBG("TO TLS reset OK");
		}
	}

	errTO = TOSE_helper_tls_init_session(to_se_ctx, &to_tls_ctx, 0,
					   socket,
					   user_send, user_recv);
	if (errTO != TO_OK)
	{
		TO_LOG_ERR("TO_KO: %d, %d", __LINE__, errTO);
		return -1;
	}
	else
	{
		TO_LOG_DBG("TO_helper_tls_init OK");
	}

	// Activate SNI extension if hostname is a DNS name
	if ((remote_hostname != NULL) && (!isdigit(remote_hostname[0])))
	{

		errTO = TOSE_helper_tls_set_server_name(to_tls_ctx, remote_hostname);
		if (errTO != TO_OK)
		{
			TO_LOG_ERR("Failed to activate SNI extension %04x", errTO);
			return -1;
		}
		else
		{
			TO_LOG_INF("SNI activated");
		}
	}
	else
	{
		TO_LOG_INF("HostName is only an IP address (not DNS), so do NOT activate SNI extension");
	}

	// call TO_helper_tls_set_config AFTER TO_helper_tls_init_session
	errTO = TOSE_helper_tls_set_config_certificate_slot(to_tls_ctx, libTO_cert_slot) ;

	if (errTO != TO_OK)
	{
		TO_LOG_ERR("Failed to force certificate slot with error %04x", errTO);
		return -1;
	}
	else
	{
		TO_LOG_INF("using certificate slot %d", libTO_cert_slot);
	}

	errTO = TOSE_helper_tls_do_handshake(to_tls_ctx);
	if (errTO != TO_OK)
	{
		TO_LOG_ERR("TO_KO: %d, %d", __LINE__, errTO);
		return -1;
	}
	else
	{
		TO_LOG_INF("TO_helper_tls_do_handshake OK");
	}

	return 0;

error_to:
	return -1;
}

int POC_disconnect_tls_server(void *socket)
{
	int errTO;

	errTO = TOSE_helper_tls_cleanup(to_tls_ctx);
	if (errTO != TO_OK)
	{
		TO_LOG_ERR("TO_KO: %d, %d", __LINE__, errTO);
		return -1;
	}
	else
	{
		TO_LOG_INF("TO_helper_tls_cleanup OK");
	}

	return 0;
}


/**                                                                           */
/*  Issue an HTTP command                                                     */
/*                                                                            */
/*   @param url = a string with the URL address to contact                    */
/*   @param postData = an HTTP request string                                 */
/*   @param pRespData = a pointer to a string where the HTTP response         */
/*                      data gets set.  NOTE: This memory gets DYNAMICALLY    */
/*   @return 0 on successfull completion                                      */
/*                                                                            */
int POC_http_post(const char *url, char *http_request, int http_request_len, char **http_response)
{
	int errTO;
	uint32_t response_len;

	TO_LOG_INF("HTTP request: \"\n%s\n\"\n", http_request);

	errTO = TOSE_helper_tls_send(to_tls_ctx, (uint8_t *)http_request, http_request_len);
	if (errTO != TO_OK)
	{
		TO_LOG_ERR("TO_KO: %d, %d", __LINE__, errTO);
		goto error;
	}
	else
	{
		TO_LOG_DBG("TO_helper_tls_send OK");
	}

	response[0] = 0;

	errTO = TOSE_helper_tls_receive(to_tls_ctx, (uint8_t *)response, sizeof(response) - 1, &response_len, 5000);
	if (errTO != TO_OK)
	{
		TO_LOG_ERR("TO_KO: %d, %d", __LINE__, errTO);
		goto error;
	}

	if (response_len <= 0)
	{
		TO_LOG_ERR("no response");
		goto error;
	}

	TO_LOG_DBG("TO_helper_tls_receive OK");

	response[response_len] = 0; // AsciiZ
	TO_LOG_INF("response : \"\n%s\n\"\n", response);

	if (errTO != TO_OK)
	{
		TO_LOG_ERR("TO_KO: %d, %d", __LINE__, errTO);
		goto error;
	}

	*http_response = response;

	return 0;

error:
	*http_response = NULL;
	return -1;
}

/*
	Implement SSE logging 'weak' function
*/
void print_log_function(const TO_log_level_t level, const char *log)
{
	POC_display_time(); printf("%s\n", log);
}

