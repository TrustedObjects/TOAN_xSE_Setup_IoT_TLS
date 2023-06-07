/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2017 Trusted Objects. All rights reserved.
 */

/**
 * @file sample_https.h
 * @brief POC sample defines and prototypes
 */

#ifndef _SAMPLE_HTTPS_H_
#define _SAMPLE_HTTPS_H_

#ifdef __cplusplus
extern "C" {
#endif

	int POC_init_se(void);
	int POC_fini_se(void);
	int POC_display_se_infos(void);

	int POC_set_certificate_slot(uint8_t cert_slot);

	int POC_connect_tls_server(void *socket, int reset_tls, char *remote_hostname);
	int POC_disconnect_tls_server(void *socket);

	int POC_http_post(const char *url, char *http_request, int http_request_len, char **http_response);

	void POC_display_time(void);

#ifdef __cplusplus
}
#endif

#define LOG(...) do { POC_display_time(); printf(__VA_ARGS__); printf("\n"); } while(0)

#endif // _SAMPLE_HTTPS_H_

