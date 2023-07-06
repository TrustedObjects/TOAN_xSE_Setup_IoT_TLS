/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright 2016-2021 Trusted Objects
 */

/**
 * @file get_sn
 * @brief Example getting and printing Secure Element serial number.
 */

#include <stdlib.h>
#include "TO.h"
#include "TO_driver.h"
#include "TO_retcodes.h"

void print_log_function(const TO_log_level_t level, const char *log)
{
	switch (level & TO_LOG_LEVEL_MASK) {
		case TO_LOG_LEVEL_ERR:
			fprintf(stderr,"%s\n",log);
			break;

		case TO_LOG_LEVEL_DBG:
		case TO_LOG_LEVEL_INF:
		case TO_LOG_LEVEL_WRN:
			fprintf(stdout,"%s\n",log);
			break;

		default:
			break;
	}
}

int main(void)
{
	unsigned int i;

	if (TOSE_init(DEFAULT_CTX) != TO_OK) {
		fprintf(stderr, "Unable to initialize TO\n");
		TOSE_fini(DEFAULT_CTX);
		exit (-1);
	}
	printf("Secure Element initialized\n");
	uint16_t serial_number_length = 0;
	if (TOSE_get_serial_number(DEFAULT_CTX, NULL, &serial_number_length) != TORSP_INVALID_OUTPUT_LEN) {
		fprintf(stderr, "Unable to get Secure Element serial number\n");
		TOSE_fini(DEFAULT_CTX);
		exit (-3);
	}
	uint8_t serial_number[serial_number_length];
	if (TOSE_get_serial_number(DEFAULT_CTX, serial_number, &serial_number_length) != TORSP_SUCCESS) {
		fprintf(stderr, "Unable to get Secure Element serial number\n");
		TOSE_fini(DEFAULT_CTX);
		exit (-4);
	}
	printf("Secure Element serial number:");
	for (i = 0; i < serial_number_length; i++)
		printf(" %02X", serial_number[i]);
	printf("\n");

	TOSE_fini(DEFAULT_CTX);
	exit(0);
}

