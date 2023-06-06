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
 * @file main.cpp
 * @brief Trusted Objects' TLS Stack usage example
 */

#include "mbed.h"
#include "wifi.h"

#include "sample_https.h"

/* Private defines -----------------------------------------------------------*/
#define CONNECTION_TRIAL_MAX 10

enum
{
	TLS_CNX_FULL_HANDHAKE,
	TLS_CNX_RESUME_HANDHAKE,
};

/* Private macro -------------------------------------------------------------*/

#define TEST_AND_CHECK(action)                                    \
	{                                                         \
		int status;                                       \
		status = (action);                                \
		if (status != 0)                                  \
		{                                                 \
			LOG("DA_KO: %d, %d", __LINE__, status); \
			goto exit;                                    \
		}                                                 \
	}

/* Private prototypes --------------------------------------------------------*/

static int initialize_wifi(void);

static int connect_wifi(void);
static int disconnect_wifi(void);

static int connect_tls_server(int mode);
static int disconnect_tls_server(void);


/* Private variables ---------------------------------------------------------*/

static char http_request[] = "GET /index.html HTTP/1.1\r\n\r\n";

Serial pc(SERIAL_TX, SERIAL_RX);
DigitalIn button(USER_BUTTON);

static uint8_t RemoteIP[4];
static uint8_t MAC_Addr[6];
static uint8_t IP_Addr[4];

static int32_t Socket = -1;

Timer t_elapsed;

/**
 * @brief main function
 *
 * This main function will start a Command line interface
 * The main USB (emulating a RS232 line) is used
 *
 * @return
 * - 0: success
 * - 1: failure
 */
int main()
{
	pc.baud(115200);
	char *server_response;

	t_elapsed.start();

	LOG(" ");
	LOG("************************************");
	LOG("* Trusted Objects TLS Demonstrator *");
	LOG("************************************");

	// Enable writing to ROM while in main (mandatory when using STM32 HAL)
	ScopedRomWriteLock make_rom_writable;

	LOG("********** Initialize Secure Element ***************************");

	TEST_AND_CHECK(POC_init_se());
	TEST_AND_CHECK(POC_display_se_infos());

	LOG("********** Initialize and connect Wifi *************************");

	TEST_AND_CHECK(initialize_wifi());
	TEST_AND_CHECK(connect_wifi());

	LOG("********** Connect in TLS to remote server *********************");

	TEST_AND_CHECK(connect_tls_server(TLS_CNX_FULL_HANDHAKE));

	LOG("********** Send HTTP GET request an get `Hello world !` answer *");

	TEST_AND_CHECK(POC_http_post(MBED_CONF_APP_SERVER_HOSTNAME, http_request, strlen(http_request), &server_response));

	/* Here, HTTP server normally cut the connection already */
	goto end;

exit:
	disconnect_tls_server();

end:
	disconnect_wifi();

	POC_fini_se();

	LOG("Terminated ! Press RESET (black) button to restart");

	t_elapsed.stop();
	return 0;
}

/**
 * @brief Initializes the WiFi
 * @param none
 *
 * WiFi SSID & Password comes from mbed_app.json
 * and can can be overriden by pressing the User Button right after Reset
 *
 * @return
 * - 0: success
 * - -1: an error occured
 */
static int initialize_wifi(void)
{
	/*Initialize  WIFI module */
	if (WIFI_Init() == WIFI_STATUS_OK)
	{
		LOG("WIFI Module Initialized.");
	}
	else
	{
		LOG("ERROR: WIFI Module cannot be initialized.");
		return -1;
	}

	if (WIFI_GetMAC_Address(MAC_Addr) == WIFI_STATUS_OK)
	{
		LOG("es-wifi module MAC Address : %X:%X:%X:%X:%X:%X",
		    MAC_Addr[0],
		    MAC_Addr[1],
		    MAC_Addr[2],
		    MAC_Addr[3],
		    MAC_Addr[4],
		    MAC_Addr[5]);
	}
	else
	{
		LOG("ERROR: CANNOT get MAC address");
		return -1;
	}

	return 0;
}

/**
 * @brief Connects the WiFi
 * @param none
 *
 * WiFi SSID & Password comes from mbed_app.json
 * and can can be overriden by pressing the User Button right after Reset
 *
 * @return
 * - 0: success
 * - -1: an error occured
 */
static int connect_wifi(void)
{
	LOG("connecting to : %s", MBED_CONF_APP_WIFI_SSID);
	if (WIFI_Connect(MBED_CONF_APP_WIFI_SSID, MBED_CONF_APP_WIFI_PASSWORD, WIFI_ECN_WPA2_PSK) == WIFI_STATUS_OK)
	{
		LOG("es-wifi module connected");
		/* Get Device local Address */
		if (WIFI_GetIP_Address(IP_Addr) == WIFI_STATUS_OK)
		{
			LOG("es-wifi module got IP Address : %d.%d.%d.%d",
			    IP_Addr[0],
			    IP_Addr[1],
			    IP_Addr[2],
			    IP_Addr[3]);
		}
		else
		{
			LOG("ERROR: es-wifi module CANNOT get IP address");
			return -1;
		}
	}
	else
	{
		LOG("ERROR: es-wifi module CANNOT connect");
		return -1;
	}

	return 0;
}

/**
 * @brief Disconnects the WiFi
 * @param none
 *
 * @return
 * - 0: success
 * - -1: an error occured
 */
static int disconnect_wifi(void)
{
	if (WIFI_Disconnect() == WIFI_STATUS_OK)
	{
		LOG("es-wifi disconnected");
	}
	else
	{
		LOG("ERROR disconnecting WiFi ");
		return -1;
	}

	return 0;
}

/**
 * @brief Initiate a TLS connection with the remote server
 * @param mode  perform FULL or RESUME handshake  (TLS_CNX_FULL_HANDHAKE ...)
 *
 * Server HostName comes from mbed_app.json
 * and can can be overriden by pressing the User Button right after Reset
 *
 * @return
 * - 0: success
 * - -1: an error occured
 */


int connect_tls_server(int mode)
{
	uint16_t Trials = CONNECTION_TRIAL_MAX;

	/* Check that WiFi is connected first */
	if (WIFI_GetIP_Address(IP_Addr) != WIFI_STATUS_OK)
	{
		LOG("WiFi is NOT connected; You need to connect WiFi FIRST !!!");
		return -1;
	}

	/* Get Host Remote Address */
	LOG("Converting Server remote address from [%s]", MBED_CONF_APP_SERVER_HOSTNAME);
	if (WIFI_GetHostAddress((char *)MBED_CONF_APP_SERVER_HOSTNAME, RemoteIP) == WIFI_STATUS_OK)
	{
		LOG("Trying to connect to Server: %d.%d.%d.%d:%d ...",
		    RemoteIP[0],
		    RemoteIP[1],
		    RemoteIP[2],
		    RemoteIP[3],
		    MBED_CONF_APP_SERVER_PORT);
	}
	else
	{
		LOG("Exiting ... cannot get Server remote address from [%s]", MBED_CONF_APP_SERVER_HOSTNAME);
		return -1;
	}

	while (Trials--)
	{
		if (WIFI_OpenClientConnection(0, WIFI_TCP_PROTOCOL, "TCP_CLIENT", RemoteIP, MBED_CONF_APP_SERVER_PORT, 0) == WIFI_STATUS_OK)
		{
			LOG("TCP Connection opened successfully.");
			Socket = 0;
			break;
		}
	}
	if (!Trials)
	{
		LOG("ERROR: Cannot open Connection");
		return -1;
	}

	int errTO;
	int reset_tls;
	reset_tls = (mode == TLS_CNX_FULL_HANDHAKE) ? 1 : 0;
	// connect in TLS
	errTO = POC_connect_tls_server(static_cast<void *>(&Socket), reset_tls, (char *)MBED_CONF_APP_SERVER_HOSTNAME);
	if (errTO != 0)
	{
		LOG("TO_KO: %d, %d", __LINE__, errTO);
		return -1;
	}

	return 0;
}

/**
 * @brief Terminates a TLS connection with the remote server
 * @param none
 *
 * @return
 * - 0: success
 * - -1: an error occured
 */
static int disconnect_tls_server(void)
{
	if (Socket == -1)
	{
		LOG("You are NOT connected !");
		return -1;
	}

	POC_disconnect_tls_server(static_cast<void *>(&Socket));

	WIFI_CloseClientConnection(0);

	Socket = -1;

	return 0;
}

/**
 * @brief Display elapsed time
 *
 */

void POC_display_time(void)
{
	printf("[t=%f] ", t_elapsed.read());
}

