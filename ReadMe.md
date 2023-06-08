# Application Note: Setup TLS connection with Trusted Objects' Secure Elements

## Prepare the project directory

    mkdir AN_TO_SE_tls_wifi && cd AN_TO_SE_tls_wifi

## Clone Trusted Object demo

    git clone git@github.com:TrustedObjects/TOAN_xSE_Setup_IoT_TLS .
    git checkout main

## Install MBED OS library and DISCO_L475VG_IOT01A_wifi library

    mbed deploy

## Check the directory tree

	.
	├── DISCO_L475VG_IOT01A_wifi/
	├── DISCO_L475VG_IOT01A_wifi.lib
	├── hal_nvm_mbed.cpp
	├── libTO/
	│      ├── doc
	│      ├── examples
	│      ├── include
	│      └── src
	├── main.cpp
	├── mbed_app.json
	├── mbed-os/
	│      ├── ...
	├── mbed-os.lib
	├── ReadMe.md
	├── sample_https_get.c
	├── sample_https.h
	├── to-protect/
	│      ├── Files4Flashing/
	│      ├── TOP_info.h
	│      └── TOP_technical_info.h
	└── TO_user_config.h

## Adapt the project to your configuration
### mbed_app.json

Edit ./mbed_app.json
You will have to change WiFi credentials, and remote server.

	{
		"config": {
			"wifi-ssid": {
				"help": "WiFi SSID",
				"value": "\"to be updated with your Wifi SSID\""
			},
			"wifi-password": {
				"help": "WiFi Password",
				"value": "\"to be updated with your Wifi password\""
			},
			"server-hostname": {
				"help": "Remote Server Host Name",
				"value": "\"localhost\""
			},
			"server-go-port": {
				"help": "CA Server TCP Port",
				"value": "4443"
			}
		}
	}

## Optional: Select your Secure Element (TO136 or to-protect)

Open POC_settings.h and #define POC_SECURE_ELEMENT_USED accordingly to your choice:
	- POC_SE_TO136, if you want to test with TO136
	- POC_SE_TOPROTECT (default), if you want to test with to-protect

If you select TO136, don't forget to mount the board Arduino_TO136
onto the Arduino R3 connector of the board DISCO_L475VG_IOT01A.

## Flash the SSE (to-protect version only)

For TO136, skip this step, as TO136 comes ready and personalized by AVNET.

For to-protect, you need first to flash the SSE (Software Secure Element) and
its secure storage

The script to-protect/Files4Flashing/Flash-TOProtect-and-Storage.sh is provided
It is based on ST MicroElectronics tool named "STM32_Programmer_CLI"

	cd to-protect/Files4Flashing
	./Flash-TOProtect-and-Storage.sh

It will flash these 2 files:

	- TO-Protect-eval.cortexm3.bin, the SSE
	- SecureStorage_1.bin, the personalization data

## Generate and flash the firmware

Generate the firmware

    mbed compile -m DISCO_L475VG_IOT01A -t GCC_ARM -DTO_USER_CONFIG

Flash the firmware

    mbed compile ... -f

or copy the generated .bin file to the virtual disk associated to the MBED Board

## Start the openssl server

	Open a shell and launch the following command (there is a tls_server.sh
	in the "server" subdirectory) :

		openssl.exe s_server -WWW -accept 4443 -cert CertsTrusted\ServerCertificate-01011E0002000001.pem -key CertsTrusted\ServerKeyPair-01011E0002000001.pem -Verify 10 -CAfile CertsTrusted\Trusted-Objects-RoussetProduction-Generic_Samples_AWS-CA-Certificate-0101100002000000.pem  -state -debug -msg

	The following message will be displayed by openssl.
	The stest server is ready to accept incoming connections:

		verify depth is 10, must return a certificate
		Using default temp DH parameters
		ACCEPT

## Test the firmware

	Open a terminal after flashing the board
	Terminal configuration MUST be 115200,n,8,1

	Example with mbed-cli:

		mbed sterm --baudrate 115200

	The firmware will do the following operations

		- Initialize Secure Element, and display SECURE Element version
		- Initialize and connect Wifi
		- Connect in TLS to remote server
		- Send HTTP GET request an get `Hello world !` answer

## UART output Log

	Press the reset (black) button on the STM32L475 board
	The following kind of log will be displayed:

	[mbed] Detecting connected targets/boards to your system...
	[mbed] Opening serial terminal to "DISCO_L475VG_IOT01A"
	--- Terminal on /dev/ttyACM0 - 115200,8,N,1 ---
	[t=0.000006]
	[t=0.001298] ************************************
	[t=0.005635] * Trusted Objects TLS Demonstrator *
	[t=0.009973] ************************************
	[t=0.014313] ********** Initialize Secure Element ***************************
	[t=0.341567] POC_display_se_infos: SE version: 2.4.6
	[t=0.346128] ********** Initialize and connect Wifi *************************
	[t=0.933548] WIFI Module Initialized.
	[t=0.982506] es-wifi module MAC Address : C4:7F:51:8D:17:86
	[t=0.987735] connecting to : Freebox-4F25F0
	[t=6.097588] es-wifi module connected
	[t=6.100841] es-wifi module got IP Address : 192.168.1.174
	[t=6.105985] ********** Connect in TLS to remote server *********************
	[t=6.112752] Converting Server remote address from [192.168.1.9]
	[t=6.163503] Trying to connect to Server: 192.168.1.9:4443 ...
	[t=6.446495] TCP Connection opened successfully.
	[t=6.664601] TOSE_helper_tls_init_session: Using session 0
	[t=6.670454] POC_connect_tls_server: HostName is only an IP address (not DNS), so do NOT activate SNI extension
	[t=6.680208] POC_connect_tls_server: using certificate slot 0
	[t=6.685566] TOSE_helper_tls_do_handshake_step: *** Flight 1 ***
	[t=6.691209] TOSE_helper_tls_do_handshake_step: SNI len : 0
	[t=6.697057] TOSE_helper_tls_do_handshake_step: ==> ClientHello
	[t=6.702582] TOSE_helper_tls_do_handshake_step: *** Flight 4 ***
	[t=7.119506] TOSE_helper_tls_do_handshake_step: <== ServerHello
	[t=7.125611] TOSE_helper_tls_do_handshake_step: Detected cipher suite: c023
	[t=7.132187] TOSE_helper_tls_do_handshake_step: <== Certificate
	[t=7.654507] TOSE_helper_tls_do_handshake_step: <== ServerKeyExchange
	[t=7.967813] TOSE_helper_tls_do_handshake_step: Client authentication not requested
	[t=7.975162] TOSE_helper_tls_do_handshake_step: <== ServerHelloDone
	[t=7.981481] TOSE_helper_tls_do_handshake_step: *** Flight 5 ***
	[t=8.272055] TOSE_helper_tls_do_handshake_step: ==> ClientKeyExchange
	[t=8.420970] TOSE_helper_tls_do_handshake_step: ==> ChangeCipherSpec
	[t=8.786955] TOSE_helper_tls_do_handshake_step: ==> Finished
	[t=8.792217] TOSE_helper_tls_do_handshake_step: *** Flight 6 ***
	[t=9.155507] TOSE_helper_tls_do_handshake_step: <== ChangeCipherSpec
	[t=9.165308] TOSE_helper_tls_do_handshake_step: <== Finished
	[t=9.172577] POC_connect_tls_server: TO_helper_tls_do_handshake OK
	[t=9.178341] ********** Send HTTP GET request an get `Hello world !` answer *
	[t=9.185134] POC_http_post: HTTP request: "
	GET /index.html HTTP/1.1


	"

	[t=9.556926] POC_http_post: response : "
	HTTP/1.0 200 ok
	Content-type: text/html

	<html>
	<header><title>Hello</title></header>
	<body>
	Hello, world.
	</body>
	</html>
	"

	[t=9.615491] es-wifi disconnected
	[t=9.853851] Terminated ! Press RESET (black) button to restart

## openssl output Log

	Using only informational "-state" option on the command line, you get
	this output in the server terminal:

	openssl.exe s_server -WWW -accept 4443 -cert CertsTrusted\ServerCertificate-01011E0002000001.pem -key CertsTrusted\ServerKeyPair-01011E0002000001.pem -Verify 10 -CAfile CertsTrusted\Trusted-Objects-RoussetProduction-Generic_Samples_AWS-CA-Certificate-0101100002000000.pem  -state
	ACCEPT
	SSL_accept:before SSL initialization
	SSL_accept:before SSL initialization
	SSL_accept:SSLv3/TLS read client hello
	SSL_accept:SSLv3/TLS write server hello
	SSL_accept:SSLv3/TLS write certificate
	SSL_accept:SSLv3/TLS write key exchange
	SSL_accept:SSLv3/TLS write server done
	SSL_accept:SSLv3/TLS write server done
	SSL_accept:SSLv3/TLS read client key exchange
	SSL_accept:SSLv3/TLS read change cipher spec
	SSL_accept:SSLv3/TLS read finished
	SSL_accept:SSLv3/TLS write change cipher spec
	SSL_accept:SSLv3/TLS write finished
	FILE:index.html
	ACCEPT

## openssl output Log (Verbose)

	Adding option "-debug -msg" on the command line, you get this verbose output:

	openssl.exe s_server -WWW -accept 4443 -cert CertsTrusted\ServerCertificate-01011E0002000001.pem -key CertsTrusted\ServerKeyPair-01011E0002000001.pem -Verify 10 -CAfile CertsTrusted\Trusted-Objects-RoussetProduction-Generic_Samples_AWS-CA-Certificate-0101100002000000.pem  -state -debug -msg
	verify depth is 10, must return a certificate
	Using default temp DH parameters
	ACCEPT
	SSL_accept:before SSL initialization
	read from 0x1e109f36010 [0x1e109f4a293] (5 bytes => 5 (0x5))
	0000 - 16 03 03 00 4b                                    ....K
	<<< ??? [length 0005]
	16 03 03 00 4b
	read from 0x1e109f36010 [0x1e109f4a298] (75 bytes => 75 (0x4B))
	0000 - 01 00 00 47 03 03 00 00-00 00 be a9 e2 42 73 df   ...G.........Bs.
	0010 - 02 89 61 15 1a ac a8 4c-32 54 ad 7e 92 20 b1 ad   ..a....L2T.~. ..
	0020 - f3 f9 e9 e2 d0 2a 00 00-04 00 ae c0 23 01 00 00   .....*......#...
	0030 - 1a 00 0d 00 04 00 02 04-03 00 0a 00 04 00 02 00   ................
	0040 - 17 00 0b 00 02 01 00 00-04 00 00                  ...........
	SSL_accept:before SSL initialization
	<<< TLS 1.2Handshake [length 004b], ClientHello
	01 00 00 47 03 03 00 00 00 00 be a9 e2 42 73 df
	02 89 61 15 1a ac a8 4c 32 54 ad 7e 92 20 b1 ad
	f3 f9 e9 e2 d0 2a 00 00 04 00 ae c0 23 01 00 00
	1a 00 0d 00 04 00 02 04 03 00 0a 00 04 00 02 00
	17 00 0b 00 02 01 00 00 04 00 00
	SSL_accept:SSLv3/TLS read client hello
	>>> ??? [length 0005]
	16 03 03 00 54
	>>> TLS 1.2Handshake [length 0054], ServerHello
	02 00 00 50 03 03 4b b6 6a a3 c6 fc ff 8d 57 b8
	92 1b 59 4e 7c 20 10 45 f9 8f 07 3f 0c 77 08 99
	a3 92 3f 2f b8 36 20 86 29 bd 5d 62 a1 a6 0c 66
	e4 0e 60 cf 04 c8 9a 95 70 6e 0f a7 2e 84 99 53
	77 d4 cb f8 e5 c5 c0 c0 23 00 00 08 00 0b 00 04
	03 00 01 02
	SSL_accept:SSLv3/TLS write server hello
	>>> ??? [length 0005]
	16 03 03 04 27
	>>> TLS 1.2Handshake [length 0427], Certificate
	0b 00 04 23 00 04 20 00 01 e9 30 82 01 e5 30 82
	01 8b a0 03 02 01 02 02 08 01 01 1e 00 02 00 00
	01 30 0a 06 08 2a 86 48 ce 3d 04 03 02 30 7f 31
	1c 30 1a 06 03 55 04 07 0c 13 47 65 6e 65 72 69
	63 5f 53 61 6d 70 6c 65 73 5f 41 57 53 31 18 30
	16 06 03 55 04 0a 0c 0f 54 72 75 73 74 65 64 2d
	4f 62 6a 65 63 74 73 31 1a 30 18 06 03 55 04 0b
	0c 11 52 6f 75 73 73 65 74 50 72 6f 64 75 63 74
	69 6f 6e 31 29 30 27 06 03 55 04 03 0c 20 54 72
	75 73 74 65 64 2d 4f 62 6a 65 63 74 73 20 30 31
	30 31 31 30 30 30 30 32 30 30 30 30 30 30 30 22
	18 0f 32 30 31 34 30 31 32 31 30 30 30 30 30 30
	5a 18 0f 33 30 30 30 31 32 32 39 32 33 35 39 35
	39 5a 30 2b 31 29 30 27 06 03 55 04 03 0c 20 54
	72 75 73 74 65 64 2d 4f 62 6a 65 63 74 73 20 30
	31 30 31 31 45 30 30 30 32 30 30 30 30 30 31 30
	59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86
	48 ce 3d 03 01 07 03 42 00 04 93 ae c7 32 dc bf
	2f 49 be a9 0b 4d 24 a6 d5 4c 56 7e c3 3d 21 a2
	a7 4e 04 af 46 b5 1c d7 b1 12 01 16 8e 1c 67 dc
	c1 be be 8e 19 a8 5f e9 ff f2 d3 e2 fa ac a3 64
	b1 e0 da cc 71 5a dc 5d f3 d2 a3 41 30 3f 30 0e
	06 03 55 1d 0f 01 01 ff 04 04 03 02 03 c8 30 0c
	06 03 55 1d 13 01 01 ff 04 02 30 00 30 1f 06 03
	55 1d 23 04 18 30 16 80 14 7b b5 84 fa ee 59 71
	7e 1c 05 47 3f 1e a5 d4 e6 04 f2 87 0e 30 0a 06
	08 2a 86 48 ce 3d 04 03 02 03 48 00 30 45 02 21
	00 b3 80 ec 82 b4 ba 2e 6b bd 09 79 5d dc 1a 52
	78 17 8d 8c b1 15 98 53 17 34 70 ef 7e be 49 63
	00 02 20 68 ea 40 b4 57 71 d9 03 7d 68 c0 06 c7
	ab 51 73 7d b1 f0 01 59 76 c7 6e 9b 3c 22 25 38
	f4 9d 97 00 02 31 30 82 02 2d 30 82 01 d3 a0 03
	02 01 02 02 08 01 01 10 00 02 00 00 00 30 0a 06
	08 2a 86 48 ce 3d 04 03 02 30 61 31 18 30 16 06
	03 55 04 0a 0c 0f 54 72 75 73 74 65 64 2d 4f 62
	6a 65 63 74 73 31 1a 30 18 06 03 55 04 0b 0c 11
	52 6f 75 73 73 65 74 50 72 6f 64 75 63 74 69 6f
	6e 31 29 30 27 06 03 55 04 03 0c 20 54 72 75 73
	74 65 64 2d 4f 62 6a 65 63 74 73 20 30 30 30 31
	31 30 30 30 30 30 30 30 30 30 30 30 30 22 18 0f
	32 30 31 34 30 31 32 31 30 30 30 30 30 30 5a 18
	0f 33 30 30 30 31 32 32 39 32 33 35 39 35 39 5a
	30 7f 31 1c 30 1a 06 03 55 04 07 0c 13 47 65 6e
	65 72 69 63 5f 53 61 6d 70 6c 65 73 5f 41 57 53
	31 18 30 16 06 03 55 04 0a 0c 0f 54 72 75 73 74
	65 64 2d 4f 62 6a 65 63 74 73 31 1a 30 18 06 03
	55 04 0b 0c 11 52 6f 75 73 73 65 74 50 72 6f 64
	75 63 74 69 6f 6e 31 29 30 27 06 03 55 04 03 0c
	20 54 72 75 73 74 65 64 2d 4f 62 6a 65 63 74 73
	20 30 31 30 31 31 30 30 30 30 32 30 30 30 30 30
	30 30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08
	2a 86 48 ce 3d 03 01 07 03 42 00 04 a8 cd 31 9c
	f8 f2 ad ea 95 6a 98 89 a1 8f f4 65 ac 0c dc 0a
	58 15 b2 fc c2 63 89 45 f7 63 6e 57 1b 31 47 37
	49 9c 80 0d fc 28 40 33 3b 94 2b 4a e0 b5 45 09
	6b 52 9a 5f 1d ee fc 22 55 f9 9e 52 a3 53 30 51
	30 1d 06 03 55 1d 0e 04 16 04 14 7b b5 84 fa ee
	59 71 7e 1c 05 47 3f 1e a5 d4 e6 04 f2 87 0e 30
	0f 06 03 55 1d 13 01 01 ff 04 05 30 03 01 01 ff
	30 1f 06 03 55 1d 23 04 18 30 16 80 14 57 c2 2d
	87 76 02 58 f9 a8 e8 b2 14 20 f8 27 57 fb 82 4b
	4f 30 0a 06 08 2a 86 48 ce 3d 04 03 02 03 48 00
	30 45 02 21 00 99 ea f4 45 78 0b 89 6b f9 bb 46
	b0 66 e3 1a d5 fa dc 62 56 a3 14 9d 1e 23 e6 b6
	70 a1 7b 1a f2 02 20 6f a4 2f 7a 62 59 d2 4e 22
	d0 dd a4 43 f5 76 f0 1c d2 22 63 9a 2c 93 93 2d
	59 a0 c3 65 03 01 67
	SSL_accept:SSLv3/TLS write certificate
	>>> ??? [length 0005]
	16 03 03 00 95
	>>> TLS 1.2Handshake [length 0095], ServerKeyExchange
	0c 00 00 91 03 00 17 41 04 0b ad 31 b4 33 b5 6a
	73 71 71 b4 96 3b f5 29 eb 2f 58 d2 3c 00 7a 3c
	f4 8b f5 07 ca 4a f2 f0 be 97 11 de f9 4e 4d 3d
	4f 4d f7 91 4d e7 50 45 95 80 d1 02 9d 8b 75 0f
	9c 48 f4 05 8c 24 02 e5 96 04 03 00 48 30 46 02
	21 00 fd 98 ee 43 2d 83 bc f7 58 12 63 3b c8 7e
	ac b0 e1 f7 16 b9 cb 90 1d 99 14 37 6d 25 f9 65
	96 c1 02 21 00 ed bc c8 60 a9 ab cc 58 7c d9 9a
	b4 81 76 f5 16 20 a5 f4 73 d7 3c 87 66 83 88 33
	64 63 21 65 5b
	SSL_accept:SSLv3/TLS write key exchange
	>>> ??? [length 0005]
	16 03 03 00 ad
	>>> TLS 1.2Handshake [length 00ad], CertificateRequest
	0d 00 00 a9 03 01 02 40 00 1e 06 01 06 02 06 03
	05 01 05 02 05 03 04 01 04 02 04 03 03 01 03 02
	03 03 02 01 02 02 02 03 00 83 00 81 30 7f 31 1c
	30 1a 06 03 55 04 07 0c 13 47 65 6e 65 72 69 63
	5f 53 61 6d 70 6c 65 73 5f 41 57 53 31 18 30 16
	06 03 55 04 0a 0c 0f 54 72 75 73 74 65 64 2d 4f
	62 6a 65 63 74 73 31 1a 30 18 06 03 55 04 0b 0c
	11 52 6f 75 73 73 65 74 50 72 6f 64 75 63 74 69
	6f 6e 31 29 30 27 06 03 55 04 03 0c 20 54 72 75
	73 74 65 64 2d 4f 62 6a 65 63 74 73 20 30 31 30
	31 31 30 30 30 30 32 30 30 30 30 30 30
	SSL_accept:SSLv3/TLS write certificate request
	>>> ??? [length 0005]
	16 03 03 00 04
	>>> TLS 1.2Handshake [length 0004], ServerHelloDone
	0e 00 00 00
	write to 0x1e109f36010 [0x1e109f58a10] (1498 bytes => 1498 (0x5DA))
	0000 - 16 03 03 00 54 02 00 00-50 03 03 4b b6 6a a3 c6   ....T...P..K.j..
	0010 - fc ff 8d 57 b8 92 1b 59-4e 7c 20 10 45 f9 8f 07   ...W...YN| .E...
	0020 - 3f 0c 77 08 99 a3 92 3f-2f b8 36 20 86 29 bd 5d   ?.w....?/.6 .).]
	0030 - 62 a1 a6 0c 66 e4 0e 60-cf 04 c8 9a 95 70 6e 0f   b...f..`.....pn.
	0040 - a7 2e 84 99 53 77 d4 cb-f8 e5 c5 c0 c0 23 00 00   ....Sw.......#..
	0050 - 08 00 0b 00 04 03 00 01-02 16 03 03 04 27 0b 00   .............'..
	0060 - 04 23 00 04 20 00 01 e9-30 82 01 e5 30 82 01 8b   .#.. ...0...0...
	0070 - a0 03 02 01 02 02 08 01-01 1e 00 02 00 00 01 30   ...............0
	0080 - 0a 06 08 2a 86 48 ce 3d-04 03 02 30 7f 31 1c 30   ...*.H.=...0.1.0
	0090 - 1a 06 03 55 04 07 0c 13-47 65 6e 65 72 69 63 5f   ...U....Generic_
	00a0 - 53 61 6d 70 6c 65 73 5f-41 57 53 31 18 30 16 06   Samples_AWS1.0..
	00b0 - 03 55 04 0a 0c 0f 54 72-75 73 74 65 64 2d 4f 62   .U....Trusted-Ob
	00c0 - 6a 65 63 74 73 31 1a 30-18 06 03 55 04 0b 0c 11   jects1.0...U....
	00d0 - 52 6f 75 73 73 65 74 50-72 6f 64 75 63 74 69 6f   RoussetProductio
	00e0 - 6e 31 29 30 27 06 03 55-04 03 0c 20 54 72 75 73   n1)0'..U... Trus
	00f0 - 74 65 64 2d 4f 62 6a 65-63 74 73 20 30 31 30 31   ted-Objects 0101
	0100 - 31 30 30 30 30 32 30 30-30 30 30 30 30 22 18 0f   1000020000000"..
	0110 - 32 30 31 34 30 31 32 31-30 30 30 30 30 30 5a 18   20140121000000Z.
	0120 - 0f 33 30 30 30 31 32 32-39 32 33 35 39 35 39 5a   .30001229235959Z
	0130 - 30 2b 31 29 30 27 06 03-55 04 03 0c 20 54 72 75   0+1)0'..U... Tru
	0140 - 73 74 65 64 2d 4f 62 6a-65 63 74 73 20 30 31 30   sted-Objects 010
	0150 - 31 31 45 30 30 30 32 30-30 30 30 30 31 30 59 30   11E00020000010Y0
	0160 - 13 06 07 2a 86 48 ce 3d-02 01 06 08 2a 86 48 ce   ...*.H.=....*.H.
	0170 - 3d 03 01 07 03 42 00 04-93 ae c7 32 dc bf 2f 49   =....B.....2../I
	0180 - be a9 0b 4d 24 a6 d5 4c-56 7e c3 3d 21 a2 a7 4e   ...M$..LV~.=!..N
	0190 - 04 af 46 b5 1c d7 b1 12-01 16 8e 1c 67 dc c1 be   ..F.........g...
	01a0 - be 8e 19 a8 5f e9 ff f2-d3 e2 fa ac a3 64 b1 e0   ...._........d..
	01b0 - da cc 71 5a dc 5d f3 d2-a3 41 30 3f 30 0e 06 03   ..qZ.]...A0?0...
	01c0 - 55 1d 0f 01 01 ff 04 04-03 02 03 c8 30 0c 06 03   U...........0...
	01d0 - 55 1d 13 01 01 ff 04 02-30 00 30 1f 06 03 55 1d   U.......0.0...U.
	01e0 - 23 04 18 30 16 80 14 7b-b5 84 fa ee 59 71 7e 1c   #..0...{....Yq~.
	01f0 - 05 47 3f 1e a5 d4 e6 04-f2 87 0e 30 0a 06 08 2a   .G?........0...*
	0200 - 86 48 ce 3d 04 03 02 03-48 00 30 45 02 21 00 b3   .H.=....H.0E.!..
	0210 - 80 ec 82 b4 ba 2e 6b bd-09 79 5d dc 1a 52 78 17   ......k..y]..Rx.
	0220 - 8d 8c b1 15 98 53 17 34-70 ef 7e be 49 63 00 02   .....S.4p.~.Ic..
	0230 - 20 68 ea 40 b4 57 71 d9-03 7d 68 c0 06 c7 ab 51    h.@.Wq..}h....Q
	0240 - 73 7d b1 f0 01 59 76 c7-6e 9b 3c 22 25 38 f4 9d   s}...Yv.n.<"%8..
	0250 - 97 00 02 31 30 82 02 2d-30 82 01 d3 a0 03 02 01   ...10..-0.......
	0260 - 02 02 08 01 01 10 00 02-00 00 00 30 0a 06 08 2a   ...........0...*
	0270 - 86 48 ce 3d 04 03 02 30-61 31 18 30 16 06 03 55   .H.=...0a1.0...U
	0280 - 04 0a 0c 0f 54 72 75 73-74 65 64 2d 4f 62 6a 65   ....Trusted-Obje
	0290 - 63 74 73 31 1a 30 18 06-03 55 04 0b 0c 11 52 6f   cts1.0...U....Ro
	02a0 - 75 73 73 65 74 50 72 6f-64 75 63 74 69 6f 6e 31   ussetProduction1
	02b0 - 29 30 27 06 03 55 04 03-0c 20 54 72 75 73 74 65   )0'..U... Truste
	02c0 - 64 2d 4f 62 6a 65 63 74-73 20 30 30 30 31 31 30   d-Objects 000110
	02d0 - 30 30 30 30 30 30 30 30-30 30 30 22 18 0f 32 30   00000000000"..20
	02e0 - 31 34 30 31 32 31 30 30-30 30 30 30 5a 18 0f 33   140121000000Z..3
	02f0 - 30 30 30 31 32 32 39 32-33 35 39 35 39 5a 30 7f   0001229235959Z0.
	0300 - 31 1c 30 1a 06 03 55 04-07 0c 13 47 65 6e 65 72   1.0...U....Gener
	0310 - 69 63 5f 53 61 6d 70 6c-65 73 5f 41 57 53 31 18   ic_Samples_AWS1.
	0320 - 30 16 06 03 55 04 0a 0c-0f 54 72 75 73 74 65 64   0...U....Trusted
	0330 - 2d 4f 62 6a 65 63 74 73-31 1a 30 18 06 03 55 04   -Objects1.0...U.
	0340 - 0b 0c 11 52 6f 75 73 73-65 74 50 72 6f 64 75 63   ...RoussetProduc
	0350 - 74 69 6f 6e 31 29 30 27-06 03 55 04 03 0c 20 54   tion1)0'..U... T
	0360 - 72 75 73 74 65 64 2d 4f-62 6a 65 63 74 73 20 30   rusted-Objects 0
	0370 - 31 30 31 31 30 30 30 30-32 30 30 30 30 30 30 30   1011000020000000
	0380 - 59 30 13 06 07 2a 86 48-ce 3d 02 01 06 08 2a 86   Y0...*.H.=....*.
	0390 - 48 ce 3d 03 01 07 03 42-00 04 a8 cd 31 9c f8 f2   H.=....B....1...
	03a0 - ad ea 95 6a 98 89 a1 8f-f4 65 ac 0c dc 0a 58 15   ...j.....e....X.
	03b0 - b2 fc c2 63 89 45 f7 63-6e 57 1b 31 47 37 49 9c   ...c.E.cnW.1G7I.
	03c0 - 80 0d fc 28 40 33 3b 94-2b 4a e0 b5 45 09 6b 52   ...(@3;.+J..E.kR
	03d0 - 9a 5f 1d ee fc 22 55 f9-9e 52 a3 53 30 51 30 1d   ._..."U..R.S0Q0.
	03e0 - 06 03 55 1d 0e 04 16 04-14 7b b5 84 fa ee 59 71   ..U......{....Yq
	03f0 - 7e 1c 05 47 3f 1e a5 d4-e6 04 f2 87 0e 30 0f 06   ~..G?........0..
	0400 - 03 55 1d 13 01 01 ff 04-05 30 03 01 01 ff 30 1f   .U.......0....0.
	0410 - 06 03 55 1d 23 04 18 30-16 80 14 57 c2 2d 87 76   ..U.#..0...W.-.v
	0420 - 02 58 f9 a8 e8 b2 14 20-f8 27 57 fb 82 4b 4f 30   .X..... .'W..KO0
	0430 - 0a 06 08 2a 86 48 ce 3d-04 03 02 03 48 00 30 45   ...*.H.=....H.0E
	0440 - 02 21 00 99 ea f4 45 78-0b 89 6b f9 bb 46 b0 66   .!....Ex..k..F.f
	0450 - e3 1a d5 fa dc 62 56 a3-14 9d 1e 23 e6 b6 70 a1   .....bV....#..p.
	0460 - 7b 1a f2 02 20 6f a4 2f-7a 62 59 d2 4e 22 d0 dd   {... o./zbY.N"..
	0470 - a4 43 f5 76 f0 1c d2 22-63 9a 2c 93 93 2d 59 a0   .C.v..."c.,..-Y.
	0480 - c3 65 03 01 67 16 03 03-00 95 0c 00 00 91 03 00   .e..g...........
	0490 - 17 41 04 0b ad 31 b4 33-b5 6a 73 71 71 b4 96 3b   .A...1.3.jsqq..;
	04a0 - f5 29 eb 2f 58 d2 3c 00-7a 3c f4 8b f5 07 ca 4a   .)./X.<.z<.....J
	04b0 - f2 f0 be 97 11 de f9 4e-4d 3d 4f 4d f7 91 4d e7   .......NM=OM..M.
	04c0 - 50 45 95 80 d1 02 9d 8b-75 0f 9c 48 f4 05 8c 24   PE......u..H...$
	04d0 - 02 e5 96 04 03 00 48 30-46 02 21 00 fd 98 ee 43   ......H0F.!....C
	04e0 - 2d 83 bc f7 58 12 63 3b-c8 7e ac b0 e1 f7 16 b9   -...X.c;.~......
	04f0 - cb 90 1d 99 14 37 6d 25-f9 65 96 c1 02 21 00 ed   .....7m%.e...!..
	0500 - bc c8 60 a9 ab cc 58 7c-d9 9a b4 81 76 f5 16 20   ..`...X|....v..
	0510 - a5 f4 73 d7 3c 87 66 83-88 33 64 63 21 65 5b 16   ..s.<.f..3dc!e[.
	0520 - 03 03 00 ad 0d 00 00 a9-03 01 02 40 00 1e 06 01   ...........@....
	0530 - 06 02 06 03 05 01 05 02-05 03 04 01 04 02 04 03   ................
	0540 - 03 01 03 02 03 03 02 01-02 02 02 03 00 83 00 81   ................
	0550 - 30 7f 31 1c 30 1a 06 03-55 04 07 0c 13 47 65 6e   0.1.0...U....Gen
	0560 - 65 72 69 63 5f 53 61 6d-70 6c 65 73 5f 41 57 53   eric_Samples_AWS
	0570 - 31 18 30 16 06 03 55 04-0a 0c 0f 54 72 75 73 74   1.0...U....Trust
	0580 - 65 64 2d 4f 62 6a 65 63-74 73 31 1a 30 18 06 03   ed-Objects1.0...
	0590 - 55 04 0b 0c 11 52 6f 75-73 73 65 74 50 72 6f 64   U....RoussetProd
	05a0 - 75 63 74 69 6f 6e 31 29-30 27 06 03 55 04 03 0c   uction1)0'..U...
	05b0 - 20 54 72 75 73 74 65 64-2d 4f 62 6a 65 63 74 73    Trusted-Objects
	05c0 - 20 30 31 30 31 31 30 30-30 30 32 30 30 30 30 30    010110000200000
	05d0 - 30 16 03 03 00 04 0e 00-00 00                     0.........
	SSL_accept:SSLv3/TLS write server done
	read from 0x1e109f36010 [0x1e109f4a293] (5 bytes => 5 (0x5))
	0000 - 16 03 03 01 f1                                    .....
	<<< ??? [length 0005]
	16 03 03 01 f1
	read from 0x1e109f36010 [0x1e109f4a298] (497 bytes => 497 (0x1F1))
	0000 - 0b 00 01 ed 00 01 ea 00-01 e7 30 82 01 e3 30 82   ..........0...0.
	0010 - 01 89 a0 03 02 01 02 02-07 01 10 00 02 00 01 e6   ................
	0020 - 30 0a 06 08 2a 86 48 ce-3d 04 03 02 30 81 87 31   0...*.H.=...0..1
	0030 - 29 30 27 06 03 55 04 07-0c 20 54 72 75 73 74 65   )0'..U... Truste
	0040 - 64 2d 4f 62 6a 65 63 74-73 20 30 30 30 31 31 30   d-Objects 000110
	0050 - 30 30 30 32 30 30 30 30-30 30 31 18 30 16 06 03   00020000001.0...
	0060 - 55 04 0a 0c 0f 54 72 75-73 74 65 64 2d 4f 62 6a   U....Trusted-Obj
	0070 - 65 63 74 73 31 1a 30 18-06 03 55 04 0b 0c 11 52   ects1.0...U....R
	0080 - 6f 75 73 73 65 74 50 72-6f 64 75 63 74 69 6f 6e   oussetProduction
	0090 - 31 24 30 22 06 03 55 04-03 0c 1b 41 56 4e 45 54   1$0"..U....AVNET
	00a0 - 20 54 4f 31 33 36 20 47-65 6e 65 72 69 63 20 53    TO136 Generic S
	00b0 - 61 6d 70 6c 65 73 30 22-18 0f 32 30 31 34 30 31   amples0"..201401
	00c0 - 32 31 30 30 30 30 30 30-5a 18 0f 33 30 30 30 31   21000000Z..30001
	00d0 - 32 32 39 32 33 35 39 35-39 5a 30 21 31 1f 30 1d   229235959Z0!1.0.
	00e0 - 06 03 55 04 03 0c 16 54-4f 31 33 36 2d 30 30 30   ..U....TO136-000
	00f0 - 31 31 30 30 30 30 32 30-30 30 31 45 36 30 59 30   11000020001E60Y0
	0100 - 13 06 07 2a 86 48 ce 3d-02 01 06 08 2a 86 48 ce   ...*.H.=....*.H.
	0110 - 3d 03 01 07 03 42 00 04-d1 f7 97 94 38 24 58 ab   =....B......8$X.
	0120 - c1 a3 3c 45 d2 05 3a 3e-b9 42 f7 a5 eb c1 5c 06   ..<E..:>.B....\.
	0130 - 4d f6 1e 53 91 fb 76 b9-b0 7f 4d 5b 22 84 99 30   M..S..v...M["..0
	0140 - 52 4b 88 e0 84 23 b4 5d-38 b2 21 8a 80 d4 76 9f   RK...#.]8.!...v.
	0150 - e6 a5 67 ba 28 ca 1d a3-a3 41 30 3f 30 0e 06 03   ..g.(....A0?0...
	0160 - 55 1d 0f 01 01 ff 04 04-03 02 03 c8 30 0c 06 03   U...........0...
	0170 - 55 1d 13 01 01 ff 04 02-30 00 30 1f 06 03 55 1d   U.......0.0...U.
	0180 - 23 04 18 30 16 80 14 7b-b5 84 fa ee 59 71 7e 1c   #..0...{....Yq~.
	0190 - 05 47 3f 1e a5 d4 e6 04-f2 87 0e 30 0a 06 08 2a   .G?........0...*
	01a0 - 86 48 ce 3d 04 03 02 03-48 00 30 45 02 21 00 db   .H.=....H.0E.!..
	01b0 - 5b cd 8d a0 d9 41 e3 df-8a bc f2 83 49 18 e4 ec   [....A......I...
	01c0 - 54 3b 1d 19 8e 2d 32 84-c2 1b 04 c2 8d a9 af 02   T;...-2.........
	01d0 - 20 7a 8b 9a 36 db 25 cd-82 fc 8f 48 bc a3 2f b6    z..6.%....H../.
	01e0 - c5 8c 1e f0 33 8f 3e 6a-29 1c 03 47 5b 12 82 ea   ....3.>j)..G[...
	01f0 - 7b                                                {
	SSL_accept:SSLv3/TLS write server done
	<<< TLS 1.2Handshake [length 01f1], Certificate
	0b 00 01 ed 00 01 ea 00 01 e7 30 82 01 e3 30 82
	01 89 a0 03 02 01 02 02 07 01 10 00 02 00 01 e6
	30 0a 06 08 2a 86 48 ce 3d 04 03 02 30 81 87 31
	29 30 27 06 03 55 04 07 0c 20 54 72 75 73 74 65
	64 2d 4f 62 6a 65 63 74 73 20 30 30 30 31 31 30
	30 30 30 32 30 30 30 30 30 30 31 18 30 16 06 03
	55 04 0a 0c 0f 54 72 75 73 74 65 64 2d 4f 62 6a
	65 63 74 73 31 1a 30 18 06 03 55 04 0b 0c 11 52
	6f 75 73 73 65 74 50 72 6f 64 75 63 74 69 6f 6e
	31 24 30 22 06 03 55 04 03 0c 1b 41 56 4e 45 54
	20 54 4f 31 33 36 20 47 65 6e 65 72 69 63 20 53
	61 6d 70 6c 65 73 30 22 18 0f 32 30 31 34 30 31
	32 31 30 30 30 30 30 30 5a 18 0f 33 30 30 30 31
	32 32 39 32 33 35 39 35 39 5a 30 21 31 1f 30 1d
	06 03 55 04 03 0c 16 54 4f 31 33 36 2d 30 30 30
	31 31 30 30 30 30 32 30 30 30 31 45 36 30 59 30
	13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce
	3d 03 01 07 03 42 00 04 d1 f7 97 94 38 24 58 ab
	c1 a3 3c 45 d2 05 3a 3e b9 42 f7 a5 eb c1 5c 06
	4d f6 1e 53 91 fb 76 b9 b0 7f 4d 5b 22 84 99 30
	52 4b 88 e0 84 23 b4 5d 38 b2 21 8a 80 d4 76 9f
	e6 a5 67 ba 28 ca 1d a3 a3 41 30 3f 30 0e 06 03
	55 1d 0f 01 01 ff 04 04 03 02 03 c8 30 0c 06 03
	55 1d 13 01 01 ff 04 02 30 00 30 1f 06 03 55 1d
	23 04 18 30 16 80 14 7b b5 84 fa ee 59 71 7e 1c
	05 47 3f 1e a5 d4 e6 04 f2 87 0e 30 0a 06 08 2a
	86 48 ce 3d 04 03 02 03 48 00 30 45 02 21 00 db
	5b cd 8d a0 d9 41 e3 df 8a bc f2 83 49 18 e4 ec
	54 3b 1d 19 8e 2d 32 84 c2 1b 04 c2 8d a9 af 02
	20 7a 8b 9a 36 db 25 cd 82 fc 8f 48 bc a3 2f b6
	c5 8c 1e f0 33 8f 3e 6a 29 1c 03 47 5b 12 82 ea
	7b
	depth=0 CN = TO136-00011000020001E6
	verify error:num=20:unable to get local issuer certificate
	verify return:1
	depth=0 CN = TO136-00011000020001E6
	verify error:num=21:unable to verify the first certificate
	verify return:1
	read from 0x1e109f36010 [0x1e109f4a293] (5 bytes => 5 (0x5))
	0000 - 16 03 03 00 46                                    ....F
	<<< ??? [length 0005]
	16 03 03 00 46
	read from 0x1e109f36010 [0x1e109f4a298] (70 bytes => 70 (0x46))
	0000 - 10 00 00 42 41 04 5e 9f-a0 ae 52 2c 4d 5e a6 09   ...BA.^...R,M^..
	0010 - a2 24 db 7b 88 76 de 55-68 76 de cc 67 a6 07 b2   .$.{.v.Uhv..g...
	0020 - c8 63 62 06 17 40 1c b0-a0 5c 22 a5 1e f9 82 92   .cb..@...\".....
	0030 - 14 56 d4 46 a2 cc 4f ca-17 e9 b2 23 5b 6d f9 a4   .V.F..O....#[m..
	0040 - 50 12 69 c7 37 98                                 P.i.7.
	SSL_accept:SSLv3/TLS read client certificate
	<<< TLS 1.2Handshake [length 0046], ClientKeyExchange
	10 00 00 42 41 04 5e 9f a0 ae 52 2c 4d 5e a6 09
	a2 24 db 7b 88 76 de 55 68 76 de cc 67 a6 07 b2
	c8 63 62 06 17 40 1c b0 a0 5c 22 a5 1e f9 82 92
	14 56 d4 46 a2 cc 4f ca 17 e9 b2 23 5b 6d f9 a4
	50 12 69 c7 37 98
	read from 0x1e109f36010 [0x1e109f4a293] (5 bytes => 5 (0x5))
	0000 - 16 03 03 00 50                                    ....P
	<<< ??? [length 0005]
	16 03 03 00 50
	read from 0x1e109f36010 [0x1e109f4a298] (80 bytes => 80 (0x50))
	0000 - 0f 00 00 4c 04 03 00 48-30 46 02 21 00 ff b4 e6   ...L...H0F.!....
	0010 - 1b 4d 54 d8 62 ce 8a 3d-e5 9f 7c de 6d 6f 0c e7   .MT.b..=..|.mo..
	0020 - 02 1c 44 fe d0 8b 44 4c-a1 47 8a 55 89 02 21 00   ..D...DL.G.U..!.
	0030 - b9 6c d3 a1 89 54 b0 45-53 39 15 0a 3b 35 3b f1   .l...T.ES9..;5;.
	0040 - 5c 21 36 c6 d6 bf 51 fa-3a d9 86 ec 0b b4 19 9f   \!6...Q.:.......
	SSL_accept:SSLv3/TLS read client key exchange
	<<< TLS 1.2Handshake [length 0050], CertificateVerify
	0f 00 00 4c 04 03 00 48 30 46 02 21 00 ff b4 e6
	1b 4d 54 d8 62 ce 8a 3d e5 9f 7c de 6d 6f 0c e7
	02 1c 44 fe d0 8b 44 4c a1 47 8a 55 89 02 21 00
	b9 6c d3 a1 89 54 b0 45 53 39 15 0a 3b 35 3b f1
	5c 21 36 c6 d6 bf 51 fa 3a d9 86 ec 0b b4 19 9f
	read from 0x1e109f36010 [0x1e109f4a293] (5 bytes => 5 (0x5))
	0000 - 14 03 03 00 01                                    .....
	<<< ??? [length 0005]
	14 03 03 00 01
	read from 0x1e109f36010 [0x1e109f4a298] (1 bytes => 1 (0x1))
	0000 - 01                                                .
	SSL_accept:SSLv3/TLS read certificate verify
	read from 0x1e109f36010 [0x1e109f4a293] (5 bytes => 5 (0x5))
	0000 - 16 03 03 00 50                                    ....P
	<<< ??? [length 0005]
	16 03 03 00 50
	read from 0x1e109f36010 [0x1e109f4a298] (80 bytes => 80 (0x50))
	0000 - 58 2f 5c d1 c5 98 4c 49-0b 0e 87 f1 a6 38 cc 26   X/\...LI.....8.&
	0010 - 16 eb c1 f8 69 7c 7d 5e-c1 76 42 6a 65 7c 23 fd   ....i|}^.vBje|#.
	0020 - ca f9 ca e4 8c 04 6d 4c-84 f0 ef 3f 7f 8f 76 7b   ......mL...?..v{
	0030 - 5f 13 03 d0 93 2b 0e 75-56 0b ec 36 7b ae 04 92   _....+.uV..6{...
	0040 - e3 de 4a 4b 60 30 2e 13-34 7b e4 a5 73 f8 d9 87   ..JK`0..4{..s...
	SSL_accept:SSLv3/TLS read change cipher spec
	<<< TLS 1.2Handshake [length 0010], Finished
	14 00 00 0c 68 ee 0a c6 60 d8 bf 48 96 87 90 69
	SSL_accept:SSLv3/TLS read finished
	>>> ??? [length 0005]
	14 03 03 00 01
	>>> TLS 1.2ChangeCipherSpec [length 0001]
	01
	SSL_accept:SSLv3/TLS write change cipher spec
	>>> ??? [length 0005]
	16 03 03 00 50
	>>> TLS 1.2Handshake [length 0010], Finished
	14 00 00 0c f3 7a d8 fb 20 04 f1 d8 e4 26 99 6b
	write to 0x1e109f36010 [0x1e109f58a10] (91 bytes => 91 (0x5B))
	0000 - 14 03 03 00 01 01 16 03-03 00 50 3e e9 0c a1 b7   ..........P>....
	0010 - 5b 77 7b 3d 11 23 c1 a3-89 22 10 4d 08 8a 7e c3   [w{=.#...".M..~.
	0020 - 36 b6 dd bb 64 5d ce af-55 a1 ff ea 4c 6c a3 57   6...d]..U...Ll.W
	0030 - c9 a1 90 11 c1 71 44 16-59 8f cc 3d 67 67 d6 2c   .....qD.Y..=gg.,
	0040 - 5f a2 4b 7f 6f 13 0f aa-91 5b e4 5d 80 43 90 ac   _.K.o....[.].C..
	0050 - 17 82 50 84 09 e3 45 f0-bb 2b 4b                  ..P...E..+K
	SSL_accept:SSLv3/TLS write finished
	read from 0x1e109f36010 [0x1e109f4a293] (5 bytes => 5 (0x5))
	0000 - 17 03 03 00 50                                    ....P
	<<< ??? [length 0005]
	17 03 03 00 50
	read from 0x1e109f36010 [0x1e109f4a298] (80 bytes => 80 (0x50))
	0000 - 4d 1b a8 ce 07 a8 d0 f1-71 5a c8 1d 46 cf 9a d1   M.......qZ..F...
	0010 - 12 7c 48 cb a9 67 f1 b4-9f 63 91 57 ee 82 64 bd   .|H..g...c.W..d.
	0020 - 40 ba 9c 2f 1d 7d 4e 7a-d3 61 22 7e 6e 26 82 ff   @../.}Nz.a"~n&..
	0030 - 6a 60 14 d6 72 f0 c2 cf-b1 ff c4 4b 9b 0d 41 e8   j`..r......K..A.
	0040 - 59 59 66 dc 93 85 eb 8d-81 4d b7 21 43 ef 3a 41   YYf......M.!C.:A
	FILE:index.html
	>>> ??? [length 0005]
	17 03 03 00 b0
	write to 0x1e109f36010 [0x1e109f53943] (181 bytes => 181 (0xB5))
	0000 - 17 03 03 00 b0 31 95 5a-44 15 44 e0 51 96 cc 8b   .....1.ZD.D.Q...
	0010 - 46 6d 7b c8 87 66 f5 99-03 00 a9 c5 e6 7a f2 33   Fm{..f.......z.3
	0020 - 6a 6a 9a 53 84 4d 3b 40-c1 74 90 f3 50 cd 7f c3   jj.S.M;@.t..P...
	0030 - 2a 7b e7 14 df fa ae 5e-74 aa 26 33 89 e5 91 43   *{.....^t.&3...C
	0040 - 87 b1 75 40 b3 61 70 42-40 7b 72 31 da f2 d2 d9   ..u@.apB@{r1....
	0050 - a4 fc e1 a0 f1 28 66 57-20 53 86 fe 76 e0 34 78   .....(fW S..v.4x
	0060 - 17 fc bc 4f 0c 86 44 3a-01 43 f9 ac 20 be 08 e1   ...O..D:.C.. ...
	0070 - c8 a1 90 3a 0d c0 95 7e-9e 6d 52 14 79 ec 51 bd   ...:...~.mR.y.Q.
	0080 - f6 5c 28 73 10 08 8d cf-e1 dd db 48 75 65 2c c5   .\(s.......Hue,.
	0090 - f8 86 1a 49 0f 62 5a b6-64 2c 5c d3 35 36 89 2b   ...I.bZ.d,\.56.+
	00a0 - c8 ff 19 84 dc fc 8b c9-8f 5f 55 14 93 86 ad 9c   ........._U.....
	00b0 - 90 57 55 bc ef                                    .WU..
	ACCEPT

