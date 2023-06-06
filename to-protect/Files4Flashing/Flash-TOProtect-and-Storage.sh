#!/bin/bash

# Flash PoC Firmware TLS WiFi to 0x800.0000
# STM32_Programmer_CLI -c port=SWD -d PoC_generic_tls_wifi_TOP.bin 0x08000000 --verify

# Flash TO-Protect to 0x860.0000
STM32_Programmer_CLI -c port=SWD -d TO-Protect-eval.cortexm3.bin 0x08060000 --verify

# Flash its Secure Storage to 0x80A.0000
STM32_Programmer_CLI -c port=SWD -d SecureStorage_1.bin 0x080A0000 --verify
