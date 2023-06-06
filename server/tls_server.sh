#!/bin/bash

openssl s_server -WWW -accept 443 -cert CertsAvnet/ServerCertificate-00021E0002000001.pem -key CertsAvnet/ServerKeyPair-00021E0002000001.pem -Verify 10 -CAfile CertsAvnet/Avnet-MunichProduction-Generic_Samples_AWS-CA-Certificate-0002100002000000.pem   -state -debug -msg
