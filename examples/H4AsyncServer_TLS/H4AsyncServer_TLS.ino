#include <Arduino.h>
// Only available for ESP32 targets for now.
#include<WiFi.h>

/* 	
	TLS BUILD INSTRUCTIONS:
	
	USE the custom Arduino build available at: https://github.com/hamzahajeir/arduino-esp32 on branch lwip-tls
	URL:https://github.com/HamzaHajeir/arduino-esp32/tree/lwip-tls
	
	ENSURE H4AT_USE_TLS is defined to 1 at <h4async_config.h> file.
	ENSURE the build flags contains the definitions: 
	
	LWIP_ALTCP=1
	LWIP_ALTCP_TLS=1
	LWIP_ALTCP_TLE_MBEDTLS=1
 */

// This is an illustration for TLS setup. FOR Advanced servers (HTTP), checkout HamzaHajeir/H4AsyncWebServer repository.
// You'll need to make similar changes over them to support the TLS.
#include <H4.h>
#include <H4AsyncTCP.h>
#include <H4Tools.h>

#define YOUR_SSID "XXXXXXXX"
#define YOUR_PWD "XXXXXXXX"

H4 h4(115200);

// Taken from H4AsyncWebServer/src/EchoServer.h
class EchoServer: public H4AsyncServer {
  public:
    EchoServer(uint16_t port): H4AsyncServer(port){}
        void            route(void* c,const uint8_t* data,size_t len) override { reinterpret_cast<H4AsyncClient*>(c)->TX(data,len); };
};

EchoServer server(443);

// Exampe certificate,, make your own for any serious use.
std::string serverCert = R"(-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIUTTk4lTotgitbnMP+Et/ehNdXOwEwDQYJKoZIhvcNAQEL
BQAwSTELMAkGA1UEBhMCSk8xDDAKBgNVBAgMA0FNTTEMMAoGA1UEBwwDQU1NMQsw
CQYDVQQKDAJINDERMA8GA1UEAwwISDRUZXN0ZXIwHhcNMjMwNjEwMTQwODI3WhcN
MjQwNjA5MTQwODI3WjBJMQswCQYDVQQGEwJKTzEMMAoGA1UECAwDQU1NMQwwCgYD
VQQHDANBTU0xCzAJBgNVBAoMAkg0MREwDwYDVQQDDAhINFRlc3RlcjCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAL0NUrK9JrCHeosEk1aAPP+igwljqE2p
HHH738S8p1KvQNaRsEVOLnGrHc6oy1pEM55vk/Ag1QrEBaIbCWDQOsjfPi0KKlub
4nn5vCae32p58ZpNCIfE6KyHhHUXyTCIgOIwuSeVWYIhYE4aFrSJzo5lVa3hQzu4
AAFZtmT6pPf5ZkCgJjuvwCi1tmeBrb25wb4SU493I/zsY68Cu7Wugyoh2N9bnLyK
NlMy3xR8LHG21sqMWfOnRiqxp5LQh5GLY4huPfVW3/jJVX8cMt5FQP3lJFqMKr66
t1VqWXMk2eAxrcsKh8h08pAD2YGry0FseAMDnepOirZDOoI948qX3M8CAwEAAaNT
MFEwHQYDVR0OBBYEFEPjIgsZHRGxf8hvbarcVEOM9llzMB8GA1UdIwQYMBaAFEPj
IgsZHRGxf8hvbarcVEOM9llzMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAFPrDIrKb+jqbSunBbNzo7sgihjqYarKeEH3Cq7/QJ8XnvOlU/9puZSg
erHw+vhGe4UHSX+vOsBKvj9tzJUeTqHuzFFZRBHz1gWt+MIflHoSTqCt9oYfAT/S
s+Ld4sAumsg3KzoNQWjVLomAFvrgbIANuzGnT4hVbZPxxT8pr4knnCvpL87+5wy+
6RR8gy0JaWiZs21nYUjCf7oWtafI1yHjVhC+EIGet6x91GLTqnTD8EH8L/F6T92I
FHCgtCDKU1vTuKsLpxeiZCI0ju5cbc2//ZMim7Lz4Kk/BgwQBEfHD3AsSjh4LcI1
lejnr3NL/azDA4uulkfKlkOOgHT0j/Y=
-----END CERTIFICATE-----
)";
std::string serverPrivateKey = R"(-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC9DVKyvSawh3qL
BJNWgDz/ooMJY6hNqRxx+9/EvKdSr0DWkbBFTi5xqx3OqMtaRDOeb5PwINUKxAWi
Gwlg0DrI3z4tCipbm+J5+bwmnt9qefGaTQiHxOish4R1F8kwiIDiMLknlVmCIWBO
Gha0ic6OZVWt4UM7uAABWbZk+qT3+WZAoCY7r8AotbZnga29ucG+ElOPdyP87GOv
Aru1roMqIdjfW5y8ijZTMt8UfCxxttbKjFnzp0YqsaeS0IeRi2OIbj31Vt/4yVV/
HDLeRUD95SRajCq+urdVallzJNngMa3LCofIdPKQA9mBq8tBbHgDA53qToq2QzqC
PePKl9zPAgMBAAECggEARviochdWXfEOTQATu+Z6f9Fnde/mr/jrh9Lxp27XNdA6
/BJHZU07XErL7tgpNyLhafojRINe1yLNppSVybWCTASa19e4HRoBRJ8/RhRgdR2A
WNfQev+uBY7+Z+LdEY49LCz0ZWrI5nRXLhrXKUGOvKBIMPWfAt1Jizg9o90Ab2KY
mVMPQ3LbbvV+vC8Juh5EEaqEttgWCXlW8QwiGedFmW52UeF4cVMdJcuXxxZ7pLiz
AEs4AuULk43CWtdhwtyLG6VCzsZLl8SIG+cqYHuvYM9kB6IkQemOSs4e0oHQ0Ygd
Cxz1wm364T4ZF+m5DC1gMJTjAGY1fAyuqVEfjYcBiQKBgQDtj+vlBrkzD2DYDMhn
VBCjdv8vBkcZTs8lrJPyEmrUhOPOvm5SX3o+fdrbPSklCKjqb8ks/XciYavzeIDd
AtyimOHZG2VIRV401nq0nn8PaYZ9gukdSKxmSzNyWRZYu4Ow/dTzDrGxKSG6z5ED
MHE8t13x7Oelw0pkgJxVGPFp/QKBgQDLuZAB1W5uXSH9etOEmmtsdpmLDg3fRil5
dgNqG1491cLlbQB0HIih+GbYzvIGE40Oq8vMY7aEvChtP032w0R8PQhIzGfKz4ri
uOQwFAeqM8puSiUOhZ0bAHM3Id/wCeWzmTGI3rmN+MEnEmLb5lYYws6e6vuDdbOf
k5u+ApuFuwKBgFFgxdwUq4h0MiaQam4K/BAjCVNggSaIOqmbLqrz6CiYxTjjPwN0
tXmGv1vu3ZNUHhkA5hdFVHQwpSioFOyguFfyqxsmKVHSgWz0M+B/kuMCsRF5sMVZ
ScVY6Wy4W9FVms0chsAkPnaDsow94l0HUSMNZV8kWk4MUgWPkP4Np1U5AoGAKI0O
Kh9GtPcaze7F7Y4jNdrBo1kvz7KSjNe9xEAgWSSUf8Bbp8EKPVtJdXxz1lvL5xCx
J0Ttzqv5TA2ewjCKEETBwmPVgRwgpBJzcVJ7WBipAZ0GlUZpSDelt2KpxYjizQYA
QyM6QhUytUlGnkjR+GnGYQGbAMbL80aZaI/yTwMCgYBCzBPFPt7IsKDLSbCSmBwX
PgzoQBU0Z1kMFulTEbdaikMYwDP9spJrePSxS3KefltSo6fHz+W8fxKzgHql8l7v
yx1X4kTgIMK9wt96hW5lgZUyOZz/oSLO5YNuYT54DEs/HFWnX3s7HoeC0mC5qIIi
C+rU6AEiQVPvNQVim9/+4g==
-----END PRIVATE KEY-----
)";

bool onTCPError(int error, int info){
	Serial.printf("onError %d info=%d\n",error,info);
	return true; // to close the connection (if error it will close anyway)
}
void begin(){
	server.reset();
	_heap_alloc=10000; // Set an estimation of memory consumed for a new connection receive, to cancel the request and further prevent out of memory errors.
    server.onError(onTCPError);
	server.secureTLS((const uint8_t*)serverCert.c_str(), serverCert.length() + 1, 
						NULL, 0,
					(const uint8_t*)serverPrivateKey.c_str(), serverPrivateKey.length() + 1);
    server.begin();
}
void h4setup() {
	WiFi.mode(WIFI_STA);
	WiFi.begin(YOUR_SSID, YOUR_PWD);
	while (WiFi.waitForConnectResult() != WL_CONNECTED) {
		Serial.println("Connection Failed! Rebooting...");
		Serial.print(".");
		delay(5000);
	}
	Serial.printf("\nIP: %s\n",WiFi.localIP().toString().c_str());
	Serial.printf("Runing on %s\n",ARDUINO_BOARD);

	Serial.printf("SERVER CERT Validation: %s\n", H4AsyncClient::isCertValid((const uint8_t*)serverCert.c_str(), serverCert.length() + 1) ? "SUCCEEDED" : "FAILED");
	Serial.printf("SERVER KEY Validation: %s\n", H4AsyncClient::isPrivKeyValid((const uint8_t*)serverPrivateKey.c_str(), serverPrivateKey.length() + 1) ? "SUCCEEDED" : "FAILED");

	begin(); // For event-based system, call this onWiFiConnect() callback;
}