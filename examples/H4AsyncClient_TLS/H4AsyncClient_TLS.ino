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
#include <H4.h>
#include <H4AsyncTCP.h>
#include <H4Tools.h>

#if H4AT_TLS_SESSION
#include "lwip/apps/altcp_tls_mbedtls_opts.h"
#endif

#define YOUR_SSID "XXXXXXXX"
#define YOUR_PWD "XXXXXXXX"

#define URL 	"https://192.168.1.34" // Replace with a valid server if not running

H4 h4(115200);
H4AsyncClient* asyncTCP;

std::string rootCA = R"(-----BEGIN CERTIFICATE-----
....
....
-----END CERTIFICATE-----
)";

void onData(uint8_t* data, uint32_t len){
	Serial.printf("Received Data %p %d\n", data, len);
	dumphex(data,len);
}
bool state=false;
enum ConnectionState : uint8_t {
	DISCONNECTED,
	CONNECTING,
	CONNECTED
} TCPState;

void connect();

void onTCPConnect(){
	Serial.printf("on TCP/TLS Connect\n");
	// asyncTCP->nagle(true); // Enable if needed
	_state=CONNECTED;
	h4.every(5000,[]{
		if (_state==CONNECTED){
			std::string message {"HelloWorld"}; // OR any raw data!
			asyncTCP->TX((uint8_t*)message.data(), message.length());
		}
	});
}
void onTCPConnectFail(){
	Serial.printf("onConnectFail - reconnect\n");
	_state = DISCONNECTED;
	asyncTCP = nullptr; // Invalidate the pointer (Important)
	connect();
}
void onTCPDisconnect(){
	Serial.printf("onDisconnect - reconnect\n");
	if(_state==H4AMC_RUNNING) if(_cbMQTTDisconnect) _cbMQTTDisconnect();
	_state=H4AMC_DISCONNECTED;
	asyncTCP = nullptr;
	connect();
}
bool onTCPError(int error, int info){
	Serial.printf("onError %d info=%d\n",error,info);
	return true; // to close the connection (if error it will close anyway)
}
void connect(){
	asyncTCP=new H4AsyncClient;

    if (TCPState != DISCONNECTED) {
        Serial.printf("Already connecting/connected\n");
        return;
    }
    TCPState = CONNECTING;
    
    asyncTCP->onConnect(onTCPConnect);
    asyncTCP->onConnectFail(onTCPConnectFail); // Happens when the connecting timeout
    asyncTCP->onDisconnect(onTCPDisconnect);
    asyncTCP->onError(onTCPError);
    asyncTCP->onRX([=](const uint8_t* data,size_t len){ onData((uint8_t*) data,len); });

	// Leave untouched if to reuse TLS sessions
#if H4AT_TLS_SESSION
    static void* _tlsSession;
    static uint32_t _lastSessionMs;
    asyncTCP->enableTLSSession();
    asyncTCP->onSession(
        [=](void *tls_session)
        {
            _tlsSession = const_cast<void *>(tls_session);
            _lastSessionMs = millis();
        });

    if (_tlsSession && (millis() - _lastSessionMs < ALTCP_MBEDTLS_SESSION_CACHE_TIMEOUT_SECONDS * 1000)) {
        asyncTCP->setTLSSession(_tlsSession);
    }
    else {
        if (_tlsSession) {
            asyncTCP->freeTLSSession(_tlsSession);
            _tlsSession = nullptr;
        }
    }
#endif


#if H4AT_TLS
	auto testRootCA = reinterpret_cast<const uint8_t*>(const_cast<char*>(rootCA.c_str()));
	asyncTCP->secureTLS(testRootCA, rootCA.length() + 1); // +1 for PEM-based certificates (DER doesn't need it)
#endif
    asyncTCP->connect(_url);
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
	Serial.printf("CA CERT Validation: %s\n", H4AsyncClient::isCertValid((const uint8_t*)rootCA.c_str(), rootCA.length() + 1) ? "SUCCEEDED" : "FAILED");

	connect();
}