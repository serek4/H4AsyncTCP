/*
MIT License

Copyright (c) 2020 Phil Bowles with huge thanks to Adam Sharp http://threeorbs.co.uk
for testing, debugging, moral support and permanent good humour.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#include<H4AsyncTCP.h>
#include "lwip/altcp.h"
#include "lwip/altcp_tcp.h"
#include "lwip/altcp_tls.h"

bool H4AsyncServer::_bakov=false;
err_t _raw_accept(void *arg, struct altcp_pcb *p, err_t err){
    H4AT_PRINT1("RAW _raw_accept <-- arg=%p p=%p e=%d\n",arg,p,err);
    if ((err != ERR_OK) || (p == NULL))
        return ERR_VAL;

    if(!err){
        altcp_setprio(p, TCP_PRIO_MIN); // postpone it and check the server for priority ...?
        H4AT_PRINT1("Remote IP %s\n", ipaddr_ntoa(altcp_get_ip(p,0)));
        auto srv=reinterpret_cast<H4AsyncServer*>(arg);
        if (!srv->checkMemory(*srv)) {
            H4AT_PRINT1("LOW HEAP %u DISCARDING %p\n",_HAL_freeHeap(),p);
            return ERR_MEM;
        }
        auto c=srv->_instantiateRequest(p); // Needs to set callbacks now; to catch the request in our callback. 
        if(c){
            h4.queueFunction([=](){
#if H4AT_DEBUG
                            tcp_state state = -1;
#endif
                            if (c->pcb == NULL || c->__willClose || c->_closing) {
                                H4AT_PRINT1("%p %p %s\n",c,p, (!c->pcb) ? "PCB FREED" : (c->__willClose ? "WILL CLOSE" : "CLOSING"));
                                return;
                            } 
#if H4AT_DEBUG
                            else {
                                state = getTCPState(p, c->_isSecure);
                            }
#endif
                            H4AT_PRINT1("c->pcb=%p c->_isSecure=%d\n", c->pcb, c->_isSecure);
                            H4AT_PRINT1("NEW CONNECTION %p --> pcb=%p state=%d\n",c,p, c->pcb ? state:-1); // [x] getTCPState might result Undefined Behavior if pcb is freed beforehand
                            c->_lastSeen=millis();
                            c->onError([=](int e,int i){
                                if(e==ERR_MEM){
                                    H4AT_PRINT1("OOM ERROR %d\n",i); // Retry-After: 120
                                    return false;
                                } 
                                if(srv->_srvError) 
                                    return srv->_srvError(e,i);
                                return true;
                            });
                            H4AT_PRINT3("QF 1 %p\n",c);
                            c->onRX([=](const uint8_t* data,size_t len){ srv->route(c,data,len); });
                            H4AT_PRINT3("QF insert c --> in %p\n",c);
                            H4AsyncClient::openConnections.insert(c);
                            H4AsyncClient::checkPCBs("ACCEPT", 1);
                            H4AT_PRINT3("QF insert c --> out %p\n",c);
                    });
        } else {
            H4AT_PRINT1("_instantiateRequest returns WRONG VALUE !!!!! p=%p c=%p\n", p, c); // Might abort/close the connection
            return ERR_MEM;
        }
    } // else H4AT_PRINT1("RAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAW %d\n",err);

    return ERR_OK;
}
//
//      H4AsyncServer
//
H4AsyncClient*  H4AsyncServer::_instantiateRequest(struct altcp_pcb *p){
    auto c=new H4AsyncClient(p);
    return c;
};

void H4AsyncServer::begin() {
//    h4.every(1000,[]{ heap_caps_check_integrity_all(true); });
    H4AT_PRINT1("SERVER %p listening on port %d\n",this,_port);
    LwIPCoreLocker lock;
#if LWIP_ALTCP
    altcp_allocator_t allocator;
#if H4AT_TLS
    altcp_tls_config * conf = nullptr;
    // altcp_pcb* _raw_pcb = nullptr;
    if (_secure) {
        H4AT_PRINT1("Setting up secured server\n");
        auto &privkey = _keys[H4AT_TLS_PRIVATE_KEY];
        auto &privkey_pass = _keys[H4AT_TLS_PRIVAKE_KEY_PASSPHRASE];
        auto &cert = _keys[H4AT_TLS_CERTIFICATE];
        conf = altcp_tls_create_config_server_privkey_cert(privkey->data, privkey->len,
                                                            privkey_pass? privkey_pass->data : NULL, privkey_pass ? privkey_pass->len : 0,
                                                            cert->data, cert->len);
        H4AT_PRINT3("SERVER conf=%p\n", conf);
        if (conf) {
            allocator = altcp_allocator_t{altcp_tls_alloc, conf};
        }
        else {
            H4AT_PRINT1("INVALID TLS CONFIGURATION\n");
            if (_srvError) _srvError(H4AT_BAD_TLS_CONFIG,0);
            return; // Don't initiate an unsecured webserver
        }
    }
    else {
        H4AT_PRINT1("Setting up unsecured server\n");
        allocator = altcp_allocator_t {altcp_tcp_alloc, conf};
    }
#endif
#else
#endif
    _raw_pcb = altcp_new_ip_type(&allocator, IPADDR_TYPE_ANY);
    if (_raw_pcb != NULL) {
        err_t err;
        altcp_arg(_raw_pcb,this);
        err = altcp_bind(_raw_pcb, IP_ADDR_ANY, _port);
        if (err == ERR_OK) {
            _raw_pcb = altcp_listen(_raw_pcb);
            altcp_accept(_raw_pcb, _raw_accept);
        } else H4AT_PRINT1("RAW CANT BIND\n");
    } else H4AT_PRINT1("RAW CANT GET NEW PCB\n");
}

void H4AsyncServer::reset()
{
#if H4AT_TLS
    for (auto &key : _keys) {
        if (key && key->data)
            key->clear();
    }
    _secure = false;
#endif
    if (_raw_pcb) {
        altcp_close(_raw_pcb);
        _raw_pcb = NULL;
    }
}

#if H4AT_TLS
void H4AsyncServer::secureTLS(const u8_t *privkey, size_t privkey_len,
                              const u8_t *privkey_pass, size_t privkey_pass_len,
                              const u8_t *cert, size_t cert_len)
{
    if (!privkey || !cert || !privkey_len || !cert_len) return;
    _keys[H4AT_TLS_PRIVATE_KEY] = new mbx{const_cast<u8_t*>(privkey), privkey_len};
    if (privkey_pass && privkey_pass_len)
        _keys[H4AT_TLS_PRIVAKE_KEY_PASSPHRASE] = new mbx{const_cast<u8_t*>(privkey_pass), privkey_pass_len};
    _keys[H4AT_TLS_CERTIFICATE] = new mbx{const_cast<u8_t*>(cert), cert_len};

    _secure = true;
}
#endif