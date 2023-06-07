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

#ifdef ARDUINO_ARCH_ESP32
    #include "lwip/priv/tcpip_priv.h"
#endif
// https://lists.nongnu.org/archive/html/lwip-users/2010-03/msg00142.html "Listening connection issue"

bool H4AsyncServer::_bakov=false;
static err_t _raw_accept(void *arg, struct altcp_pcb *p, err_t err){
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
        auto c=srv->_instantiateRequest(p); // Needs to be processed within lwip thread.
        h4.queueFunction([=](){
                    H4AT_PRINT1("NEW CONNECTION %p --> pcb=%p state=%d\n",c,p,p->state);
                    if(c){
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
                        // h4.queueFunction([](){ H4AsyncClient::checkPCBs("ACCEPT", 1); });
                        
                       H4AT_PRINT3("QF insert c --> out %p\n",c);
                    } else H4AT_PRINT1("_instantiateRequest returns WRONG VALUE !!!!! p=%p c=%p\n",p,c); // Might abort/close the connection
        });
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
// altcp_allocator_t* tcp_allocator = new altcp_allocator_t{altcp_tcp_alloc, nullptr};
void H4AsyncServer::begin(){
//    h4.every(1000,[]{ heap_caps_check_integrity_all(true); });
    H4AT_PRINT1("SERVER %p listening on port %d\n",this,_port);
#if LWIP_ALTCP
    static altcp_allocator_t allocator {altcp_tcp_alloc, conf};
#endif
    auto _raw_pcb = altcp_new(&allocator);
    if (_raw_pcb != NULL) {
        err_t err;
        altcp_arg(_raw_pcb,this);
        err = altcp_bind(_raw_pcb, IP_ADDR_ANY, _port);
        if (err == ERR_OK) {
            _raw_pcb = altcp_listen(_raw_pcb);
            altcp_accept(_raw_pcb, _raw_accept);
        } //else Serial.printf("RAW CANT BIND\n");
    } // else Serial.printf("RAW CANT GET NEW PCB\n");
}