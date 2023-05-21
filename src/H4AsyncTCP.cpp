/* Licence: 
Creative Commons
Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode

You are free to:

Share — copy and redistribute the material in any medium or format
Adapt — remix, transform, and build upon the material

The licensor cannot revoke these freedoms as long as you follow the license terms. Under the following terms:

Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made. 
You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.

NonCommercial — You may not use the material for commercial purposes.

ShareAlike — If you remix, transform, or build upon the material, you must distribute your contributions 
under the same license as the original.

No additional restrictions — You may not apply legal terms or technological measures that legally restrict others 
from doing anything the license permits.

Notices:
You do not have to comply with the license for elements of the material in the public domain or where your use is 
permitted by an applicable exception or limitation. To discuss an exception, contact the author:

philbowles2012@gmail.com

No warranties are given. The license may not give you all of the permissions necessary for your intended use. 
For example, other rights such as publicity, privacy, or moral rights may limit how you use the material.
*/
#include <H4AsyncTCP.h>
#include "IPAddress.h"

extern "C"{
    #include "lwip/tcp.h"
    #include "lwip/dns.h"
}

#ifdef ARDUINO_ARCH_ESP32
    #include "lwip/priv/tcpip_priv.h"
#endif

std::unordered_set<H4AsyncClient*> H4AsyncClient::openConnections;
std::unordered_set<H4AsyncClient*> H4AsyncClient::unconnectedClients;

H4_INT_MAP H4AsyncClient::_errorNames={
#if H4AT_DEBUG
    {ERR_OK,"No error, everything OK"},
    {ERR_MEM,"Out of memory error"}, // -1
    {ERR_BUF,"Buffer error"},
    {ERR_TIMEOUT,"Timeout"},
    {ERR_RTE,"Routing problem"},
    {ERR_INPROGRESS,"Operation in progress"}, // -5
    {ERR_VAL,"Illegal value"},
    {ERR_WOULDBLOCK,"Operation would block"},
    {ERR_USE,"Address in use"},
    {ERR_ALREADY,"Already connecting"},
    {ERR_ISCONN,"Conn already established"}, // -10
    {ERR_CONN,"Not connected"}, // -11
    {ERR_IF,"Low-level netif error"}, // -12
    {ERR_ABRT,"Connection aborted"}, // -13
    {ERR_RST,"Connection reset"}, // -14
    {ERR_CLSD,"Connection closed"},
    {ERR_ARG,"Illegal argument"},
    {H4AT_ERR_DNS_FAIL,"DNS Fail"},
    {H4AT_ERR_DNS_NF,"Remote Host not found"},
    {H4AT_HEAP_LIMITER_ON,"Heap Limiter ON"},
    {H4AT_HEAP_LIMITER_OFF,"Heap Limiter OFF"},
    {H4AT_HEAP_LIMITER_LOST,"Heap Limiter: packet discarded"},
    {H4AT_INPUT_TOO_BIG,"Input exceeds safe heap"},
    {H4AT_CLOSING,"Client closing"},
    {H4AT_OUTPUT_TOO_BIG,"Output exceeds safe heap"}
#endif
};

//#define TF_ACK_DELAY   0x01U   /* Delayed ACK. */
//#define TF_ACK_NOW     0x02U   /* Immediate ACK. */
//#define TF_INFR        0x04U   /* In fast recovery. */
//#define TF_TIMESTAMP   0x08U   /* Timestamp option enabled */
//#define TF_RXCLOSED    0x10U   /* rx closed by tcp_shutdown */
//#define TF_FIN         0x20U   /* Connection was closed locally (FIN segment enqueued). */
//#define TF_NODELAY     0x40U   /* Disable Nagle algorithm */
//#define TF_NAGLEMEMERR 0x80U   /* nagle enabled, memerr, try to output to prevent delayed ACK to happen */
/*
enum tcp_state {
  CLOSED      = 0,
  LISTEN      = 1,
  SYN_SENT    = 2,
  SYN_RCVD    = 3,
  ESTABLISHED = 4,
  FIN_WAIT_1  = 5,
  FIN_WAIT_2  = 6,
  CLOSE_WAIT  = 7,
  CLOSING     = 8,
  LAST_ACK    = 9,
  TIME_WAIT   = 10
};
*/

#if H4AT_DEBUG
static const char * const tcp_state_str[] = {
  "CLOSED",
  "LISTEN",
  "SYN_SENT",
  "SYN_RCVD",
  "ESTABLISHED",
  "FIN_WAIT_1",
  "FIN_WAIT_2",
  "CLOSE_WAIT",
  "CLOSING",
  "LAST_ACK",
  "TIME_WAIT"
};
#endif
typedef struct {
    H4AsyncClient* c;
    struct tcp_pcb* pcb;
    const uint8_t* data;
    size_t size;
    uint8_t apiflags;
} tcp_api_call_t;
struct TXData {
    H4AsyncClient* c;
    const uint8_t* data;
    size_t size;
};
#if NO_SYS == 0
typedef struct {
    H4AsyncClient* c;
    const uint8_t* data;
    size_t size;
    bool copy;
} tcp_tx_api_call_t;
typedef struct {
    H4AsyncClient* c;
    bool value;
} tcp_bool_api_call_t;
typedef struct {
    H4AsyncClient* c;
} tcp_void_api_call_t;
typedef struct {
    H4AsyncClient* c;
    tcp_pcb* pcb;
} tcp_pcb_api_call_t;

// #if ARDUINO_ARCH_ESP32 (Because of API differenes) (as _tcp_write_api)
err_t _tcp_tx_api(struct tcpip_api_call_data *api_call_params){
    H4AT_PRINT2("_tcp_tx_api\n");
    auto params = (tcp_tx_api_call_t *)api_call_params;
    auto c=params->c;
    err_t err = ERR_ARG;
    if (c) err=c->__TX(params->data,params->size,params->copy);
    return err;
}
err_t _tcp_connect_api(struct tcpip_api_call_data *api_call_params){
    H4AT_PRINT2("_tcp_connect_api\n");
    auto params = (tcp_pcb_api_call_t*)api_call_params;
    auto c=params->c;
    auto pcb=c->pcb;
    err_t err = ERR_ARG;
    if (c)
        err = c->__connect(pcb?nullptr:tcp_new());
    return err;
}
/* err_t _tcp_nagle_api(struct tcpip_api_call_data *api_call_params){
    Serial.printf("_tcp_nagle_api\n");
    tcp_bool_api_call_t * params = (tcp_bool_api_call_t *)api_call_params;
    auto c= params->c;
    err_t err = ERR_OK;
    if (c) err = c->__nagle(params->value);
    return err;
} */
err_t _tcp_shutdown_api(struct tcpip_api_call_data *api_call_params){
    tcp_bool_api_call_t * params = (tcp_bool_api_call_t *)api_call_params;
    auto c= params->c;
    H4AT_PRINT2("_tcp_shutdown_api c=%p b=%d\n",c,params->value);
    if (c) c->__shutdown(params->value);
    return ERR_OK;
}
err_t _tcp_retryclose_api(struct tcpip_api_call_data *api_call_params){
    tcp_pcb_api_call_t * params = (tcp_pcb_api_call_t *)api_call_params;
    auto  c = params->c;
    auto pcb = params->pcb;
    if (c && pcb)
        H4AsyncClient::__retryClose(params->c,params->pcb);
    return ERR_OK;
}
err_t _raw_sent(void* arg,struct tcp_pcb *tpcb, u16_t len);
err_t _raw_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
void _raw_error(void *arg, err_t err);

err_t _assignServer(struct tcpip_api_call_data* p){
    tcp_pcb_api_call_t* params = (tcp_pcb_api_call_t*)p;
    auto c = params->c;
    auto pcb = params->pcb;
    H4AsyncClient::__assignServer(c,pcb);
    return ERR_OK;
}

#endif
void H4AsyncClient::printState(std::string context){
    H4AT_PRINT2("%s\tpcb=%p s=%d \"%s\"\n", context.c_str(), pcb, pcb->state, (pcb->state >= CLOSED && pcb->state <=TIME_WAIT)? tcp_state_str[pcb->state]:"???");
}

void H4AsyncClient::__retryClose(H4AsyncClient* c,tcp_pcb *pcb)
{

    Serial.printf("retryClose %p state=%d\n", pcb, pcb->state);
    // Check the presence of the PCB with other Clients ??
    auto checkOtherOwners = [c,pcb] (std::unordered_set<H4AsyncClient*>& set){
        for (auto& _c : set){
            if (_c->pcb == pcb && _c!=c){
                Serial.printf("%p found in other client %p\n", pcb, _c);
                return true;
            }
        }
        return false;
    };

    // If there's another client with this pcb, don't close it, and NULLify the PCB for not closing it again at SCAVENGE
    if (checkOtherOwners(openConnections)){
        if (std::find(openConnections.begin(), openConnections.end(), c) != openConnections.end())
            c->pcb=NULL;
        return;
    }
    else if (checkOtherOwners(unconnectedClients)){ 
        if (std::find(unconnectedClients.begin(), unconnectedClients.end(), c) != unconnectedClients.end())
            c->pcb=NULL;
        return;
    }
    
    if (pcb->state <= CLOSED || pcb->state > TIME_WAIT){
        Serial.printf("Already freed/closed\n", pcb);
        return;
    }
    err_t err = tcp_close(pcb);
    if (err != ERR_OK){
        Serial.printf("failed with %d\n", pcb, err);
    }
    if (err == ERR_MEM){
        h4.queueFunction([c, pcb](){ retryClose(c,pcb); }); // h4.once(1000, [pcb](){retruClose(pcb);}); ???
    }
    if (err == ERR_OK){
        Serial.printf("freed %p\n", pcb);
    }
    
}
void H4AsyncClient::retryClose(H4AsyncClient* c,tcp_pcb *pcb)
{
#if NO_SYS
    __retryClose(c,pcb);
#else
    if (strcmp(H4AS_RTOS_GET_THREAD_NAME, TCPIP_THREAD_NAME) == 0){
        __retryClose(c,pcb);
    }
    else {
        tcp_pcb_api_call_t call_data {c,pcb};
        tcpip_api_call(_tcp_retryclose_api, (tcpip_api_call_data*)&call_data);
    }
#endif
    // Check the state of the connection
}

void H4AsyncClient::_notify(int e,int i) { 
    if(e) if (_cbError(e,i)) _shutdown(e==ERR_ABRT/*  || e==ERR_CONN */); // ERR_CONN due to ESP32 multithreading calls
    /* "The "myclose()" function is not a simple call to tcp_close(pcb) because
    it may fail and you need to retry later by means of the poll callback or
    your own method."
    https://lists.nongnu.org/archive/html/lwip-users/2016-01/msg00020.html
    */
}
err_t H4AsyncClient::__shutdown(bool aborted){
    H4AT_PRINT1("__shutdown %p\n",this);
    _closing=true;
    _lastSeen=0;
    if(pcb){
#if 0
        std::string context = "SHUTDOWN";
        context.push_back(' ');
        if (aborted)
            context += "(ABORTED)";
        printState(context);
#endif
        H4AT_PRINT1("RAW 1 PCB=%p STATE=%d \"%s\"\n",pcb,pcb->state,(pcb->state >= CLOSED && pcb->state <=TIME_WAIT)? tcp_state_str[pcb->state]:"???");
        _clearDanglingInput();
        if (aborted || pcb->state > TIME_WAIT || pcb->state < CLOSED){
            if (aborted)
                H4AT_PRINT1("ABORTED CONNECTION\n");
            else
                H4AT_PRINT1("H4AT Wrong state on Shutdown!\n"); // There's an occurance of this source of error
        }
        else
        {
            H4AT_PRINT1("RAW 2 clean STATE=%d\n",pcb->state);
            tcp_arg(pcb, NULL);
            //***************************************************
            tcp_sent(pcb, NULL);
            tcp_recv(pcb, NULL);
            tcp_err(pcb, NULL);
            err_t err;
            H4AT_PRINT1("*********** pre closing\n");

            if (pcb->state) err=tcp_close(pcb);
                else H4AT_PRINT1("*********** already closed?\n");
            
            if (err)
            {
                H4AT_PRINT1("Error closing %d \"%s\"\n", err, _errorNames[err].c_str());
                if (err==ERR_MEM)
                {
                    auto pcb_cpy = pcb;
                    h4.queueFunction([this, pcb_cpy]
                                     {
                                         // Might try closing later ... ?
                                         // What if we don't close it? Will it be closed by lwip automatically?
                                         // What if lwip reused this pcb for another connection?
                                         retryClose(this,pcb_cpy);
                                     });
                }
            }
        }
        if (openConnections.count(this)) { // There's an open connection
            if (_cbDisconnect) _cbDisconnect();
            else
                H4AT_PRINT1("NO DISCONNECT HANDLER\n");
        }
        else { // The connection (as a client) was never established
            if (_cbConnectFail) _cbConnectFail();
            else
                H4AT_PRINT1("NO CONNECT FAIL HANDLER\n");
        }

        H4AT_PRINT1("*********** NULL IT\n");
        pcb=NULL; // == eff = reset;
        checkPCBs("SHUTDOWN", -1);
    }
    else
    {
        H4AT_PRINT1("ALREADY SHUTDOWN %p pcb=0!\n", this);
        return ERR_ABRT;
    }
    return ERR_OK;
}
void H4AsyncClient::_shutdown(bool aborted){
    H4AT_PRINT1("_shutdown %p %d %s\n",this,aborted, pcTaskGetName(NULL));
#if NO_SYS
    __shutdown(aborted);
#else

    if ((pcb && aborted) || (strcmp(H4AS_RTOS_GET_THREAD_NAME, TCPIP_THREAD_NAME)==0))// No need to sync with tcpip_thread, all is internal management.|| Or we're in the tcpip_thread
    {
        __shutdown(aborted); 
        return;
    }
    tcp_bool_api_call_t call_data {this, aborted};
    tcpip_api_call(_tcp_shutdown_api, (tcpip_api_call_data*)&call_data);
#endif
}

void _raw_error(void *arg, err_t err){
#if NO_SYS  // To offloed the call to a new main loop iteration
    h4.queueFunction([arg,err]{
#endif
    auto c=reinterpret_cast<H4AsyncClient*>(arg);
    H4AT_PRINT1("CONNECTION %p *ERROR* pcb=%p err=%d\n",arg,c->pcb, err);
    // if (!err) c->pcb=NULL;  // _shutdown() will be called by _notify() if there's an err and pcb will be set to NULL
    auto it=H4AsyncClient::openConnections.find(c);
    auto it2=H4AsyncClient::unconnectedClients.find(c);
    if (it != H4AsyncClient::openConnections.end() || it2 != H4AsyncClient::unconnectedClients.end()) // has not been deleted.
        c->_notify(err);
#if NO_SYS
    });
#endif
}

err_t _raw_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err){
    H4AT_PRINT1("_raw_recv %p tpcb=%p p=%p err=%d data=%p tot_len=%d\n",arg,tpcb,p, err, p ? p->payload:0,p ? p->tot_len:0);
    auto rq=reinterpret_cast<H4AsyncClient*>(arg);
    auto it=H4AsyncClient::openConnections.find(rq);
    if (it == H4AsyncClient::openConnections.end()){ // has been deleted.
        Serial.printf("HOOOW CAN THIS BE?\n");
        return ERR_ABRT;
    }
    // Serial.printf("_raw_recv %p p=%p err=%d _closing=%d\n", tpcb, p, err, rq->_closing);
    if (p == NULL || rq->_closing || err!=ERR_OK) rq->_notify(ERR_CLSD,err); // * warn ...hanging data when closing?
    // https://lists.nongnu.org/archive/html/lwip-users/2016-01/msg00020.html
    else {
        auto cpydata=static_cast<uint8_t*>(malloc(p->tot_len));
        if(cpydata){
            // memcpy(cpydata,p->payload,p->tot_len);
            pbuf_copy_partial(p,cpydata,p->tot_len,0); // instead of direct memcpy that only considers the first pbuf of the possible pbufs chain.
            auto cpyflags=p->flags;
            auto cpylen=p->tot_len;

            // [ ] Might run at another context so tpcb might be invalid???
            tcp_recved(tpcb, p->tot_len);
            H4AT_PRINT2("* p=%p * FREE DATA %p %d 0x%02x bpp=%p\n",p,p->payload,p->tot_len,p->flags,rq->_bpp);
            err=ERR_OK;
            h4.queueFunction([rq,cpydata,cpylen,cpyflags]{
                H4AT_PRINT2("_raw_recv %p data=%p L=%d f=0x%02x \n",rq,cpydata,cpylen,cpyflags);
                rq->_lastSeen=millis();
                rq->_handleFragment((const uint8_t*) cpydata,cpylen,cpyflags);
            },[cpydata]{
                H4AT_PRINT3("FREEING NON REBUILT @ %p\n",cpydata);
                free(cpydata);
            });
        } 
        else
        {
            rq->_notify(ERR_MEM, _HAL_freeHeap());
        }
        pbuf_free(p); // [x] This line fixes a possible memory leak (we must pbuf_free(p) even if !cpydata).
    }
    return err;
}

err_t _raw_sent(void* arg,struct tcp_pcb *tpcb, u16_t len){
    H4AT_PRINT2("_raw_sent %p pcb=%p len=%d\n",arg,tpcb,len);
    auto rq=reinterpret_cast<H4AsyncClient*>(arg);
    rq->_lastSeen=millis();
    return ERR_OK;
}

err_t _tcp_connected(void* arg, void* tpcb, err_t err){
    h4.queueFunction([arg,tpcb,err]{
        H4AT_PRINT1("_tcp_connected %p %p e=%d\n",arg,tpcb,err);
        H4AsyncClient::checkPCBs("CONNECTED", 1);
        auto rq=reinterpret_cast<H4AsyncClient*>(arg);
        auto p=reinterpret_cast<tcp_pcb*>(tpcb);
    #if H4AT_DEBUG
        IPAddress ip(ip_addr_get_ip4_u32(&p->remote_ip));
        H4AT_PRINT1("C=%p _tcp_connected p=%p e=%d IP=%s:%d\n",rq,tpcb,err,ip.toString().c_str(),p->remote_port);
    #endif
        H4AsyncClient::openConnections.insert(rq);
        H4AsyncClient::unconnectedClients.erase(rq);
        if(rq->_cbConnect) rq->_cbConnect();
        tcp_recv(p, &_raw_recv);
        // ***************************************************
        tcp_sent(p, &_raw_sent);
    });
    return ERR_OK;
}

void _tcp_dns_found(const char * name, struct ip_addr * ipaddr, void * arg) {
    H4AT_PRINT2("_tcp_dns_found %s i=%p p=%p\n",name,ipaddr,arg);
    auto p=reinterpret_cast<H4AsyncClient*>(arg);
    if(ipaddr){
        ip_addr_copy(p->_URL.addr, *ipaddr);
        p->_connect();
    } else p->_notify(H4AT_ERR_DNS_NF);
}

#ifdef ARDUINO_ARCH_ESP32
static err_t _tcp_write_api(struct tcpip_api_call_data *api_call_params){
#else
static err_t _tcp_write_api(void *api_call_params){
#endif
    tcp_api_call_t * params = (tcp_api_call_t *)api_call_params;
    auto c=reinterpret_cast<H4AsyncClient*>(params->c);
    if (!c->pcb || c->pcb != params->pcb)
    {
        H4AT_PRINT2("BAD PCB %p %p\n",c->pcb,params->pcb);// [x] Double check this (Sample output: "BAD PCB 0x0 0x3ffe4834")
        return pcb_deleted;
    }
    auto err = tcp_write(params->pcb, params->data, params->size, params->apiflags);

    if(err) H4AT_PRINT1("ERR %d after write H=%u sb=%d Q=%d\n",err,_HAL_freeHeap(),tcp_sndbuf(params->pcb),tcp_sndqueuelen(params->pcb));
    else {
        err=tcp_output(params->pcb);
        if(err) H4AT_PRINT1("ERR %d after output H=%u sb=%d Q=%d\n",err,_HAL_freeHeap(),tcp_sndbuf(params->pcb),tcp_sndqueuelen(params->pcb));
        // else
        // params->pcb->
        // TXData* td = new TXData{params->c,params->data,params->size}; [ ] // Replace all args with td??
    }
    return err;
}

static err_t _tcp_write(H4AsyncClient* c,struct tcp_pcb* p,const uint8_t* data, size_t size, uint8_t apiflags) {
    tcp_api_call_t params{c,p,data,size,apiflags};
    #ifdef ARDUINO_ARCH_ESP32
        return tcpip_api_call(_tcp_write_api, (struct tcpip_api_call_data*)&params);
    #else
        return _tcp_write_api((void*) &params);
    #endif
}
//
//
//

H4AsyncClient::H4AsyncClient(struct tcp_pcb *newpcb): pcb(newpcb){
//    _heapLO=(_HAL_freeHeap() * H4T_HEAP_CUTOUT_PC) / 100;
//    _heapHI=(_HAL_freeHeap() * H4T_HEAP_CUTIN_PC) / 100;
    H4AT_PRINT1("H4AC CTOR %p PCB=%p\n",this,pcb);
    if(pcb){ // H4AsyncServer receives the pcb, already connected.
        // A server.
#if NO_SYS
        __assignServer(this,pcb);
#else
        if (strcmp(H4AS_RTOS_GET_THREAD_NAME, TCPIP_THREAD_NAME)==0) {
            __assignServer(this,pcb);
        }
        else {
            tcp_pcb_api_call_t params{this,pcb};
            tcpip_api_call(_assignServer, (struct tcpip_api_call_data*)&params);
        }
#endif
        _lastSeen=millis();
    }
    else
    {
        // A client.
        unconnectedClients.insert(this);
        _creatTime = millis();
    }
}

void H4AsyncClient::_clearDanglingInput() {
    if(_bpp){
        H4AT_PRINT1("_clearDanglingInput p=%p _s=%d\n",_bpp,_stored);
        free(_bpp);
        _bpp=nullptr;
        _stored=0;
    }
}

err_t H4AsyncClient::__connect(tcp_pcb* pcb){
    if (pcb)
        this->pcb = pcb;
    tcp_arg(pcb, this);
    tcp_err(pcb, &_raw_error);
    return tcp_connect(pcb, &_URL.addr, _URL.port,(tcp_connected_fn)&_tcp_connected);
}

void H4AsyncClient::__assignServer(H4AsyncClient *client, tcp_pcb *pcb)
{
    if (!client || !pcb)
        return;
    client->pcb = pcb;
    tcp_arg(pcb, client);
    tcp_recv(pcb, &_raw_recv);
    tcp_err(pcb, &_raw_error);
    tcp_sent(pcb, &_raw_sent);
}

void H4AsyncClient::_connect() {
    H4AT_PRINT2("_connect p=%p state=%d\n",pcb, pcb ? pcb->state : -1);
#if NO_SYS
    if(!pcb) pcb=tcp_new();
    auto err = __connect(pcb);
#else
    err_t err = ERR_OK;
    if (strcmp(H4AS_RTOS_GET_THREAD_NAME, TCPIP_THREAD_NAME)==0) {
        if(!pcb) pcb=tcp_new();
        err = __connect(pcb);
    }
    else {
        tcp_pcb_api_call_t params{this,pcb};
        tcpip_api_call(_tcp_connect_api, (struct tcpip_api_call_data*)&params);
    }
#endif
    _notify(err);
}

void  H4AsyncClient::_parseURL(const std::string& url){
    if(url.find("http",0)) _parseURL(std::string("http://")+url);
    else {
        std::vector<std::string> vs=split(url,"//");
        _URL = {};
        _URL.secure=url.find("https",0)==std::string::npos ? false:true;
        H4AT_PRINT4("SECURE = %d  %s\n",_URL.secure,_URL.secure ? "TRUE":"FALSE");
        _URL.scheme=vs[0]+"//";
        H4AT_PRINT4("scheme %s\n", _URL.scheme.data());

        std::vector<std::string> vs2=split(vs[1],"?");
        _URL.query=vs2.size()>1 ? vs2[1]:"";
        H4AT_PRINT4("query %s\n", _URL.query.data());

        std::vector<std::string> vs3=split(vs2[0],"/");
        _URL.path=std::string("/")+((vs3.size()>1) ? join(std::vector<std::string>(++vs3.begin(),vs3.end()),"/")+"/":"");
        H4AT_PRINT4("path %s\n", _URL.path.data());

        std::vector<std::string> vs4=split(vs3[0],":");
        _URL.port=vs4.size()>1 ? atoi(vs4[1].data()):(_URL.secure ? 443:80);
        H4AT_PRINT4("port %d\n", _URL.port);

        _URL.host=vs4[0];
        H4AT_PRINT4("host %s\n",_URL.host.data());
    }
}

uint8_t* H4AsyncClient::_addFragment(const uint8_t* data,u16_t len){
    uint8_t* p=nullptr;
    if(_stored + len > maxPacket()){
        _clearDanglingInput();
        _notify(H4AT_INPUT_TOO_BIG,_stored + len);
    }
    else {
        p=static_cast<uint8_t*>(realloc(_bpp,_stored+len));
        if(p){
            _bpp=p;
            memcpy(_bpp+_stored,data,len);
            _stored+=len;
        }
        else {
        //  shouldn't ever happen!
            H4AT_PRINT1("not enough realloc mem\n");
            _clearDanglingInput();
        }
    }
    return p;
}

void H4AsyncClient::_handleFragment(const uint8_t* data,u16_t len,u8_t flags) {
    H4AT_PRINT1("%p _handleFragment %p %d f=0x%02x bpp=%p _s=%d\n",this,data,len,flags,_bpp,_stored);
    if(!_closing){
        if(flags & PBUF_FLAG_PUSH){
            if(!_stored) _rxfn(data,len);
            else {
                if(_addFragment(data,len)){
                    _rxfn(_bpp,_stored);
                    _clearDanglingInput();
                } else _notify(ERR_MEM,len); 
            }
        } else if(!_addFragment(data,len)) _notify(ERR_MEM,len);
    } //else Serial.printf("HF while closing!!!\n");
}

void H4AsyncClient::_scavenge(){
    h4.every(
        H4AS_SCAVENGE_FREQ,
        []{
            H4AT_PRINT1("SCAVENGE CONNECTIONS! oc=%u uc=%u\n", openConnections.size(), unconnectedClients.size());
            std::vector<H4AsyncClient*> tbd;
            for(auto &oc:openConnections){
                H4AT_PRINT1("T=%u OC %p ls=%u age(s)=%u SCAV=%u\n",millis(),oc,oc->_lastSeen,(millis() - oc->_lastSeen) / 1000,H4AS_SCAVENGE_FREQ);
                if((millis() - oc->_lastSeen) > H4AS_SCAVENGE_FREQ) tbd.push_back(oc);
            }
            for(auto &uc:unconnectedClients){
                H4AT_PRINT1("T=%u UC %p ct=%u age(s)=%u SCAV=%u\n",millis(),uc,uc->_creatTime,(millis() - uc->_creatTime) / 1000,H4AS_SCAVENGE_FREQ);
                if((millis() - uc->_creatTime) > H4AS_SCAVENGE_FREQ) tbd.push_back(uc);
            }
            for(auto &rq:tbd) {
                H4AT_PRINT1("Scavenging %p\n",rq); 
                    rq->_shutdown();
                if (openConnections.count(rq))
                    openConnections.erase(rq);
                else
                    unconnectedClients.erase(rq);
                delete rq;
            }
        },
        nullptr,
        H4AT_SCAVENGER_ID,
        true
    );
}
//
//      PUBLICS
//
void H4AsyncClient::connect(const std::string& host,uint16_t port){
    H4AT_PRINT2("connect h=%s, port=%d\n",host.data(),port);
    IPAddress ip;
    if(ip.fromString(host.data())) connect(ip,port);
    else {
        _URL.port=port;
        err_t err = dns_gethostbyname(host.data(), &_URL.addr, (dns_found_callback)&_tcp_dns_found, this);
        if(err) _notify(H4AT_ERR_DNS_FAIL,err);
    }
}

void H4AsyncClient::connect(const std::string& url){
    _parseURL(url);
   connect(_URL.host.data(),_URL.port);
}

void H4AsyncClient::connect(IPAddress ip,uint16_t port){
    H4AT_PRINT2("connect ip=%s, port=%d\n",ip.toString().c_str(),_URL.port);
    _URL.port=port;
    ip_addr_set_ip4_u32(&_URL.addr, ip);
    _connect();
}

bool H4AsyncClient::connected(){ return pcb && pcb->state== 4; }

std::string H4AsyncClient::errorstring(int e){
    #ifdef H4AT_DEBUG
        if(_errorNames.count(e)) return _errorNames[e];
        else return stringFromInt(e); 
    #else
        return stringFromInt(e); 
    #endif
}

uint32_t H4AsyncClient::localAddress(){ return ip_addr_get_ip4_u32(&pcb->local_ip); }
IPAddress H4AsyncClient::localIP(){ return IPAddress( localAddress()); }
std::string H4AsyncClient::localIPstring(){ return std::string(ipaddr_ntoa(&pcb->local_ip));}
    // { return std::string(localIP().toString().c_str()); }
uint16_t H4AsyncClient::localPort(){ return pcb->local_port; };

void H4AsyncClient::nagle(bool enable){
//     Serial.printf("NAGLE %s\n",enable?"ON":"OFF");
// #if NO_SYS
//     __nagle(enable);
// #elif 1
//     __nagle(enable);
// #else
//     Serial.printf("threadname = %s\n",H4AS_RTOS_GET_THREAD_NAME);
//     if (strcmp(H4AS_RTOS_GET_THREAD_NAME, TCPIP_THREAD_NAME)==0) {
//         __nagle(enable);
//     } else {
//         tcp_bool_api_call_t call_data{this,enable};
//         tcpip_api_call(_tcp_nagle_api,(tcpip_api_call_data*)&call_data);
//     }
// #endif
// }
// err_t H4AsyncClient::__nagle(bool enable){
//     Serial.printf("__nagle %s\n",enable?"ON":"OFF");
    if(pcb){
        if(enable) { tcp_nagle_enable(pcb); _nagle=true; }
        else { tcp_nagle_disable(pcb); _nagle=false; }
//        Serial.printf("PCB FLAGS=0x%02x\n",pcb->flags);
    } // else Serial.printf("NAGLE PCB NULL\n");
}

uint32_t H4AsyncClient::remoteAddress(){ return ip_addr_get_ip4_u32(&pcb->remote_ip); }
IPAddress H4AsyncClient::remoteIP(){ return IPAddress( remoteAddress()); }
std::string H4AsyncClient::remoteIPstring(){ return std::string(remoteIP().toString().c_str()); }
uint16_t H4AsyncClient::remotePort(){ return pcb->remote_port;  }

err_t H4AsyncClient::__TX(const uint8_t* data,size_t len,bool copy, uint8_t* copy_data){ 
    H4AT_PRINT1("__TX pcb=%p data=%p len=%d copy=%d max=%d\n",pcb,data,len,copy, maxPacket());
    if(!_closing){
        uint8_t flags;
        size_t  sent=0;
        size_t  left=len;

        while(left){
// // Might short this block to an OS-based macro: 
// // #if NO_SYS == 0 
//             if (!pcb || (pcb->state != ESTABLISHED) &&
//                             (pcb->state != CLOSE_WAIT) &&
//                             (pcb->state != SYN_SENT) &&
//                             (pcb->state != SYN_RCVD))
//             { // ESP32 switch context, we might being in this loop --> switch context --> TCP disconnection --> NULLs the PCB --> return to this context --> crash
//                 if (!pcb)
//                     H4AT_PRINT1("NULL PCB!\n");
//                 else
//                     printState("TX WRONG STATE!\n"); // It has been freed previously by another thread.
//                 break;
//             }
// // #endif
            size_t available=tcp_sndbuf(pcb);
            // Serial.printf("Av=%d QL=%d\n",available,tcp_sndqueuelen(pcb));
            // printState("TX");
            if(available && (tcp_sndqueuelen(pcb) < TCP_SND_QUEUELEN )){
                auto chunk=std::min(left,available);
                flags=copy ? TCP_WRITE_FLAG_COPY:0;
                if(left - chunk) flags |= TCP_WRITE_FLAG_MORE;
                H4AT_PRINT2("WRITE %p L=%d F=0x%02x LEFT=%d Q=%d\n",data+sent,chunk,flags,left,tcp_sndqueuelen(pcb));

                auto err = tcp_write(pcb, data+sent, chunk, flags);
                if(!err) {
                    err=tcp_output(pcb);
                    if(err) H4AT_PRINT1("ERR %d after output H=%u sb=%d Q=%d\n",err,_HAL_freeHeap(),tcp_sndbuf(pcb),tcp_sndqueuelen(pcb));
                }
                if (err) {
                    H4AT_PRINT1("ERR %d after write H=%u sb=%d Q=%d\n", err, _HAL_freeHeap(), tcp_sndbuf(pcb), tcp_sndqueuelen(pcb));
                    _notify(err,44); // [x] ((FIXED)) POTENTIAL ERROR SOURCE When err==-11 (ERR_CONN) --> it's because the PCB has been freed by another thread.
                    // break;
                    return err;
                }
                else {
                    sent+=chunk;
                    left-=chunk;
                }
/*                 if(auto err=_tcp_write(this,pcb,data+sent,chunk,flags)){
                    _notify(err,44); // [x] ((FIXED)) POTENTIAL ERROR SOURCE When err==-11 (ERR_CONN) --> it's because the PCB has been freed by another thread.
                    break;
                } else {
                    sent+=chunk;
                    left-=chunk;
                } */
            } 
            else {
                /* [x] Solve an error where it's stuck here, because of unspecified error. */
                H4AT_PRINT1("Cannot write: available=%d QL=%d\n",available,tcp_sndqueuelen(pcb));
                _HAL_feedWatchdog();
                yield();

                if (millis() - _lastSeen > H4AS_WRITE_TIMEOUT) {
                    _shutdown();
                    H4AT_PRINT2("Write TIMEOUT: %d\n", millis() - _lastSeen);
                    if (copy_data) free(copy_data);
                    return ERR_TIMEOUT; // Discard the rest of the data.
                }
#if H4AS_QUQUE_ON_CANNOT_WRITE
                // [ ] Might improve mbx to utilize shared_ptr
                // [ ] if copy flag, then copy the data itself and manage it...
                if (!copy_data && copy) {
                    copy_data = (uint8_t *)malloc(left);
                    memcpy(copy_data, data + sent, left);
                }
                h4.queueFunction([this,data,len,copy,left,sent,copy_data](){ TX(data+sent/*== data+len-left*/,left,copy,copy_data);});
                return ERR_OK;
#endif
            }
        }
    } else H4AT_PRINT1("%p __TX called during close!\n",this);
    
    if (copy_data) free(copy_data);
    return ERR_OK;
}


void H4AsyncClient::TX(const uint8_t* data,size_t len,bool copy, uint8_t* copy_data){ 
    H4AT_PRINT1("TX pcb=%p data=%p len=%d copy=%d max=%d\n",pcb,data,len,copy, maxPacket());
#if NO_SYS
    __TX(data,len,copy);
#else
    if (strcmp(H4AS_RTOS_GET_THREAD_NAME, TCPIP_THREAD_NAME)==0) {
        __TX(data,len,copy,copy_data);
        return;
    }
    tcp_tx_api_call_t call_data{this,data,len,copy};

    auto err = tcpip_api_call(_tcp_tx_api,(struct tcpip_api_call_data*)&call_data);
    if (err) H4AT_PRINT1("ERR %d \"%s\"\n",err, errorstring(err).c_str());
#endif
}