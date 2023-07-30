#pragma once 
#include "h4async_config.h"

/* lwip_altcp.h
  A common file for including lwip/altcp.h, and adds the proper content if it wasn missing from the build system.

 */
#if H4AT_HAS_ALTCP
#include "lwip/altcp.h"
#else // H4AT_HAS_ALTCP

// Link altcp_xxx to tcp_xxx API calls
/* ALTCP disabled, define everything to link against tcp callback API (e.g. to get a small non-ssl httpd) */

#include "lwip/tcp.h"

#define altcp_accept_fn tcp_accept_fn
#define altcp_connected_fn tcp_connected_fn
#define altcp_recv_fn tcp_recv_fn
#define altcp_sent_fn tcp_sent_fn
#define altcp_poll_fn tcp_poll_fn
#define altcp_err_fn tcp_err_fn

#define altcp_pcb tcp_pcb
#define altcp_tcp_new_ip_type tcp_new_ip_type
#define altcp_tcp_new tcp_new
#define altcp_tcp_new_ip6 tcp_new_ip6

#define altcp_new(allocator) tcp_new()
#define altcp_new_ip6(allocator) tcp_new_ip6()
#define altcp_new_ip_type(allocator, ip_type) tcp_new_ip_type(ip_type)

#define altcp_arg tcp_arg
#define altcp_accept tcp_accept
#define altcp_recv tcp_recv
#define altcp_sent tcp_sent
#define altcp_poll tcp_poll
#define altcp_err tcp_err

#define altcp_recved tcp_recved
#define altcp_bind tcp_bind
#define altcp_connect tcp_connect

#define altcp_listen_with_backlog_and_err tcp_listen_with_backlog_and_err
#define altcp_listen_with_backlog tcp_listen_with_backlog
#define altcp_listen tcp_listen

#define altcp_abort tcp_abort
#define altcp_close tcp_close
#define altcp_shutdown tcp_shutdown

#define altcp_write tcp_write
#define altcp_output tcp_output

#define altcp_mss tcp_mss
#define altcp_sndbuf tcp_sndbuf
#define altcp_sndqueuelen tcp_sndqueuelen
#define altcp_nagle_disable tcp_nagle_disable
#define altcp_nagle_enable tcp_nagle_enable
#define altcp_nagle_disabled tcp_nagle_disabled
#define altcp_setprio tcp_setprio

#define altcp_get_tcp_addrinfo tcp_get_tcp_addrinfo
#define altcp_get_ip(pcb, local) ((local) ? (&(pcb)->local_ip) : (&(pcb)->remote_ip))

#ifdef LWIP_DEBUG
#define altcp_dbg_get_tcp_state tcp_dbg_get_tcp_state
#endif

#endif // H4AT_HAS_ALTCP