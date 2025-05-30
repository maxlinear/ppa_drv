
/*******************************************************************************
 **
 ** FILE NAME    : ppa_api_sw_accel_module.h
 ** PROJECT      : PPA
 ** MODULES      : PPA API (Wrapper for Software Fastpath Implementation)
 **
 ** DATE         : 13 Mar 2014
 ** AUTHOR       : Lantiq
 ** DESCRIPTION  : Function to bypass the linux stack for packets belonging to the PPA sessions which are not in PPE firmware.
 ** COPYRIGHT    :              Copyright (c) 2013
 **                          Lantiq Deutschland GmbH
 **                   Am Campeon 3; 85579 Neubiberg, Germany
 **
 **   For licensing information, see the file 'LICENSE' in the root folder of
 **   this software module.
 **
 ** HISTORY
 ** $Date        $Author                $Comment
 *******************************************************************************/

/*! \file ppa_api_sw_accel_module.h
  \brief This file contains es.
  software fastpath wrapper function declarations
 */

extern signed long sw_fastpath_send(PPA_SKBUF *skb);
extern signed long get_sw_fastpath_status(unsigned long *f_enable, unsigned long flags);
extern signed long sw_fastpath_enable(unsigned long f_enable, unsigned long flags);

extern void sw_del_session(void* pitem);
extern signed long sw_add_session(PPA_BUF *skb, void* pitem);
extern signed long sw_update_session(PPA_BUF *skb, void *p_item,void *txifinfo);

extern int32_t (*ppa_sw_fastpath_enable_hook)(uint32_t, uint32_t);
extern int32_t (*ppa_get_sw_fastpath_status_hook)(uint32_t *, uint32_t);
extern int32_t (*ppa_sw_fastpath_send_hook)(PPA_SKBUF *);
#if defined(CONFIG_PPA_TCP_LITEPATH) && CONFIG_PPA_TCP_LITEPATH
extern int32_t (*ppa_sw_litepath_tcp_send_hook)(PPA_SKBUF *);
#endif
#if IS_ENABLED(CONFIG_PPA_UDP_LITEPATH)
extern int32_t (*ppa_sw_litepath_udp_send_hook)(PPA_SKBUF *);
#endif
extern int32_t (*ppa_sw_add_session_hook)(PPA_BUF *skb, void *pitem);
extern int32_t (*ppa_sw_update_session_hook)(PPA_BUF *skb, void *pitem, void *txifinfo);
extern void (*ppa_sw_del_session_hook)(void *pitem);

