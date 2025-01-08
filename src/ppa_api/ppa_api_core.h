#ifndef __PPA_API_CORE_H__20081103_1920__
#define __PPA_API_CORE_H__20081103_1920__

/*******************************************************************************
 **
 ** FILE NAME    : ppa_api_core.h
 ** PROJECT      : PPA
 ** MODULES      : PPA API (Routing/Bridging Acceleration APIs)
 **
 ** DATE         : 3 NOV 2008
 ** AUTHOR       : Xu Liang
 ** DESCRIPTION  : PPA Protocol Stack Hook API Implementation Header File
 ** COPYRIGHT    : Copyright © 2020-2021 MaxLinear, Inc. 
 **                Copyright (c) 2017 Intel Corporation
 **
 **   For licensing information, see the file 'LICENSE' in the root folder of
 **   this software module.
 **
 ** HISTORY
 ** $Date        $Author         $Comment
 ** 03 NOV 2008  Xu Liang        Initiate Version
 *******************************************************************************/
/*! \file ppa_api_core.h
  \brief This file contains es.
  provide PPA API.
 */

/** \addtogroup PPA_CORE_API PPA Core API
  \brief  PPA Core API provide PPA core accleration logic and API
  The API is defined in the following two source files
  - ppa_api_core.h: Header file for PPA API
  - ppa_api_core.c: C Implementation file for PPA API
 */
/* @{ */

/*
 * ####################################
 *              Definition
 * ####################################
 */

#define PPA_SESSION_FILTER_PROTO 0x0001
#define PPA_SESSION_FILTER_SPORT 0x0002
#define PPA_SESSION_FILTER_DPORT 0x0004
typedef struct {
	struct list_head list;
	uint16_t		ip_proto;			/* IP prorocol */
	uint16_t		src_port;			/* Source port */
	uint16_t		dst_port;			/* Destination port */
	uint16_t		flags;			  	/* Indicates which parameters to be checked */
	uint16_t		hit_cnt;			/* Indicates hit count */
} FILTER_INFO;

enum VERSION_INDEX {
	VERSION_MAJOR = 0, /*!< Major Version Index */
	VERSION_MID, /*!< Mid Version Index */
	VERSION_MINOR, /*!< Minor Version Index */
	VERSION_TAG, /*!< Tag Version Index */
	VERSION_MAX /*!< Tag Version Index */
};

#define VERSION_STR_LEN	16

#if IS_ENABLED(CONFIG_MCAST_HELPER)
#include <net/mcast_helper_api.h>

int32_t mcast_module_config(uint32_t grp_idx,
			    struct net_device *member,
			    void *mc_stream,
			    uint32_t flags);
#endif /* CONFIG_MCAST_HELPER */

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
extern uint32_t ppa_add_ipsec_tunnel_tbl_entry(PPA_XFRM_STATE * entry,
					       sa_direction dir,
					       uint32_t *tunnel_index);
extern uint32_t ppa_get_ipsec_tunnel_tbl_entry(PPA_XFRM_STATE *entry,
					       sa_direction *dir,
					       uint32_t *tunnel_index);
extern uint32_t ppa_add_ipsec_tunnel_tbl_update(sa_direction dir,
						uint32_t tunnel_index);
#endif
extern FILTER_INFO* get_matched_entry (PPA_HAL_ID hal_id, FILTER_INFO *entry);
extern bool add_filter_entry (PPA_HAL_ID hal_id, FILTER_INFO *entry);
extern bool del_filter_entry (PPA_HAL_ID hal_id, FILTER_INFO *entry);
extern void del_routing_session_cb(void *p_item);

#endif  /*  __PPA_API_CORE_H__20081103_1920__ */
/* @} */
