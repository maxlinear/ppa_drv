/*************************************************************************
 **
 ** FILE NAME    : qos_mgr_tc.h
 ** PROJECT      : QOS MGR
 ** MODULES      : QOS MGR (TC APIs)
 **
 ** DATE         : 18 APR 2019
 ** AUTHOR       : Purnendu Ghosh
 ** DESCRIPTION  : QOS MGR TC API Header file
 ** COPYRIGHT :   Copyright © 2025 MaxLinear, Inc.
 **               Copyright (c) 2019 Intel Corporation
 **
 ** For licensing information, see the file 'LICENSE' in the root folder of
 ** this software module.
 *************************************************************************/

#include <net/flow_dissector.h>
#include <net/pkt_cls.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_vlan.h>
#if IS_ENABLED(CONFIG_NET_ACT_COLMARK)
#include <net/tc_act/tc_colmark.h>
#endif
#include <net/tc_act/tc_mirred.h>

#include <net/datapath_api_vlan.h>
#include <net/datapath_api.h>
#include <net/datapath_api_qos.h>
#include "qos_mgr_stack_al.h"
#include <net/qos_mgr/qos_mgr_tc_hook.h>
#include <net/qos_mgr/qos_hal_api.h>
#include "qos_mgr_api.h"
#include "qos_mgr_tc_ds_qos.h"
#include <net/switch_api/lantiq_gsw_api.h>
#include <net/switch_api/lantiq_gsw_flow.h>

#define QOS_MGR_VLAN_NUM 2
#define QOS_MGR_MAX_IFACE 64
#define QOS_MGR_MAX_QUEUE_IFACE 8
#define QOS_MGR_8021P_HIGHEST_PRIO 7
#define QOS_MGR_INVALID_PARENT_HANDLER 0
#define QOS_MGR_DOT1P_SZ 8

#define QOS_MGR_TC_INGRESS 0
#define QOS_MGR_TC_EGRESS 1
#define QOS_MGR_TC_INVALID 2
#define QOS_MGR_TC_SP_WRR 4

enum qos_mgr_tc_sched_type {
	QOS_MGR_TC_MQPRIO,
	QOS_MGR_TC_DRR,
	QOS_MGR_TC_PRIO,
};

struct qos_mgr_match_vlan {
#define QOS_MGR_VLAN_ID		0x01
#define QOS_MGR_VLAN_PRIO	0x02
#define QOS_MGR_VLAN_PROTO	0x04
#define QOS_MGR_VLAN_TPID	0x08
	int32_t			vlan_mask;

	int32_t prio; /* match exact VLAN tag priority: 0-7 */
	int32_t vid; /* match exact VID: 0 - 4093 */
	int32_t tpid; /* match exact TPID: 0x8100 or another configured TPID */
	int32_t dei; /* match exact DEI: 0 or 1 */
	int32_t proto; /* match exact ether type (protocol) */
};

struct qos_mgr_act_vlan {
#define QOS_MGR_ACT_FWD   0x01  /* forward packet */
#define QOS_MGR_ACT_DROP   0x02  /* drop packet */
#define QOS_MGR_VLAN_ACT_POP    0x04  /* pop/remove VLAN */
#define QOS_MGR_VLAN_ACT_PUSH   0x08  /* push/insert VLAN */
#define QOS_MGR_VLAN_ACT_MODIFY   0x10  /* modify  VLAN */

	int32_t act;  /* if act == QOS_MGR_ACT_DROP, drop the packet
		   * if act == QOS_MGR_VLAN_ACT_POP, remove VLAN
		   * if act == QOS_MGR_VLAN_ACT_PUSH, insert VLAN
		   */
	int32_t pop_n;  /*the number of VLAN tag to pop
		     *the valid number: 1 or 2
		     */
	int32_t push_n;  /*the number of VLAN tag to push
		      *the valid number: 1 or 2
		      */
#define CP_FROM_IN    -1 /*copy from inner VLAN header*/
#define CP_FROM_OUT   -2 /*copy from inner VLAN header*/
	int32_t tpid[QOS_MGR_VLAN_NUM]; /* the tpid of VLAN to push:
				* support two TPID 0x8100 and
				* another programmable TPID
				* or
				*  copy from recv pkt's inner tag(CP_FROM_IN)
				*  copy from recv pkt's outer tag(CP_FROM_OUT)
				*/
	int32_t vid[QOS_MGR_VLAN_NUM]; /* the VID of VLAN to push:
				*  support range: 0 - 4093
				* or
				*  copy from recv pkt's inner tag(CP_FROM_IN)
				*  copy from recv pkt's outer tag(CP_FROM_OUT)
				*/
	int32_t dei[QOS_MGR_VLAN_NUM]; /* the DEI of VLAN to push:
				*  support range: 0 - 1
				* or
				*  copy from recv pkt's inner tag(CP_FROM_IN)
				*  copy from recv pkt's outer tag(CP_FROM_OUT)
				*  keep existing value
				*/
	int32_t prio[QOS_MGR_VLAN_NUM]; /* the prority of VLAN to push:
				*  support range: 0 - 7
				* or
				*  copy from recv pkt's inner tag(CP_FROM_IN)
				*  copy from recv pkt's outer tag(CP_FROM_OUT)
				*/
};

struct qos_mgr_tc_flow_rule_act {
	int8_t			act_type;
	struct qos_mgr_act_vlan		action; /*action once matched */
	uint64_t cookie_prio;
};

struct qos_mgr_vlan_entry_match {
	uint32_t			no_of_tag;
	struct qos_mgr_match_vlan	entry[QOS_MGR_VLAN_NUM];/* match pattern.
					* only proto is valid for this case
					*/
};

struct qos_mgr_eth_mac_match {
#define QOS_MGR_ETH_SRC_MAC	0x01
#define QOS_MGR_ETH_DST_MAC	0x02
	uint8_t which_mac;
	uint8_t dst[ETH_ALEN];
	uint8_t src[ETH_ALEN];
};

enum flow_rule_match_to {
	QOS_MGR_MATCH_UNKNOWN,
	QOS_MGR_MATCH_ETH_ADDRS,
	QOS_MGR_MATCH_PROTO,
	QOS_MGR_MATCH_VLAN,
	QOS_MGR_MATCH_METER,
};

struct qos_mgr_tc_flow_rule_match {
	uint32_t		used_keys;
	uint32_t		match_to;
	union {
		struct qos_mgr_vlan_entry_match vlan_match;
		struct qos_mgr_eth_mac_match	eth_match;
	};
};

/** This structure contains DSCP settings for TC flow rule */
struct qos_mgr_tc_flow_rule_dscp {
#define QOS_MGR_DSCP_MAX 64
	/** Enable DSCP prioritization for following rule */
	uint8_t enable;
	/** DSCP identifier */
	uint8_t value;
	/* DSCP to PCP map */
	uint8_t map[QOS_MGR_DSCP_MAX];
};

struct qos_mgr_tc_flow_rule_list_item {
	QOS_MGR_ATOMIC					count;
	uint32_t					dir;
	uint32_t					status;
	uint32_t					priority;
	uint32_t					proto;
	uint32_t					parentid;
	int32_t						meter_id;
	struct net_device				*indev;
	struct qos_mgr_tc_flow_rule_list_item		*next;
	struct qos_mgr_tc_flow_rule_act			flow_action;
	struct qos_mgr_tc_flow_rule_match		flow_pattern;
	/** DSCP settings */
	struct qos_mgr_tc_flow_rule_dscp		dscp;
};

struct qos_mgr_tc_csched;

struct __qos_mgr_tc_queue_info {
	uint32_t p_handle;
	uint32_t priority;
	int32_t queue_id;
	int32_t shaper_id;
	int32_t shaper_index;
	uint32_t quantum;
	uint32_t ref_cnt;
	uint32_t sched_type;
	struct qos_mgr_tc_csched *cshed;
	QOS_QUEUE_LIST_ITEM *p_item;
	struct tc_tbf_qopt_offload tbf;
};

struct qos_mgr_tc_csched {
	uint32_t p_handle;
	struct __qos_mgr_tc_queue_info q_info[QOS_MGR_MAX_QUEUE_IFACE];
};

struct qos_mgr_tc_queue_info {
	int32_t deq_idx;
	int32_t port_id;
	uint32_t no_of_queue;
	uint32_t quanta;
	union {
#if IS_ENABLED(CONFIG_NET_SCH_MQPRIO)
		struct tc_mqprio_qopt mqprio;
#endif
#if IS_ENABLED(CONFIG_NET_SCH_DRR)
		struct tc_drr_qopt_offload drr;
#endif
#if IS_ENABLED(CONFIG_NET_SCH_PRIO)
		struct tc_prio_qopt_offload prio;
#endif
	};
	struct __qos_mgr_tc_queue_info q_info[QOS_MGR_MAX_QUEUE_IFACE];
};

struct qos_mgr_dot1p {
	bool en;
	unsigned int tcid;
};

struct _tc_qos_mgr_db {
	struct net_device				*dev;
	struct qos_mgr_tc_queue_info			qos_info;
	struct qos_mgr_tc_flow_rule_list_item		*flow_item_ig;
	struct qos_mgr_tc_flow_rule_list_item		*flow_item_eg;
	struct qos_mgr_dot1p				dot1p[QOS_MGR_DOT1P_SZ];
	int32_t						flags;
};

int32_t qos_mgr_get_db_handle(struct net_device *dev,
				uint32_t oper,
				struct _tc_qos_mgr_db **handle);

int32_t qos_mgr_free_db_handle(struct _tc_qos_mgr_db *db_handle);

void qos_mgr_free_dev_node_index(uint32_t index);

int32_t qos_mgr_add_queue(struct net_device *dev,
			struct net_device *in_dev,
			uint32_t parentid,
			int32_t tc);

int32_t qos_mgr_del_queue(struct net_device *dev,
			struct net_device *in_dev,
			uint32_t parentid);

int32_t qos_mgr_get_dev_node_match_index(struct net_device *dev);

int32_t qos_mgr_get_free_dev_node_index(void);

struct qos_mgr_tc_flow_rule_list_item *tc_qos_mgr_alloc_list_item(void);

void qos_mgr_tc_free_list_item(struct qos_mgr_tc_flow_rule_list_item *obj);

struct qos_mgr_tc_flow_rule_list_item *tc_qos_mgr_retrieve_list_item(
		uint32_t prio,
		struct qos_mgr_tc_flow_rule_list_item **obj_head);

void qos_mgr_tc_list_item_put(struct qos_mgr_tc_flow_rule_list_item *obj);

int32_t qos_mgr_tc_flow_find_parentid(
			int32_t prio,
			struct qos_mgr_tc_flow_rule_list_item  *fl_list,
			struct net_device **indev,
			uint32_t *classid);

void __qos_mgr_tc_add_list_item(struct qos_mgr_tc_flow_rule_list_item *obj,
			   struct qos_mgr_tc_flow_rule_list_item **obj_head);

int32_t qos_mgr_set_ext_vlan_to_dp(
				struct net_device *dev,
				uint32_t dir,
				struct qos_mgr_tc_flow_rule_list_item  *fl_list);
void qos_mgr_tc_lock_list(void);
void qos_mgr_tc_unlock_list(void);
#if IS_ENABLED(CONFIG_NET_ACT_COLMARK)
int32_t qos_mgr_cfg_meter_to_dp(
				struct net_device *dev,
				struct dp_meter_cfg  *meter_cfg,
				int32_t flag);
#endif
