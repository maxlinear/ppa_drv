/*******************************************************************************
 **
 ** FILE NAME	: ltq_mpe_hal.c
 ** PROJECT	: MPE HAL
 ** MODULES	: MPE (Routing/Bridging Acceleration )
 **
 ** DATE	: 20 Mar 2014
 ** AUTHOR	: Purnendu Ghosh
 ** DESCRIPTION	: MPE HAL Layer
 ** COPYRIGHT	: Copyright © 2020-2024 MaxLinear, Inc.
 **               Copyright (c) 2009, Lantiq Deutschland GmbH
 **	              Am Campeon 3; 85579 Neubiberg, Germany
 **
 **	 For licensing information, see the file 'LICENSE' in the root folder of
 **	 this software module.
 **
 ** HISTORY
 ** $Date		$Author			$Comment
 ** 20 Mar 2014		Purnendu Ghosh		Initiate Version
 *******************************************************************************/

/*
 *	Common Header File
 */
#include <linux/version.h>
#include <generated/autoconf.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/inet.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <linux/firmware.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <net/ip_tunnels.h>
#include <linux/if_arp.h>
#include <linux/in.h>
#include <asm/uaccess.h>
#include <net/ip6_tunnel.h>
#include <net/ipv6.h>
#include <linux/smp.h>

/*
 *	Chip Specific Head File
 */
#include <net/ppa/ppa_api.h>
#include <net/ppa/ppa_hal_api.h>
#include <net/ppa/ppa_hal_wrapper.h>
#include "../../ppa_api/ppa_api_netif.h"
#include "../../ppa_api/ppa_api_session.h"
#include "ltq_mpe_api.h"
#include "ltq_mpe_hal.h"
#include "mpe_debug_hdr.h"
#include <asm/ltq_vmb.h>
#include <linux/of_irq.h>
#include <net/datapath_api.h>

#include <linux/platform_device.h>
#include <linux/of.h>
#include "mpe_fw_ver.h"

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
#include "ltq_tmu_hal_dp_connectivity.h"
#include <net/datapath_api.h>
#include <net/esp.h>
#include <uapi/linux/xfrm.h>
extern ppa_tunnel_entry*		g_tunnel_table[MAX_TUNNEL_ENTRIES];
#include <crypto/ltq_ipsec_ins.h>
#endif
#include <linux/dma-mapping.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <net/datapath_api_qos.h>
#include "ltq_gsw.h"
#include "mpe_hal_qos.h"
#include "ltq_itc.h"

#define FIRMWARE	 "mpe_fw_be.img" /*Firmware Name */
#define FIRMWARE_REQUEST 1

#define MAX_VPE_NUM				2		/*!< Maximum number VPE's that MPE FW supports */
#define DEFAULT_WORKER_THREAD_COUNT 2
#define MPE_TC_STACK_SIZE			0x4000	/*!< TC Stack pointer size */
#define MPE_FILE_PATH "/opt/lantiq/bin/"
#define MPE_PAGE_SIZE				0x1000
#define VIR_TO_PHY(addr) ((addr & 0x7FFFFFFF) | 0x20000000)

#define MPE_HAL_NO_FREE_ENTRY			0x8000
#define MAX_CMP_TABLE_SUPPORTED 		2
#define MAX_ENTRY_ERROR 			0x0001

static int32_t init_pae_flows(void);
static int32_t uninit_pae_flows(void);
static int32_t init_class_mgmt(void);
static int32_t uninit_class_mgmt(void);

/*MPE version*/
char *g_mpe_version;
uint32_t g_Cbm_Inst=0;
struct platform_device *pdev;
const struct firmware *fw_entry;

int32_t sem_id_log[MAX_ITC_SEMID]={0};
#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
#define MAX_RING 4
int32_t ring_id_pool[MAX_RING] = {-1};
#endif

struct tlb_auguments tlb_info __attribute__((aligned(4)));
uint32_t g_MPELaunch_CPU=0;
char * g_MpeFw_load_addr = NULL;
char * g_MpeFw_stack_addr = NULL;
int32_t gImage_size=0;
struct genconf *g_GenConf = NULL;
struct fw_hdr g_MpeFwHdr;
struct buffer_free_list *g_Dispatch_buffer = NULL;
struct buffer_free_list *g_Dl_dispatch_buffer = NULL;
uint32_t dl_free_list_semid; /*!<MIPS itc semaphore address for free list of DMA descriptor */
uint32_t dl_disp_q_cnt_semid; /*!< MIPS itc semaphore address for buffer allocation from cbm */
uint32_t display_action=0;
static int session_counter = 0;

uint8_t logic_tc_mapping[MAX_MPE_TC_NUM];
char str[INET6_ADDRSTRLEN];

uint32_t g_dl1_pmac_port;
uint32_t g_MPE_accl_mode;
bool g_MPE_mc_accl_mode = true;
long unsigned int g_pmac_cfg = 0;
uint16_t max_ipv4_sess_cnt = 0;
uint16_t max_ipv6_sess_cnt = 0;
uint16_t max_compl_sess_cnt = 0;
typedef enum
{
	TMASK0=0,	 /* No mask applied, all fields are used to calculate hash */
	TMASK1,	 /* Mask routing extension */
	TMASK2,	 /* Mask ports and routing extension */
	TMASK3		/* Mask source IP, ports and routing extension */
} eTMASK;

uint32_t g_HAL_State =0;
typedef enum
{
	MPE_HAL_FW_NOT_LOADED = 0,
	MPE_HAL_FW_LOADED,
	MPE_HAL_FW_RESOURCE_ALLOC,
	MPE_HAL_FW_RUNNING
} e_HAL_FW_STATE;

typedef struct
{
	uint8_t ucState; /*!<The VPE state, 0 - VPE_FREE 1 - VPE_RUNNING */
	uint8_t ucActualVpeNo;
	uint8_t ucNoOfAssocTc;
} mpe_hal_vpe_t;

typedef struct
{
	mpe_hal_vpe_t	vpe[MAX_VPE_NUM];
} mpe_hal_vpe_info_t;

mpe_hal_vpe_info_t g_VpeInfo;

typedef struct
{
	uint32_t mpe_tc_id;
} mpe_hal_dl_tc_info;

static DEFINE_PER_CPU(PPA_HAL_STATS, rtstats);
#define PPA_HAL_RTSTATS_INC(field) raw_cpu_inc(rtstats.field)
#define PPA_HAL_RTSTATS_DEC(field) raw_cpu_dec(rtstats.field)

#define get_tm_from_vpe(vpe)		(vpe % 2)

extern int32_t (*mpe_hal_set_checksum_queue_map_hook_fn)(uint32_t pmac_port, uint32_t flags);

static int mpe_hal_load_fw(char* filename);
static int mpe_hal_run_fw(uint8_t ucCpu, uint8_t ucNum_worker);
static int mpe_hal_stop_fw(uint8_t ucCpu);
static int32_t mpe_hal_set_fw_connectivity(u32 dp_port);
static int32_t mpe_hal_set_checksum_queue_map(uint32_t port_id, uint32_t flags);

int32_t ppa_tmplbuf_register_hooks(void);
void ppa_tmplbuf_unregister_hooks(void);
static inline bool is_mpe_restricted(struct uc_session_node *p_item);
int32_t ppa_form_session_tmpl(PPA_SESSMETA_INFO *metainfo);
void ppa_remove_session_tmpl(void *p_item);

int32_t mpe_hal_add_routing_entry(PPA_ROUTING_INFO *route);
int32_t mpe_hal_del_routing_entry(PPA_ROUTING_INFO *route);
uint32_t mpe_hal_add_hw_session(PPA_ROUTING_INFO *route);
uint32_t mpe_hal_del_hw_session(PPA_ROUTING_INFO *route);

int32_t mpe_hal_add_wan_mc_entry(PPA_MC_INFO *mc);
int32_t mpe_hal_del_wan_mc_entry(PPA_MC_INFO *mc);

#if  IS_ENABLED(CONFIG_PPA_MPE_IP97)
int32_t mpe_hal_add_ipsec_tunl_entry(PPA_ROUTING_INFO *route);
int32_t mpe_hal_del_ipsec_tunl_entry(PPA_ROUTING_INFO *route);

int32_t mpe_hal_dump_ipsec_tunnel_info(uint32_t tun_id);
int32_t mpe_hal_alloc_cdr_rdr(void);
int32_t mpe_hal_free_cdr_rdr(void);

int32_t mpe_hal_get_ipsec_tunnel_mib(IPSEC_TUNNEL_MIB_INFO *route);
int32_t mpe_hal_clear_ipsec_tunnel_mib(int32_t tunnel_id);
#endif

int32_t mpe_hal_test_and_clear_hit_stat(PPA_ROUTING_INFO *route);
int32_t mpe_hal_get_session_acc_bytes(PPA_ROUTING_INFO *route);

static int32_t mpe_hal_deregister_caps(void);

#define IsLanSession(flags)           ( (flags) & SESSION_LAN_ENTRY )

static PPA_LOCK		g_mpe_session_list_lock_v4;
static PPA_LOCK		g_mpe_session_list_lock_v6;

#define IDX_MAP_MAX 32
#define IDX_MAP_SHIFT 5
#define IDX_MAP_MASK 0x1f
struct sess_idx_tbl {
	uint32_t *base;	/* table base */
	uint16_t size;	/* table size */
} g_session_idx_table[2];

static int g_ucNum_worker = DEFAULT_WORKER_THREAD_COUNT;
module_param(g_ucNum_worker, int, 0644);
MODULE_PARM_DESC(g_ucNum_worker, "MPE FW worker thread count.");

static void ppa_mpe_session_list_lock_init(void)
{
	ppa_lock_init(&g_mpe_session_list_lock_v4);
	ppa_lock_init(&g_mpe_session_list_lock_v6);
}

static void ppa_mpe_session_list_lock_destroy(void)
{
	ppa_lock_destroy(&g_mpe_session_list_lock_v4);
	ppa_lock_destroy(&g_mpe_session_list_lock_v6);
}

static void ppa_mpe_session_list_lock_v4(void)
{
	ppa_lock_get(&g_mpe_session_list_lock_v4);
}

static void ppa_mpe_session_list_unlock_v4(void)
{
	ppa_lock_release(&g_mpe_session_list_lock_v4);
}

static void ppa_mpe_session_list_lock_v6(void)
{
	ppa_lock_get(&g_mpe_session_list_lock_v6);
}

static void ppa_mpe_session_list_unlock_v6(void)
{
	ppa_lock_release(&g_mpe_session_list_lock_v6);
}

#ifdef MPE_IFMIB
struct iface_index {
	PPA_IFNAME ifname[PPA_IF_NAME_SIZE];
	unsigned long cnt;
};

struct iface_index if_table[PPA_MAX_IFS_NUM];

long unsigned int interface_bitmap = 0;
int32_t alloc_session_interfaceindex(struct uc_session_node *p_item,uint8_t *rx_id,uint8_t *tx_id );
int32_t delete_session_interfaceindex(struct uc_session_node *p_item);
uint8_t get_interface_idx(PPA_IFNAME *pifname);
int32_t put_interface_idx(PPA_IFNAME *pifname);

int32_t get_itf_mib(PPA_ITF_MIB_INFO *mib)
{
	int i=0;
	uint32_t rx_pkt_sum=0, tx_pkt_sum=0 ;
	unsigned long long tx_byte=0, rx_byte=0;
	uint8_t indx=0;


	struct mpe_itf_mib *base;

	if(mib->ifinfo->name != NULL)
		indx = get_interface_idx(mib->ifinfo->name);
	else
		return PPA_FAILURE;

	for(i=0; i<MAX_WORKER_NUM; i++) {
		base = (struct mpe_itf_mib *)(g_GenConf->mib_itf_tbl_base[i] +(indx* sizeof(struct mpe_itf_mib) ) );
		rx_pkt_sum += base->rx_mib.pkt;
		rx_byte+=base->rx_mib.bytes;
		tx_pkt_sum += base->tx_mib.pkt;
		tx_byte+= base->tx_mib.bytes;
	}

	mib->mib.rx_packets = rx_pkt_sum ;
	mib->mib.rx_bytes = rx_byte;

	mib->mib.tx_packets = tx_pkt_sum;
	mib->mib.tx_bytes = tx_byte;
	return PPA_SUCCESS;
}


int32_t clear_itf_mib(PPA_IFNAME *pifname)
{
	int i=0;
	uint8_t indx=0;

	struct mpe_itf_mib *base;

	if (pifname != NULL)
		indx = get_interface_idx(pifname);
	else
		return PPA_FAILURE;

	for (i = 0; i < MAX_WORKER_NUM; i++) {
		base = (struct mpe_itf_mib *)(g_GenConf->mib_itf_tbl_base[i] +(indx* sizeof(struct mpe_itf_mib) ) );
		base->rx_mib.pkt = 0;
		base->rx_mib.bytes = 0;
		base->tx_mib.pkt = 0;
		base->tx_mib.bytes = 0;
	}

	return PPA_SUCCESS;
}



int32_t alloc_session_interfaceindex(struct uc_session_node *p_item,uint8_t *rx_id,uint8_t *tx_id )
{
	PPA_IFNAME rxifname[PPA_IF_NAME_SIZE];
	PPA_IFNAME txifname[PPA_IF_NAME_SIZE];

	if(!p_item) return PPA_FAILURE;
	if (p_item->br_rx_if)
		ppa_strncpy(rxifname, ppa_get_netif_name(p_item->br_rx_if), PPA_IF_NAME_SIZE);
	else if (p_item->rx_if)
		ppa_strncpy(rxifname, ppa_get_netif_name(p_item->rx_if), PPA_IF_NAME_SIZE);

	if (p_item->br_tx_if)
		ppa_strncpy(txifname, ppa_get_netif_name(p_item->br_tx_if), PPA_IF_NAME_SIZE);
	else if (p_item->tx_if)
		ppa_strncpy(txifname, ppa_get_netif_name(p_item->tx_if), PPA_IF_NAME_SIZE);

	if( (rxifname == NULL) || (txifname == NULL) || (rx_id == NULL) || (tx_id == NULL) )
		return PPA_FAILURE;

	*rx_id = get_interface_idx(rxifname);
	*tx_id = get_interface_idx(txifname);

	return PPA_SUCCESS;
}

int32_t delete_session_interfaceindex(struct uc_session_node *p_item)
{
	PPA_IFNAME rxifname[PPA_IF_NAME_SIZE];
	PPA_IFNAME txifname[PPA_IF_NAME_SIZE];

	if (p_item->br_rx_if)
		ppa_strncpy(rxifname, ppa_get_netif_name(p_item->br_rx_if), PPA_IF_NAME_SIZE);
	else if (p_item->rx_if)
		ppa_strncpy(rxifname, ppa_get_netif_name(p_item->rx_if), PPA_IF_NAME_SIZE);

	if (p_item->br_tx_if)
		ppa_strncpy(txifname, ppa_get_netif_name(p_item->br_tx_if), PPA_IF_NAME_SIZE);
	else if (p_item->tx_if)
		ppa_strncpy(txifname, ppa_get_netif_name(p_item->tx_if), PPA_IF_NAME_SIZE);

	if( (rxifname == NULL) || (txifname == NULL) )
		return PPA_FAILURE;

	if (put_interface_idx(rxifname) == PPA_SUCCESS)
		return (put_interface_idx(txifname));
	else {
		put_interface_idx(txifname);
		return PPA_FAILURE;
	}
}

uint8_t get_interface_idx(PPA_IFNAME *pifname)
{
	uint8_t indx=0;

	for_each_set_bit(indx, &interface_bitmap, (PPA_MAX_IFS_NUM - 1))
	if(strncmp(if_table[indx].ifname, pifname,
				PPA_IF_NAME_SIZE) == 0) {
		if_table[indx].cnt ++;
		return indx;
	}

	indx = find_first_zero_bit(&interface_bitmap, (PPA_MAX_IFS_NUM - 1));
	ppa_strncpy(if_table[indx].ifname, pifname, PPA_IF_NAME_SIZE);
	if_table[indx].cnt = 1;
	set_bit(indx,&interface_bitmap);

	return indx;
}

int32_t put_interface_idx(PPA_IFNAME *pifname)
{
	bool found = false;
	int indx;


	for_each_set_bit(indx, &interface_bitmap, (PPA_MAX_IFS_NUM - 1))
		if(strncmp(if_table[indx].ifname,pifname,PPA_IF_NAME_SIZE) == 0) {
			found = true;
			break;
		}
	if (!found) {
		return PPA_FAILURE;
	}

	if(if_table[indx].cnt > 0) {
		if_table[indx].cnt -= 1;
		return PPA_SUCCESS;
	}

	clear_bit(indx,&interface_bitmap);
	memset(&if_table[indx], 0x00, sizeof(struct iface_index));
	return PPA_SUCCESS;
}
#endif

static uint32_t get_number_of_phys_port(void)
{
	return MAX_PAE_PORTS;
}

static void get_phys_port_info(uint32_t port, uint32_t *p_flags,
				PPA_IFNAME ifname[PPA_IF_NAME_SIZE])
{
	/* This function can only set the flags based on GSWIP-O configuration
	Interface name needs to be retrieved from the dp */

	if ( port >= MAX_PAE_PORTS) {
		if ( p_flags )
			*p_flags = 0;
		if ( ifname )
			*ifname = 0;
		return;
	}

	if(p_flags) {
		*p_flags = 0;
		switch(port) {
			case 0: /*CPU port */
				*p_flags = PPA_PHYS_PORT_FLAGS_MODE_CPU_VALID;
				*ifname = 0;
				break;
			case 1:
				break;
			case 2:
					*p_flags = PPA_PHYS_PORT_FLAGS_MODE_ETH_WAN_VALID;
				break;
			case 3:
				break;
			case 4:
					*p_flags = PPA_PHYS_PORT_FLAGS_MODE_ETH_LAN_VALID;
				break;
			case 5:
			case 6:
			case 7:
			case 8:
			case 9:
			case 10:
			case 11:
			case 12:
			case 13:
			case 14:
			case 15:
					*p_flags = PPA_PHYS_PORT_FLAGS_MODE_ETH_MIX_VALID;
				break;
			default:
				*p_flags = 0;
				break;
		}
	}
}

static void get_hal_stats(PPA_HAL_STATS *stat)
{
	unsigned int cpu;
	const PPA_HAL_STATS *rt;

	memset(stat, 0, sizeof(PPA_HAL_STATS));
	stat->max_uc_session = MAX_FW_SESSION_NUM + MAX_HW_SESSION_NUM;
	stat->max_mc_session = MAX_MC_NUM;
	stat->max_uc_ipv4_session = MAX_FW_SESSION_NUM;
	stat->max_uc_ipv6_session = MAX_HW_SESSION_NUM;
	for_each_possible_cpu(cpu) {
		rt = per_cpu_ptr(&rtstats, cpu);
		stat->curr_uc_ipv4_session += rt->curr_uc_ipv4_session;
		stat->curr_uc_ipv6_session += rt->curr_uc_ipv6_session;
		stat->curr_mc_ipv4_session += rt->curr_mc_ipv4_session;
		stat->curr_mc_ipv6_session += rt->curr_mc_ipv6_session;
		stat->uc_dropped_sess += rt->uc_dropped_sess;
		stat->mc_dropped_sess += rt->mc_dropped_sess;
	}
}

/*================================================================================================ */
static int32_t mpe_hal_generic_hook(PPA_GENERIC_HOOK_CMD cmd, void *buffer, uint32_t flag)
{
	uint32_t res = PPA_SUCCESS;
	switch (cmd)	{
	case PPA_GENERIC_HAL_INIT: /*init HAL*/ {
		if((res = ppa_drv_register_cap(SESS_IPV4, 2, MPE_HAL)) != PPA_SUCCESS) {
			pr_err("ppa_drv_register_cap returned failure for capability SESS_IPV4!!!\n");
		}

		if((res = ppa_drv_register_cap(SESS_IPV6, 2, MPE_HAL)) != PPA_SUCCESS) {
			pr_err("ppa_drv_register_cap returned failure for capability SESS_IPV6!!!\n");
		}

		if((res = ppa_drv_register_cap(SESS_BRIDG, 1, MPE_HAL)) != PPA_SUCCESS) {
			pr_err("ppa_drv_register_cap returned failure for capability SESS_BRIDG!!!\n");
		}

		if((res = ppa_drv_register_cap(TUNNEL_6RD, 1, MPE_HAL)) != PPA_SUCCESS) {
			pr_err("ppa_drv_register_cap returned failure for capability TUNNEL_6RD!!!\n");
		}

		if((res = ppa_drv_register_cap(TUNNEL_DSLITE, 1, MPE_HAL)) != PPA_SUCCESS) {
			pr_err("ppa_drv_register_cap returned failure for capability TUNNEL_DSLITE!!!\n");
		}

		if((res = ppa_drv_register_cap(TUNNEL_L2TP_US, 1, MPE_HAL)) != PPA_SUCCESS) {
			pr_err("ppa_drv_register_cap returned failure for capability TUNNEL_L2TP_US,!!!\n");
		}

		res = ppa_drv_register_cap(TUNNEL_L2TP_DS, 1, MPE_HAL);
		if (res != PPA_SUCCESS)
			pr_err("ppa_drv_register_cap returned failure for capability TUNNEL_L2TP_DS,!!!\n");

		if((res = ppa_drv_register_cap(TUNNEL_GRE_US, 1, MPE_HAL)) != PPA_SUCCESS) {
			pr_err("ppa_drv_register_cap returned failure for capability TUNNEL_GRE_US,!!!\n");
		}

		res = ppa_drv_register_cap(TUNNEL_GRE_DS, 1, MPE_HAL);
		if (res != PPA_SUCCESS)
			pr_err("ppa_drv_register_cap returned failure for capability TUNNEL_GRE_DS,!!!\n");

		res = ppa_drv_register_cap(SESS_MC_DS, 2, MPE_HAL);
		if (res != PPA_SUCCESS)
			pr_err("ppa_drv_register_cap returned failure for capability SESS_MC_DS,!!!\n");

		if((res = ppa_drv_register_cap(SESS_MC_DS_VAP, 1, MPE_HAL)) != PPA_SUCCESS) {
			pr_err("ppa_drv_register_cap returned failure for capability SESS_MC_DS_VAP,!!!\n");
		}
#if IS_ENABLED(CONFIG_PPA_NAT_LOOP_BACK)
		if((res = ppa_drv_register_cap(SESS_NAT_LOOPBACK, 1, MPE_HAL)) != PPA_SUCCESS) {
			pr_err("ppa_drv_register_cap returned failure for capability SESS_NAT_LOOPBACK,!!!\n");
		}
#endif

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
		if((res = ppa_drv_register_cap(TUNNEL_IPSEC_US, 1, MPE_HAL)) != PPA_SUCCESS) {
			pr_err("ppa_drv_register_cap returned failure for capability TUNNEL_IPSEC_US!!!\n");
		}

		if((res = ppa_drv_register_cap(TUNNEL_IPSEC_DS, 1, MPE_HAL)) != PPA_SUCCESS) {
			pr_err("ppa_drv_register_cap returned failure for capability TUNNEL_IPSEC_US!!!\n");
		}

		if((res = ppa_drv_register_cap(TUNNEL_IPSEC_MIB, 1, MPE_HAL)) != PPA_SUCCESS) {
			pr_err("ppa_drv_register_cap returned failure for capability TUNNEL_IPSEC_MIB!!!\n");
		}
#endif
#if IS_ENABLED(CONFIG_INTEL_IPQOS_MPE_DS_ACCEL)
		if((res = ppa_drv_register_cap(MPE_DS_QOS, 1, MPE_HAL)) != PPA_SUCCESS) {
			pr_err("ppa_drv_register_cap returned failure for capability MPE_DS_QOS!!!\n");
		}
#endif
		/* init the multicast template buffer hooks*/
		ppa_tmplbuf_register_hooks();

		pr_err(KERN_INFO"Init Success\n");
			return PPA_SUCCESS;
	}
	case PPA_GENERIC_HAL_EXIT: /*EXIT HAL*/ {
		/* uninit the multicast template buffer hooks*/
		ppa_tmplbuf_unregister_hooks();
		return mpe_hal_deregister_caps();
	}
	case PPA_GENERIC_HAL_GET_HAL_VERSION: {
		PPA_VERSION *v = (PPA_VERSION *)buffer;
		strncpy(v->version, "1.0.1", 6);
		return PPA_SUCCESS;
	}
	case PPA_GENERIC_HAL_GET_PPE_FW_VERSION: {
		PPA_VERSION *v=(PPA_VERSION *)buffer;

		v->family = g_GenConf->fw_hdr.family;
		v->type = g_GenConf->fw_hdr.package;
		v->major = g_GenConf->fw_hdr.v_maj;
		v->mid = g_GenConf->fw_hdr.v_mid;
		v->minor = g_GenConf->fw_hdr.v_min;
		return PPA_SUCCESS;
	}
	case PPA_GENERIC_HAL_UPDATE_SESS_META: {
		if (g_MPE_accl_mode) {
			PPA_SESSMETA_INFO *metainfo = (PPA_SESSMETA_INFO *)buffer;
			if (metainfo) {
				if (is_mpe_restricted(metainfo->p_item))
					return PPA_FAILURE;
				return ppa_form_session_tmpl(metainfo);
			} else {
				return PPA_FAILURE;
			}
		} else {
			return PPA_FAILURE;
		}

	}
	case PPA_GENERIC_HAL_CLEAR_SESS_META: {
		struct uc_session_node *p_item = (struct uc_session_node *)buffer;
		ppa_remove_session_tmpl(p_item);
		return res;
	}
	case PPA_GENERIC_HAL_ADD_ROUTE_ENTRY: {
		PPA_ROUTING_INFO *route=(PPA_ROUTING_INFO *)buffer;
		if(g_MPE_accl_mode)
			return mpe_hal_add_routing_entry(route);
		else
			return PPA_FAILURE;
	}
	case PPA_GENERIC_HAL_DEL_ROUTE_ENTRY: {
		PPA_ROUTING_INFO *route=(PPA_ROUTING_INFO *)buffer;
		return mpe_hal_del_routing_entry( route );
	}
	case PPA_GENERIC_HAL_ADD_COMPLEMENT_ENTRY: {
		PPA_ROUTING_INFO *route=(PPA_ROUTING_INFO *)buffer;
		if(g_MPE_accl_mode)
			return mpe_hal_add_hw_session(route);
		else
			return PPA_FAILURE;
	}
	case PPA_GENERIC_HAL_DEL_COMPLEMENT_ENTRY: {
		PPA_ROUTING_INFO *route=(PPA_ROUTING_INFO *)buffer;
		return mpe_hal_del_hw_session(route);
	}
	case PPA_GENERIC_HAL_ADD_MC_ENTRY: {
		PPA_MC_INFO *mc = (PPA_MC_INFO *)buffer;
		if (g_MPE_accl_mode && g_MPE_mc_accl_mode)
			return mpe_hal_add_wan_mc_entry(mc);
		else
			return PPA_FAILURE;
	}
	case PPA_GENERIC_HAL_DEL_MC_ENTRY: {
		PPA_MC_INFO *mc = (PPA_MC_INFO *)buffer;
		mpe_hal_del_wan_mc_entry(mc);
		return PPA_SUCCESS;
	}
#ifdef MPE_IFMIB
	case PPA_GENERIC_HAL_GET_NEW_ITF_MIB:	 {
		PPA_ITF_MIB_INFO *mib=(PPA_ITF_MIB_INFO *)buffer;
		return ( get_itf_mib(mib));
	}
#endif
	case PPA_GENERIC_HAL_TEST_CLEAR_ROUTE_HIT_STAT:	/*check whether a routing entry is hit or not */ {
		PPA_ROUTING_INFO *route=(PPA_ROUTING_INFO *)buffer;
		mpe_hal_test_and_clear_hit_stat(route);
		return PPA_SUCCESS;
	}
	case PPA_GENERIC_HAL_GET_ROUTE_ACC_BYTES: /*Get accelerated bytes of the session*/ {
		PPA_ROUTING_INFO *route=(PPA_ROUTING_INFO *)buffer;
		mpe_hal_get_session_acc_bytes(route);
		return PPA_SUCCESS;
	}
#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	case PPA_GENERIC_HAL_GET_IPSEC_TUNNEL_MIB:/*Get accelerated bytes of the session */{
		IPSEC_TUNNEL_MIB_INFO *mib =(IPSEC_TUNNEL_MIB_INFO *)buffer;
		mpe_hal_get_ipsec_tunnel_mib(mib);
		return PPA_SUCCESS;
	}
#endif
	case PPA_GENERIC_HAL_GET_PHYS_PORT_NUM: {
		PPA_COUNT_CFG *count = (PPA_COUNT_CFG *) buffer;

		count->num = get_number_of_phys_port();
		return PPA_SUCCESS;
	}
	case PPA_GENERIC_HAL_GET_PHYS_PORT_INFO: {
		PPE_IFINFO *info = (PPE_IFINFO *) buffer;
		get_phys_port_info(info->port, &info->if_flags, info->ifname);
		return PPA_SUCCESS;
	}
	case PPA_GENERIC_HAL_GET_STATS:{
			PPA_HAL_STATS *stat = (PPA_HAL_STATS *)buffer;

			if (!stat)
				return PPA_FAILURE;

			get_hal_stats(stat);

			return PPA_SUCCESS;
	}
	default:
		return PPA_FAILURE;
	}

	return PPA_FAILURE;
}


/* ======================================================================================================= */
char *inet_ntoa(u32 in)
{
    static char b[18];
    register char *p;

    p = (char *)&in;
#define	UC(b)	(((int)b)&0xff)
    (void)snprintf(b, sizeof(b),
            "%d.%d.%d.%d", UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]));
    return (b);
}

static char * inet_ntop4(const unsigned char *src, char *dst, u32 size) {
    static const char fmt[] = "%u.%u.%u.%u";
    char tmp[sizeof "255.255.255.255"];
    int l;

    l = snprintf(tmp, sizeof(tmp), fmt, src[0], src[1], src[2], src[3]);
    if (l <= 0 ||  l >= size) {
        return (NULL);
    }
    strlcpy(dst, tmp, size);
    return (dst);
}

static char * inet_ntop6(const unsigned char *src, char *dst, u32 size) {
    char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
    struct { int base, len; } best, cur;
#define NS_IN6ADDRSZ 16
#define NS_INT16SZ 2
    u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
    int i;

    memset(words, '\0', sizeof words);
    for (i = 0; i < NS_IN6ADDRSZ; i++)
        words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
    best.base = -1;
    best.len = 0;
    cur.base = -1;
    cur.len = 0;
    for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
        if (words[i] == 0) {
            if (cur.base == -1)
                cur.base = i, cur.len = 1;
            else
                cur.len++;
        } else {
            if (cur.base != -1) {
                if (best.base == -1 || cur.len > best.len)
                    best = cur;
                cur.base = -1;
            }
        }
    }
    if (cur.base != -1) {
        if (best.base == -1 || cur.len > best.len)
            best = cur;
    }
    if (best.base != -1 && best.len < 2)
        best.base = -1;
    tp = tmp;
    for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
        /* Are we inside the best run of 0x00's? */
        if (best.base != -1 && i >= best.base &&
                i < (best.base + best.len)) {
            if (i == best.base)
                *tp++ = ':';
            continue;
        }
        if (i != 0)
            *tp++ = ':';
        if (i == 6 && best.base == 0 && (best.len == 6 ||
                    (best.len == 7 && words[7] != 0x0001) ||
                    (best.len == 5 && words[5] == 0xffff))) {
            if (!inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
                return (NULL);
            tp += strlen(tp);
            break;
        }
        tp += sprintf(tp, "%x", words[i]);
    }
    if (best.base != -1 && (best.base + best.len) ==
            (NS_IN6ADDRSZ / NS_INT16SZ))
        *tp++ = ':';
    *tp++ = '\0';
    if ((tp - tmp) > size) {
        return (NULL);
    }
    strncpy(dst, tmp, (size - 1));
    dst[size - 1] = '\0';
    return (dst);
}


uint16_t mpe_hal_crcmsb(const uint8_t *data, unsigned int len)
{
    uint16_t crc = 0;
    int i;
    if (len) do {
    crc ^= ((*data)<<8);
    data++;
    for (i=0; i<8; i++) {
        if (crc & 0x8000) crc = (crc << 1) ^ 0x1021;
        else crc <<= 1;
        crc=crc&0xFFFF;
        }
    } while (--len);
    return crc;
}

uint16_t mpe_cal_hash(struct ipv4_hash_auto_key *p4, struct ipv6_hash_auto_key *p6, eTMASK tm)
{
    uint8_t  b[13];
    uint16_t b2 = 0;
    uint32_t b4, b6[4];
    uint16_t crc;

    memset(b, 0, sizeof (b));
    // Extract the structure into bytes
    // Arrange MSB first for CRC16 calculation
#ifdef CONFIG_BIG_ENDIAN // tested with EB mode MIPS
    if (p4) {
        b4 = (((TMASK0==tm) || (TMASK1==tm) || (TMASK2==tm)) ? p4->srcip:0x00000000);
        //if(TMASK3==tm) p->srcip.ip = 0;
        //b4 = p->srcip.ip;
        b[0]  = ((uint8_t *)&b4)[0]; // (b4 & 0xff000000)>>24;
        b[1]  = ((uint8_t *)&b4)[1]; // (b4 & 0x00ff0000)>>16;
        b[2]  = ((uint8_t *)&b4)[2]; // (b4 & 0x0000ff00)>> 8;
        b[3]  = ((uint8_t *)&b4)[3]; // (b4 & 0x000000ff)>> 0;

        b4 = p4->dstip;
        b[4]  = ((uint8_t *)&b4)[0];
        b[5]  = ((uint8_t *)&b4)[1];
        b[6]  = ((uint8_t *)&b4)[2];
        b[7]  = ((uint8_t *)&b4)[3];
    } else if (p6) {
        //b4 = (((TMASK0==tm) || (TMASK1==tm) || (TMASK2==tm)) ?
        //        b6[0]^b6[1]^b6[2]^ b6[3] : 0x00000000)

        b6[0] = ((TMASK3==tm) ? 0: p6->srcip[0]);
        b6[1] = ((TMASK3==tm) ? 0: p6->srcip[1]);
        b6[2] = ((TMASK3==tm) ? 0: p6->srcip[2]);
        b6[3] = ((TMASK3==tm) ? 0: p6->srcip[3]);
        b4    = b6[0] ^ b6[1] ^ b6[2] ^ b6[3];
        b[0]  = ((uint8_t *)&b4)[0];
        b[1]  = ((uint8_t *)&b4)[1];
        b[2]  = ((uint8_t *)&b4)[2];
        b[3]  = ((uint8_t *)&b4)[3];

        b6[0] = p6->dstip[0];
        b6[1] = p6->dstip[1];
        b6[2] = p6->dstip[2];
        b6[3] = p6->dstip[3];
        b4    = b6[0] ^ b6[1] ^ b6[2] ^ b6[3];
        b[4]  = ((uint8_t *)&b4)[0];
        b[5]  = ((uint8_t *)&b4)[1];
        b[6]  = ((uint8_t *)&b4)[2];
        b[7]  = ((uint8_t *)&b4)[3];
    }

    if(p4)      b2 = (((TMASK0==tm) || (TMASK1==tm)) ? p4->srcport:0x0000);
    else if(p6) b2 = (((TMASK0==tm) || (TMASK1==tm)) ? p6->srcport:0x0000);
    //if(((TMASK2==tm) || (TMASK3==tm))) p->srcport = 0;
    //b2 = p->srcport;
    b[8]  = ((uint8_t *)&b2)[0];
    b[9]  = ((uint8_t *)&b2)[1];

    if(p4)      b2 = (((TMASK0==tm) || (TMASK1==tm)) ? p4->dstport:0x0000);
    else if(p6) b2 = (((TMASK0==tm) || (TMASK1==tm)) ? p6->dstport:0x0000);
    //if((TMASK2==tm) || (TMASK3==tm)) p->dstport = 0;
    //b2 = p->dstport;
    b[10] = ((uint8_t *)&b2)[0];
    b[11] = ((uint8_t *)&b2)[1];

    //b1 = ((TMASK0==tm) ? p->extn:0x00);
    //if (TMASK0!=tm) p->extn &= 1; // FLAGS_UDP is unmaskable
    if(p4)      b[12] = ((TMASK0==tm) ? p4->extn:(p4->extn &= 1));
    else if(p6) b[12] = ((TMASK0==tm) ? p6->extn:(p6->extn &= 1));

#else
    if (p4) {
        b4 = (((TMASK0==tm) || (TMASK1==tm) || (TMASK2==tm)) ? p4->srcip:0x00000000);
        //if(TMASK3==tm) p->srcip.ip = 0;
        //b4 = p->srcip.ip;
        b[0]  = ((uint8_t *)&b4)[3]; // (b4 & 0xff000000)>>24;
        b[1]  = ((uint8_t *)&b4)[2]; // (b4 & 0x00ff0000)>>16;
        b[2]  = ((uint8_t *)&b4)[1]; // (b4 & 0x0000ff00)>> 8;
        b[3]  = ((uint8_t *)&b4)[0]; // (b4 & 0x000000ff)>> 0;

        b4 = p4->dstip;
        b[4]  = ((uint8_t *)&b4)[3];
        b[5]  = ((uint8_t *)&b4)[2];
        b[6]  = ((uint8_t *)&b4)[1];
        b[7]  = ((uint8_t *)&b4)[0];
    } else if (p6) {
        //b4 = (((TMASK0==tm) || (TMASK1==tm) || (TMASK2==tm)) ?
        //        b6[0]^b6[1]^b6[2]^ b6[3] : 0x00000000)

        b6[0] = ((TMASK3==tm) ? 0: p6->srcip[0]);
        b6[1] = ((TMASK3==tm) ? 0: p6->srcip[1]);
        b6[2] = ((TMASK3==tm) ? 0: p6->srcip[2]);
        b6[3] = ((TMASK3==tm) ? 0: p6->srcip[3]);
        b4    = b6[0] ^ b6[1] ^ b6[2] ^ b6[3];
        b[0]  = ((uint8_t *)&b4)[3];
        b[1]  = ((uint8_t *)&b4)[2];
        b[2]  = ((uint8_t *)&b4)[1];
        b[3]  = ((uint8_t *)&b4)[0];

        b6[0] = p6->dstip[0];
        b6[1] = p6->dstip[1];
        b6[2] = p6->dstip[2];
        b6[3] = p6->dstip[3];
        b4    = b6[0] ^ b6[1] ^ b6[2] ^ b6[3];
        b[4]  = ((uint8_t *)&b4)[3];
        b[5]  = ((uint8_t *)&b4)[2];
        b[6]  = ((uint8_t *)&b4)[1];
        b[7]  = ((uint8_t *)&b4)[0];
    }

    if(p4)      b2 = (((TMASK0==tm) || (TMASK1==tm)) ? p4->srcport:0x0000);
    else if(p6) b2 = (((TMASK0==tm) || (TMASK1==tm)) ? p6->srcport:0x0000);
    //if(((TMASK2==tm) || (TMASK3==tm))) p->srcport = 0;
    //b2 = p->srcport;
    b[8]  = ((uint8_t *)&b2)[1];
    b[9]  = ((uint8_t *)&b2)[0];

    if(p4)      b2 = (((TMASK0==tm) || (TMASK1==tm)) ? p4->dstport:0x0000);
    else if(p6) b2 = (((TMASK0==tm) || (TMASK1==tm)) ? p6->dstport:0x0000);
    //if((TMASK2==tm) || (TMASK3==tm)) p->dstport = 0;
    //b2 = p->dstport;
    b[10] = ((uint8_t *)&b2)[1];
    b[11] = ((uint8_t *)&b2)[0];

    //b1 = ((TMASK0==tm) ? p->extn:0x00);
    //if (TMASK0!=tm) p->extn &= 1; // FLAGS_UDP is unmaskable
    if(p4)      b[12] = ((TMASK0==tm) ? p4->extn:(p4->extn &= 1));
    else if(p6) b[12] = ((TMASK0==tm) ? p6->extn:(p6->extn &= 1));
#endif
    crc = mpe_hal_crcmsb(b, sizeof(b));
    return (crc);
}


uint16_t mpe_hal_calculate_hash(void *pKey, uint32_t type)
{
	uint32_t len;

        if(type == 0) {
		len = sizeof(struct ipv4_hash_auto_key);
	} else
		len = sizeof(struct ipv6_hash_auto_key);

	mpe_cal_hash(pKey, NULL, 0);
	return PPA_SUCCESS;
}

static inline void
mpe_hal_set_session_index(uint8_t type, uint32_t cum_idx)
{
	uint16_t tbl_idx = cum_idx >> IDX_MAP_SHIFT;
	uint8_t lcl_idx = cum_idx & IDX_MAP_MASK;

	g_session_idx_table[type].base[tbl_idx] |= (1 << lcl_idx);
}

static inline void
mpe_hal_reset_session_index(uint8_t type, uint32_t cum_idx)
{
	uint16_t tbl_idx = cum_idx >> IDX_MAP_SHIFT;
	uint8_t lcl_idx = cum_idx & IDX_MAP_MASK;

	g_session_idx_table[type].base[tbl_idx] &= ~(1 << lcl_idx);
}

static inline uint32_t
mpe_hal_find_free_index(uint8_t type)
{
	uint16_t tbl_idx;
	uint8_t lcl_idx;
	uint16_t cum_idx = MPE_HAL_NO_FREE_ENTRY;

	for (tbl_idx = 0; tbl_idx < g_session_idx_table[type].size; tbl_idx++) {
		if (!(g_session_idx_table[type].base[tbl_idx] ^ U32_MAX))
			continue;
		lcl_idx = find_first_zero_bit((unsigned long *)&g_session_idx_table[type].base[tbl_idx],
				IDX_MAP_MAX);
		if (likely(lcl_idx < IDX_MAP_MAX)) {
			cum_idx = ((tbl_idx << IDX_MAP_SHIFT) | lcl_idx);
			break;
		}
	}

	return cum_idx;
}

static inline void dump_pkt(u32 len, char *pData){
        int i;
        for(i=0;i<len;i++){
                ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%2.2x ",(u8)(pData[i]));
                if (i % 16 == 15)
                        pr_err("\n");
        }
	pr_err("\n");
}

uint32_t mpe_hal_add_session_ipv4(struct fw_compare_hash_auto_ipv4 *pIp4CmpTbl, struct ipv4_hash_auto_key *p_key, uint32_t sess_action,struct uc_session_node *p_item)
{
	uint32_t free_index = 0;
	uint32_t count = 0;
	uint32_t current_index = 0;
	uint32_t last_index = 0;
	uint32_t hash_index = 0;
	uint32_t tmp = 0;
	struct fw_compare_hash_auto_ipv4 *hash_index_ptr = NULL;
	struct fw_compare_hash_auto_ipv4 *temp_ptr = NULL;
#ifdef MPE_IFMIB
	uint8_t rx_id = 0, tx_id = 0;
#endif

	if (pIp4CmpTbl == NULL) {
		pr_err("No IPV4 Compare Table is allocated\n");
		return PPA_FAILURE;
	}

	if (((struct session_action *)(sess_action)) == NULL) {
		pr_err("No Session Action Pointer\n");
		return PPA_FAILURE;
	}

	if (max_ipv4_sess_cnt >= (g_GenConf->fw_sess_tbl_num[0] - 1))
		return PPA_FAILURE;

	/* dump_pkt(sizeof(struct ipv4_hash_auto_key), (char *)p_key);*/
	hash_index = mpe_cal_hash(p_key, NULL, 0);
	hash_index &= (g_GenConf->fw_sess_tbl_num[0] - 1);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT, "<%s> Hash Index %d g_GenConf->fw_sess_tbl_num[0]=%d\n",
			__FUNCTION__, hash_index, g_GenConf->fw_sess_tbl_num[0]);

	hash_index_ptr = (pIp4CmpTbl + hash_index);
	tmp = hash_index_ptr->first_ptr;
	last_index = tmp;
	while (tmp != (pIp4CmpTbl + tmp)->nxt_ptr) {
		last_index = tmp;
		tmp = (pIp4CmpTbl + tmp)->nxt_ptr;
		count++;
	}
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tmp index %d last index %d\n", tmp, last_index);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s>Iteration count : %d\n", __FUNCTION__, count);
	if (count > (MAX_SEARCH_ITRN - 1)) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Number of entries for hash=%X[%d] is %d\n", hash_index, hash_index, count);
		return PPA_FAILURE;
	}

	current_index = (hash_index_ptr->first_ptr);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"current index %d\n",current_index);
	if (current_index == (g_GenConf->fw_sess_tbl_num[0] -1)) {
		/*not valid first_ptr. it means there is no session yet in this hash_index*/
		temp_ptr = hash_index_ptr;
		if(temp_ptr->valid) {
			free_index = mpe_hal_find_free_index(0);
			if (free_index == MPE_HAL_NO_FREE_ENTRY) {
				ppa_debug(DBG_ENABLE_MASK_ERR,"No Free Entry !!!\n");
				return PPA_FAILURE;
			}
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n free_index[%d]\n", free_index);
		} else {
			free_index = hash_index;
		}
	} else {
		/*some session already exists in hash_index*/
		temp_ptr = (pIp4CmpTbl + current_index);
		if (temp_ptr->valid) {
			free_index = mpe_hal_find_free_index(0);
			if (free_index == MPE_HAL_NO_FREE_ENTRY) {
				ppa_debug(DBG_ENABLE_MASK_ERR," No Free Entry for session already exist in hash index \n");
				return PPA_FAILURE;
			}
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"free_index[%d] for hash[%d]\n", free_index, hash_index);
		} else {
			free_index = current_index;
		}
	}

	temp_ptr = pIp4CmpTbl + free_index;
	if (count > 0) {
		if (((pIp4CmpTbl + last_index)->nxt_ptr) == (g_GenConf->fw_sess_tbl_num[0] - 1))
			(pIp4CmpTbl + last_index)->nxt_ptr = free_index;
	}

	if (hash_index_ptr->first_ptr == (g_GenConf->fw_sess_tbl_num[0] - 1))
		hash_index_ptr->first_ptr = free_index;
	else {
		if (hash_index_ptr == temp_ptr) {
			hash_index_ptr->nxt_ptr = current_index;
			hash_index_ptr->first_ptr = free_index;
			(pIp4CmpTbl + last_index)->nxt_ptr = g_GenConf->fw_sess_tbl_num[0] - 1;
		}
	}

	temp_ptr->key.srcip     = p_key->srcip;
	temp_ptr->key.dstip     = p_key->dstip;
	temp_ptr->key.srcport   = p_key->srcport;
	temp_ptr->key.dstport   = p_key->dstport;
	temp_ptr->key.extn      = p_key->extn;
	temp_ptr->act           = sess_action;
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Action Pointer: %x \n", temp_ptr->act);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> returning Free Index: %d \n", __FUNCTION__, free_index);


	/* Set the MIB and Hit counter for this session index */
	((struct session_action *)(temp_ptr->act))->sess_mib_ix_en = 1;
	((struct session_action *)(temp_ptr->act))->sess_mib_hit_en = 1;
	((struct session_action *)(temp_ptr->act))->sess_mib_ix = free_index;

	wmb();
	temp_ptr->valid = 1;
	max_ipv4_sess_cnt += 1;

	mpe_hal_set_session_index(0, free_index);
#ifdef MPE_IFMIB
	if (alloc_session_interfaceindex(p_item,&rx_id,&tx_id) == PPA_SUCCESS) {
		((struct session_action *)(temp_ptr->act))->rx_itf_mib_num = 1;
		((struct session_action *)(temp_ptr->act))->rx_itf_mib_ix[0] = rx_id; /* eth0_1*/
		((struct session_action *)(temp_ptr->act))->tx_itf_mib_num = 1;
		((struct session_action *)(temp_ptr->act))->tx_itf_mib_ix[0] = tx_id; /* eth1 */
	}
#endif

	return free_index;
}


uint32_t mpe_hal_add_session_ipv6(struct fw_compare_hash_auto_ipv6 *pIp6CmpTbl, struct ipv6_hash_auto_key *p_key, uint32_t sess_action)
{
	uint32_t free_index = 0;
	uint32_t count = 0;
	uint32_t current_index = 0;
	uint32_t last_index = 0;
	uint32_t hash_index = 0;
	uint32_t tmp = 0;
	struct fw_compare_hash_auto_ipv6 *hash_index_ptr = NULL;
	struct fw_compare_hash_auto_ipv6 *temp_ptr = NULL;

	if (pIp6CmpTbl == NULL) {
		pr_err("No IPV6 Compare Table is allocated\n");
		return PPA_FAILURE;
	}

	if (((struct session_action *)(sess_action)) == NULL) {
		pr_err("No Session Action Pointer\n");
		return PPA_FAILURE;
	}

	if (max_ipv6_sess_cnt >= (g_GenConf->fw_sess_tbl_num[1] - 1))
		return PPA_FAILURE;

	/*dump_pkt(sizeof(struct ipv6_hash_auto_key), (char *)p_key); */
	hash_index = mpe_cal_hash(NULL, p_key, 0);
	/*pr_err("\n CRC Calculation %x\n",hash_index);*/
	hash_index &= (g_GenConf->fw_sess_tbl_num[1] - 1);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n<%s> Hash Index %d\n",__FUNCTION__, hash_index);

	hash_index_ptr = (pIp6CmpTbl + hash_index);
	tmp = (hash_index_ptr->first_ptr);
	last_index = tmp;
	while (tmp != (pIp6CmpTbl + tmp)->nxt_ptr) {
		last_index = tmp;
		tmp = (pIp6CmpTbl + tmp)->nxt_ptr;
		count++;
	}

	if (count > (MAX_SEARCH_ITRN - 1)) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"\nNumber of entries for hash=%X is %d \n", hash_index, count);
		return PPA_FAILURE;
	}

	current_index = hash_index_ptr->first_ptr;
	if (current_index == (g_GenConf->fw_sess_tbl_num[1] - 1)) {
		/*not valid first_ptr. it means there is no session yet in this hash_index*/
		temp_ptr = hash_index_ptr;
		if (temp_ptr->valid) {
			free_index = mpe_hal_find_free_index(1);
			if (free_index == MPE_HAL_NO_FREE_ENTRY) {
				ppa_debug(DBG_ENABLE_MASK_ERR,"No Free Entry !!!\n");
				return PPA_FAILURE;
			}
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n free_index[%d]\n", free_index);
		} else {
			free_index = hash_index;
		}
	} else {
		/*valid first_ptr with some session already in hash_index*/
		temp_ptr = (pIp6CmpTbl + current_index);
		if (temp_ptr->valid) {
			free_index = mpe_hal_find_free_index(1);
			if (free_index == MPE_HAL_NO_FREE_ENTRY) {
				ppa_debug(DBG_ENABLE_MASK_ERR," No Free Entry !!!\n");
				return PPA_FAILURE;
			}
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"free_index[%d] for hash[%d]\n",free_index,hash_index);
		} else
			free_index = current_index;
	}

	temp_ptr = pIp6CmpTbl + free_index;
	if (count > 0) {
		if (((pIp6CmpTbl + last_index)->nxt_ptr) == (g_GenConf->fw_sess_tbl_num[1] - 1))
				(pIp6CmpTbl + last_index)->nxt_ptr = free_index;
	}

	if (hash_index_ptr->first_ptr == (g_GenConf->fw_sess_tbl_num[1] - 1))
		hash_index_ptr->first_ptr = free_index;
	else {
		if (hash_index_ptr == temp_ptr) {
			hash_index_ptr->nxt_ptr = current_index;
			hash_index_ptr->first_ptr = free_index;
			(pIp6CmpTbl + last_index)->nxt_ptr = g_GenConf->fw_sess_tbl_num[1] - 1;
		}
	}

	temp_ptr->key.srcip[3] = p_key->srcip[0];
	temp_ptr->key.srcip[2] = p_key->srcip[1];
	temp_ptr->key.srcip[1] = p_key->srcip[2];
	temp_ptr->key.srcip[0] = p_key->srcip[3];
	temp_ptr->key.dstip[3] = p_key->dstip[0];
	temp_ptr->key.dstip[2] = p_key->dstip[1];
	temp_ptr->key.dstip[1] = p_key->dstip[2];
	temp_ptr->key.dstip[0] = p_key->dstip[3];

	temp_ptr->key.srcport  = p_key->srcport;
	temp_ptr->key.dstport  = p_key->dstport;
	temp_ptr->key.extn     = p_key->extn;
	temp_ptr->act          = sess_action;
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Action Pointer: %x \n",temp_ptr->act);

	/* Set the MIB and Hit counter for this session index */
	((struct session_action *)(temp_ptr->act))->sess_mib_ix_en = 1;
	((struct session_action *)(temp_ptr->act))->sess_mib_hit_en = 1;
	((struct session_action *)(temp_ptr->act))->sess_mib_ix = free_index;
	mpe_hal_set_session_index(1, free_index);

	wmb();
	temp_ptr->valid = 1;
	max_ipv6_sess_cnt += 1;

	return free_index;
}

uint32_t mpe_hal_del_session_ipv4(struct fw_compare_hash_auto_ipv4 *pIp4CmpTbl, struct ipv4_hash_auto_key *p_key, uint32_t entry_index)
{
	uint32_t index = 0;
	uint32_t counter = 0;
	uint32_t previous;
	uint32_t hash_start = 0;
	uint32_t start, next;

	if (entry_index > (g_GenConf->fw_sess_tbl_num[0] - 1)) {
		pr_err("Why entry index [0x%x] exceeds max index [0x%x]???\n",
			entry_index, (g_GenConf->fw_sess_tbl_num[0] - 1));
		return MAX_ENTRY_ERROR;
	}

	if (!((pIp4CmpTbl + entry_index)->valid)) {
		pr_err("Why entry index [0x%x] is not valid???\n", entry_index);
		return MAX_ENTRY_ERROR;
	} else {
		(pIp4CmpTbl + entry_index)->valid = 0;
		wmb();
		/* udelay is added to make sure FW can complete current packet handling before its action buffer is freed */
		udelay(8);
	}

	hash_start = mpe_cal_hash(p_key, NULL, 0);
	hash_start &= (g_GenConf->fw_sess_tbl_num[0] - 1);

	previous = hash_start;
	index = ((pIp4CmpTbl + previous)->first_ptr);
	while (entry_index != index) {
		if (counter > (MAX_SEARCH_ITRN - 1)) {
			pr_err("Search iter [%d] exceeds max iter [%d] for entry index [%d], hash [0x%x] and last index [0x%x]!!!\n",
				counter, (MAX_SEARCH_ITRN - 1), entry_index, hash_start, index);
			return MAX_ENTRY_ERROR;
		}

		previous = index;
		index = (pIp4CmpTbl + index)->nxt_ptr;
		counter++;
	}
	start = (pIp4CmpTbl + previous)->first_ptr;
	next = (pIp4CmpTbl + index)->nxt_ptr;

	if (entry_index == start) /* delete first entry */ {
		if ((entry_index == hash_start) && (next == hash_start))
			(pIp4CmpTbl + hash_start)->first_ptr = g_GenConf->fw_sess_tbl_num[0] - 1;
		else
			(pIp4CmpTbl + previous)->first_ptr = (pIp4CmpTbl + index)->nxt_ptr;

	} else if (entry_index == next) /* delete last entry */ {
		(pIp4CmpTbl + previous)->nxt_ptr = previous;
	} else /* delete middle entry */ {
		(pIp4CmpTbl + previous)->nxt_ptr = (pIp4CmpTbl + index)->nxt_ptr;
	}

	(pIp4CmpTbl + index)->nxt_ptr = g_GenConf->fw_sess_tbl_num[0] - 1;

	mpe_hal_reset_session_index(0, index);
	max_ipv4_sess_cnt -= 1;

	return index;
}

uint32_t mpe_hal_del_session_ipv6(struct fw_compare_hash_auto_ipv6 *pIp6CmpTbl, struct ipv6_hash_auto_key *p_key, uint32_t hash_index)
{
	uint32_t index = 0;
	uint32_t counter = 0;
	uint32_t previous;
	uint32_t hash_start = 0;
	uint32_t start, next;

	if (hash_index > (g_GenConf->fw_sess_tbl_num[1] - 1)) {
		pr_err("Why entry index [0x%x] exceeds max index [0x%x]???\n",
			hash_index, (g_GenConf->fw_sess_tbl_num[1] - 1));
		return MAX_ENTRY_ERROR;
	}

	if (!((pIp6CmpTbl + hash_index)->valid)) {
		pr_err("Why entry index [0x%x] is not valid???\n", hash_index);
		return MAX_ENTRY_ERROR;
	} else {
		(pIp6CmpTbl + hash_index)->valid = 0;
		wmb();
		/* udelay is added to make sure FW can complete current packet handling before its action buffer is freed */
		udelay(8);
	}

	hash_start = mpe_cal_hash(NULL, p_key, 0);
	hash_start &= (g_GenConf->fw_sess_tbl_num[1] - 1);

	previous = hash_start;
	index = ((pIp6CmpTbl + previous)->first_ptr);
	while (hash_index != index) {
		if (counter > (MAX_SEARCH_ITRN - 1)) {
			pr_err("Search iter [%d] exceeds max iter [%d] for entry index [%d], hash [0x%x] and last index [0x%x]!!!\n",
				counter, (MAX_SEARCH_ITRN - 1), hash_index, hash_start, index);
			return MAX_ENTRY_ERROR;
		}
		previous = index;
		index = (pIp6CmpTbl + index)->nxt_ptr;
		counter++;
	}

	start = (pIp6CmpTbl + previous)->first_ptr;
	next = (pIp6CmpTbl + index)->nxt_ptr;

	if (hash_index == start) /* delete first entry */ {
		if ((hash_index == hash_start) && (next == hash_start))
			(pIp6CmpTbl + hash_start)->first_ptr = g_GenConf->fw_sess_tbl_num[1] - 1;
		else
			(pIp6CmpTbl + previous)->first_ptr = (pIp6CmpTbl + index)->nxt_ptr;

	} else if (hash_index == next) /* delete last entry */ {
		(pIp6CmpTbl + previous)->nxt_ptr = previous;
	} else /* delete middle entry */ {
		(pIp6CmpTbl + previous)->nxt_ptr = (pIp6CmpTbl + index)->nxt_ptr;
	}
	(pIp6CmpTbl + index)->nxt_ptr = g_GenConf->fw_sess_tbl_num[1] - 1;

	mpe_hal_reset_session_index(1, index);

	max_ipv6_sess_cnt -= 1;
	return index;
}



#ifdef HW_SESS_TEST

uint8_t src_mac_ipv4[6] = {0x00, 0x10, 0x20, 0x30, 0x40, 0x50};
uint8_t dst_mac_ipv4[6] = {0x00, 0x10, 0x20, 0x30, 0x40, 0x50};

struct session_action paction = {0};

void create_action(void)
{
	paction.entry_vld = 1;
	paction.pkt_len_delta = 4;
	paction.templ_len = 18;
	paction.tunnel_type = 0;
	paction.pppoe_offset_en = 0;
	paction.outer_dscp_mode = 0;
	paction.dst_pmac_port_list[0] = 15;
	paction.in_eth_iphdr_offset = 30;
	paction.new_dst_ip_en = 1;
	paction.new_dst_ip.ip4.ip = 0x64640A01;
	paction.protocol = 1;
	paction.new_dst_port = 0x5000;
}
int32_t create_hw_action(struct session_action *paction)
{
	paction->entry_vld = 1;
	paction->pkt_len_delta = 4;
	paction->templ_len = 18;
	paction->tunnel_type = 0;
	paction->pppoe_offset_en = 0;
	paction->outer_dscp_mode = 0;
	paction->dst_pmac_port_num = 1;
	paction->dst_pmac_port_list[0] = 15;
	paction->in_eth_iphdr_offset = 30;
	paction->new_dst_ip_en = 1;
	paction->new_dst_ip.ip4.ip = 0x64640A01;
	paction->new_src_ip.ip4.ip = 0x65650B02;
	paction->protocol = 1;
	paction->new_dst_port = 0x5000;
	return PPA_SUCCESS;
}

uint32_t create_templ_buffer(unsigned char *buffer)
{

	unsigned char *buf = buffer;
	uint32_t buf_len=0;
	memcpy(buf, dst_mac_ipv4,sizeof(dst_mac_ipv4));
	buf += sizeof(dst_mac_ipv4);
	memcpy(buf, src_mac_ipv4,sizeof(src_mac_ipv4));
	buf += sizeof(src_mac_ipv4);

	*buf='\0';
	buf_len = (unsigned int)buf - (unsigned int)buffer;
	return buf_len;
}

#endif

static void mpe_hal_pon_handling(uint32_t port_id)
{
	mpe_hal_set_fw_connectivity(port_id);
	g_GenConf->pon_ip  = 2; /* pon port is fixed */
	g_GenConf->vuni_ip = port_id & 0xf;

	/* Create mpe0 dummy interface */
	mpe_hal_create_mpe_netdev();

	return;
}

static inline bool is_mpe_restricted(struct uc_session_node *p_item)
{
	bool is_restricted;

	if (!p_item)
		return true;

	is_restricted = false;
	if ((p_item->flags & SESSION_ADDED_IN_HW)) {
		if (max_compl_sess_cnt >= (g_GenConf->hw_act_num))
			is_restricted = true;
	} else if ((p_item->flags & SESSION_IS_IPV6)) {
		if (max_ipv6_sess_cnt >= (g_GenConf->fw_sess_tbl_num[1] - 1))
			is_restricted = true;
	} else {
		if (max_ipv4_sess_cnt >= (g_GenConf->fw_sess_tbl_num[0] - 1))
			is_restricted = true;
	}

	return is_restricted;
}

int32_t mpe_hal_add_routing_entry(PPA_ROUTING_INFO *route)
{
	struct fw_compare_hash_auto_ipv4 hIpv4;
	struct fw_compare_hash_auto_ipv6 hIpv6;
	int32_t ret = PPA_SUCCESS;

	struct uc_session_node *p_item = (struct uc_session_node *)route->p_item;
	if(!p_item) return PPA_FAILURE;

	if(p_item->flags & SESSION_IS_IPV6) {
		memset(&hIpv6, 0, sizeof(struct fw_compare_hash_auto_ipv6));
		if(p_item->flags & SESSION_IS_TCP) {
			if ( ppa_is_IngressGreSession(p_item) )
				hIpv6.key.extn = 0x80; /* GRE TCP DS */
			else if ( ppa_is_IngressL2tpSession(p_item) )
				hIpv6.key.extn = 0x20; /* L2TP TCP DS */
			else
				hIpv6.key.extn = 0;
		} else {
			if ( ppa_is_IngressGreSession(p_item) )
				hIpv6.key.extn = 0x81; /* GRE UDP DS */
			else if ( ppa_is_IngressL2tpSession(p_item) )
				hIpv6.key.extn = 0x21; /* L2TP UDP DS */
			else
				hIpv6.key.extn = 1;
		}
		ppa_memcpy(hIpv6.key.srcip,p_item->pkt.src_ip.ip6,sizeof(uint16_t)*8);
		ppa_memcpy(hIpv6.key.dstip,p_item->pkt.dst_ip.ip6,sizeof(uint16_t)*8);
		hIpv6.key.srcport = p_item->pkt.src_port;
		hIpv6.key.dstport = p_item->pkt.dst_port;
		ppa_mpe_session_list_lock_v6();
		if (g_GenConf->fw_cmp_tbl_base[1]) {
			if ((ret = mpe_hal_add_session_ipv6((struct fw_compare_hash_auto_ipv6 *)g_GenConf->fw_cmp_tbl_base[1],
							(struct ipv6_hash_auto_key *) &hIpv6.key,
							(uint32_t)p_item->session_meta)) != PPA_FAILURE) {
				route->entry = ret;
				p_item->flags |= SESSION_ADDED_IN_HW;
				PPA_HAL_RTSTATS_INC(curr_uc_ipv6_session);
				ret = PPA_SUCCESS;
			} else
				PPA_HAL_RTSTATS_INC(uc_dropped_sess);
		}
		ppa_mpe_session_list_unlock_v6();
	} else {
		memset(&hIpv4, 0, sizeof(struct fw_compare_hash_auto_ipv4));
		if(p_item->flags & SESSION_IS_TCP) {
			if ( ppa_is_IngressGreSession(p_item) )
				hIpv4.key.extn = 0x80; /* GRE TCP DS */
			else if ( ppa_is_IngressL2tpSession(p_item) )
				hIpv4.key.extn = 0x20; /* L2TP TCP DS */
			else
				hIpv4.key.extn = 0;
		} else {
			if ( ppa_is_IngressGreSession(p_item) )
				hIpv4.key.extn = 0x81; /* GRE UDP DS */
			else if ( ppa_is_IngressL2tpSession(p_item) )
				hIpv4.key.extn = 0x21; /* L2TP UDP DS */
			else
				hIpv4.key.extn = 1;
		}

		hIpv4.key.rsvd = 0;
		hIpv4.key.srcip = p_item->pkt.src_ip.ip;
		hIpv4.key.dstip = p_item->pkt.dst_ip.ip;
		hIpv4.key.srcport = p_item->pkt.src_port;
		hIpv4.key.dstport = p_item->pkt.dst_port;

		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"key :extn	 = %d\n",hIpv4.key.extn);
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"key :srcip	 = %s\n",inet_ntoa(hIpv4.key.srcip));
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"key :dstip	 = %s\n",inet_ntoa(hIpv4.key.dstip));
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"key :srcport	 = %d\n",hIpv4.key.srcport);
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"key :dstport	 = %d\n",hIpv4.key.dstport);

		ppa_mpe_session_list_lock_v4();
		if(g_GenConf->fw_cmp_tbl_base[0]) {
			if((ret = mpe_hal_add_session_ipv4((struct fw_compare_hash_auto_ipv4 *)g_GenConf->fw_cmp_tbl_base[0],
					(struct ipv4_hash_auto_key *) &hIpv4.key,
					(uint32_t)p_item->session_meta,p_item)) != PPA_FAILURE) {
				route->entry = ret;
				p_item->flags |= SESSION_ADDED_IN_HW;
				PPA_HAL_RTSTATS_INC(curr_uc_ipv4_session);
				ret = PPA_SUCCESS;
			} else
				PPA_HAL_RTSTATS_INC(uc_dropped_sess);
		}
		ppa_mpe_session_list_unlock_v4();
	}

	return ret;
}


int32_t mpe_hal_del_routing_entry(PPA_ROUTING_INFO *route)
{
	struct fw_compare_hash_auto_ipv4 hIpv4;
	struct fw_compare_hash_auto_ipv6 hIpv6;
	uint32_t index = 0;

	struct uc_session_node *p_item = (struct uc_session_node *)route->p_item;
	if(!p_item) return PPA_FAILURE;

	if(p_item->flags & SESSION_IS_IPV6) {
		memset(&hIpv6, 0, sizeof(struct fw_compare_hash_auto_ipv6));
		if(p_item->flags & SESSION_IS_TCP) {
			if ( ppa_is_IngressGreSession(p_item) )
				hIpv6.key.extn = 0x80; /* GRE TCP DS */
			else if ( ppa_is_IngressL2tpSession(p_item) )
				hIpv6.key.extn = 0x20; /* L2TP TCP DS */
			else
				hIpv6.key.extn = 0;
		} else {
			if ( ppa_is_IngressGreSession(p_item) )
				hIpv6.key.extn = 0x81; /* GRE UDP DS */
			else if ( ppa_is_IngressL2tpSession(p_item) )
				hIpv6.key.extn = 0x21; /* L2TP UDP DS */
			else
				hIpv6.key.extn = 1;
		}
		ppa_memcpy(hIpv6.key.srcip,p_item->pkt.src_ip.ip6,sizeof(uint16_t)*8);
		ppa_memcpy(hIpv6.key.dstip,p_item->pkt.dst_ip.ip6,sizeof(uint16_t)*8);
			hIpv6.key.srcport = p_item->pkt.src_port;
			hIpv6.key.dstport = p_item->pkt.dst_port;
		ppa_mpe_session_list_lock_v6();
		if(g_GenConf->fw_cmp_tbl_base[1])
			index = mpe_hal_del_session_ipv6((struct fw_compare_hash_auto_ipv6 *)g_GenConf->fw_cmp_tbl_base[1],
							(struct ipv6_hash_auto_key *)&hIpv6.key,
							route->entry);
		ppa_mpe_session_list_unlock_v6();
		if (index != MAX_ENTRY_ERROR)
			PPA_HAL_RTSTATS_DEC(curr_uc_ipv6_session);
		return index;
	} else {
		memset(&hIpv4, 0, sizeof(struct fw_compare_hash_auto_ipv4));
		if(p_item->flags & SESSION_IS_TCP) {
			if ( ppa_is_IngressGreSession(p_item) )
				hIpv4.key.extn = 0x80; /* GRE TCP DS */
			else if ( ppa_is_IngressL2tpSession(p_item) )
				hIpv4.key.extn = 0x20; /* L2TP TCP DS */
			else
				hIpv4.key.extn = 0;
		} else {
			if ( ppa_is_IngressGreSession(p_item) )
				hIpv4.key.extn = 0x81; /* GRE UDP DS */
			else if ( ppa_is_IngressL2tpSession(p_item) )
				hIpv4.key.extn = 0x21; /* L2TP UDP DS */
			else
				hIpv4.key.extn = 1;
		}
		hIpv4.key.srcip = p_item->pkt.src_ip.ip;
		hIpv4.key.dstip = p_item->pkt.dst_ip.ip;
		hIpv4.key.srcport = p_item->pkt.src_port;
		hIpv4.key.dstport = p_item->pkt.dst_port;

		ppa_mpe_session_list_lock_v4();
		if(g_GenConf->fw_cmp_tbl_base[0])
			index = mpe_hal_del_session_ipv4((struct fw_compare_hash_auto_ipv4 *)g_GenConf->fw_cmp_tbl_base[0],
						(struct ipv4_hash_auto_key *)&hIpv4.key,
						route->entry);
		ppa_mpe_session_list_unlock_v4();
		if (index != MAX_ENTRY_ERROR)
			PPA_HAL_RTSTATS_DEC(curr_uc_ipv4_session);
		return index;
	}

#ifdef MPE_IFMIB
	return (delete_session_interfaceindex(p_item));
#else
	return PPA_SUCCESS;
#endif
}

uint32_t mpe_hal_add_hw_session(PPA_ROUTING_INFO *route)
{
	struct hw_act_ptr *hw_index;
	struct uc_session_node *p_item = (struct uc_session_node *)route->p_item;
	if(!p_item) return PPA_FAILURE;

	if(route->entry > g_GenConf->hw_act_num ){
		pr_err("Not a valid entry\n");
		return PPA_FAILURE;
	}

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	if(route->tnnl_info.tunnel_type == TUNNEL_TYPE_IPSEC) {
		if((((p_item->flag2 & SESSION_FLAG2_VALID_IPSEC_OUTBOUND_SA) == SESSION_FLAG2_VALID_IPSEC_OUTBOUND_SA) && (IsLanSession(p_item->flags)))
				||  (!IsLanSession(p_item->flags)) ) //inbound
		{
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> Add SA \n",__FUNCTION__);
			return mpe_hal_add_ipsec_tunl_entry(route);
		}

	}
#endif
	if(((struct session_action *)(p_item->session_meta)) == NULL){
		pr_err("Entry %d has null action pointer\n",route->entry);
		return PPA_FAILURE;
	}

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s>Routing session index is : %d\n",__FUNCTION__,route->entry);
	hw_index =(struct hw_act_ptr *)(g_GenConf->hw_act_tbl_base + (route->entry * sizeof(struct hw_act_ptr)) );
	hw_index->act = (uint32_t)p_item->session_meta;

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"HW index base %x\n",g_GenConf->hw_act_tbl_base);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"HW Entry %d base %p\n",route->entry, hw_index);

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Template buffer len		= %d\n",((struct session_action *)(hw_index->act))->templ_len);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"pkt_len_delta			= %d\n",((struct session_action *)(hw_index->act))->pkt_len_delta);

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	if(route->tnnl_info.tunnel_type == TUNNEL_TYPE_IPSEC) {
		((struct session_action *)(hw_index->act))->rx_itf_mib_num = 1;
		((struct session_action *)(hw_index->act))->tx_itf_mib_num = 1;
		((struct session_action *)(hw_index->act))->tx_itf_mib_ix[0] = ((struct session_action *)(hw_index->act))->tunnel_id * 2;
		((struct session_action *)(hw_index->act))->rx_itf_mib_ix[0] = ((struct session_action *)(hw_index->act))->tunnel_id * 2 + 1;
	}
#endif

	return PPA_SUCCESS;
}

#ifdef HW_SESS_TEST
uint32_t mpe_hal_add_hw_session_test(void)
{

	uint32_t action = 0;
	PPA_ROUTING_INFO route;

	struct session_action sess_action = {0};
	struct uc_session_node pitem = {0};

	ppa_memset( &route, 0, sizeof(route));
	route.p_item = &pitem;

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mpe_hal_add_hw_session_test\n");
	create_hw_action(&sess_action);

	sess_action.templ_buf = ppa_malloc(sess_action.templ_len);
	ppa_memset(sess_action.templ_buf, 0, sess_action.templ_len);

	create_templ_buffer((unsigned char *)&sess_action.templ_buf);
		action = (uint32_t)&sess_action;
	pitem.session_meta = action;
	route.entry = 2;
	mpe_hal_add_hw_session(&route);
	return PPA_SUCCESS;
}
#endif

uint32_t mpe_hal_del_hw_session(PPA_ROUTING_INFO *route)
{
	struct hw_act_ptr *hw_index;
	struct uc_session_node *p_item = (struct uc_session_node *)route->p_item;

	if(!p_item || (route->entry > g_GenConf->hw_act_num ))
		return PPA_FAILURE;

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s>Routing session index is : %d\n",__FUNCTION__,route->entry);
#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	if(route->tnnl_info.tunnel_type == TUNNEL_TYPE_IPSEC) //outbound
	{
		if((((p_item->flag2 & SESSION_FLAG2_VALID_IPSEC_OUTBOUND_SA) == SESSION_FLAG2_VALID_IPSEC_OUTBOUND_SA) && (IsLanSession(p_item->flags)))
				|| (!IsLanSession(p_item->flags)) ) //inbound
			return mpe_hal_del_ipsec_tunl_entry(route);
	}
#endif

	hw_index =(struct hw_act_ptr *)(g_GenConf->hw_act_tbl_base + (route->entry * sizeof(struct hw_act_ptr)) );
	hw_index->act = 0;
	return PPA_SUCCESS;
}

int32_t mpe_hal_add_wan_mc_entry(PPA_MC_INFO *mc)
{
	int32_t ret;
	uint32_t i, k, port;
	struct hw_act_ptr *hw_index;
	struct vap_entry *ve;
	struct fw_compare_hash_auto_ipv4 hIpv4;
	struct fw_compare_hash_auto_ipv6 hIpv6;

	struct mc_session_node *p_item = (struct mc_session_node *)mc->p_item;

	if (((struct session_action *)(p_item->session_action)) == NULL){
		pr_err("Entry %d has null action pointer\n",mc->p_entry);
		return PPA_FAILURE;
	}

	/** Now populate the VAP table */
	for (i = 0; i < MAX_PMAC_PORT; i++) {
		uint32_t vap;
		port = (1 << i) & (mc->dest_list);
		if (port) {
			uint8_t ve_idx = 0;
			port = i;
			ve = (struct vap_entry *)(g_GenConf->mc_vap_tbl_base[port] + (sizeof(struct vap_entry) * p_item->grp.group_id));
			ve->num = 0;
			udelay(3);
			for (k = 0; k < MAX_VAP_PER_PORT; k++) {
				vap = (1 << k) & (mc->dest_subif[port]);
				if (vap) {
					ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> mc->dest_subif[%u]:0x%X\n", __func__, port, mc->dest_subif[port]);
					ve->vap_list[ve_idx] = p_item->grp.group_id;
					/*This is one final multicast replication point. Group flag should not be set.*/
					ve->vap_list[ve_idx] |= k << 8;/* VAP[8:11] */
					ve->vap_list[ve_idx] |= 1 << 14;/* MC bit set for multicast*/
					ve_idx++;
				}
			}
			ve->num = ve_idx;
		}
	}

	/* PAE+MPE complementary processing */
	if (p_item->flags & SESSION_ADDED_IN_HW) {
		if (mc->p_entry > g_GenConf->hw_act_num) {
			pr_err("Not a valid entry\n");
			return PPA_FAILURE;
		}

		hw_index =(struct hw_act_ptr *)(g_GenConf->hw_act_tbl_base + (mc->p_entry * sizeof(struct hw_act_ptr)));
		hw_index->act = (uint32_t)p_item->session_action;

		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s>Routing session index is : %d\nHW index base : 0x%x\nHW Entry Base : %p\nTemplate buffer len        = %d\npkt_len_delta              = %d\nmc->group_id = %d mc->dest_list = 0x%X\n", __func__, mc->p_entry, g_GenConf->hw_act_tbl_base, hw_index, ((struct session_action *)(hw_index->act))->templ_len, ((struct session_action *)(hw_index->act))->pkt_len_delta, p_item->grp.group_id,  mc->dest_list);

		ret = PPA_SUCCESS;

	/* MPE full processing */
	} else {
		if (p_item->flags & SESSION_IS_IPV6) {
			memset(&hIpv6, 0, sizeof(struct fw_compare_hash_auto_ipv6));
			hIpv6.key.extn = 1;
			ppa_memcpy(hIpv6.key.srcip, p_item->grp.sess_info->source_ip.ip.ip6, sizeof(uint16_t)*8);
			ppa_memcpy(hIpv6.key.dstip, p_item->grp.sess_info->ip_mc_group.ip.ip6, sizeof(uint16_t)*8);
			hIpv6.key.srcport = p_item->grp.sess_info->src_port;
			hIpv6.key.dstport = p_item->grp.sess_info->dst_port;
			ppa_mpe_session_list_lock_v6();
			ret = mpe_hal_add_session_ipv6((struct fw_compare_hash_auto_ipv6 *)g_GenConf->fw_cmp_tbl_base[1],
							(struct ipv6_hash_auto_key *)&hIpv6.key,
							(uint32_t)p_item->session_action);
			ppa_mpe_session_list_unlock_v6();
		} else {
			memset(&hIpv4, 0, sizeof(struct fw_compare_hash_auto_ipv4));
			hIpv4.key.extn = 1;
			hIpv4.key.srcip = p_item->grp.sess_info->source_ip.ip.ip;
			hIpv4.key.dstip = p_item->grp.sess_info->ip_mc_group.ip.ip;
			hIpv4.key.srcport = p_item->grp.sess_info->src_port;
			hIpv4.key.dstport = p_item->grp.sess_info->dst_port;

			ppa_mpe_session_list_lock_v4();
			ret = mpe_hal_add_session_ipv4((struct fw_compare_hash_auto_ipv4 *)g_GenConf->fw_cmp_tbl_base[0],
					(struct ipv4_hash_auto_key *)&hIpv4.key,
					(uint32_t)p_item->session_action, NULL);
			ppa_mpe_session_list_unlock_v4();
		}
		if (ret != PPA_FAILURE) {
			mc->p_entry = ret;
			ret = PPA_SUCCESS;
			if (p_item->flags & SESSION_IS_IPV6)
				PPA_HAL_RTSTATS_INC(curr_mc_ipv6_session);
			else
				PPA_HAL_RTSTATS_INC(curr_mc_ipv4_session);
		} else
			PPA_HAL_RTSTATS_INC(mc_dropped_sess);
	}
	return ret;
}

int32_t mpe_hal_del_wan_mc_entry(PPA_MC_INFO *mc)
{
	uint32_t i, port;
	struct hw_act_ptr *hw_index;
	struct vap_entry *ve;
	struct fw_compare_hash_auto_ipv4 hIpv4;
	struct fw_compare_hash_auto_ipv6 hIpv6;

	struct mc_session_node *p_item = (struct mc_session_node *)mc->p_item;

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s>Routing session index is : %d\n",__FUNCTION__,mc->p_entry);

	/* PAE+MPE complementary processing */
	if (!(p_item->flags & SESSION_ADDED_IN_HW)) {
		if (mc->p_entry > g_GenConf->hw_act_num)
			return PPA_FAILURE;
		hw_index =(struct hw_act_ptr *)(g_GenConf->hw_act_tbl_base + (mc->p_entry * sizeof(struct hw_act_ptr)));
		hw_index->act = 0;

	/* MPE full processing */
	} else {
		if (p_item->flags & SESSION_IS_IPV6) {
			memset(&hIpv6, 0, sizeof(struct fw_compare_hash_auto_ipv6));
			hIpv6.key.extn = 1;
			ppa_memcpy(hIpv6.key.srcip, p_item->grp.sess_info->source_ip.ip.ip6, sizeof(uint16_t)*8);
			ppa_memcpy(hIpv6.key.dstip, p_item->grp.sess_info->ip_mc_group.ip.ip6, sizeof(uint16_t)*8);
			hIpv6.key.srcport = p_item->grp.sess_info->src_port;
			hIpv6.key.dstport = p_item->grp.sess_info->dst_port;

			ppa_mpe_session_list_lock_v6();
			mpe_hal_del_session_ipv6((struct fw_compare_hash_auto_ipv6 *)g_GenConf->fw_cmp_tbl_base[1],
						(struct ipv6_hash_auto_key *)&hIpv6.key,
						mc->p_entry);
			ppa_mpe_session_list_unlock_v6();
			PPA_HAL_RTSTATS_DEC(curr_mc_ipv6_session);
		} else {
			memset(&hIpv4, 0, sizeof(struct fw_compare_hash_auto_ipv4));
			hIpv4.key.extn = 1;
			hIpv4.key.srcip = p_item->grp.sess_info->source_ip.ip.ip;
			hIpv4.key.dstip = p_item->grp.sess_info->ip_mc_group.ip.ip;
			hIpv4.key.srcport = p_item->grp.sess_info->src_port;
			hIpv4.key.dstport = p_item->grp.sess_info->dst_port;

			ppa_mpe_session_list_lock_v4();
			mpe_hal_del_session_ipv4((struct fw_compare_hash_auto_ipv4 *)g_GenConf->fw_cmp_tbl_base[0],
						(struct ipv4_hash_auto_key *)&hIpv4.key,
						mc->p_entry);
			ppa_mpe_session_list_unlock_v4();
			PPA_HAL_RTSTATS_DEC(curr_mc_ipv4_session);
		}
	}

	/** Now populate the VAP table */
	for (i = 0; i < MAX_PMAC_PORT; i++) {
		port = (1 << i) & (mc->dest_list);
		if (port) {
			port = i;
			ve = (struct vap_entry *)(g_GenConf->mc_vap_tbl_base[port] + (sizeof(struct vap_entry) * p_item->grp.group_id));
			ve->num = 0;
			udelay(3);
			memset(ve, 0, sizeof(struct vap_entry));
		}
	}

	return PPA_SUCCESS;
}

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)

#define MPE_HAL_MASK_CTX_SIZE 0x0000FF00
#define MPE_HAL_MASK_CTX_FETCH_MODE 0x80000000

int32_t mpe_hal_alloc_cdr_rdr(void)
{
	int32_t i, j;

	for (i = 0; i < MAX_WORKER_NUM; i++) {
		for (j = 0; j < IPSEC_TUN_MAX; j++) {
			g_GenConf->e97_cdr_in[i][j] = (uint32_t)kmalloc((EIP97_CD_SIZE * 4), GFP_DMA);
			if (!g_GenConf->e97_cdr_in[i][j]) {
				ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate memory for e97_cdr_in table for Worker %d and tunnel index %d\n",i,j);
				return PPA_FAILURE;
			}
			memset((void *)g_GenConf->e97_cdr_in[i][j], 0, (EIP97_CD_SIZE * 4));
		}
	}
	for(i=0; i< MAX_WORKER_NUM; i++) {
		for(j=0; j< IPSEC_TUN_MAX; j++) {
			g_GenConf->e97_cdr_out[i][j] = (uint32_t ) kmalloc((EIP97_CD_SIZE * 4), GFP_DMA);
			if (!g_GenConf->e97_cdr_out[i][j]) {
				ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate memory for e97_cdr_out table for Worker %d and tunnel index %d\n",i,j);
				return PPA_FAILURE;
			}
			memset((void *)g_GenConf->e97_cdr_out[i][j], 0, (EIP97_CD_SIZE * 4));
		}
	}
	for(i=0; i< MAX_WORKER_NUM; i++) {
		for(j=0; j< IPSEC_TUN_MAX; j++) {
			g_GenConf->e97_acd_in[i][j] = (uint32_t ) kmalloc((EIP97_ACD_MAX_SIZE), GFP_DMA);
			if (!g_GenConf->e97_acd_in[i][j]) {
				ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate memory for e97_acd_in table for Worker %d and tunnel index %d\n",i,j);
				return PPA_FAILURE;
			}
			memset((void *)g_GenConf->e97_acd_in[i][j], 0, (EIP97_ACD_MAX_SIZE));
		}
	}
	for(i=0; i< MAX_WORKER_NUM; i++) {
		for(j=0; j< IPSEC_TUN_MAX; j++) {
			g_GenConf->e97_acd_out[i][j] = (uint32_t ) kmalloc((EIP97_ACD_MAX_SIZE), GFP_DMA);
			if (!g_GenConf->e97_acd_out[i][j]) {
				ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate memory for e97_acd_out table for Worker %d and tunnel index %d\n",i,j);
				return PPA_FAILURE;
			}
			memset((void *)g_GenConf->e97_acd_out[i][j], 0, (EIP97_ACD_MAX_SIZE));
		}
	}
	for(i=0; i< MAX_WORKER_NUM; i++) {
		g_GenConf->e97_rdr[i] = (uint32_t ) kmalloc((EIP97_CD_SIZE * 4), GFP_DMA);
		if (!g_GenConf->e97_rdr[i]) {
			ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate memory for e97_rdr table for Worker %d \n",i);
			return PPA_FAILURE;
		}
		memset((void *)g_GenConf->e97_rdr[i], 0, (EIP97_CD_SIZE * 4));
	}
	return PPA_SUCCESS;
}

int32_t mpe_hal_free_cdr_rdr(void)
{
	int32_t i, j;
	for(i=0; i< MAX_WORKER_NUM; i++) {
		for(j=0; j< IPSEC_TUN_MAX; j++) {
			if (g_GenConf->e97_cdr_in[i][j])
				g_GenConf->e97_cdr_in[i][j] = 0;
		}
	}
	for(i=0; i< MAX_WORKER_NUM; i++) {
		for(j=0; j< IPSEC_TUN_MAX; j++) {
			if (g_GenConf->e97_cdr_out[i][j])
				g_GenConf->e97_cdr_out[i][j] = 0;
		}
	}
	for(i=0; i< MAX_WORKER_NUM; i++) {
		for(j=0; j< IPSEC_TUN_MAX; j++) {
			if (g_GenConf->e97_acd_in[i][j])
				g_GenConf->e97_acd_in[i][j] = 0;
		}
	}
	for(i=0; i< MAX_WORKER_NUM; i++) {
		for(j=0; j< IPSEC_TUN_MAX; j++) {
			if (g_GenConf->e97_acd_out[i][j])
				g_GenConf->e97_acd_out[i][j] = 0;
		}
	}
	for(i=0; i< MAX_WORKER_NUM; i++) {
		if (g_GenConf->e97_rdr[i])
			g_GenConf->e97_rdr[i] = 0;
	}
	return PPA_SUCCESS;
}
int32_t mpe_hal_construct_cdr_rdr(struct ltq_crypto_ipsec_params *eip97_params, struct ipsec_info *ipsec_info)
{
	ipsec_info->mode = eip97_params->ipsec_tunnel;
	ipsec_info->cd_info.dw0.acd_size = eip97_params->tokenwords;
	ipsec_info->cd_info.dw0.first_seg = 1;
	ipsec_info->cd_info.dw0.last_seg = 1;
	ipsec_info->cd_info.dw0.buf_size = 0;

	ipsec_info->cd_info.dw2.acd_ptr = (uint32_t)eip97_params->token_buffer;
	memcpy(&ipsec_info->cd_info.dw3 ,&eip97_params->token_headerword, sizeof(uint32_t));

	ipsec_info->cd_info.dw4.res = 0;
	ipsec_info->cd_info.dw4.app_id = 0;
	ipsec_info->cd_info.dw5.ctx_ptr = (uint32_t)eip97_params->SA_buffer;
	ipsec_info->pad_instr_offset = (eip97_params->total_pad_offs * 4);
	ipsec_info->pad_en = 1;
	ipsec_info->crypto_instr_offset = (eip97_params->crypto_offs * 4);
	ipsec_info->hash_pad_instr_offset = eip97_params->hash_pad_offs;
	ipsec_info->msg_len_instr_offset = eip97_params->msg_len_offs;
	ipsec_info->cd_size = EIP97_CD_SIZE;
	ipsec_info->iv_len = eip97_params->ivsize;
	ipsec_info->icv_len = eip97_params->ICV_length;
	ipsec_info->blk_size = eip97_params->pad_blksize;

	return PPA_SUCCESS;
}

int32_t mpe_hal_construct_ipsec_buffer(int32_t dir, int32_t tunlId, struct ltq_crypto_ipsec_params *eip97_params)
{

	if(dir == LTQ_SAB_DIRECTION_INBOUND ){
		if(g_GenConf->ipsec_input_flag[tunlId] != 1){
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> ipsec Buffer for inbound tunnel %d\n",__FUNCTION__, tunlId);
			memset(&g_GenConf->ipsec_input[tunlId], 0, sizeof(struct ipsec_info));
			mpe_hal_construct_cdr_rdr(eip97_params, &g_GenConf->ipsec_input[tunlId]);
			g_GenConf->ipsec_input_flag[tunlId] = 1;
		}

	} else if(dir == LTQ_SAB_DIRECTION_OUTBOUND) {
		if(g_GenConf->ipsec_output_flag[tunlId] != 1) {
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> ipsec Buffer for outbound tunnel %d\n",__FUNCTION__, tunlId);
			memset(&g_GenConf->ipsec_output[tunlId], 0, sizeof(struct ipsec_info));
			mpe_hal_construct_cdr_rdr(eip97_params, &g_GenConf->ipsec_output[tunlId]);
			g_GenConf->ipsec_output_flag[tunlId] = 1;
		}
	} else {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Wrong SA Direction !!!\n");
		return PPA_FAILURE;
	}
	return PPA_SUCCESS;
}

int32_t mpe_hal_get_ipsec_spi(uint32_t tunnel_index, uint32_t dir, uint32_t *spi)
{
	ppa_tunnel_entry *t_entry = NULL;
	PPA_XFRM_STATE *xfrm_sa = NULL;

	if(tunnel_index > (IPSEC_TUN_MAX-1))
		return PPA_FAILURE;
	t_entry = g_tunnel_table[tunnel_index];
	if ( t_entry == NULL )
		return PPA_FAILURE;

	if (dir == LTQ_SAB_DIRECTION_INBOUND ) {
		xfrm_sa = g_tunnel_table[tunnel_index]->tunnel_info.ipsec_hdr.inbound;
	} else if(dir == LTQ_SAB_DIRECTION_OUTBOUND) {
		xfrm_sa = g_tunnel_table[tunnel_index]->tunnel_info.ipsec_hdr.outbound;
	}

	if(xfrm_sa != NULL) {
		*spi = xfrm_sa->id.spi;
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> SPI: %x\n",__FUNCTION__,*spi);
		return PPA_SUCCESS;
	}

	return PPA_FAILURE;
}

int32_t mpe_hal_dump_ipsec_xfrm_sa(uint32_t tunnel_index)
{
	ppa_tunnel_entry *t_entry = NULL;
	PPA_XFRM_STATE *xfrm_sa_in;
	PPA_XFRM_STATE *xfrm_sa_out;
	uint32_t key_len, i;

	if(tunnel_index > (IPSEC_TUN_MAX-1))
		return PPA_FAILURE;

	t_entry = g_tunnel_table[tunnel_index];
	if ( t_entry == NULL )
		return PPA_FAILURE;


	xfrm_sa_in = g_tunnel_table[tunnel_index]->tunnel_info.ipsec_hdr.inbound;
	xfrm_sa_out = g_tunnel_table[tunnel_index]->tunnel_info.ipsec_hdr.outbound;

	if(xfrm_sa_in != NULL) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Inbound\n");
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"esp mode: %d SPI: %x\n",xfrm_sa_in->props.mode, xfrm_sa_in->id.spi);

		if(xfrm_sa_in->ealg->alg_name != NULL) {
			key_len = (xfrm_sa_in->ealg->alg_key_len + 7)/8 ;
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Crypto Key length: %d\n",key_len);
			for (i=0; i< key_len; i++) {
				if( i != 0 && i%8 == 0)
					pr_err("  ");
			}
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
		}

		if(xfrm_sa_in->aalg->alg_name != NULL) {
			key_len = (xfrm_sa_in->aalg->alg_key_len + 7)/8 ;
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Auth Key length: %d\n",key_len);
			for (i=0; i< key_len; i++) {
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%2x",(xfrm_sa_in->aalg->alg_key[i]) & 0xFF);
				if( i != 0 && i%8 == 0)
					pr_err("  ");
			}
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
		}

	}

	if(xfrm_sa_out != NULL) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Outbound\n");
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"esp mode: %d  SPI: %x\n",xfrm_sa_out->props.mode, xfrm_sa_out->id.spi);
		if(xfrm_sa_out->ealg->alg_name !=NULL) {
			key_len = (xfrm_sa_out->ealg->alg_key_len + 7)/8 ;
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Crypto Key length: %d\n",key_len);
			for (i=0; i< key_len; i++) {
				if( i != 0 && i%8 == 0)
					pr_err("  ");
			}
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
		}

		if(xfrm_sa_out->aalg->alg_name != NULL) {
			key_len = (xfrm_sa_out->aalg->alg_key_len + 7)/8 ;
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Auth Key length: %d\n",key_len);
			for (i=0; i< key_len; i++) {
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%2x",(xfrm_sa_out->aalg->alg_key[i]) & 0xFF);
				if( i != 0 && i%8 == 0)
					pr_err("  ");
			}
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
		}
	}

	return PPA_SUCCESS;
}

int32_t mpe_hal_dump_ipsec_eip97_params_info(struct ltq_crypto_ipsec_params *eip97_params)
{
	int32_t i=0;

	if(eip97_params->ipad[0] !=0) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<ipad> ");
		for(i=0; i < 64; i++) {
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT," [%2x]",eip97_params->ipad[i]);
			if( i != 0 && i%16 == 0)
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n\t ");
		}
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	}

	if(eip97_params->opad[0] !=0) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<opad> ");
		for(i=0; i < 64; i++) {
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT," [%2x]",eip97_params->opad[i]);
			if( i != 0 && i%16 == 0)
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n          ");
		}
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	}

	if(eip97_params->nonce[0] !=0) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<nonce> ");
		for(i=0; i < MAX_NONCE_LEN; i++)
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT," [%2x]",eip97_params->nonce[i]);
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	}

	if(eip97_params->IV[0] !=0) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<IV> ");
		for(i=0; i < MAX_IV_LEN; i++) {
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT," [%2x]",eip97_params->IV[i]);
			if( i != 0 && i%8 == 0)
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n ");
		}
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	}

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tokenheaderword %x\n",eip97_params->token_headerword);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tokenword length: [%d] Context Buffer length:[%d]\n",eip97_params->tokenwords, eip97_params->SAWords);

	if(eip97_params->SAWords != 0) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<Context> ");
		for(i=0; i < eip97_params->SAWords; i++)
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT," [%2x]\n",eip97_params->SA_buffer[i]);
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	}

	if(eip97_params->tokenwords != 0) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<Token> ");
		for(i=0; i < eip97_params->tokenwords; i++)
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT," [%2x]\n",eip97_params->token_buffer[i]);
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	}

	return PPA_SUCCESS;
}

int32_t mpe_hal_dump_ipsec_eip97_params(int32_t tunnel_index)
{
	struct ltq_crypto_ipsec_params *ipsec_eip97_params;
	PPA_XFRM_STATE *xfrm_sa;
	xfrm_sa = g_tunnel_table[tunnel_index]->tunnel_info.ipsec_hdr.inbound;
	ipsec_eip97_params = ltq_ipsec_get_params(xfrm_sa->id.spi);
	if (!ipsec_eip97_params) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"<%s> GetKey failed!!!\n",__FUNCTION__);
		return PPA_FAILURE;
	}
	mpe_hal_dump_ipsec_eip97_params_info(ipsec_eip97_params);

	xfrm_sa = g_tunnel_table[tunnel_index]->tunnel_info.ipsec_hdr.outbound;
	ipsec_eip97_params = ltq_ipsec_get_params(xfrm_sa->id.spi);
	if (!ipsec_eip97_params) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"<%s> GetKey failed!!!\n",__FUNCTION__);
		return PPA_FAILURE;
	}
	mpe_hal_dump_ipsec_eip97_params_info(ipsec_eip97_params);
	return PPA_SUCCESS;
}
int32_t mpe_hal_add_ipsec_tunl_entry(PPA_ROUTING_INFO *route)
{
	int32_t tunnel_index, dir;
	struct ltq_crypto_ipsec_params *ipsec_eip97_params;
	PPA_XFRM_STATE *xfrm_sa;

	tunnel_index = route->tnnl_info.tunnel_idx;

	if ((tunnel_index < 0) || (tunnel_index > (IPSEC_TUN_MAX-1)))
		return PPA_FAILURE;

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> Tunnel Index: %d\n",__FUNCTION__,tunnel_index);

	dir = g_tunnel_table[tunnel_index]->tunnel_info.ipsec_hdr.dir;
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> Direction: %d\n",__FUNCTION__, dir);

	if(dir == LTQ_SAB_DIRECTION_INBOUND ) {
		xfrm_sa = g_tunnel_table[tunnel_index]->tunnel_info.ipsec_hdr.inbound;
	} else if(dir == LTQ_SAB_DIRECTION_OUTBOUND) {
		xfrm_sa = g_tunnel_table[tunnel_index]->tunnel_info.ipsec_hdr.outbound;
	} else
		return PPA_FAILURE;

	ipsec_eip97_params = ltq_ipsec_get_params(xfrm_sa->id.spi);
	if (!ipsec_eip97_params) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"<%s> SetKey failed!!!\n",__FUNCTION__);

		return PPA_FAILURE;
	}

	ipsec_eip97_params->ipsec_tunnel = (xfrm_sa->props.mode == XFRM_MODE_TRANSPORT) ? ESP_TR : ESP_TU;
	return mpe_hal_construct_ipsec_buffer(dir, tunnel_index, ipsec_eip97_params);
}

int32_t mpe_hal_ipsec_active_tunnel_get(void)
{
	int32_t i, count=0;

	for(i=0; i< IPSEC_TUN_MAX; i++) {
		if((g_GenConf->ipsec_output_flag[i] == 1) && (g_GenConf->ipsec_input_flag[i] == 1))
			count++;

	}
	return count;
}

int32_t mpe_hal_delete_ipsec_buffer(int32_t dir, int32_t tunlId)
{

	if(dir == LTQ_SAB_DIRECTION_INBOUND ){
		g_GenConf->ipsec_input_flag[tunlId] = 0;
		udelay(200);
		memset(&g_GenConf->ipsec_input[tunlId], 0, sizeof(struct ipsec_info));

	} else if(dir == LTQ_SAB_DIRECTION_OUTBOUND) {
		g_GenConf->ipsec_output_flag[tunlId] = 0;
		udelay(200);
		memset(&g_GenConf->ipsec_output[tunlId], 0, sizeof(struct ipsec_info));
	} else {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Wrong SA Direction !!!\n");
		return PPA_FAILURE;
	}
	return PPA_SUCCESS;
}

int32_t mpe_hal_del_ipsec_tunl_entry(PPA_ROUTING_INFO *route)
{
	int32_t tunnel_index, dir;

	tunnel_index = route->tnnl_info.tunnel_idx;

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> <%d> Tunnel Index %d\n",__FUNCTION__,__LINE__, tunnel_index);
	if ((tunnel_index < 0) || (tunnel_index > (IPSEC_TUN_MAX-1)))
		return PPA_FAILURE;

	dir = g_tunnel_table[tunnel_index]->tunnel_info.ipsec_hdr.dir;

	mpe_hal_delete_ipsec_buffer(dir, tunnel_index);
	mpe_hal_clear_ipsec_tunnel_mib(tunnel_index);
	return PPA_SUCCESS;
}

struct module module_loopback;
static struct net_device *loop_dev;
struct loopdev_priv {
	struct module		*owner;
	dp_subif_t		dp_subif;
	int32_t			dev_port;
	int32_t			id;
};

static int loopdev_init(struct net_device *dev)
{
	return 0;
}

static struct net_device_ops loopdev_ops = {
		.ndo_init	= loopdev_init,

};

static void loop_setup(struct net_device *dev)
{
	ether_setup(dev);/*	assign some members */
	return;
}

static int32_t mpe_hal_set_ipsec_loopback_connectivity(void)
{
	char ifname[IFNAMSIZ];
	uint32_t dp_port_id;
	dp_cb_t cb={0};
	struct loopdev_priv *priv;

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> Enter\n",__FUNCTION__);
	snprintf(ifname, sizeof(ifname), "loopdev%d", 0);

	loop_dev = alloc_netdev(sizeof(struct loopdev_priv), ifname, NET_NAME_UNKNOWN, loop_setup);

	if (loop_dev == NULL) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"alloc_netdev fail\n");
		return -1;
	}

	loop_dev->dev_addr[0] = 0x00;
	loop_dev->dev_addr[1] = 0x00;
	loop_dev->dev_addr[2] = 0x00;
	loop_dev->dev_addr[3] = 0x00;
	loop_dev->dev_addr[4] = 0x00;
	loop_dev->dev_addr[5] = 0x92;
	priv = netdev_priv(loop_dev);

	loop_dev->netdev_ops = &loopdev_ops;
	if (register_netdev(loop_dev)) {
		free_netdev(loop_dev);
		loop_dev = NULL;
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"register device \"%s\" fail ??\n", ifname);
	} else {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"add \"%s\" successfully\n", ifname);
	}

	priv->owner = &module_loopback;
	priv->id =1;
	snprintf(priv->owner->name, sizeof(priv->owner->name), "modloop%d", 0);

	dp_port_id = dp_alloc_port(priv->owner, loop_dev, 0, 0, NULL, DP_F_LOOPBACK);
	if(dp_port_id == DP_FAILURE) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"%s: dp_alloc_port failed \n", __func__);
		return -ENODEV;
	}

	if (dp_register_dev (priv->owner, dp_port_id, &cb, 0) != DP_SUCCESS) {

		ppa_debug(DBG_ENABLE_MASK_ERR,"%s: dp_register_dev failed \n", __func__);
		return -ENODEV;
	}

	priv->dev_port = dp_port_id;
	tmu_hal_setup_dp_ingress_connectivity(loop_dev, dp_port_id);

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Redirect Port %d is configured\n",dp_port_id);

	g_GenConf->tunnel_redir_port = dp_port_id;
	return PPA_SUCCESS;
}

static int32_t mpe_hal_remove_ipsec_loopback_connectivity(void)
{
	dp_cb_t cb={0};

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Remove IPSEC loopback connectivity for the interface %s: redirect port %d\n",module_loopback.name,g_GenConf->tunnel_redir_port);
	if (dp_register_dev (&module_loopback, g_GenConf->tunnel_redir_port, &cb, DP_F_DEREGISTER) != DP_SUCCESS) {

		ppa_debug(DBG_ENABLE_MASK_ERR,"%s: dp_register_dev failed \n", __func__);
		return -ENODEV;
	}
	if(dp_alloc_port(&module_loopback, loop_dev, g_GenConf->tunnel_redir_port, 0, NULL, DP_F_DEREGISTER) != DP_SUCCESS) {

		ppa_debug(DBG_ENABLE_MASK_ERR,"dp_unregister_dev failed for port_id %d", g_GenConf->tunnel_redir_port);
	}
	tmu_hal_remove_dp_ingress_connectivity(loop_dev, g_GenConf->tunnel_redir_port);

	unregister_netdev(loop_dev);
	free_netdev(loop_dev);

	g_GenConf->tunnel_redir_port = 0;
	return PPA_SUCCESS;
}

uint32_t mpe_hal_get_seq_num_offset_from_ctx(uint32_t *sa_buffer, uint32_t buf_len, uint32_t spi)
{
	int32_t i=0;
	for(i=0; i<buf_len; i++) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"SA[%d] = %x\n",i,sa_buffer[i]);
		if(sa_buffer[i] == spi)
			break;
	}
	return i+1;
}

void mpe_hal_dump_context(uint32_t *sa_buffer, uint32_t buf_len)
{
	int32_t i=0;
	for(i=0; i<buf_len; i++) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"SA[%d] = %x\n",i,sa_buffer[i]);
	}
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"=============\n");
}

void mpe_hal_dump_token(uint32_t *token_buffer, uint32_t buf_len)
{
	int32_t i=0;
	for(i=0; i<buf_len; i++) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Token[%d] = %x\n",i,token_buffer[i]);
	}
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"=============\n");
}

int32_t mpe_hal_dump_ipsec_tunnel_info(uint32_t tun_id)
{
	uint32_t ctx_size;
	uint32_t *ctx = NULL;
	uint32_t spi =0, seq_offset=0;

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Tunnel Id: %d\n", tun_id);
	if(g_GenConf->ipsec_output_flag[tun_id] == 1) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Outbound:\n");
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Token length: %d\n",g_GenConf->ipsec_output[tun_id].cd_info.dw0.acd_size);
		if(g_GenConf->ipsec_output[tun_id].cd_info.dw0.acd_size !=0)
			mpe_hal_dump_token((uint32_t *)g_GenConf->ipsec_output[tun_id].cd_info.dw2.acd_ptr,
						g_GenConf->ipsec_output[tun_id].cd_info.dw0.acd_size);
		ctx = (uint32_t *)g_GenConf->ipsec_output[tun_id].cd_info.dw5.ctx_ptr;
		if(ctx != NULL) {
			ctx_size = (ctx[0] & MPE_HAL_MASK_CTX_SIZE);
			ctx_size = ctx_size >> 8;
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Context Size: %d\n",ctx_size+2);
			if(ctx_size != 0)
				mpe_hal_dump_context((uint32_t *)g_GenConf->ipsec_input[tun_id].cd_info.dw5.ctx_ptr, ctx_size+2);
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"crypto_instr_offset: %d	pad_instr_offset:%d \n",
				g_GenConf->ipsec_output[tun_id].crypto_instr_offset,g_GenConf->ipsec_output[tun_id].pad_instr_offset);
			mpe_hal_get_ipsec_spi( tun_id, LTQ_SAB_DIRECTION_OUTBOUND, &spi);
			seq_offset = mpe_hal_get_seq_num_offset_from_ctx((uint32_t *)g_GenConf->ipsec_output[tun_id].cd_info.dw5.ctx_ptr, ctx_size+2, spi );
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Sequence number Offset %d\n", seq_offset);
		}
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"DW3: ");
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"len:[%d] ip:[%d] cp:[%d] ct:[%d] rc:[%d] too:[%d] c:[%d] iv:[%d] u:[%d] type:[%d]\n",
				g_GenConf->ipsec_output[tun_id].cd_info.dw3.len,
				g_GenConf->ipsec_output[tun_id].cd_info.dw3.ip,
				g_GenConf->ipsec_output[tun_id].cd_info.dw3.cp,
				g_GenConf->ipsec_output[tun_id].cd_info.dw3.ct,
				g_GenConf->ipsec_output[tun_id].cd_info.dw3.rc,
				g_GenConf->ipsec_output[tun_id].cd_info.dw3.too,
				g_GenConf->ipsec_output[tun_id].cd_info.dw3.c,
				g_GenConf->ipsec_output[tun_id].cd_info.dw3.iv,
				g_GenConf->ipsec_output[tun_id].cd_info.dw3.u,
				g_GenConf->ipsec_output[tun_id].cd_info.dw3.type);

		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"IV Length: [%d] ICV Length: [%d]\n",
				g_GenConf->ipsec_output[tun_id].iv_len, g_GenConf->ipsec_output[tun_id].icv_len);
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"hash_pad_instr_offset: [%d] msg_len_instr_offset: [%d]\n",
				g_GenConf->ipsec_output[tun_id].hash_pad_instr_offset, g_GenConf->ipsec_output[tun_id].msg_len_instr_offset);
	}

	if(g_GenConf->ipsec_input_flag[tun_id] == 1) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Inbound:\n");
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Token length: %d\n",g_GenConf->ipsec_input[tun_id].cd_info.dw0.acd_size);
		if(g_GenConf->ipsec_input[tun_id].cd_info.dw0.acd_size !=0)
			mpe_hal_dump_token((uint32_t *)g_GenConf->ipsec_input[tun_id].cd_info.dw2.acd_ptr,
						g_GenConf->ipsec_input[tun_id].cd_info.dw0.acd_size);
		ctx = (uint32_t *)g_GenConf->ipsec_input[tun_id].cd_info.dw5.ctx_ptr;
		if(ctx != NULL) {
			ctx_size = (ctx[0] & MPE_HAL_MASK_CTX_SIZE);
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"CW0 : %x Context Size: %d\n",ctx[0], ctx_size);
			ctx_size = ctx_size >> 8;
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Context Size: %d\n",ctx_size+2);
			if(ctx_size != 0)
				mpe_hal_dump_context((uint32_t *)g_GenConf->ipsec_input[tun_id].cd_info.dw5.ctx_ptr, ctx_size+2);
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"crypto_instr_offset: %d	pad_instr_offset:%d \n",
				g_GenConf->ipsec_input[tun_id].crypto_instr_offset,g_GenConf->ipsec_input[tun_id].pad_instr_offset);
			mpe_hal_get_ipsec_spi( tun_id, LTQ_SAB_DIRECTION_INBOUND, &spi);
			seq_offset = mpe_hal_get_seq_num_offset_from_ctx((uint32_t *)g_GenConf->ipsec_input[tun_id].cd_info.dw5.ctx_ptr, ctx_size+2, spi );
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Sequence number Offset %d\n", seq_offset);
		}
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"DW3: ");
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"len:[%d] ip:[%d] cp:[%d] ct:[%d] rc:[%d] too:[%d] c:[%d] iv:[%d] u:[%d] type:[%d]\n",
				g_GenConf->ipsec_input[tun_id].cd_info.dw3.len,
				g_GenConf->ipsec_input[tun_id].cd_info.dw3.ip,
				g_GenConf->ipsec_input[tun_id].cd_info.dw3.cp,
				g_GenConf->ipsec_input[tun_id].cd_info.dw3.ct,
				g_GenConf->ipsec_input[tun_id].cd_info.dw3.rc,
				g_GenConf->ipsec_input[tun_id].cd_info.dw3.too,
				g_GenConf->ipsec_input[tun_id].cd_info.dw3.c,
				g_GenConf->ipsec_input[tun_id].cd_info.dw3.iv,
				g_GenConf->ipsec_input[tun_id].cd_info.dw3.u,
				g_GenConf->ipsec_input[tun_id].cd_info.dw3.type);
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"IV Length: [%d] ICV Length: [%d]\n",
				g_GenConf->ipsec_input[tun_id].iv_len, g_GenConf->ipsec_input[tun_id].icv_len);
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"hash_pad_instr_offset: [%d] msg_len_instr_offset: [%d]\n",
				g_GenConf->ipsec_input[tun_id].hash_pad_instr_offset, g_GenConf->ipsec_input[tun_id].msg_len_instr_offset);
	}

	return PPA_SUCCESS;
}

int32_t mpe_hal_get_ring_id(int32_t *id)
{
	int32_t i=0;
	for(i=0; i<MAX_RING;i++) {
		if(ring_id_pool[i] == -1) {
			*id = i;
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> i:%d Ring Id: %d\n",__FUNCTION__, i, *id);
			ring_id_pool[i] = i;
			return PPA_SUCCESS;
		}
	}
	return PPA_FAILURE;
}

int32_t mpe_hal_free_ring_id(int32_t id)
{
	ring_id_pool[id] = -1;
	return PPA_SUCCESS;
}

#ifdef IPSEC_TEST
int32_t mpe_hal_ipsec_test(void)
{

	PPA_XFRM_STATE xfrm_sa;
	PPA_XFRM_STATE *xfrm, *xfrm_out;
	PPA_ROUTING_INFO route;
	struct xfrm_algo_auth *xfrm_auth = NULL;
	struct xfrm_algo *xfrm_crypt=NULL;
	ppa_tunnel_entry *t_entry = NULL;

	memset(&route, 0, sizeof(PPA_ROUTING_INFO));
	memset(&xfrm_sa, 0, sizeof(PPA_XFRM_STATE));

	xfrm = (PPA_XFRM_STATE *) ppa_malloc(sizeof(PPA_XFRM_STATE));
	xfrm_crypt = (struct xfrm_algo *) ppa_malloc(sizeof(struct xfrm_algo));
	xfrm_auth = (struct xfrm_algo_auth *) ppa_malloc(sizeof(struct xfrm_algo_auth));

	route.entry = 0;
	route.flags |= SESSION_LAN_ENTRY;
	route.tnnl_info.tunnel_idx = 2;
	route.tnnl_info.tunnel_type = TUNNEL_TYPE_IPSEC;

	xfrm->props.mode = LTQ_SAB_IPSEC_TUNNEL;
	xfrm->id.spi = 0x40002016;
	xfrm->id.proto = 50;

	strncpy(xfrm_crypt->alg_name, "cbc(aes)", 9);
	xfrm_crypt->alg_key_len = 128;
	xfrm_crypt->alg_key[0] = "c994ab76 99a0a6d2 7667ab17 2b00f96f";

	xfrm->ealg = xfrm_crypt;

	strncpy(xfrm_auth->alg_name, "hmac(sha1)", 11);
	xfrm_auth->alg_key_len = 160; /*5 * 4;*/
	xfrm_auth->alg_key[0] = "3b3b34bb 069198a7 a63a1b90 a45d1c27 9c3f4e30";

	xfrm->aalg = xfrm_auth;

	t_entry = (ppa_tunnel_entry *) ppa_malloc(sizeof(ppa_tunnel_entry));
	if (t_entry) {

		t_entry->tunnel_type = TUNNEL_TYPE_IPSEC;
		t_entry->hal_buffer = NULL;
		g_tunnel_table[route.tnnl_info.tunnel_idx] = t_entry;
	}


	t_entry->tunnel_info.ipsec_hdr.dir = LTQ_SAB_DIRECTION_INBOUND;
	t_entry->tunnel_info.ipsec_hdr.inbound = xfrm;

	mpe_hal_add_ipsec_tunl_entry(&route);

	xfrm_out = (PPA_XFRM_STATE *) ppa_malloc(sizeof(PPA_XFRM_STATE));
	xfrm_out->props.mode = LTQ_SAB_IPSEC_TUNNEL;
	xfrm_out->id.spi = 0x069f2b79;
	xfrm_out->id.proto = 50;

	strncpy(xfrm_crypt->alg_name, "cbc(aes)", 9);
	xfrm_crypt->alg_key_len = 128; /* 4 * 4; */
	xfrm_crypt->alg_key[0] = "0a3a5878 1831add8 5e5ee250 12569e35";

	xfrm_out->ealg = xfrm_crypt;

	strncpy(xfrm_auth->alg_name, "hmac(sha1)", 11);
	xfrm_auth->alg_key_len = 160; /*5 * 4;*/
	xfrm_auth->alg_key[0] = "79f4877b aabe4bf4 b72c0a33 b7c11924 8d0075d3";

	xfrm_out->aalg = xfrm_auth;

	t_entry->tunnel_info.ipsec_hdr.dir = LTQ_SAB_DIRECTION_OUTBOUND;
	t_entry->tunnel_info.ipsec_hdr.outbound = xfrm_out;

	mpe_hal_add_ipsec_tunl_entry(&route);

	return PPA_SUCCESS;
}
#endif
#endif

int32_t mpe_hal_get_session_bytes(uint32_t cmb_tbl_typ, uint32_t sess_index, uint32_t * f_bytes)
{
	int j;
	unsigned long long sum;
	struct session_mib * bases;

	sum = 0;
	for(j=0;j < MAX_WORKER_NUM;j++) {
		bases = (struct session_mib *)(g_GenConf->fw_sess_mib_tbl_base[cmb_tbl_typ][j] + sess_index * sizeof(struct session_mib));
		sum+=bases->mib.bytes;
		memset(bases, 0, sizeof(struct session_mib));
	}

	*f_bytes = sum;
	return PPA_SUCCESS;
}

int32_t mpe_hal_get_session_hit_cnt(uint32_t cmb_tbl_typ, uint32_t sess_index, uint8_t *f_hit)
{
	int j;
	uint8_t *baseh= NULL;
	unsigned char sum;
	unsigned char hn[MAX_WORKER_NUM] = {0};
	sum = 0;
	*f_hit = 0;
	for(j=0;j < MAX_WORKER_NUM;j++) {
		baseh = (uint8_t *)(g_GenConf->fw_sess_hit_tbl_base[cmb_tbl_typ][j] + sess_index * sizeof(uint8_t));
		hn[j] = *baseh;
		sum += hn[j];
	}
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Total Hit count %d\n",sum);

	if(sum)
		*f_hit = 1;

	//Now clear it.
	for(j=0;j < MAX_WORKER_NUM;j++)
		memset((void *)g_GenConf->fw_sess_hit_tbl_base[cmb_tbl_typ][j] + sess_index * sizeof(uint8_t), 0, sizeof(uint8_t));

	return PPA_SUCCESS;
}

int32_t mpe_hal_get_session_acc_bytes(PPA_ROUTING_INFO *route)
{
	uint8_t fHit;
	uint32_t bytes;
	struct uc_session_node *p_item = (struct uc_session_node *)route->p_item;
	if(!p_item) return PPA_FAILURE;
	if(p_item->flags & SESSION_IS_IPV6) {
		mpe_hal_get_session_hit_cnt(1, route->entry, &fHit);
		mpe_hal_get_session_bytes(1, route->entry, &bytes);
	} else {
		mpe_hal_get_session_hit_cnt(0, route->entry, &fHit);
		mpe_hal_get_session_bytes(0, route->entry, &bytes);
	}
	route->f_hit = fHit;
	route->bytes = bytes;
	return PPA_SUCCESS;
}

int32_t mpe_hal_test_and_clear_hit_stat(PPA_ROUTING_INFO *route)
{
	uint8_t fHit;
	struct uc_session_node *p_item = (struct uc_session_node *)route->p_item;
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mpe_hal_test_and_clear_hit_stat\n");
	if (!p_item) return PPA_FAILURE;
	if (p_item->flags & SESSION_IS_IPV6) {
		mpe_hal_get_session_hit_cnt(1, route->entry, &route->f_hit);
	} else {
		mpe_hal_get_session_hit_cnt(0, route->entry, &fHit);
		route->f_hit = fHit;
	}
	return PPA_SUCCESS;
}

int add_route_entry(uint8_t *wanSrcMAC, uint8_t *wanDstMAC, uint8_t f_ipv6,
			IP_ADDR *Src_IP, IP_ADDR *Dst_IP, uint8_t f_tcp, uint32_t SrcPort, uint32_t DstPort,
			uint8_t rt_type, IP_ADDR *NATIPaddr, uint32_t TcpUdpPort,
			uint8_t f_islan, uint32_t mtu, uint32_t portmap, uint16_t subifid,
			uint8_t pppoe_mode, uint32_t pppoe_sessionid)
{
	int ret = PPA_SUCCESS;
	PPA_ROUTING_INFO route = {0};
	struct uc_session_node pitem = {0};

	ppa_memset( &route, 0, sizeof(route));

	route.p_item = &pitem;

	if( rt_type == PPA_ROUTE_TYPE_NAPT) pitem.flags |= SESSION_VALID_NAT_PORT | SESSION_VALID_NAT_IP;
	if(f_islan)	pitem.flags |= SESSION_LAN_ENTRY;
	if(f_ipv6)	pitem.flags |= SESSION_IS_IPV6;
	if(f_tcp) pitem.flags |= SESSION_IS_TCP;

	route.pppoe_mode = pppoe_mode;
	pitem.pkt.pppoe_session_id = pppoe_sessionid;

	pitem.mtu = mtu;

	pitem.dest_ifid = portmap;
	pitem.dest_subifid = subifid;
	pitem.pkt.nat_port = TcpUdpPort;
	memcpy(&pitem.pkt.nat_ip, NATIPaddr, sizeof(IP_ADDR));
	memcpy(pitem.pkt.src_mac,wanSrcMAC,sizeof(uint8_t)*PPA_ETH_ALEN);
	memcpy(pitem.pkt.dst_mac,wanDstMAC,sizeof(uint8_t)*PPA_ETH_ALEN);

	pitem.pkt.dst_port = DstPort;
	pitem.pkt.src_port = SrcPort;
	memcpy(&pitem.pkt. src_ip, Src_IP, sizeof(IP_ADDR));
	memcpy(&pitem.pkt.dst_ip, Dst_IP, sizeof(IP_ADDR));

	if((ret = mpe_hal_add_routing_entry(&route)) < PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add_routing_entry returned Failure %d\n", ret);
	}

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT, "add_routing_entry Success sip=%u dip=%u sp=%u dp=%u\n", Src_IP->ip, Dst_IP->ip, SrcPort, DstPort);

	return ret;
}


int ipv4_routing_test(void)
{
	int session_index = -1;

	u8 lanpcMAC[6]	= {0x00, 0x00, 0x00, 0x00, 0x00, 0x20}; /* lan pc interface mac */
	u8 br0MAC[6]	= {0x00, 0x00, 0x00, 0x00, 0x00, 0x02}; /* br0 port mac */
	u8 eth1MAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0xee}; /* eth1 interface mac*/
	u8 gwMAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x16}; /* smb wan port mac */

	char *lanip = "192.168.1.20";
	char *brip = "192.168.1.1";
	char *wanip = "100.100.105.1";
	char *gwip = "100.100.100.17";

	uint8_t f_ipv6, f_tcp, f_islan;
	uint32_t portmap;

	IP_ADDR lanpc_IP, br0_IP, eth1_IP, gw_IP;

	uint32_t lanPort =5000;
	uint32_t wanPort = 80;
	uint32_t TcpUdpPort = 4000;

	uint8_t rt_type = PPA_ROUTE_TYPE_NAPT;
	uint32_t mtu = 1500;

	lanpc_IP.ip = in_aton(lanip);
	br0_IP.ip	= in_aton(brip);
	eth1_IP.ip	= in_aton(wanip);
	gw_IP.ip	= in_aton(gwip);

	/* LAN to WAN session */
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Add LAN to WAN session\n");
	f_ipv6 = 0;
	f_tcp = 1;
	f_islan = 1;
	portmap = 0x8000;
	session_index = add_route_entry(eth1MAC, gwMAC, f_ipv6, &lanpc_IP, &gw_IP, f_tcp, lanPort, wanPort,
							rt_type, &eth1_IP, TcpUdpPort, f_islan, mtu, portmap, 0, 0, 0);

	/* WAN to LAN session*/
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Add WAN to LAN session\n");
	f_ipv6 = 0;
	f_tcp = 1;
	f_islan = 0;
	portmap = 0x04; /* lan port 2 */
	session_index = add_route_entry(br0MAC, lanpcMAC, f_ipv6, &gw_IP, &eth1_IP, f_tcp, wanPort, TcpUdpPort,
							rt_type, &lanpc_IP, lanPort, f_islan, mtu, portmap, 0, 0, 0);

	lanPort =5001;
	wanPort = 100;
	TcpUdpPort = 4001;

	/* LAN to WAN session */
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Add LAN to WAN session\n");
	f_ipv6 = 0;
	f_tcp = 1;
	f_islan = 1;
	portmap = 0x8000;
	session_index = add_route_entry(eth1MAC, gwMAC, f_ipv6, &lanpc_IP, &gw_IP, f_tcp, lanPort, wanPort,
							rt_type, &eth1_IP, TcpUdpPort, f_islan, mtu, portmap, 0, 0, 0);
	return 0;
}
#if 1
int ipv6_routing_test(void)
{
	int session_index = -1;

	u8 lanpcMAC[6]	= {0x00, 0x00, 0x00, 0x00, 0x00, 0x20}; /* lan pc interface mac */
	u8 br0MAC[6]	= {0x00, 0x00, 0x00, 0x00, 0x00, 0x02}; /* br0 port mac */
	u8 eth1MAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0xee}; /* eth1 interface mac */
	u8 gwMAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x16}; /* smb wan port mac */

	char *v6lan = "3ffe:507:0:1:200:86ff:fe05:80da";
	char *v6wan = "3ffe:501:410:0:2c0:dfff:fe47:33e";

	uint8_t f_ipv6, f_tcp, f_islan;
	uint32_t portmap;

	IP_ADDR lanpc_IP, gw_IP;

	uint32_t lanPort =1022;
	uint32_t wanPort = 22;
	uint32_t TcpUdpPort = 0;

	uint8_t rt_type = PPA_ROUTE_TYPE_IPV4;
	uint32_t mtu = 1500;
	const char *end;

	in6_pton(v6lan,-1,(void*)&lanpc_IP.ip6,-1,&end);
	in6_pton(v6wan,-1,(void*)&gw_IP.ip6,-1,&end);

	/* LAN to WAN session */
	f_ipv6 = 1;
	f_tcp = 1;
	f_islan = 1;
	portmap = 1 << 15;
	session_index = add_route_entry(eth1MAC, gwMAC, f_ipv6, &lanpc_IP, &gw_IP, f_tcp, lanPort, wanPort,
							rt_type, &lanpc_IP, TcpUdpPort, f_islan, mtu, portmap, 0, 0, 0);

	/* WAN to LAN session*/
	f_islan = 0;
	portmap = 1 << 2;

	session_index = add_route_entry(br0MAC, lanpcMAC, f_ipv6, &gw_IP, &lanpc_IP, f_tcp, wanPort, lanPort,
							rt_type, &lanpc_IP, lanPort, f_islan, mtu, portmap, 0, 0, 0);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT, "ipv6 route added.. !\n");

	return 0;
}

#ifdef MULTICAST_VAP_TEST
int multicast_routing_test(void)
{
	PPA_MC_INFO mc = {0};
	struct mc_session_node pitem={0};

	char *mcastip = "235.0.10.10";
	char *gwip = "100.100.100.1";

	uint8_t f_ipv6;
	uint32_t portmap=0, numvap=0, subifid=0;

	IP_ADDR gw_IP, mc_IP;

	mc_IP.ip	= in_aton(mcastip);
	gw_IP.ip	= in_aton(gwip);

	/* LAN to WAN session */
	f_ipv6 = 0;
	portmap = 1;
	portmap |= (1 << 2);
	subifid = 0;
	numvap = 0;

	memset(&mc, 0, sizeof(PPA_MC_INFO));
	mc.p_item = &pitem;

	mc.p_entry = 32;
	pitem.grp.group_id = 5;
	mc.dest_list |= 1 << 8;
	mc.dest_list |= 1 << 9;

	mc.dest_subif[8] |= 1 << 2;
	mc.dest_subif[8] |= 1 << 3;
	mc.dest_subif[8] |= 1 << 4;


	mc.dest_subif[9] |= 1 << 6;
	mc.dest_subif[9] |= 1 << 12;

	pitem.session_action = (uint32_t) kmalloc(sizeof(struct session_action), GFP_KERNEL);

	mpe_hal_add_wan_mc_entry(&mc);


	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT, "multicast route added.. !\n");
	return 0;
}
#endif
#endif

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
int32_t	IsValidRingId(uint32_t ring_id)
{
	if((ring_id > 0) || (ring_id <= MAX_RING))
		return 1;
	else
		return 0;
}

int32_t mpe_hal_get_ipsec_tunnel_mib(IPSEC_TUNNEL_MIB_INFO *mib_info)
{
	unsigned int i, rx_pkt_sum, tx_pkt_sum, tx_byte, rx_byte;
	struct mpe_itf_mib * base;
		unsigned int rxp[MAX_WORKER_NUM] = {0};
		unsigned int txp[MAX_WORKER_NUM] = {0};

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Get tunnel mib for tunnel id %d\n",mib_info->tunnel_id);
	rx_pkt_sum=0;
	tx_pkt_sum=0;
	tx_byte=0;
	rx_byte=0;

	for(i=0; i<MAX_WORKER_NUM; i++) {
		base = (struct mpe_itf_mib *)(g_GenConf->mib_itf_tbl_base[i] + (mib_info->tunnel_id * 2)*sizeof(struct mpe_itf_mib));
		txp[i] = base->tx_mib.pkt;
		tx_pkt_sum += txp[i];
		tx_byte+=base->tx_mib.bytes;
	}

	for(i=0;i < MAX_WORKER_NUM;i++) {
		if(!g_GenConf->hw_res[i].flag)
			continue;
		if(IsValidRingId(g_GenConf->hw_res[i].e97_ring_id)) {
			base = (struct mpe_itf_mib *)(g_GenConf->mib_e97_dec_base[i] + (mib_info->tunnel_id * sizeof(struct mib_info)));
			rxp[i] = base->rx_mib.pkt;
			rx_pkt_sum += rxp[i];
			rx_byte+= base->rx_mib.bytes;
		}
	}
	mib_info->rx_pkt_count = rx_pkt_sum;
	mib_info->tx_pkt_count = tx_pkt_sum;
	mib_info->tx_byte_count = tx_byte;
	mib_info->rx_byte_count = rx_byte;
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> rx_pkt_count [%d] tx_pkt_count:[%d] tx_byte_count: [%d] rx_byte_count: [%d]\n", __FUNCTION__,mib_info->rx_pkt_count,mib_info->tx_pkt_count,mib_info->tx_byte_count,mib_info->rx_byte_count);
	return PPA_SUCCESS;
}

int32_t mpe_hal_clear_ipsec_tunnel_mib(int32_t tunnel_id)
{
	unsigned int i;
	struct mpe_itf_mib * base;

	for(i=0; i<MAX_WORKER_NUM; i++) {
		base = (struct mpe_itf_mib *)(g_GenConf->mib_itf_tbl_base[i] + (tunnel_id * 2)*sizeof(struct mpe_itf_mib));
		base->tx_mib.pkt = 0;
		base->tx_mib.bytes = 0;
	}

	for (i = 0; i < MAX_WORKER_NUM; ++i) {
		if(!g_GenConf->hw_res[i].flag)
			continue;
		if(IsValidRingId(g_GenConf->hw_res[i].e97_ring_id)) {
			base = (struct mpe_itf_mib *)(g_GenConf->mib_e97_dec_base[i] + (tunnel_id * sizeof(struct mib_info)));
			base->rx_mib.pkt =0;
			base->rx_mib.bytes = 0;
		}
	}

	return PPA_SUCCESS;
}
#endif

/* ======================================================================================================= */
#define REG32(addr)	(*(volatile unsigned int *) (addr))
static irqreturn_t print_content(void)
{
	struct tc_hw_res *hw_res = &g_GenConf->hw_res[0];
	struct mperesp_itc *reg = (struct mperesp_itc *)(hw_res->MpeDebugRespReg);
	struct mperesp_itc resp_itc;

	if(CHECK_BIT(REG32(MPE_RESP_INT_STS), hw_res->MpeDebugQid)) {
		resp_itc.reg0 = reg->reg0;
		resp_itc.reg1 = reg->reg1;

		REG32(MPE_RESP_INT_STS) = (1<<hw_res->MpeDebugQid);

#ifdef BLOCKED
		gic_clear_edge(hw_res->MpeDebugRespRegIrq);
#endif
		if(g_GenConf->g_mpe_dbg_enable)
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%s",(char *)(resp_itc.reg1.fdf));

		cbm_buffer_free(g_GenConf->cbm_buffer_req_port, (void *) resp_itc.reg1.fdf,0);

		reg->reg0.vld = MPE_FW; // clear the valid bit
	}
	return IRQ_HANDLED;
}


static int mpe_hal_to_vmb_callback_hdlr(uint32_t status)
{
	switch (status)	{
		case FW_RESET:
			/*MPE FW hangs. So VMB has already configured the VPE in bootloader mode.
			// Start the MPE FW again.*/
			if (mpe_hal_run_fw(MAX_CPU, (uint8_t)g_ucNum_worker) == PPA_FAILURE) {
				ppa_debug(DBG_ENABLE_MASK_ERR,"Cannot run MPE FW.\n");
				return PPA_FAILURE;
			}
			break;
		default:
			ppa_debug(DBG_ENABLE_MASK_ERR,"mpe_hal_to_vmb_callback_hdlr not support status 0x%x\n", status);
			return PPA_FAILURE;
	}

	return PPA_SUCCESS;
}

static void mpe_hal_prepare_tc_launch(uint8_t tc_num, uint8_t tcType, struct tc_hw_res *tc_priv, struct TC_launch_t *tc_launch)
{
	tc_launch->tc_num = tc_num;
	tc_launch->mt_group = 1 ;

	tc_launch->start_addr = (uint32_t)g_GenConf->fw_hdr.worker_info.start_addr;

	tc_launch->sp = (uint32_t)(g_MpeFw_stack_addr + g_GenConf->fw_hdr.fw_stack_priv_data_size * (tc_priv->logic_mpe_tc_id +1));
	tc_launch->state = TC_INACTIVE;
	tc_launch->priv_info =(uint32_t) tc_priv->logic_mpe_tc_id;
	return;
}
static int mpe_hal_get_yield(uint8_t cpu_num, uint8_t tc_num)
{
	/* VMB manager will provide the API */
	return vmb_yr_get(cpu_num, 1);
}

static int mpe_hal_free_yield(uint8_t cpu_num, uint8_t tc_num)
{
	/* VMB manager will provide the API */
	vmb_yr_free(cpu_num, 1);
	return 0;
}

static int mpe_hal_get_ipi(uint8_t cpu)
{
	return fw_vmb_get_irq(cpu);
}

static int mpe_hal_get_vmbfwipi(uint8_t cpu)
{
	int32_t ret=0;
	struct device_node *np;
	char str1[16];
	uint32_t vmbfwipi;

	memset(str1, '\0', sizeof(str1));
	sprintf(str1, "%s%d", "/cpus/cpu@", cpu);
	np = of_find_node_by_path(str1);
	if (!np)
		return -ENODEV;

	ret = of_property_read_u32(np, "vmb-fw-ipi", &vmbfwipi);
	if (ret < 0 && ret != -EINVAL) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"ERROR : Property could be read from DT\n");
		return ret;
	}

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s >VMB-FW-IPI : %d\n",__FUNCTION__, vmbfwipi);
	return vmbfwipi;
}

static int32_t mpe_hal_get_semid(uint8_t cpu_num, uint8_t tc_num)
{
	int32_t semid = 0;
	uint32_t sem_addr ;
	/* VMB manager will provide the API */
	semid= vmb_itc_sem_get(cpu_num, tc_num);
	if(semid != -VMB_EBUSY) {
		sem_addr = itc_sem_addr(semid);
		sem_id_log[semid] = sem_addr; /*keep for free later */
		return sem_addr;
	}

	return PPA_FAILURE;
}

uint32_t mpe_hal_free_semid(uint32_t semid_ptr)
{
	int i;
	if( !semid_ptr ) return 0;

	for(i=0; i<MAX_ITC_SEMID; i++ ) {
		if( sem_id_log[i] == semid_ptr ) {
			sem_id_log[i] = 0;
			break;
		}
	}

	if( i>= MAX_ITC_SEMID) /*not found*/
		return -1;

	vmb_itc_sem_free(i);

	return PPA_SUCCESS;
}

static int32_t mpe_hal_set_checksum_queue_map(uint32_t port_id, uint32_t flags)
{
	if (port_id >= MAX_PMAC_PORT) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d Invalid port number \n",__func__, __LINE__);
		return PPA_FAILURE;
	}

	if (flags & NETIF_PMAC_NEEDED) {
		g_GenConf->port[port_id].pmac_len_out = 8;
		set_bit(port_id, &g_pmac_cfg);
	}else {
		g_GenConf->port[port_id].pmac_len_out = 0;
		clear_bit(port_id, &g_pmac_cfg);
	}

	if (flags & NETIF_LAN_WAN) {
		g_GenConf->port[port_id].port_type = PMAC_PORT_ETH;
	}

	if ((flags & NETIF_VANI_INTERFACE) && g_GenConf->vuni_ip == 0xf) {
		mpe_hal_pon_handling(port_id);
	}

	return PPA_SUCCESS;
}

static int32_t mpe_hal_set_fw_connectivity(u32 dp_port)
{
	struct dp_queue_map_set qmap_set = {0};
	struct dp_dequeue_res dq_res = {0};
	int32_t i, sch_id, q_id;

	memset(&dq_res, 0, sizeof(struct dp_dequeue_res));
	dq_res.dp_port = 0;
	dq_res.cqm_deq_idx = DEQ_PORT_OFFSET_ALL;

	if (dp_deq_port_res_get(&dq_res, 0) != 0) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d ERROR Failed to Get QOS Resources\n",__func__, __LINE__);
		return PPA_FAILURE;
	}

	dq_res.q_res = kmalloc(sizeof(struct dp_queue_res) * dq_res.num_q, GFP_KERNEL);
	if (dq_res.q_res == NULL) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d ERROR Malloc failed for q res\n",__func__, __LINE__);
		return PPA_FAILURE;
	}
	memset(dq_res.q_res, 0, sizeof(struct dp_queue_res)*dq_res.num_q);

	dq_res.q_res_size = dq_res.num_q;
	if (dp_deq_port_res_get(&dq_res, 0) != 0) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d ERROR Failed to Get QOS Resources\n",__func__, __LINE__);
		kfree(dq_res.q_res);
		return PPA_FAILURE;
	}

	for (i=0; i<dq_res.num_q ;i++){
		if (dq_res.q_res[i].cqm_deq_port_type == DP_DATA_PORT_MPE) {
			qmap_set.q_id = dq_res.q_res[i].q_id;
			break;
		}
	}

	if (dp_port) {
		sch_id = mpe_hal_add_sched(&dq_res);
		if (sch_id < 0) {
			ppa_debug(DBG_ENABLE_MASK_ERR, "%s:%d ERROR Failed to Get QOS Resources\n", __func__, __LINE__);
			return PPA_FAILURE;
		}

		/* Create new queue for DS traffic and link it to WRR scheduler. */
		q_id = mpe_hal_add_ds_queue(sch_id);
		if (q_id < 0) {
			ppa_debug(DBG_ENABLE_MASK_ERR, "%s: failed to add queue for mpe port\n",
					__func__);
			return PPA_FAILURE;
		}
		qmap_set.q_id = q_id;
		qmap_set.mask.subif = 1;

		/* Update mpe port QoS details */
		mpe_hal_update_mpe_qos_info(dp_port, q_id);
	}
	kfree(dq_res.q_res);
	dq_res.q_res = NULL;

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%s:%d qid for mpe fw [0x%x]\n",__func__, __LINE__,qmap_set.q_id);

	/* Update qid queue map table. */
	qmap_set.inst = 0;
	qmap_set.map.dp_port = dp_port;
	qmap_set.map.mpe1 = 1;
	qmap_set.map.mpe2 = 0;

	qmap_set.mask.enc = 1;
	qmap_set.mask.dec = 1;
	qmap_set.mask.flowid = 1;
	qmap_set.mask.class = 1;

	if (dp_queue_map_set(&qmap_set, 0) != DP_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d ERROR Failed to set q map for mpe q\n",__func__, __LINE__);
		return PPA_FAILURE;
	}

	g_MPE_accl_mode = 1;
	g_GenConf->pon_ip  = 0xf;;
	g_GenConf->vuni_ip = 0xf;

	return PPA_SUCCESS;
}

static int32_t mpe_hal_remove_fw_connectivity(void)
{
	struct dp_queue_map_set qmap_set = {0};
	struct dp_queue_map_get qmap_get = {0};
	struct dp_dequeue_res dq_res = {0};
	uint32_t i = 0;

	memset(&dq_res, 0, sizeof(struct dp_dequeue_res));
	dq_res.dp_port = 0;
	dq_res.cqm_deq_idx = DEQ_PORT_OFFSET_ALL;

	if (dp_deq_port_res_get(&dq_res, 0) != 0) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d ERROR Failed to Get QOS Resources\n",__func__, __LINE__);
		return PPA_FAILURE;
	}

	dq_res.q_res = kmalloc(sizeof(struct dp_queue_res) * dq_res.num_q, GFP_KERNEL);
	if (dq_res.q_res == NULL) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d ERROR Malloc failed for q res\n",__func__, __LINE__);
		return PPA_FAILURE;
	}

	memset(dq_res.q_res, 0, sizeof(struct dp_queue_res)*dq_res.num_q);
	dq_res.q_res_size = dq_res.num_q;
	if (dp_deq_port_res_get(&dq_res, 0) != 0) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d ERROR Failed to Get QOS Resources\n",__func__, __LINE__);
		kfree(dq_res.q_res);
		return PPA_FAILURE;
	}

	for (i=0; i<dq_res.num_q ;i++){
		if (dq_res.q_res[i].cqm_deq_port_type == DP_DATA_PORT_MPE) {
			qmap_get.q_id = dq_res.q_res[i].q_id;
		}
		else {
			qmap_set.q_id = dq_res.q_res[i].q_id;
		}
		if (qmap_get.q_id &&  qmap_set.q_id) {
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%s:%d mpe qid: [%d, ]cpu qid: [%d]\n",__func__, __LINE__,qmap_get.q_id,qmap_set.q_id);
			break;
		}
	}

	if (dp_queue_map_get(&qmap_get, 0) != DP_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d ERROR Failed to set q map for mpe q\n",__func__, __LINE__);
		kfree(dq_res.q_res);
		return PPA_FAILURE;
	}

	if (qmap_get.num_entry == 0) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d No MAP Entries found for mpe queue[%d]\n",__func__, __LINE__,qmap_get.q_id);
	} else {
		qmap_get.qmap_entry = kmalloc(sizeof(struct dp_queue_map_entry) * qmap_get.num_entry, GFP_KERNEL);
		if (qmap_get.qmap_entry == NULL) {
			ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d ERROR Malloc failed for q map entries\n",__func__, __LINE__);
			kfree(dq_res.q_res);
			return PPA_FAILURE;
		}

		qmap_get.qmap_size = qmap_get.num_entry;

		if (dp_queue_map_get(&qmap_get, 0) != DP_SUCCESS) {
			ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d ERROR Failed to set q map for mpe q\n",__func__, __LINE__);
			kfree(dq_res.q_res);
			kfree(qmap_get.qmap_entry);
			return PPA_FAILURE;
		}
		qmap_set.inst = 0;
		qmap_get.inst = 0;
		for (i=0; i<qmap_get.num_entry; i++){
			memcpy(&qmap_set.map, &qmap_get.qmap_entry[i].qmap, sizeof(struct dp_q_map));
			if (dp_queue_map_set(&qmap_set, 0) != DP_SUCCESS) {
				ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d ERROR Failed to set q map for mpe q\n",__func__, __LINE__);
				kfree(dq_res.q_res);
				kfree(qmap_get.qmap_entry);
				return PPA_FAILURE;
			}
		}
	}
	kfree(dq_res.q_res);
	dq_res.q_res = NULL;
	kfree(qmap_get.qmap_entry);
	qmap_get.qmap_entry = NULL;
	g_MPE_accl_mode = 0;

	g_GenConf->pon_ip  = 0xf;;
	g_GenConf->vuni_ip = 0xf;
	return PPA_SUCCESS;
}

static int32_t mpe_hal_get_cbm_deq_port(uint8_t tcType)
{
	int32_t deq_port= -1;
	struct dp_dequeue_res dq_res = {0};
	uint32_t i = 0;

	memset(&dq_res, 0, sizeof(struct dp_dequeue_res));
	dq_res.dp_port = 0;
	dq_res.cqm_deq_idx = DEQ_PORT_OFFSET_ALL;
	if (dp_deq_port_res_get(&dq_res, 0) != 0) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d ERROR Failed to Get QOS Resources\n",__func__, __LINE__);
		return PPA_FAILURE;
	}
	dq_res.q_res = kmalloc(sizeof(struct dp_queue_res) * dq_res.num_q, GFP_KERNEL);
	if (dq_res.q_res == NULL) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d ERROR Malloc failed for q res\n",__func__, __LINE__);
		return PPA_FAILURE;
	}
	memset(dq_res.q_res, 0, sizeof(struct dp_queue_res)*dq_res.num_q);

	dq_res.q_res_size = dq_res.num_q;
	if (dp_deq_port_res_get(&dq_res, 0) != 0) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"%s:%d ERROR Failed to Get QOS Resources\n",__func__, __LINE__);
		kfree(dq_res.q_res);
		return PPA_FAILURE;
	}

	for (i=0; i<dq_res.num_q ;i++){
		if (dq_res.q_res[i].cqm_deq_port_type == DP_DATA_PORT_MPE){
			deq_port = dq_res.q_res[i].cqm_deq_port;
			break;
		}
	}
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%s:%d MPE fw deq port is [0x%x]\n",__func__, __LINE__,deq_port);
	kfree(dq_res.q_res);
	dq_res.q_res = NULL;
	return deq_port;
}

/****************DUMP for PROC ENTRIES**********************************************************/
int32_t mpe_hal_test(uint32_t testcase)
{
	switch(testcase) {
	case 1: {
		ipv4_routing_test();
		break;
	}
	case 2: {
		ipv6_routing_test();
		break;
	}
	case 3: {
#ifdef HW_SESS_TEST
		mpe_hal_add_hw_session_test();
#endif
		return PPA_SUCCESS;
	}
	case 4: {
#ifdef MULTICAST_VAP_TEST
		multicast_routing_test();
#endif
		return PPA_SUCCESS;
	}
	case 5: {
#ifdef IPSEC_TEST
#if IS_ENABLED(CONFIG_PPA_MPE_IP97
		mpe_hal_ipsec_test();
#endif
#endif
		return PPA_SUCCESS;
	}
	default:
		break;

	}
	return 0;
}

int32_t mpe_hal_display_ipv4_session_action(uint32_t current_ptr)
{
	uint32_t size, i;
	struct fw_compare_hash_auto_ipv4 *phtable;
	int v =0,vap_entry_index=0,dst_pmac_port_no = 0, pmac_port_num =0;
	struct vap_entry *ve = NULL;

	if(current_ptr > (g_GenConf->fw_sess_tbl_num[0]-1) ) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Index is exceeding the table size \n");
		return PPA_FAILURE;
	}
	size = 1; /*sizeof( struct fw_compare_hash_auto_ipv4); */
	phtable = (struct fw_compare_hash_auto_ipv4 *)g_GenConf->fw_cmp_tbl_base[0];

	if((phtable + (current_ptr * size))->act == 0){
		ppa_debug(DBG_ENABLE_MASK_ERR,"NULL Action Pointer !!!\n");
		return PPA_FAILURE;
	}

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\nAction Table:\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Valid		        = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->entry_vld);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Template buffer len        = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->templ_len);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"pkt_len_delta              = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->pkt_len_delta);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"traffic_class              = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->traffic_class);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"ingress traffic_class      = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->ig_traffic_class);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mtu                        = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->mtu);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"protocol                   = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->protocol);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"routing_flag               = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->routing_flag );
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_src_ip_en              = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_src_ip_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_dst_ip_en              = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_dst_ip_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_inner_dscp_en          = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_inner_dscp_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"pppoe_offset_en            = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->pppoe_offset_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_ip_offset_en        = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tunnel_ip_offset_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_udp_offset_en       = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tunnel_udp_offset_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"in_eth_iphdr_offset_en     = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->in_eth_iphdr_offset_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"sess_mib_ix_en             = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->sess_mib_ix_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_traffic_class_en       = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_traffic_class_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_rm_en               = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tunnel_rm_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"meter_id1_en               = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->meter_id1_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"fcs_bd                     = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->fcs_bd);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"outer_dscp_mode            = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->outer_dscp_mode);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"meter_id0                  = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->meter_id0);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"meter_id1                  = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->meter_id1);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_inner_dscp             = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_inner_dscp);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"pkt_loop                   = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->pkt_loop);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"qmap                       = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->qmap);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_type                = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tunnel_type);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"pppoe_offset               = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->pppoe_offset);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_ip_offset           = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tunnel_ip_offset);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"in_eth_iphdr_offset        = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->in_eth_iphdr_offset);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_udp_offset          = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tunnel_udp_offset);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"key_en                     = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->key_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"rx_itf_mib_num             = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->rx_itf_mib_num);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tx_itf_mib_num             = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tx_itf_mib_num);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"sess_mib_ix                = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->sess_mib_ix);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"dst_pmac_port_num          = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_num);

	pmac_port_num = ((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_num;
	/*multicast*/
	vap_entry_index=((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->mc_index;
	if(vap_entry_index) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mc_index                   = %d\n",vap_entry_index);
		for(i=0;i < pmac_port_num;i++) {
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"dst_pmac_port_list[%d]      = %d\n",i,
				((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i]);
			dst_pmac_port_no = ((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i];
			if(dst_pmac_port_no) {
				ve = (struct vap_entry *)(g_GenConf->mc_vap_tbl_base[dst_pmac_port_no] + (sizeof(struct vap_entry) * vap_entry_index));
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mc_vap_num                 = 0x%x \n",ve->num);
				for(v=0; v < ve->num ;v++) {
					ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mc_vap_list[%d]            = 0x%x \n",v,ve->vap_list[v]);
				}
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
			}
		}
	} else {
		for(i=0;i < pmac_port_num;i++)
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"dst_pmac_port_list[%d]      = %d\n",i,((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i]);
		for(i=0;i < pmac_port_num;i++)
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"uc_vap_list[%d]             = %d\n",i,((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->uc_vap_list[i]);
	}
	for(i=0;i < MAX_ITF_PER_SESSION;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"rx_itf_mib_ix[%d]           = %d\n",i,((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->rx_itf_mib_ix[i]);
	for(i=0;i < MAX_ITF_PER_SESSION;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tx_itf_mib_ix[%d]           = %d\n",i,((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tx_itf_mib_ix[i]);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_src_ip                 = %s\n",inet_ntoa(((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_src_ip.ip4.ip));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_dst_ip                 = %s\n",inet_ntoa(((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_dst_ip.ip4.ip));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_src_port               = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_src_port);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_dst_port               = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_dst_port);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Template buffer:\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\t");
	for (i=0;i < ((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->templ_len;i++)  {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%02x ",((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->templ_buf[i]);
	}
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n\n");
	return 0;

}

int32_t mpe_hal_display_ipv6_session_action(uint32_t current_ptr)
{
	uint32_t size, i;
	struct fw_compare_hash_auto_ipv6 *phtable;
	int v =0,vap_entry_index=0,dst_pmac_port_no = 0, pmac_port_num =0;
	struct vap_entry *ve = NULL;

	if(current_ptr > (g_GenConf->fw_sess_tbl_num[1]-1) ) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Index is exceeding the table size \n");
		return PPA_FAILURE;
	}
	size = 1; /*sizeof( struct fw_compare_hash_auto_ipv4);*/
	phtable = (struct fw_compare_hash_auto_ipv6 *)g_GenConf->fw_cmp_tbl_base[1];

	if((phtable + (current_ptr * size))->act == 0){
		ppa_debug(DBG_ENABLE_MASK_ERR,"NULL Action Pointer !!!\n");
		return PPA_FAILURE;
	}

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\nAction Table:\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Valid		        = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->entry_vld);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Template buffer len        = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->templ_len);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"pkt_len_delta              = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->pkt_len_delta);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"traffic_class              = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->traffic_class);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mtu                        = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->mtu);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"protocol                   = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->protocol);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"routing_flag               = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->routing_flag );
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_src_ip_en              = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_src_ip_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_dst_ip_en              = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_dst_ip_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_inner_dscp_en          = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_inner_dscp_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"pkt_loop                   = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->pkt_loop);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"qmap                       = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->qmap);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"pppoe_offset_en            = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->pppoe_offset_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_ip_offset_en        = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tunnel_ip_offset_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_udp_offset_en       = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tunnel_udp_offset_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"in_eth_iphdr_offset_en     = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->in_eth_iphdr_offset_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"sess_mib_ix_en             = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->sess_mib_ix_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_traffic_class_en       = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_traffic_class_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_rm_en               = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tunnel_rm_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"meter_id1_en               = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->meter_id1_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"fcs_bd                     = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->fcs_bd);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"outer_dscp_mode            = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->outer_dscp_mode);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"meter_id0                  = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->meter_id0);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"meter_id1                  = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->meter_id1);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_inner_dscp             = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_inner_dscp);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_type                = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tunnel_type);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"pppoe_offset               = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->pppoe_offset);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_ip_offset           = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tunnel_ip_offset);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"in_eth_iphdr_offset        = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->in_eth_iphdr_offset);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_udp_offset          = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tunnel_udp_offset);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"key_en                     = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->key_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"rx_itf_mib_num             = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->rx_itf_mib_num);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tx_itf_mib_num             = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tx_itf_mib_num);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"sess_mib_ix                = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->sess_mib_ix);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"dst_pmac_port_num          = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_num);

	pmac_port_num = ((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_num;
	/*multicast*/
	vap_entry_index=((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->mc_index;
	if(vap_entry_index) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mc_index                   = %d\n",vap_entry_index);
		for(i=0;i < pmac_port_num;i++) {
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"dst_pmac_port_list[%d]      = %d\n",i,((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i]);
			dst_pmac_port_no = ((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i];
			if(dst_pmac_port_no) {
				ve = (struct vap_entry *)(g_GenConf->mc_vap_tbl_base[dst_pmac_port_no] + (sizeof(struct vap_entry) * vap_entry_index));
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mc_vap_num                 = 0x%x \n",ve->num);
				for(v=0; v < ve->num ;v++) {
					ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mc_vap_list[%d]            = 0x%x \n",v,ve->vap_list[v]);
				}
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
			}
		}
	} else {
		for(i=0;i < pmac_port_num;i++)
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"dst_pmac_port_list[%d]      = %d\n",i,((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i]);
		for(i=0;i < pmac_port_num;i++)
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"uc_vap_list[%d]             = %d\n",i,((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->uc_vap_list[i]);
	}
	for(i=0;i < MAX_ITF_PER_SESSION;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"rx_itf_mib_ix[%d]           = %d\n",i,((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->rx_itf_mib_ix[i]);
	for(i=0;i < MAX_ITF_PER_SESSION;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tx_itf_mib_ix[%d]           = %d\n",i,((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tx_itf_mib_ix[i]);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_src_ip                 = %s\n",inet_ntoa(((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_src_ip.ip4.ip));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_dst_ip                 = %s\n",inet_ntoa(((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_dst_ip.ip4.ip));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_src_port               = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_src_port);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_dst_port               = %d\n",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_dst_port);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Template buffer:\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\t");
	for (i=0;i < ((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->templ_len;i++)  {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%02x ",((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->templ_buf[i]);
	}
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n\n");
	return 0;

}

int32_t mpe_hal_display_hw_session_action(uint32_t current_ptr)
{
	uint32_t size, i;
	uint8_t tmpl_len = 0;
	struct hw_act_ptr *phtable;
	int v =0,vap_entry_index=0,dst_pmac_port_no = 0, pmac_port_num =0;
	struct vap_entry *ve = NULL;

	if(current_ptr > MAX_HW_SESSION_NUM) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Index is exceeding the table size \n");
		return PPA_FAILURE;
	}

	size =1; /*sizeof( struct hw_act_ptr);*/
	phtable =(struct hw_act_ptr *) g_GenConf->hw_act_tbl_base;

	if((phtable + (current_ptr * size))->act == 0) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"NULL Pointer\n");
		return PPA_FAILURE;
	}

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\nAction Table:\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Valid    		   = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->entry_vld);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Template buffer len        = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->templ_len);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"pkt_len_delta              = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->pkt_len_delta);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"traffic_class              = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->traffic_class);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mtu                        = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->mtu);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"protocol                   = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->protocol);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"routing_flag               = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->routing_flag );
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_src_ip_en              = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->new_src_ip_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_dst_ip_en              = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->new_dst_ip_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_inner_dscp_en          = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->new_inner_dscp_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"pppoe_offset_en            = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->pppoe_offset_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_ip_offset_en        = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->tunnel_ip_offset_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_udp_offset_en       = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->tunnel_udp_offset_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"in_eth_iphdr_offset_en     = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->in_eth_iphdr_offset_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"sess_mib_ix_en             = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->sess_mib_ix_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_traffic_class_en       = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->new_traffic_class_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_rm_en               = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->tunnel_rm_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"meter_id1_en               = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->meter_id1_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"fcs_bd                     = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->fcs_bd);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"outer_dscp_mode            = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->outer_dscp_mode);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"meter_id0                  = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->meter_id0);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"meter_id1                  = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->meter_id1);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_inner_dscp             = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->new_inner_dscp);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_type                = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->tunnel_type);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_id                  = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->tunnel_id);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"pppoe_offset               = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->pppoe_offset);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_ip_offset           = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->tunnel_ip_offset);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"in_eth_iphdr_offset        = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->in_eth_iphdr_offset);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tunnel_udp_offset          = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->tunnel_udp_offset);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"key_en                     = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->key_en);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"rx_itf_mib_num             = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->rx_itf_mib_num);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tx_itf_mib_num             = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->tx_itf_mib_num);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"sess_mib_ix                = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->sess_mib_ix);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"dst_pmac_port_num          = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_num);

	pmac_port_num = ((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_num;
	/*multicast*/
	vap_entry_index=((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->mc_index;
	if(vap_entry_index)  {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mc_index		= %d\n",vap_entry_index);
		for(i=0;i < pmac_port_num;i++)  {
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"dst_pmac_port_list[%d]	= %d\n",i,((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i]);
			dst_pmac_port_no = ((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i];
			if(dst_pmac_port_no) {
				ve = (struct vap_entry *)(g_GenConf->mc_vap_tbl_base[dst_pmac_port_no] + (sizeof(struct vap_entry) * vap_entry_index));
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mc_vap_num                 = 0x%x \n",ve->num);
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mc_vap_num		= 0x%x \n",ve->num);
				for(v=0; v < ve->num ;v++) {
					ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"mc_vap_list[%d]		= 0x%x \n",v,ve->vap_list[v]);
				}
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
			}
		}
	} else {
		for(i=0;i < pmac_port_num;i++)
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"dst_pmac_port_list[%d]      = %d\n",i,((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i]);
		for(i=0;i < pmac_port_num;i++)
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"uc_vap_list[%d]             = %d\n",i,((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->uc_vap_list[i]);
	}
	for(i=0;i < MAX_ITF_PER_SESSION;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"rx_itf_mib_ix[%d]           = %d\n",i,((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->rx_itf_mib_ix[i]);
	for(i=0;i < MAX_ITF_PER_SESSION;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"tx_itf_mib_ix[%d]           = %d\n",i,((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->tx_itf_mib_ix[i]);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_src_ip                 = %s\n",inet_ntoa(((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->new_src_ip.ip4.ip));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_dst_ip                 = %s\n",inet_ntoa(((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->new_dst_ip.ip4.ip));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_src_port               = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->new_src_port);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"new_dst_port               = %d\n",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->new_dst_port);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Template buffer:\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\t");
	tmpl_len = ((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->templ_len;
	for (i = 0;i < tmpl_len; i++) {
		if(i % 16 == 0)
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n%x ",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->templ_buf[i]);
		else
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%x ",((struct session_action*)(((struct hw_act_ptr *)(phtable + (current_ptr * size)))->act))->templ_buf[i]);
	}
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n\n");
	return PPA_SUCCESS;

}
int32_t mpe_hal_display_session_action(uint32_t tbl, uint32_t current_ptr)
{
	int32_t ret = PPA_SUCCESS;
	if(tbl == 1){
		ppa_mpe_session_list_lock_v4();
		ret = mpe_hal_display_ipv4_session_action(current_ptr);
		ppa_mpe_session_list_unlock_v4();
	} else if(tbl == 2) {
		ppa_mpe_session_list_lock_v6();
		ret = mpe_hal_display_ipv6_session_action(current_ptr);
		ppa_mpe_session_list_unlock_v6();
	} else if (tbl == 3) {
		ret = mpe_hal_display_hw_session_action(current_ptr);
	}
	return ret;
}

int32_t mpe_hal_dump_table_hashidx_entry(void *phtable,uint32_t hashidx,uint32_t type_flag, struct seq_file *seq)
{
	uint32_t size=0,counter=0,i=0;
	uint32_t current_ptr=0, previous_ptr=(MAX_HW_SESSION_NUM);
	struct ipv6_hash_auto_key ip6key;
	int v =0,vap_entry_index=0,dst_pmac_port_no = 0, pmac_port_num =0;
	struct vap_entry *ve = NULL;


	if(type_flag == 0)
		size=sizeof(struct fw_compare_hash_auto_ipv4);
	else
		size=sizeof(struct fw_compare_hash_auto_ipv6);

	current_ptr = ((struct fw_compare_hash_auto_ipv4 *)(phtable + (hashidx * size)))->first_ptr;
	while(previous_ptr != current_ptr) {
		if(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->valid) {
			if(type_flag==0){
				seq_printf(seq,"\nHash Index		= 0x%x : \n",hashidx);
				seq_printf(seq,"Session Id/Index	= 0x%x \n",current_ptr);
				seq_printf(seq,"MPE FW TABLE [IPV4]\n");
				seq_printf(seq,"key :srcip		= %s\n",inet_ntoa(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.srcip));
				seq_printf(seq,"key :dstip		= %s\n",inet_ntoa(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.dstip));
				seq_printf(seq,"key :dstport		= %d\n",((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.dstport);
				seq_printf(seq,"key :srcport		= %d\n",((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.srcport);

				if (((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.extn == 0x80) {
					seq_printf(seq,"key :extn		= %d GRE[TCP]\n",((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.extn);
				} else if (((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.extn == 0x81) {
					seq_printf(seq,"key :extn		= %d GRE[UDP]\n",((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.extn);
				} else if (((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.extn == 0x21) {
					seq_printf(seq,"key :extn		= %d L2TP[UDP]\n",((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.extn);
				} else if (((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.extn == 0x20) {
					seq_printf(seq,"key :extn		= %d L2TP[UDP]\n",((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.extn);
				} else if (((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.extn == 0x01) {
					seq_printf(seq,"key :extn		= %d UDP\n",((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.extn);
				} else
					seq_printf(seq,"key :extn		= %d TCP\n",((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->key.extn);

				if(display_action) {
					seq_printf(seq,"\nAction Table:\n");
					seq_printf(seq,"Template buffer len	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->templ_len);
					seq_printf(seq,"pkt_len_delta		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->pkt_len_delta);
					seq_printf(seq,"traffic_class		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->traffic_class);
					seq_printf(seq,"mtu			= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->mtu);
					seq_printf(seq,"protocol		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->protocol);
					seq_printf(seq,"routing_flag		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->routing_flag );
					seq_printf(seq,"new_src_ip_en		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_src_ip_en);
					seq_printf(seq,"new_dst_ip_en		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_dst_ip_en);
					seq_printf(seq,"new_inner_dscp_en	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_inner_dscp_en);
					seq_printf(seq,"pppoe_offset_en		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->pppoe_offset_en);
					seq_printf(seq,"tunnel_ip_offset_en	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tunnel_ip_offset_en);
					seq_printf(seq,"tunnel_udp_offset_en	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tunnel_udp_offset_en);
					seq_printf(seq,"in_eth_iphdr_offset_en	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->in_eth_iphdr_offset_en);
					seq_printf(seq,"sess_mib_ix_en		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->sess_mib_ix_en);
					seq_printf(seq,"new_traffic_class_en	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_traffic_class_en);
					seq_printf(seq,"tunnel_rm_en		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tunnel_rm_en);
					seq_printf(seq,"meter_id1_en		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->meter_id1_en);
					seq_printf(seq,"fcs_bd			= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->fcs_bd);
					seq_printf(seq,"outer_dscp_mode		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->outer_dscp_mode);
					seq_printf(seq,"meter_id0		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->meter_id0);
					seq_printf(seq,"meter_id1		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->meter_id1);
					seq_printf(seq,"new_inner_dscp		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_inner_dscp);
					seq_printf(seq,"tunnel_type		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tunnel_type);
					seq_printf(seq,"pppoe_offset		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->pppoe_offset);
					seq_printf(seq,"tunnel_ip_offset	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tunnel_ip_offset);
					seq_printf(seq,"in_eth_iphdr_offset	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->in_eth_iphdr_offset);
					seq_printf(seq,"tunnel_udp_offset	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tunnel_udp_offset);
					seq_printf(seq,"key_en			= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->key_en);
					seq_printf(seq,"rx_itf_mib_num		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->rx_itf_mib_num);
					seq_printf(seq,"tx_itf_mib_num		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tx_itf_mib_num);
					seq_printf(seq,"sess_mib_ix		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->sess_mib_ix);
					seq_printf(seq,"dst_pmac_port_num	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_num);

					pmac_port_num = ((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_num;
					/*multicast*/
					vap_entry_index=((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->mc_index;
					if(vap_entry_index)  {
						seq_printf(seq,"mc_index		= %d\n",vap_entry_index);
						for(i=0;i < pmac_port_num;i++)  {
							seq_printf(seq,"dst_pmac_port_list[%d]	= %d\n",i,((struct session_action*)
								(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i]);
							dst_pmac_port_no = ((struct session_action*)
								(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i];
							if(dst_pmac_port_no) {
								ve = (struct vap_entry *)(g_GenConf->mc_vap_tbl_base[dst_pmac_port_no] + (sizeof(struct vap_entry) * vap_entry_index));
								seq_printf(seq,"mc_vap_num				 = 0x%x \n",ve->num);
								for(v=0; v < ve->num ;v++) {
									seq_printf(seq,"mc_vap_list[%d]			= 0x%x \n",v,ve->vap_list[v]);
								}
								seq_printf(seq,"\n");
							}
						}
					} else {
						for(i=0;i < pmac_port_num;i++)
							seq_printf(seq,"dst_pmac_port_list[%d]	= %d\n",i,((struct session_action*)
							(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i]);
						for(i=0;i < pmac_port_num;i++)
							seq_printf(seq,"uc_vap_list[%d]		= %d\n",i,((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->uc_vap_list[i]);
					}
					for(i=0;i < MAX_ITF_PER_SESSION;i++)
						seq_printf(seq,"rx_itf_mib_ix[%d]	= %d\n",i,((struct session_action*)
							(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->rx_itf_mib_ix[i]);
					for(i=0;i < MAX_ITF_PER_SESSION;i++)
						seq_printf(seq,"tx_itf_mib_ix[%d]	= %d\n",i,((struct session_action*)
							(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->tx_itf_mib_ix[i]);
					seq_printf(seq,"new_src_ip		= %s\n",inet_ntoa(((struct session_action*)
							(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_src_ip.ip4.ip));
					seq_printf(seq,"new_dst_ip		= %s\n",inet_ntoa
						(((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_dst_ip.ip4.ip));
					seq_printf(seq,"new_src_port		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_src_port);
					seq_printf(seq,"new_dst_port		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->new_dst_port);
					seq_printf(seq,"Template buffer:\n");
					seq_printf(seq,"\t");
					for (i=0;i < ((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->templ_len;i++)	{
						seq_printf(seq,"%02x ",
							((struct session_action*)(((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->act))->templ_buf[i]);
					}
					seq_printf(seq,"\n\n");
				}
			} else {
				seq_printf(seq,"\nHash Index = 0x%x : \n",hashidx);
				seq_printf(seq,"Session Id/Index = 0x%x \n",current_ptr);
				seq_printf(seq,"MPE FW TABLE [IPV6]\n");
				memset(str,0,INET6_ADDRSTRLEN);
				ip6key.srcip[0] = ((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.srcip[3];
				ip6key.srcip[1] = ((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.srcip[2];
				ip6key.srcip[2] = ((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.srcip[1];
				ip6key.srcip[3] = ((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.srcip[0];
				seq_printf(seq,"key :src_ip	=%s \n",inet_ntop6((char *)&ip6key.srcip,str,INET6_ADDRSTRLEN));
				memset(str,0,INET6_ADDRSTRLEN);
				ip6key.dstip[0] = ((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.dstip[3];
				ip6key.dstip[1] = ((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.dstip[2];
				ip6key.dstip[2] = ((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.dstip[1];
				ip6key.dstip[3] = ((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.dstip[0];
				seq_printf(seq,"key :dst_ip	=%s \n",inet_ntop6((char *)&ip6key.dstip,str,INET6_ADDRSTRLEN));
				seq_printf(seq,"key :dstport	= %d\n",((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.dstport);
				seq_printf(seq,"key :srcport	= %d \n",((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.srcport);
				if (((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.extn == 0x81) {
					seq_printf(seq,"key :extn	= %d GRE[UDP]\n",((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.extn);
				} else if (((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.extn == 0x80) {
				 	seq_printf(seq,"key :extn	= %d GRE[TCP]\n",((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.extn);
				} else if (((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.extn == 0x21) {
					seq_printf(seq,"key :extn	= %d L2TP[UDP]\n",((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.extn);
				} else if (((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.extn == 0x20) {
					seq_printf(seq,"key :extn	= %d L2TP[TCP]\n",((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.extn);
				} else if (((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.extn == 0x01) {
					seq_printf(seq,"key :extn	= %d UDP\n",((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.extn);
				}
				else
					seq_printf(seq,"key :extn	= %d TCP\n",((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->key.extn);

				if(display_action) {
					seq_printf(seq,"\nAction Table:\n");
					seq_printf(seq,"Template buffer len	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->templ_len);
					seq_printf(seq,"dst_pmac_port_num	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_num);
					seq_printf(seq,"dst_pmac_port_list[0]	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[0]);
					seq_printf(seq,"pkt_len_delta		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->pkt_len_delta);
					seq_printf(seq,"traffic_class		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->traffic_class);
					seq_printf(seq,"mtu			= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->mtu);
					seq_printf(seq,"protocol		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->protocol);
					seq_printf(seq,"routing_flag		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->routing_flag );
					seq_printf(seq,"new_src_ip_en		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_src_ip_en);
					seq_printf(seq,"new_dst_ip_en		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_dst_ip_en);
					seq_printf(seq,"new_inner_dscp_en	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_inner_dscp_en);
					seq_printf(seq,"pppoe_offset_en		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->pppoe_offset_en);
					seq_printf(seq,"tunnel_ip_offset_en	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tunnel_ip_offset_en);
					seq_printf(seq,"tunnel_udp_offset_en	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tunnel_udp_offset_en);
					seq_printf(seq,"in_eth_iphdr_offset_en	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->in_eth_iphdr_offset_en);
					seq_printf(seq,"sess_mib_ix_en		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->sess_mib_ix_en);
					seq_printf(seq,"new_traffic_class_en	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_traffic_class_en);
					seq_printf(seq,"tunnel_rm_en		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tunnel_rm_en);
					seq_printf(seq,"meter_id1_en		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->meter_id1_en);
					seq_printf(seq,"fcs_bd			= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->fcs_bd);
					seq_printf(seq,"outer_dscp_mode		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->outer_dscp_mode);
					seq_printf(seq,"meter_id0		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->meter_id0);
					seq_printf(seq,"meter_id1		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->meter_id1);
					seq_printf(seq,"new_inner_dscp		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_inner_dscp);
					seq_printf(seq,"tunnel_type		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tunnel_type);
					seq_printf(seq,"pppoe_offset		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->pppoe_offset);
					seq_printf(seq,"tunnel_ip_offset	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tunnel_ip_offset);
					seq_printf(seq,"in_eth_iphdr_offset	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->in_eth_iphdr_offset);
					seq_printf(seq,"tunnel_udp_offset	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tunnel_udp_offset);
					seq_printf(seq,"key_en			= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->key_en);
					seq_printf(seq,"rx_itf_mib_num		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->rx_itf_mib_num);
					seq_printf(seq,"tx_itf_mib_num		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tx_itf_mib_num);
					seq_printf(seq,"sess_mib_ix		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->sess_mib_ix);
					seq_printf(seq,"dst_pmac_port_num	= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_num);
					pmac_port_num = ((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_num;

					/*multicast*/
					vap_entry_index=((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->mc_index;
					if(vap_entry_index)  {
						seq_printf(seq,"mc_index		= %d\n",vap_entry_index);
						for(i=0;i < pmac_port_num;i++)  {
							seq_printf(seq,"dst_pmac_port_list[%d]	= %d\n",i,((struct session_action*)
								(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i]);
							dst_pmac_port_no = ((struct session_action*)
								(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i];
							if(dst_pmac_port_no) {
								ve = (struct vap_entry *)(g_GenConf->mc_vap_tbl_base[dst_pmac_port_no] + (sizeof(struct vap_entry) * vap_entry_index));
								seq_printf(seq,"mc_vap_num		= 0x%x \n",ve->num);
								for(v=0; v < ve->num ;v++) {
									seq_printf(seq,"mc_vap_list[%d]		= 0x%x \n",v,ve->vap_list[v]);
								}
								seq_printf(seq,"\n");
							}
						}
					} else {
						for(i=0;i < pmac_port_num;i++)
							seq_printf(seq,"dst_pmac_port_list[%d]	= %d\n",i,((struct session_action*)
								(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->dst_pmac_port_list[i]);
						for(i=0;i < pmac_port_num;i++)
							seq_printf(seq,"uc_vap_list[%d]		= %d\n",i,((struct session_action*)
								(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->uc_vap_list[i]);
					}

					for(i=0;i < MAX_ITF_PER_SESSION;i++)
						seq_printf(seq,"rx_itf_mib_ix[%d]	= %d\n",i,((struct session_action*)
							(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->rx_itf_mib_ix[i]);
					for(i=0;i < MAX_ITF_PER_SESSION;i++)
						seq_printf(seq,"tx_itf_mib_ix[%d]	= %d\n",i,((struct session_action*)
							(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->tx_itf_mib_ix[i]);
					seq_printf(seq,"new_src_ip		= " NIP6_FMT "\n",
							NIP6(&((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_src_ip.ip6));
					seq_printf(seq,"new_dst_ip		= " NIP6_FMT "\n",
							NIP6(&((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_dst_ip.ip6));
					seq_printf(seq,"new_src_port		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_src_port);
					seq_printf(seq,"new_dst_port		= %d\n",((struct session_action*)
						(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->new_dst_port);

					seq_printf(seq,"Template buffer:\n");
					seq_printf(seq,"\t");
					for (i=0;i < ((struct session_action*)(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->templ_len;i++) {
						seq_printf(seq,"%02x ",((struct session_action*)
							(((struct fw_compare_hash_auto_ipv6 *)(phtable + (current_ptr * size)))->act))->templ_buf[i]);
					}
					seq_printf(seq,"\n\n");
				}
			}
			session_counter++;
		}
		counter++;
		previous_ptr=current_ptr;
		current_ptr=((struct fw_compare_hash_auto_ipv4 *)(phtable + (current_ptr * size)))->nxt_ptr;
	}
	return PPA_SUCCESS;
}

int mpe_hal_dump_ipv4_cmp_table_entry(struct seq_file *seq)
{
	int32_t i=0;
	struct fw_compare_hash_auto_ipv4 * pIp4CmpTbl;
	ppa_mpe_session_list_lock_v4();
	pIp4CmpTbl = (struct fw_compare_hash_auto_ipv4 *)g_GenConf->fw_cmp_tbl_base[0];
	for(i = 0; i < (g_GenConf->fw_sess_tbl_num[0]-1); i++ ) {
		if(((pIp4CmpTbl + (i ))->valid) == 1) {
			seq_printf(seq,"\n");
			seq_printf(seq,"Index : %d\n",i);
			seq_printf(seq,"Valid: %d\n",(pIp4CmpTbl + (i ))->valid);
			seq_printf(seq,"Next Pointer: %d\n",(pIp4CmpTbl + (i ))->nxt_ptr);
			seq_printf(seq,"First Pointer: %d\n",(pIp4CmpTbl + (i ))->first_ptr);
			seq_printf(seq,"Action Pointer: %x\n",(pIp4CmpTbl + (i ))->act);

			seq_printf(seq,"SrcIp: %s\n",inet_ntoa((pIp4CmpTbl + (i ))->key.srcip));
			seq_printf(seq,"DstIp: %s\n",inet_ntoa((pIp4CmpTbl + (i ))->key.dstip));
			seq_printf(seq,"SrcPort: %d\n",(pIp4CmpTbl + (i ))->key.srcport);
			seq_printf(seq,"DstPort: %d\n",(pIp4CmpTbl + (i ))->key.dstport);
			seq_printf(seq,"Extn: %d\n",(pIp4CmpTbl + (i ))->key.extn);
			seq_printf(seq,"====================\n");
		}
	}
	ppa_mpe_session_list_unlock_v4();
	return 0;
}

int32_t mpe_hal_dump_ipv6_cmp_table_entry( struct seq_file *seq )
{
	int32_t i=0;
	uint32_t printIPv6[4];
	struct fw_compare_hash_auto_ipv6 * pIp6CmpTbl;
	ppa_mpe_session_list_lock_v6();
	pIp6CmpTbl = (struct fw_compare_hash_auto_ipv6 *)g_GenConf->fw_cmp_tbl_base[1];
	for (i = 0; i < (g_GenConf->fw_sess_tbl_num[1]-1); i++) {
		if (((pIp6CmpTbl + (i))->valid) == 1) {
			seq_printf(seq, "\n");
			seq_printf(seq, "Index : %d\n", i);
			seq_printf(seq, "Valid: %d\n", (pIp6CmpTbl + (i))->valid);
			seq_printf(seq, "Next Pointer: %d\n", (pIp6CmpTbl + (i))->nxt_ptr);
			seq_printf(seq, "First Pointer: %d\n", (pIp6CmpTbl + (i))->first_ptr);
			seq_printf(seq, "Action Pointer: %x\n", (pIp6CmpTbl + (i))->act);
			/* Print Src IP in right format */
			printIPv6[0] = (pIp6CmpTbl + (i))->key.srcip[3];
			printIPv6[1] = (pIp6CmpTbl + (i))->key.srcip[2];
			printIPv6[2] = (pIp6CmpTbl + (i))->key.srcip[1];
			printIPv6[3] = (pIp6CmpTbl + (i))->key.srcip[0];
			seq_printf(seq, "SrcIp: %pI6\n", printIPv6);
			/* Print Dst IP in right format */
			printIPv6[0] = (pIp6CmpTbl + (i))->key.dstip[3];
			printIPv6[1] = (pIp6CmpTbl + (i))->key.dstip[2];
			printIPv6[2] = (pIp6CmpTbl + (i))->key.dstip[1];
			printIPv6[3] = (pIp6CmpTbl + (i))->key.dstip[0];
			seq_printf(seq, "DstIp: %pI6\n", printIPv6);
			seq_printf(seq, "SrcPort: %d\n", (pIp6CmpTbl + (i))->key.srcport);
			seq_printf(seq, "DstPort: %d\n", (pIp6CmpTbl + (i))->key.dstport);
			seq_printf(seq, "Extn: %d\n", (pIp6CmpTbl + (i))->key.extn);
			seq_printf(seq, "====================\n");
		}
	}
	ppa_mpe_session_list_unlock_v6();

	return 0;
}

void mpe_hal_dump_vap_list(void)
{
	int i, j, k;
	struct vap_entry *ve;
	for(i=0; i<MAX_PMAC_PORT; i++) {
		for(j=0; j<g_GenConf->mc_vap_num[i]; j++) {
			ve = (struct vap_entry *)(g_GenConf->mc_vap_tbl_base[i] + (sizeof(struct vap_entry) * j));
			if(!ve->num) continue;
			pr_err("Port%02u:%03u base(%p) num(%02u):\n", i, j, ve, ve->num);
			for(k=0; k<ve->num ;k++) {
				pr_err("%04x ", ve->vap_list[k]);
			}
			pr_err("\n");
		}
	}
}

char *get_status_str(uint32_t tc_cur_state)
{
	if(tc_cur_state == UNKNOWN)
		return ("Unknown");
	else if(tc_cur_state == TM_YD_WAIT)
		return ("TM YIELD");
	else if(tc_cur_state == WK_YD_WAIT)
		return ("WK YIELD");
	else if(tc_cur_state == WK_YD_WKUP)
		return ("WK YIELD WAKE UP");
	else if (tc_cur_state == TM_YD_WKUP)
		return ("TM YIELD WAKE UP");
	else if (tc_cur_state == MCPY_YD_WAIT)
		return ("MCPY YIELD WAKE UP");
	else if (tc_cur_state == MCPY_YD_WKUP)
		return ("MCPY YIELD WAKE UP");
	else if (tc_cur_state == MPECTRL_ENQ_YD_WAIT)
		return ("MPE CTRL ENQ YIELD");
	else if (tc_cur_state == MPECTRL_ENQ_YD_WKUP)
		return ("MPE CTRL ENQ YIELD WAKE UP");
	else if (tc_cur_state == MPECTRL_DEQ_YD_WAIT)
		return ("MPE CTRL DEQ YIELD");
	else if (tc_cur_state == MPECTRL_DEQ_YD_WKUP)
		return ("MPE CTRL DEQ YIELD WAKE UP");
	else if (tc_cur_state == CBM_ENQ_YD_WAIT)
		return ("CBM ENQ YIELD");
	else if (tc_cur_state == CBM_ENQ_YD_WKUP)
		return ("CBM ENQ YIELD WAKE UP");
	else if (tc_cur_state == CBM_DEQ_YD_WAIT)
		return ("CBM DEQ YIELD");
	else if (tc_cur_state == CBM_DEQ_YD_WKUP)
		return ("CBM DEQ YIELD WAKE UP");
	else if (tc_cur_state == SEM_DISP_Q_WAIT)
		return ("SEM TAKE DISP Q");
	else if (tc_cur_state == SEM_FREELIST_WAIT)
		return ("SEM TAKE FREELIST");
	else if (tc_cur_state == SEM_CBMALLOC_WAIT)
		return ("SEM TAKE CBM ALLOC");
	else if (tc_cur_state == SEM_DISP_Q_CNT_WAIT)
		return ("SEM TAKE DISP Q COUNT");
	else if (tc_cur_state == SEM_DISP_Q_WKUP)
		return ("SEM PUT DISP Q WAKE UP");
	else if (tc_cur_state == SEM_FREELIST_WKUP)
		return ("SEM PUT FREELIST WAKE UP ");
	else if (tc_cur_state == SEM_CBMALLOC_WKUP)
		return ("SEM PUT CBM ALLOC WAKE UP");
	else if (tc_cur_state == SEM_DISP_Q_CNT_WKUP)
		return ("SEM PUT DISP Q COUNT WAKE UP");

	ppa_debug(DBG_ENABLE_MASK_ERR,"Error returning tc_cur_state %d\n",tc_cur_state);
	return ("Error");
}

char *get_tc_type(int idx)
{
	if(g_GenConf->hw_res[idx].tcType == TYPE_TM)
		return ("TM");
	else if(g_GenConf->hw_res[idx].tcType == TYPE_WORKER)
		return ("WK");
	else
		return ("Unknown");
}

char *get_tc_health_cond(int idx)
{
	if(g_GenConf->hw_res[idx].state == STATE_INACTIVE)
		return("INACTIVE");
	else if(g_GenConf->hw_res[idx].state == STATE_IN_PROGRESS)
		return("RUNNING");
	else if(g_GenConf->hw_res[idx].state == STATE_TERMINATED)
		return("TERMIND");
	else if(g_GenConf->hw_res[idx].state == STATE_PAUSE)
		return("PAUSE");
	else if(g_GenConf->hw_res[idx].state == STATE_RESUME)
		return("RESUME");
	else
		return("Unknown");
}

void dump_tc_current_status(void)
{
	int i=0;

	if(!g_GenConf)
	{
		ppa_debug(DBG_ENABLE_MASK_ERR,"Genconf is not valid\n");
		return;
	}
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"=========================TC STATUS========================\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Hw_res:	 Health:	 TcType:	 TcNum:	Vpe:		TcState:\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"==========================================================\n");
	for(i=0;i < MAX_MPE_TC_NUM;i++) {
		if(!g_GenConf->hw_res[i].flag)
			continue;
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%02d		%s	 %s		%02d		%02d	 %s	\n",
				i,
				get_tc_health_cond(i),
				get_tc_type(i),
				g_GenConf->hw_res[i].TcNum,
				g_GenConf->hw_res[i].CpuNum,
		get_status_str(g_GenConf->tc_cur_state[i]));
	}
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"==========================================================\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	return;

}

void mpe_hal_dump_fw_header(struct seq_file *seq)
{
	int i=0;
	seq_printf(seq, "MPE FW HEADER :\n\n");
	seq_printf(seq, "fw_endian			%c 0x%x\n",'=',g_MpeFwHdr.fw_endian);
	seq_printf(seq, "compatible_id			%c 0x%x\n",'=',g_MpeFwHdr.compatible_id);
	seq_printf(seq, "family				%c 0x%x\n",'=',g_MpeFwHdr.family);
	seq_printf(seq, "package			%c 0x%x\n",'=',g_MpeFwHdr.package);
	seq_printf(seq, "v_maj				%c 0x%x\n",'=',g_MpeFwHdr.v_maj);
	seq_printf(seq, "v_mid				%c 0x%x\n",'=',g_MpeFwHdr.v_mid);
	seq_printf(seq, "v_min				%c 0x%x\n",'=',g_MpeFwHdr.v_min);
	seq_printf(seq, "v_tag				%c 0x%x\n",'=',g_MpeFwHdr.v_tag);
	seq_printf(seq, "genconf_offset			%c 0x%x\n",'=',g_MpeFwHdr.genconf_offset);
	seq_printf(seq, "hdr_size			%c 0x%x\n",'=',g_MpeFwHdr.hdr_size);
	seq_printf(seq, "fw_code_size			%c 0x%x\n",'=',g_MpeFwHdr.fw_code_size);
	seq_printf(seq, "fw_data_size			%c 0x%x\n",'=',g_MpeFwHdr.fw_data_size);
	seq_printf(seq, "fw_bss_size			%c 0x%x\n",'=',g_MpeFwHdr.fw_bss_size);
	seq_printf(seq, "fw_stack_priv_data_size	%c 0x%x\n",'=',g_MpeFwHdr.fw_stack_priv_data_size);
	seq_printf(seq, "fw_priv_data_size		%c 0x%x\n",'=',g_MpeFwHdr.fw_priv_data_size);
	seq_printf(seq, "fw_code_align			%c 0x%x\n",'=',g_MpeFwHdr.fw_code_align);
	seq_printf(seq, "fw_priv_data_align		%c 0x%x\n",'=',g_MpeFwHdr.fw_priv_data_align);
	seq_printf(seq, "fw_priv_data_mapped_addr %c 0x%x\n",'=',g_MpeFwHdr.fw_priv_data_mapped_addr);
	seq_printf(seq, "\n");
	seq_printf(seq, " MPE firmware code start address	%c 0x%p \n",'=', g_MpeFw_load_addr);
		seq_printf(seq, "\n");
	for (i=0;i < MAX_MPE_TC_NUM;i++) {
		seq_printf(seq, "TC %d stack start address		%c 0x%p\n", i,'=',g_MpeFw_stack_addr + (g_GenConf->fw_hdr.fw_stack_priv_data_size * i));
		seq_printf(seq, "\n");
	}
}

void mpe_hal_dump_genconf_offset(struct seq_file *seq)
{
#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	int i;
#endif
#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	int l;
#endif
	seq_printf(seq, "EVA mode: %d\n",g_GenConf->eva_config_flag);
	seq_printf(seq, "Segment control registers SEG0 = 0:%.8x SEG1 = 1:%.8x SEG2 = 2:%.8x\n",g_GenConf->eva_SegCtl0,g_GenConf->eva_SegCtl1,g_GenConf->eva_SegCtl2);

	seq_printf(seq, "vmb_fw_msg_base %x fw_vmb_msg_base %x Cpunum: %d\n",
			g_GenConf->vmb_fw_msg_base[g_MPELaunch_CPU],g_GenConf->fw_vmb_msg_base[g_MPELaunch_CPU], g_MPELaunch_CPU);

	seq_printf(seq, "IPV4 Compare table base 0x%8x\n",g_GenConf->fw_cmp_tbl_base[0]);
	seq_printf(seq, "IPV6 Compare table base 0x%8x\n",g_GenConf->fw_cmp_tbl_base[1]);

	seq_printf(seq, "hw_act_num			%c 0x%x\n",'=',g_GenConf->hw_act_num);
	seq_printf(seq, "hw_act_tbl_base			 %c 0x%x\n",'=',g_GenConf->hw_act_tbl_base);

	seq_printf(seq, "Session hit table base 0x%8p\n",g_GenConf->fw_sess_hit_tbl_base);
	seq_printf(seq, "Session MIB table base 0x%8p\n",g_GenConf->fw_sess_mib_tbl_base);
	seq_printf(seq, "Interface MIB table base 0x%8p\n",g_GenConf->mib_itf_tbl_base);
	seq_printf(seq, "Debug : %d\n",g_GenConf->g_mpe_dbg_enable);
	seq_printf(seq, "Debug Flags : 0x%x\n",g_GenConf->fw_dbg_flag);
	seq_printf(seq, "Ports PMAC Config : 0x%lx\n",g_pmac_cfg);

	seq_printf(seq, "dbg_mpe_q_id			%c 0x%x\n",'=',g_GenConf->dbg_mpe_q_id);
	seq_printf(seq, "dbg_mpe_q_id_en			 %c 0x%x\n",'=',g_GenConf->dbg_mpe_q_id_en);
	seq_printf(seq, "mc_cmp_mode			%c mpe_fw_len0x%x\n",'=',g_GenConf->mc_cmp_mode);
	seq_printf(seq, "dispatch_q_buf_num		%c 0x%x\n",'=',g_GenConf->dispatch_q_buf_num);

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	seq_printf(seq, "	CDR in base address:		0x%x\n",g_GenConf->e97_cdr_in[0][0]);
	seq_printf(seq, "	CDR out base address:		0x%x\n",g_GenConf->e97_cdr_out[0][0]);
	seq_printf(seq, "	ACD in base address:		0x%x\n",g_GenConf->e97_acd_in[0][0]);
	seq_printf(seq, "	ACD out base address:		0x%x\n",g_GenConf->e97_acd_out[0][0]);
	seq_printf(seq, "	RDR base address:		0x%x\n",g_GenConf->e97_rdr[0]);
	seq_printf(seq, "	Tunnel redir port:		%d\n",g_GenConf->tunnel_redir_port);

	l = sizeof(g_GenConf->ipsec_input_flag)/sizeof(g_GenConf->ipsec_input_flag[0]);
	seq_printf(seq, "\nipsec_input_flag array\n");
	for(i = 0; i < l; ++i)
		seq_printf(seq, "%d", g_GenConf->ipsec_input_flag[i]);
	l = sizeof(g_GenConf->ipsec_output_flag)/sizeof(g_GenConf->ipsec_output_flag[0]);
	seq_printf(seq, "\nipsec_output_flag array\n");
	for(i = 0; i < l; ++i)
		seq_printf(seq, "%d", g_GenConf->ipsec_output_flag[i]);
	seq_printf(seq, "\n");
#endif
}

void mpe_hal_dump_tc_hw_res(struct tc_hw_res *tc_res)
{
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"=========================TC HW RES ========================\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Flag: %2d\n",tc_res->flag);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"logic_mpe_tc_id: %2d\n",tc_res->logic_mpe_tc_id);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"TC QID: %2d\n",tc_res->TcQid);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"CPU Num: %2d TC Num : %2d\n",tc_res->CpuNum, tc_res->TcNum);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"FwVmbIpi : %2d VmbFwIpi: %2d \n",tc_res->FwVmbIpi, tc_res->VmbFwIpi);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Yield : %2d\n",tc_res->yield);
	dump_tc_current_status();
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"MpeCmdReqReg: %2x MpeCmdReqRegIrq: %2d\n",tc_res->MpeCmdReqReg,tc_res->MpeCmdReqRegIrq);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"MpeCmdRespReg: %2x MpeCmdRespRegIrq: %2d\n",tc_res->MpeCmdRespReg,tc_res->MpeCmdRespRegIrq);

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"disp_q_semid :%2x \n", tc_res->disp_q_semid);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"free_list_semid :%2x \n", tc_res->free_list_semid);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"cbm_alloc_semid :%2x \n", tc_res->cbm_alloc_semid);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"dispatch_q_cnt_semid :%2x \n", tc_res->dispatch_q_cnt_semid);

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Dequeue Port : %2d CbmDeQPortReg: %2x CbmDeQPortRegIrq: %2d\n",tc_res->CbmDeQPort,tc_res->CbmDeQPortReg,tc_res->CbmDeQPortRegIrq);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Enqueue Port : %2d CbmEnQPortReg: %2x CbmEnQPortRegIrq: %2d\n",tc_res->CbmEnQPort,tc_res->CbmEnQPortReg,tc_res->CbmEnQPortRegIrq);

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Ring Id : %2d \n",tc_res->e97_ring_id);
#endif
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"================================================\n");
	return;
}

void mpe_hal_dump_tc_hw_res_all(void)
{
	int i=0;

	if(!g_GenConf) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Genconf is not valid\n");
		return;
	}

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Hw_res:			= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",i);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	Flag:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].flag));

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	logic_mpe_tc_id:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].logic_mpe_tc_id));

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	TcQid:			= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].TcQid));

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	CpuNum:			= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].CpuNum));

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	TcNum:			= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].TcNum));

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	yield:			= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].yield));

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	VmbFwIpi:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].VmbFwIpi));

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	FwVmbIpi:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].FwVmbIpi));

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	tcType:			= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].tcType));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	state:			= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].state));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeCmdReqReg:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].MpeCmdReqReg));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeCmdReqRegIrq:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].MpeCmdReqRegIrq));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeCmdRespReg:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].MpeCmdRespReg));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeCmdRespRegIrq:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].MpeCmdRespRegIrq));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	McpyPort:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].McpyPort));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");


	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	McpyTxDescBase:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].McpyTxDescBase));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");


	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	McpyRxDescBase:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].McpyRxDescBase));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	McpyTxCh:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].McpyTxCh));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");


	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	McpyRxCh:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].McpyRxCh));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");


	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	McpyCmdReg:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].McpyCmdReg));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	McpyRespReg:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].McpyRespReg));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	McpyIrq:		 = ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].McpyIrq));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	CbmDeQPort:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].CbmDeQPort));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	CbmDeQPortReg:		 = ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].CbmDeQPortReg));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	CbmDeQPortRegIrq:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].CbmDeQPortRegIrq));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");


	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	CbmEnQPort:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].CbmEnQPort));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");


	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	CbmEnQPortReg:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].CbmEnQPortReg));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	CbmEnQPortRegIrq:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].CbmEnQPortRegIrq));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeDispatchQid:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].MpeDispatchQid));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");


	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeDispatchCmdReg:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].MpeDispatchCmdReg));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");


	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeDispatchCmdRegIrq:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].MpeDispatchCmdRegIrq));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeDispatchRespReg:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].MpeDispatchRespReg));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");


	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeDispatchRespRegIrq:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].MpeDispatchRespRegIrq));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeDebugQid:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].MpeDebugQid));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeDebugCmdReg:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].MpeDebugCmdReg));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeDebugCmdRegIrq:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].MpeDebugCmdRegIrq));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeDebugRespReg:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].MpeDebugRespReg));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeDebugRespRegIrq:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].MpeDebugRespRegIrq));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	itc_view:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].itc_view));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	disp_q_semid:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].disp_q_semid));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	free_list_semid:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		if(i < (MAX_TM_NUM + MAX_WORKER_NUM))
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].free_list_semid));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	cbm_alloc_semid:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].cbm_alloc_semid));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	dispatch_q_cnt_semid:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		if(i < (MAX_TM_NUM + MAX_WORKER_NUM))
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].dispatch_q_cnt_semid));
		else
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeSearchQid:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].MpeSearchQid));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	MpeMeterQid:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",(g_GenConf->hw_res[i].MpeMeterQid));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	private_ddr_addr:	= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10x",(g_GenConf->hw_res[i].private_ddr_addr));
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"	EIP97 Ring Id:		= ");
	for(i=0;i < MAX_MPE_TC_NUM;i++)
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%10d",g_GenConf->hw_res[i].e97_ring_id);
#endif
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
}

void mpe_hal_dump_hit_mib(struct seq_file *seq)
{
	int i, j, k;
	uint8_t *baseh;
	unsigned char sum;

	seq_printf(seq, "Hit session(WK):	");
	for(j=0;j < MAX_WORKER_NUM;j++)
		seq_printf(seq, "%5u",j);

	seq_printf(seq, "	 Total	 \n");
	for(i=0; i< MAX_CMP_TABLE_SUPPORTED; i++) {
		for(k=0; k< g_GenConf->fw_sess_tbl_num[i]; k++) {
			unsigned char hn[MAX_WORKER_NUM] = {0};
			sum = 0;
			for(j=0;j < MAX_WORKER_NUM;j++) {
				baseh = (uint8_t *)(g_GenConf->fw_sess_hit_tbl_base[i][j] + k * sizeof(uint8_t));
				hn[j] = *baseh;
				sum += hn[j];
			}

			if(sum) {
				seq_printf(seq, " tbl/sess %d/%d:	 ", i, k);
				for(j=0; j<MAX_WORKER_NUM; j++)
					seq_printf(seq, "%5u", hn[j]);
				seq_printf(seq, "%5u\n", sum);
			}
		}
	}
}

void mpe_hal_clear_hit_mib(void)
{
	int i=0,j=0;
	if(g_GenConf)	{
		for(i=0; i< MAX_CMP_TABLE_SUPPORTED; i++) {
			for(j=0; j< MAX_WORKER_NUM; j++) {
				memset((void *)g_GenConf->fw_sess_hit_tbl_base[i][j], 0, (g_GenConf->fw_sess_tbl_num[i] * sizeof(uint8_t)));
			}
		}
	}

}

void mpe_hal_dump_tc_mib( struct seq_file *seq)
{
	int i=0;
	if(g_GenConf)	{
		seq_printf(seq,"Hw_res:		 =	 ");
		for(i=0;i < MAX_MPE_TC_NUM;i++) {
			if(!g_GenConf->hw_res[i].flag)
				continue;
			seq_printf(seq,"%11d	",i);
		}
		seq_printf(seq,"\n");
		seq_printf(seq,"-------------------------------------------------------------------------------------------------------------------------\n");
		seq_printf(seq,"	 acc_pkt		=	 ");
		for(i=0;i < MAX_MPE_TC_NUM;i++) {
			if(!g_GenConf->hw_res[i].flag)
				continue;
			seq_printf(seq,"%11u	",(g_GenConf->tc_mib[i].acc_pkt_cnt));
		}
		seq_printf(seq," 	\n");
		seq_printf(seq,"	 non_acc_pkt	=	 ");
		for(i=0;i < MAX_MPE_TC_NUM;i++) {
			if(!g_GenConf->hw_res[i].flag)
				continue;
			seq_printf(seq,"%11u	",(g_GenConf->tc_mib[i].nona_pkt_cnt));
		}
		seq_printf(seq," 	\n");
		seq_printf(seq,"	 deq_cnt		=	 ");
		for(i=0;i < MAX_MPE_TC_NUM;i++) {
			if(!g_GenConf->hw_res[i].flag)
				continue;
			seq_printf(seq,"%11u	",(g_GenConf->tc_mib[i].deq_cnt));
		}
		seq_printf(seq," 	\n");
		seq_printf(seq,"	 enq_cnt		=	 ");
		for(i=0;i < MAX_MPE_TC_NUM;i++) {
			if(!g_GenConf->hw_res[i].flag)
				continue;
			seq_printf(seq,"%11u	",(g_GenConf->tc_mib[i].enq_cnt));
		}
		seq_printf(seq," 	\n");
	}
}

void mpe_hal_clear_tc_mib(void)
{
	int i=0;

	if(g_GenConf)	{
		for(i=0;i < MAX_MPE_TC_NUM;i++) {
			memset(&g_GenConf->tc_mib[i], 0, sizeof(struct mib_tc));
		}
	}

}


void mpe_hal_dump_session_mib_cntr(struct seq_file *seq)
{
	int i, j, k;
	unsigned long long sum;
	unsigned int pkt_sum;
	struct session_mib * bases;

	seq_printf(seq,"Session(WK):");
	for(j=0;j < MAX_WORKER_NUM;j++)
		seq_printf(seq,"%12u	",j);
	seq_printf(seq,"			Total			\n");

	for(i=0; i< MAX_CMP_TABLE_SUPPORTED; i++) {
		for(k=0; k< g_GenConf->fw_sess_tbl_num[i]; k++) {
			int pn[MAX_WORKER_NUM] = {0}; /* accelerated */
			int qn[MAX_WORKER_NUM] = {0}; /* non-accelerated */
			pkt_sum = 0;
			for(j=0;j < MAX_WORKER_NUM;j++) {
				bases = (struct session_mib *)(g_GenConf->fw_sess_mib_tbl_base[i][j] + k * sizeof(struct session_mib));
				pn[j] = bases->mib.pkt;
				qn[j] = bases->mib.non_acc_pkt;
				if(pn[j] > 0 || qn[j] > 0) {
					pkt_sum = 1;
					break;
				}
			}

			if(pkt_sum) {
				seq_printf(seq,"tbl%d sess%d\n", i, k);
				sum = 0;
				seq_printf(seq,"	bytes : ");
				for(j=0;j < MAX_WORKER_NUM;j++) {
					bases = (struct session_mib *)(g_GenConf->fw_sess_mib_tbl_base[i][j] + k * sizeof(struct session_mib));
					sum+=bases->mib.bytes;
					seq_printf(seq,"	%012llu", bases->mib.bytes);
				}
				seq_printf(seq,"	%012llu\n", sum);

				/* accelerated */
				pkt_sum = 0;
				seq_printf(seq,"	pkts	: ");
				for(j=0; j<MAX_WORKER_NUM; j++) {
					bases = (struct session_mib *)(g_GenConf->fw_sess_mib_tbl_base[i][j] + k * sizeof(struct session_mib));
					pkt_sum+=bases->mib.pkt;
					seq_printf(seq,"	%012u", bases->mib.pkt);
				}
				seq_printf(seq,"	%012u\n", pkt_sum);

				/* non-accelerated */
				pkt_sum = 0;
				seq_printf(seq,"nona_pkts	: ");
				for(j=0; j<MAX_WORKER_NUM; j++) {
					bases = (struct session_mib *)(g_GenConf->fw_sess_mib_tbl_base[i][j] + k * sizeof(struct session_mib));
					pkt_sum+=bases->mib.non_acc_pkt;
					seq_printf(seq,"	%012u", bases->mib.non_acc_pkt);
				}
				seq_printf(seq,"	%012u\n", pkt_sum);
			}
		 }
	}
}

void mpe_hal_clear_session_mib(void)
{
	int i=0,j=0;
	if(g_GenConf)	{
		for(i=0; i< MAX_CMP_TABLE_SUPPORTED; i++) {
			for(j=0; j< MAX_WORKER_NUM; j++) {
				memset((void *)g_GenConf->fw_sess_mib_tbl_base[i][j], 0, (g_GenConf->fw_sess_tbl_num[i] * sizeof(struct session_mib)));
			}
		}
	}

}


void mpe_hal_dump_itf_mib_cntr(struct seq_file *seq)
{
	int i, j;
	struct mpe_itf_mib * base;
	unsigned long long sum;
	unsigned int pkt_sum;

	seq_printf(seq,"Interface(WK):");
	for(i=0;i < MAX_WORKER_NUM;i++)
		seq_printf(seq,"	%11u",i);
	seq_printf(seq,"			Total\n");

	for(j=0; j<g_GenConf->mib_itf_num; j++) {
		unsigned int rxp[MAX_WORKER_NUM] = {0};
		unsigned int txp[MAX_WORKER_NUM] = {0};

		/* Collect RX interface counters*/
		pkt_sum=0;
		for(i=0; i<MAX_WORKER_NUM; i++) {
			base = (struct mpe_itf_mib *)(g_GenConf->mib_itf_tbl_base[i] + j*sizeof(struct mpe_itf_mib));
			rxp[i] = base->rx_mib.pkt;
			pkt_sum += rxp[i];
		}

		if(pkt_sum > 0) {
			seq_printf(seq,"[%3d] RX\n", j);
			sum=0;
			seq_printf(seq,"	bytes : ");
			for(i=0; i<MAX_WORKER_NUM; i++) {
				base = (struct mpe_itf_mib *)(g_GenConf->mib_itf_tbl_base[i] + j*sizeof(struct mpe_itf_mib));
				sum+=base->rx_mib.bytes;
				seq_printf(seq,"	%012llu", base->rx_mib.bytes);
			}
			seq_printf(seq,"	%012llu\n", sum);

			seq_printf(seq,"	pkts	: ");
			for(i=0; i<MAX_WORKER_NUM; i++)
				seq_printf(seq,"	%012u", rxp[i]);
			seq_printf(seq,"	%012u\n", pkt_sum);
		}

		/* Collect TX interface counters */
		pkt_sum=0;
		for(i=0; i<MAX_WORKER_NUM; i++) {
			base = (struct mpe_itf_mib *)(g_GenConf->mib_itf_tbl_base[i] + j*sizeof(struct mpe_itf_mib));
			txp[i] = base->tx_mib.pkt;
			pkt_sum += txp[i];
		}

		if(pkt_sum > 0) {
			seq_printf(seq,"[%3d] TX\n", j);
			sum=0;
			seq_printf(seq,"	bytes : ");
			for(i=0; i<MAX_WORKER_NUM; i++) {
				base = (struct mpe_itf_mib *)(g_GenConf->mib_itf_tbl_base[i] + j*sizeof(struct mpe_itf_mib));
				sum+=base->tx_mib.bytes;
				seq_printf(seq,"	%012llu", base->tx_mib.bytes);
			}
			seq_printf(seq,"	%012llu\n", sum);

			seq_printf(seq,"	pkts	: ");
			for(i=0; i<MAX_WORKER_NUM; i++)
				seq_printf(seq,"	%012u", txp[i]);
			seq_printf(seq,"	%012u\n", pkt_sum);
		}
	}

}

void mpe_hal_clear_itf_mib(void)
{
	int i=0;

	if (!g_GenConf)
		return;

	for (i = 0; i < MAX_WORKER_NUM; i++) {
		memset((void *)g_GenConf->mib_itf_tbl_base[i], 0,
			(g_GenConf->mib_itf_num * sizeof(struct mpe_itf_mib)));
	}
}

void mpe_hal_debug_cfg(uint32_t ucDbg)
{

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"ucDbg:%d\n",ucDbg);
	g_GenConf->g_mpe_dbg_enable = ucDbg;

}

#if 1
int gic_pend_reg(uint32_t irq_no)
{
	volatile uint32_t mask = (0xb2320480+((irq_no>>5)*0x4));
	irq_no = (irq_no - ((irq_no>>5)*32));
	if(CHECK_BIT(REG32(mask), irq_no))
		return 1;

	return 0;
}

int inline gic_mask_reg(uint32_t irq_no)
{
	volatile uint32_t mask = (0xb2320400+((irq_no>>5)*0x4));
	irq_no = (irq_no - ((irq_no>>5)*32));
	if(CHECK_BIT(REG32(mask), irq_no))
		return 1;

	return 0;
}

void dump_mpe_ctrl_q(struct seq_file *seq)
{
	int i=0;

	if(!g_GenConf)
	{
		seq_printf(seq, "Genconf is not valid\n");
		return;
	}
	seq_printf(seq,"========================MPE CTRL Q STATUS==============================\n");
	seq_printf(seq,"Hw_res:	 CmdReg0:	CmdReg1:	RespReg0: RespReg1: CmdIntSts:RespIntSts:\n");
	seq_printf(seq,"=======================================================================\n");
	for(i=0;i < MAX_MPE_TC_NUM;i++) {
		if(!g_GenConf->hw_res[i].flag)
			continue;
		seq_printf(seq,"%02d		%08x	%08x	%08x	%08x	%s		 %s\n",
				i,
				REG32(g_GenConf->hw_res[i].MpeCmdReqReg),
				REG32(g_GenConf->hw_res[i].MpeCmdReqReg+4),
				REG32(g_GenConf->hw_res[i].MpeCmdRespReg),
				REG32(g_GenConf->hw_res[i].MpeCmdRespReg+4),
				((REG32(MPE_CMD_INT_STS) & (1 << i))?"SET":"CLR"),
				((REG32(MPE_RESP_INT_STS) & (1 << i))?"SET":"CLR"));
	}
	seq_printf(seq,"=======================================================================\n");
	seq_printf(seq,"\n");

	return;

}

void dump_mcpy_reg(struct seq_file *seq)
{
	int i=0;

	if(!g_GenConf)
	{
		seq_printf(seq,"Genconf is not valid\n");
		return;
	}
	seq_printf(seq,"=========================MCPY REG STATUS=====================\n");
	seq_printf(seq,"Hw_res:	 McpyReg0: McpyReg1: McpyReg2: McpyReg3: McpyIntSts:\n");
	seq_printf(seq,"=============================================================\n");
	for(i=0;i < MAX_MPE_TC_NUM;i++) {
		if(!g_GenConf->hw_res[i].flag)
			continue;
		seq_printf(seq,"%02d		%08x	%08x	%08x	%08x	%s	\n",
				i,
				REG32(g_GenConf->hw_res[i].McpyCmdReg),
				REG32(g_GenConf->hw_res[i].McpyCmdReg+0x4),
				REG32(g_GenConf->hw_res[i].McpyCmdReg+0x8),
				REG32(g_GenConf->hw_res[i].McpyCmdReg+0xc),
				((REG32(MPE_MCPY_INT_STAT) & (1 << i))?"SET":"CLR"));
	}
	seq_printf(seq,"=============================================================\n");
	seq_printf(seq,"\n");

	return;

}

void dump_gic_pend_mask_reg(struct seq_file *seq)
{
	int i=0;

	if(!g_GenConf)
	{
		seq_printf(seq,"Genconf is not valid\n");
		return;
	}
	seq_printf(seq,"====================GIC STATUS=====================\n");
	seq_printf(seq,"Type:	 PORT No:	IrqNo:	Pending:	Mask:		\n");
	seq_printf(seq,"===================================================\n");
	for(i=0;i<MAX_TM_NUM;i++) {
		if(!g_GenConf->hw_res[MAX_WORKER_NUM+i].flag)
			continue;
		seq_printf(seq,"CBM DEQ	 %02d		%03d		 %s		 %s\n",
				g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmDeQPort,
				g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmDeQPortRegIrq,
				(gic_pend_reg(g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmDeQPortRegIrq)?"SET":"CLR"),
				(gic_mask_reg(g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmDeQPortRegIrq)?"SET":"CLR"));
		seq_printf(seq,"CBM ENQ	 %02d		%03d		 %s		 %s\n",
				g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmEnQPort,
				g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmEnQPortRegIrq,
				(gic_pend_reg(g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmEnQPortRegIrq)?"SET":"CLR"),
				(gic_mask_reg(g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmEnQPortRegIrq)?"SET":"CLR"));
	}
	seq_printf(seq,"\n");
	for(i=0;i<MAX_MPE_TC_NUM;i++) {
		if(!g_GenConf->hw_res[i].flag)
			continue;
		seq_printf(seq,"MCPY		%02d		%03d		 %s		 %s\n",
				g_GenConf->hw_res[i].McpyPort,
				g_GenConf->hw_res[i].McpyIrq,
				(gic_pend_reg(g_GenConf->hw_res[i].McpyIrq)?"SET":"CLR"),
				(gic_mask_reg(g_GenConf->hw_res[i].McpyIrq)?"SET":"CLR"));
	}
	seq_printf(seq,"\n");
	for(i=0;i<MAX_MPE_TC_NUM;i++) {
		if(!g_GenConf->hw_res[i].flag)
			continue;
		seq_printf(seq,"MPE CMD	 %02d		%03d		 %s		 %s\n",
				g_GenConf->hw_res[i].TcQid,
				g_GenConf->hw_res[i].MpeCmdReqRegIrq,
				(gic_pend_reg(g_GenConf->hw_res[i].MpeCmdReqRegIrq)?"SET":"CLR"),
				(gic_mask_reg(g_GenConf->hw_res[i].MpeCmdReqRegIrq)?"SET":"CLR"));
	}
	for(i=0;i<MAX_MPE_TC_NUM;i++) {
		if(g_GenConf->hw_res[i].flag)
			break;
	}
	seq_printf(seq,"MPE CMD	 %02d		%03d		 %s		 %s\n",
			g_GenConf->hw_res[i].MpeDispatchQid,
			g_GenConf->hw_res[i].MpeDispatchCmdRegIrq,
			(gic_pend_reg(g_GenConf->hw_res[i].MpeDispatchCmdRegIrq)?"SET":"CLR"),
			(gic_mask_reg(g_GenConf->hw_res[i].MpeDispatchCmdRegIrq)?"SET":"CLR"));

	seq_printf(seq,"\n");
	for(i=0;i<MAX_MPE_TC_NUM;i++) {
		if(!g_GenConf->hw_res[i].flag)
			continue;
		seq_printf(seq,"MPE RESP	%02d		%03d		 %s		 %s\n",
				g_GenConf->hw_res[i].TcQid,
				g_GenConf->hw_res[i].MpeCmdRespRegIrq,
				(gic_pend_reg(g_GenConf->hw_res[i].MpeCmdRespRegIrq)?"SET":"CLR"),
				(gic_mask_reg(g_GenConf->hw_res[i].MpeCmdRespRegIrq)?"SET":"CLR"));
	}
	for(i=0;i<MAX_MPE_TC_NUM;i++) {
		if(g_GenConf->hw_res[i].flag)
			break;
	}
	seq_printf(seq,"MPE RESP	%02d		%03d		 %s		 %s\n",
			g_GenConf->hw_res[i].MpeDispatchQid,
			g_GenConf->hw_res[i].MpeDispatchRespRegIrq,
			(gic_pend_reg(g_GenConf->hw_res[i].MpeDispatchRespRegIrq)?"SET":"CLR"),
			(gic_mask_reg(g_GenConf->hw_res[i].MpeDispatchRespRegIrq)?"SET":"CLR"));

	seq_printf(seq,"===================================================\n");
	seq_printf(seq,"\n");

	return;
}


void dump_cbm_reg(struct seq_file *seq)
{
	int i=0;
	struct cbm_ls_status *ls_status;

	if(!g_GenConf) {
		seq_printf(seq,"Genconf is not valid\n");
		return;
	}
	seq_printf(seq,"======CBM REG STS========\n");
	seq_printf(seq,"Type:		Status:	 \n");
	seq_printf(seq,"=========================\n");
	for(i=0;i<MAX_TM_NUM;i++) {
		if(!g_GenConf->hw_res[MAX_WORKER_NUM+i].flag)
			continue;

		seq_printf(seq,"CBM_ENQ_IRNEN:	 %08x\n", REG32(CBM_ENQ_IRNEN_PORT(g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmEnQPort)));
		seq_printf(seq,"CBM_ENQ_IRNCR:	 %08x\n", REG32(CBM_ENQ_IRNCR_PORT(g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmEnQPort)));
	}
	seq_printf(seq,"\n");

	for(i=0;i<MAX_TM_NUM;i++) {
		if(!g_GenConf->hw_res[MAX_WORKER_NUM+i].flag)
			continue;

		seq_printf(seq,"CBM_IRNEN:		 %s\n", CHECK_BIT(REG32(CBM_IRNEN_PORT(g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmDeQPort+4)),
					(g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmDeQPort+8))?"SET":"CLR");
		seq_printf(seq,"CBM_IRNCR:		 %s\n",CHECK_BIT(REG32(CBM_IRNCR_PORT(g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmDeQPort+4)),
					(g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmDeQPort+8))?"SET":"CLR");
	}
	seq_printf(seq,"\n");

	for(i=0;i<MAX_TM_NUM;i++) {
		if(!g_GenConf->hw_res[MAX_WORKER_NUM+i].flag)
			continue;

		seq_printf(seq,"LS_INT_EN:		 %s\n",CHECK_BIT(REG32(CBM_LS_INT_EN),
					(16+(g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmDeQPort*2)))?"SET":"CLR");
		seq_printf(seq,"LS_INTSTS:		 %s\n",CHECK_BIT(REG32(CBM_LS_INT_STS),
					(16+(g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmDeQPort*2)))?"SET":"CLR");
		seq_printf(seq,"LS_REGSTS:		 %08x\n",REG32(CBM_LS_STATUS_PORT(g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmDeQPort)));
		ls_status = (struct cbm_ls_status *)(CBM_LS_STATUS_PORT(g_GenConf->hw_res[MAX_WORKER_NUM+i].CbmDeQPort));
		seq_printf(seq,"LS_REGCNT:		 %02d\n",ls_status->queue_len);
	}
	seq_printf(seq,"\n");
	seq_printf(seq,"DISP_Q_CNT:	%02d\n",g_GenConf->dispatch_q_cnt);
	seq_printf(seq,"G_LS_Q_CNT:	%02d\n",g_GenConf->ls_q_cnt);

	seq_printf(seq,"=========================\n");
	seq_printf(seq,"\n");
	return;
}


void dump_dma_setting( struct seq_file *seq )
{

	if(!g_GenConf)
	{
		seq_printf(seq,"Genconf is not valid\n");
		return;
	}
	seq_printf(seq,"=========DMA REG SETTING==========\n");
	seq_printf(seq,"Name:		Addr:		Value:\n");
	seq_printf(seq,"==================================\n");
	seq_printf(seq,"DMA4_CLC	 %08x	 %08x\n",(DMA4_CLC),REG32(DMA4_CLC));
	seq_printf(seq,"DMA4_ID		%08x	 %08x\n",(DMA4_ID),REG32(DMA4_ID));
	seq_printf(seq,"DMA4_CTRL	%08x	 %08x\n",(DMA4_CTRL),REG32(DMA4_CTRL));
	seq_printf(seq,"DMA4_CPOLL	 %08x	 %08x\n",(DMA4_CPOLL),REG32(DMA4_CPOLL));
	seq_printf(seq,"DMA4_CS		%08x	 %08x\n",(DMA4_CS),REG32(DMA4_CS));
	seq_printf(seq,"DMA4_CCTRL	 %08x	 %08x\n",(DMA4_CCTRL),REG32(DMA4_CCTRL));
	seq_printf(seq,"DMA4_CDBA	%08x	 %08x\n",(DMA4_CDBA),REG32(DMA4_CDBA));
	seq_printf(seq,"DMA4_CDLEN	 %08x	 %08x\n",(DMA4_CDLEN),REG32(DMA4_CDLEN));
	seq_printf(seq,"DMA4_CIE	 %08x	 %08x\n",(DMA4_CIE),REG32(DMA4_CIE));
	seq_printf(seq,"DMA4_PS		%08x	 %08x\n",(DMA4_PS),REG32(DMA4_PS));
	seq_printf(seq,"DMA4_PCTRL	 %08x	 %08x\n",(DMA4_PCTRL),REG32(DMA4_PCTRL));
	seq_printf(seq,"==================================\n");
	seq_printf(seq,"\n");

	return;
}
#endif

void dump_mpe_detailed_debug(struct seq_file *seq)
{
	/* dump mpe ctrl registers*/
	dump_mpe_ctrl_q( seq );
	/* dump mcpy registers */
	dump_mcpy_reg( seq	);
	/* dump gic pending registers & mask registers*/
	dump_gic_pend_mask_reg( seq );
	/* dump tc current status */
	dump_tc_current_status( );
	/* cbm interrupt status*/
	dump_cbm_reg( seq );
	/* dump dma setting */
	dump_dma_setting( seq );
	/* dump cause reg, epc, status of each tc*/
}

void mpe_hal_dump_mpe_detailed_dbg(struct seq_file *seq)
{
	dump_mpe_detailed_debug( seq );
}

int32_t mpe_hal_config_accl_mode(uint32_t mode)
{
	if(mode == 0) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT," Disable MPE Accl\n");
		if (!g_MPE_accl_mode)
			return 0;

		mpe_hal_remove_fw_connectivity();
		dp_set_gsw_parser(3,0,0,0,0);
	} else if(mode == 1) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT," Enable MPE Accl\n");
		if (g_MPE_accl_mode)
			return 0;

		mpe_hal_set_fw_connectivity(0);
		dp_set_gsw_parser(3,2,2,0,0);
	} else if(mode == 2) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Start MPE FW\n");
		mpe_hal_run_fw(MAX_CPU, (uint8_t)g_ucNum_worker);
	} else if(mode == 3) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Stop MPE FW in CPU %d\n",g_MPELaunch_CPU);
		mpe_hal_stop_fw(g_MPELaunch_CPU);

	} else {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Wrong mode!!!\n");
	}
	return 0;
}

/**************************************************************************/
/*
*	fill all the hardware resources for each TC
*	for all the hardware resources in tc_hw_res, by default is already filled by MPE FW
*/
static void mpe_hal_update_tc_hw_info(uint8_t cpu_num, uint8_t tc_num, uint8_t tcType, struct tc_hw_res *tc_res)
{
#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	int32_t id;
#endif
	tc_res->flag = 1; /* this hw resource is assigned to the TC */
	tc_res->tcType = tcType;
	tc_res->TcNum = tc_num;
	tc_res->CpuNum = cpu_num;
	tc_res->state =	STATE_INACTIVE;
	tc_res->yield = mpe_hal_get_yield(cpu_num, tc_num);
	tc_res->FwVmbIpi = mpe_hal_get_ipi(cpu_num);
	tc_res->VmbFwIpi = mpe_hal_get_vmbfwipi(cpu_num);

	if(tcType != TYPE_TM){
		int32_t j=0;
		for (j=0; j< MAX_MPE_TC_NUM; j++) {
			if((g_GenConf->hw_res[j].tcType == TYPE_TM) && (g_GenConf->hw_res[j].CpuNum == cpu_num)){
				break;
			}
		}

		tc_res->disp_q_semid = g_GenConf->hw_res[j].disp_q_semid;
		tc_res->free_list_semid = g_GenConf->hw_res[j].free_list_semid;
		tc_res->cbm_alloc_semid = g_GenConf->hw_res[j].cbm_alloc_semid;
		tc_res->dispatch_q_cnt_semid = g_GenConf->hw_res[j].dispatch_q_cnt_semid;
#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
		if(mpe_hal_get_ring_id(&id)==PPA_SUCCESS) {
			tc_res->e97_ring_id = id;
		}
#endif

	} else { /*TM */
		tc_res->disp_q_semid = mpe_hal_get_semid(cpu_num, tc_num);
		tc_res->free_list_semid = mpe_hal_get_semid(cpu_num, tc_num);
		tc_res->cbm_alloc_semid = mpe_hal_get_semid(cpu_num, tc_num);
		tc_res->dispatch_q_cnt_semid = mpe_hal_get_semid(cpu_num, tc_num);
	}

	tc_res->CbmDeQPort = mpe_hal_get_cbm_deq_port(tcType);
	tc_res->CbmEnQPort = tc_res->CbmDeQPort;
	return;
}

void ltq_strcat(char *p, char *q)
{
	 while(*p)
		p++;

	 while(*q) {
		*p = *q;
		q++;
		p++;
	 }
	 *p = '\0';
}

char *itoa(int32_t i )
{
	/* Room for INT_DIGITS digits, - and '\0' */
	static char buf[20];
	char *p = buf + 19;	/* points to terminating '\0' */
	if (i >= 0) {
	do {
		*--p = '0' + (i % 10);
		i /= 10;
	} while (i != 0);
	return p;
	}
	else {			/* i < 0 */
	do {
		*--p = '0' - (i % 10);
		i /= 10;
	} while (i != 0);
	*--p = '-';
	}
	return p;
}

void dump_mpe_version(struct seq_file *seq )
{
	g_mpe_version = kmalloc( sizeof(char) * VER_STR_MAXLEN, GFP_KERNEL );
	if (NULL != g_mpe_version) {
		memset(g_mpe_version, '\0', sizeof(char) * VER_STR_MAXLEN);
		ltq_strcat(g_mpe_version, itoa(VER_MAJ));
		ltq_strcat(g_mpe_version, ".");
		ltq_strcat(g_mpe_version, itoa(VER_MID));
		ltq_strcat(g_mpe_version, ".");
		ltq_strcat(g_mpe_version, itoa(VER_MIN));
		ltq_strcat(g_mpe_version, ".");
		ltq_strcat(g_mpe_version, itoa(VER_TAG));
		ltq_strcat(g_mpe_version, "(");
		ltq_strcat(g_mpe_version, VER_DESC);
		ltq_strcat(g_mpe_version, ")");
		seq_printf(seq, "MPE Version: V.%s\n", g_mpe_version);
		kfree(g_mpe_version);
	}
	return ;
}

void mpe_session_count ( struct seq_file *seq)
{
	int32_t i=0, count=0;
	struct fw_compare_hash_auto_ipv4 * pIp4CmpTbl;
	struct fw_compare_hash_auto_ipv6 * pIp6CmpTbl;

	ppa_mpe_session_list_lock_v4();
	pIp4CmpTbl = (struct fw_compare_hash_auto_ipv4 *)g_GenConf->fw_cmp_tbl_base[0];
	for(i = 0; i < (g_GenConf->fw_sess_tbl_num[0]-1); i++ ) {
		if(((pIp4CmpTbl + (i ))->valid) == 1) {
			count++;
		}
	}
	ppa_mpe_session_list_unlock_v4();
	seq_printf(seq, "IPv4 session count = %d\n", count);

	ppa_mpe_session_list_lock_v6();
	pIp6CmpTbl = (struct fw_compare_hash_auto_ipv6 *)g_GenConf->fw_cmp_tbl_base[1];
	for(i = 0, count = 0; i < (g_GenConf->fw_sess_tbl_num[1]-1); i++ ) {
		if(((pIp6CmpTbl + (i ))->valid) == 1) {
			count++;
		}
	}
	ppa_mpe_session_list_unlock_v6();
	seq_printf(seq, "IPv6 session count = %d\n", count);

	return;
}

int mpe_hal_pause_tc(uint8_t ucCpu, uint8_t ucTc)
{
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> Pause CPU->TC %d->%d\n",__FUNCTION__,ucCpu,ucTc);
	if(vmb_tc_pause(ucCpu, ucTc) != VMB_SUCCESS)
		return PPA_FAILURE;

	return PPA_SUCCESS;

}

int mpe_hal_resume_tc(uint8_t ucCpu, uint8_t ucTc)
{
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> Resume CPU->TC %d->%d\n",__FUNCTION__,ucCpu,ucTc);
	vmb_tc_resume(ucCpu, ucTc);
	if(vmb_tc_resume(ucCpu, ucTc) != VMB_SUCCESS)
		return PPA_FAILURE;

	return PPA_SUCCESS;
}

int mpe_hal_delete_tc(uint8_t ucCpu, uint8_t ucTc)
{
	uint32_t j=0;
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> Delete CPU->TC %d->%d\n",__FUNCTION__,ucCpu,ucTc);
	for (j=0; j< MAX_MPE_TC_NUM; j++) {
		if((logic_tc_mapping[j] == ucTc) && (g_GenConf->hw_res[j].CpuNum == ucCpu)) {
			mpe_hal_free_yield(ucCpu, 1);
			vmb_tc_stop(ucCpu, ucTc);
			g_GenConf->hw_res[j].flag = 0; /* Free this hardware resource */
			g_GenConf->hw_res[j].state = STATE_INACTIVE;
			logic_tc_mapping[j] = 0;
			break;
		}
	}
	return PPA_SUCCESS;
}
static DECLARE_WAIT_QUEUE_HEAD(dl_wq);

int mpe_hal_add_tc(uint8_t ucCpu, uint32_t tc_type)
{
	uint32_t ret;
	int32_t tc_num = -1, j;
	struct TC_launch_t tc_launch;

	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s>Launch TC to CPU %d\n",__FUNCTION__,ucCpu);
	/* Allocate a TC bound to a particular CPU */
	tc_num = vmb_tc_alloc(ucCpu);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s>Allocated TC num %d\n",__FUNCTION__,tc_num);

	if(tc_num == -VMB_ERROR){
		ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate TC for the CPU %d\n", ucCpu );
		return PPA_FAILURE;
	}else {
		/*	Find the free hw resource for the TC */
		for (j=0; j< MAX_WORKER_NUM; j++) {
			if(g_GenConf->hw_res[j].flag == 0) {
				break;
			}
		}

		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s>Free hardware resource Index is %d\n",__FUNCTION__, j );
		if (1) {
			u32 *temp = (u32 *)(g_MpeFw_stack_addr + (g_GenConf->fw_hdr.fw_stack_priv_data_size * j));
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%s: DIRECTLINK preparation	[%p]size[%x]\n", __func__,
				temp,
				g_GenConf->fw_hdr.fw_priv_data_size);
			memset(temp,
				0x0,
				g_GenConf->fw_hdr.fw_stack_priv_data_size);
		}
		logic_tc_mapping[j] = tc_num;
		mpe_hal_update_tc_hw_info(ucCpu, tc_num, tc_type, &g_GenConf->hw_res[j]);
		mpe_hal_prepare_tc_launch(tc_num, tc_type, &g_GenConf->hw_res[j], &tc_launch);
		ret = vmb_tc_start(ucCpu, &tc_launch ,1);
		if((ret == -VMB_ETIMEOUT) ||(ret == -VMB_ENACK)) {
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Failed to start TC for the CPU %d\n", ucCpu );
			return PPA_FAILURE;
		}
	}
	return j;

}

struct device * g_Mpedev;
int dl_irq_no = 0;
void mpe_hal_dl_enable_gic(int irq_no)
{
	return;
}
EXPORT_SYMBOL(mpe_hal_dl_enable_gic);

int mpe_hal_feature_start(
		enum MPE_Feature_Type mpeFeature,
		uint32_t port_id,
		uint32_t * featureCfgBase,
		uint32_t flags)
{
	int32_t tc_id;
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> Flags: %d Mpe Feature: %d\n",__FUNCTION__,flags,mpeFeature);
	if((flags & F_FEATURE_START) == F_FEATURE_START) {
		if(mpeFeature == DL_TX_1 || mpeFeature == DL_TX_2) {
			if(port_id != 0) {
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> Start DL Feature for port id %d\n",__FUNCTION__,port_id);
				g_dl1_pmac_port = port_id;
				if (dl_irq_no)
					mpe_hal_dl_enable_gic(dl_irq_no);
			}
		} else {
			tc_id = mpe_hal_add_tc(g_MPELaunch_CPU, TYPE_WORKER);
		}

	} else {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Wrong flag is passed!!");
		return PPA_FAILURE;
	}
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> EXIT\n",__FUNCTION__);
	return PPA_SUCCESS;
}
EXPORT_SYMBOL(mpe_hal_feature_start);

static int mpe_hal_read_fw_hdr(void)
{
#if FIRMWARE_REQUEST
	int count = 0 , ret = 0;
	pdev = platform_device_register_simple("MPE_FW", 0, NULL, 0);
	if (IS_ERR(pdev)) {
				ppa_debug(DBG_ENABLE_MASK_ERR,KERN_ERR "Failed to register platform device.\n");
				return -EINVAL;
	}
	while (count < 5) {
		if ((ret = request_firmware(&fw_entry, FIRMWARE, &pdev->dev)) == 0) {
			if ( (fw_entry->data != NULL) && (fw_entry->size) ) {
				break;
			} else {
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"******** Request Firmware Addr: 0x%p size: %d ********\n", fw_entry->data, fw_entry->size);
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"releasing firmware\n");
				release_firmware(fw_entry);
			}
		}
		count= count + 1;
	}
	if (count == 5 ) {
		ppa_debug(DBG_ENABLE_MASK_ERR,KERN_ERR " Firmware not	available error code=%d\n", ret);
	 	return PPA_FAILURE ;
	}

	gImage_size = fw_entry->size - sizeof(struct fw_hdr);

	memset(&g_MpeFwHdr, 0x00 , sizeof(struct fw_hdr));
	memcpy(&g_MpeFwHdr, fw_entry->data, sizeof(struct fw_hdr));
	g_GenConf = (struct genconf *)((fw_entry->data + sizeof(struct fw_hdr)) + g_MpeFwHdr.genconf_offset);

#endif

	return PPA_SUCCESS;
}

static int mpe_hal_load_fw(char* filename)
{
	int pages;
	int32_t ret = PPA_SUCCESS;
	unsigned int mpe_alloc_code_len;
	unsigned int mpe_alloc_stack_len;


	/* Allocate memory for firmware code
		 Use GFP_DMA to allocate in the lower 128/256M memory location*/
	mpe_alloc_code_len = g_MpeFwHdr.fw_code_size + g_MpeFwHdr.fw_data_size + g_MpeFwHdr.fw_bss_size;

	if( (mpe_alloc_code_len % TLB_PAGE_SIZE) != 0)
		pages = (mpe_alloc_code_len / TLB_PAGE_SIZE) + 1;
	else
		pages = (mpe_alloc_code_len / TLB_PAGE_SIZE) ;

	g_MpeFw_load_addr = (char *)kmalloc(((pages+2) * TLB_PAGE_SIZE), GFP_DMA);

	if (!g_MpeFw_load_addr) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Can't allocate Memory for Code!");
		ret = PPA_FAILURE;
		goto CLEANUP;
	}
	// Align the buffer with fw_code_align
	g_MpeFw_load_addr = g_MpeFw_load_addr + g_MpeFwHdr.fw_code_align - ((unsigned int) g_MpeFw_load_addr) % g_MpeFwHdr.fw_code_align;

	// Allocate memory for stack
	mpe_alloc_stack_len = MAX_MPE_TC_NUM * g_MpeFwHdr.fw_stack_priv_data_size;
	if( (mpe_alloc_stack_len % TLB_PAGE_SIZE) != 0)
		pages = (mpe_alloc_stack_len / TLB_PAGE_SIZE) + 1;
	else
		pages = (mpe_alloc_stack_len / TLB_PAGE_SIZE) ;

	g_MpeFw_stack_addr = (char *)kmalloc(((pages+2) * TLB_PAGE_SIZE), GFP_DMA);

	if (!g_MpeFw_stack_addr) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Can't Allocate Stack Memory!");
		ret = PPA_FAILURE;
		goto CLEANUP;
	}

	/* Copy the content from file to the memory location */
	memcpy(g_MpeFw_load_addr, (fw_entry->data + sizeof(struct fw_hdr)), mpe_alloc_code_len);

	/*	Get the GenConf information */
	g_GenConf = (struct genconf *)(g_MpeFw_load_addr + g_MpeFwHdr.genconf_offset);


	if(!strcmp(g_GenConf->fw_hdr.v_desc, "PRX300"))
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Genconf offset correct\n");
	else
	{
		ppa_debug(DBG_ENABLE_MASK_ERR,"Genconf offset wrong !!!!! desc %s\n",g_GenConf->fw_hdr.v_desc);
		ret = PPA_FAILURE;
		goto CLEANUP;
	}

	g_HAL_State = MPE_HAL_FW_LOADED;
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"MPE HAL Load FW Success.\n");

CLEANUP:
	release_firmware(fw_entry);
	platform_device_unregister(pdev);
	if(ret == PPA_FAILURE) {
		if (g_MpeFw_load_addr)
			kfree(g_MpeFw_load_addr);

		if (g_MpeFw_stack_addr)
			kfree(g_MpeFw_stack_addr);
	}
	return ret;
}

static int mpe_hal_allocate_fw_table(void)
{
	uint32_t i=0, j=0;
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"MPE HAL Allocate FW Data.\n");

	g_GenConf->eva_config_flag = 7;
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"segment control registers SEG0 = 0:%.8x SEG1 = 1:%.8x SEG2 = 2:%.8x\n",read_c0_segctl0(),read_c0_segctl1(),read_c0_segctl2());
	g_GenConf->eva_SegCtl0 = read_c0_segctl0();
	g_GenConf->eva_SegCtl1 = read_c0_segctl1();
	g_GenConf->eva_SegCtl2 = read_c0_segctl2();

	g_Dispatch_buffer = kmalloc(sizeof(struct buffer_free_list) * MAX_DISPATCH_BUF_NUM, GFP_KERNEL);
	if(!g_Dispatch_buffer) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate dispatch buffer\n");
		return PPA_FAILURE;
	}
	memset((void *)g_Dispatch_buffer, 0 , sizeof(struct buffer_free_list) * MAX_DISPATCH_BUF_NUM);

	g_Dl_dispatch_buffer = kmalloc(sizeof(struct buffer_free_list) * MAX_DISPATCH_BUF_NUM, GFP_KERNEL);
	if(!g_Dl_dispatch_buffer) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate dl dispatch buffer\n");
		return PPA_FAILURE;
	}
	memset((void *)g_Dl_dispatch_buffer, 0 , sizeof(struct buffer_free_list) * MAX_DISPATCH_BUF_NUM);

#ifdef CONFIG_IP_TABLE
	g_GenConf->ipv4_num = ;
	g_GenConf->ipv4_tbl_base = (uint32_t)kmalloc(g_GenConf->ipv4_num * 4, GFP_KERNEL );
	if (!g_GenConf->ipv4_tbl_base) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate memory for IPv4 table\n");
		return PPA_FAILURE;
	}

	g_GenConf->ipv6_num = ;
	g_GenConf->ipv6_tbl_base = (uint32_t)kmalloc(g_GenConf->ipv6_num * 16, GFP_KERNEL );
	if (!g_GenConf->ipv6_tbl_base) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate memory for IPv6 table\n");
		return PPA_FAILURE;
	}
#endif

	/* Configuration required for Full Precessing */
	/* Compare Table for IPv4 session */
	g_GenConf->fw_sess_tbl_type[0] = 1; /*IPv4 table */
	g_GenConf->fw_sess_tbl_num[0] = MAX_FW_SESSION_NUM;
	g_GenConf->fw_sess_tbl_iterate[0] = MAX_SEARCH_ITRN;
	g_GenConf->fw_cmp_tbl_base[0] = (uint32_t)kmalloc(g_GenConf->fw_sess_tbl_num[0]* sizeof(struct fw_compare_hash_auto_ipv4), GFP_DMA);
	if (!g_GenConf->fw_cmp_tbl_base[0]) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate memory for IPv4 compare table\n");
		return PPA_FAILURE;
	} else {
		memset((void *)g_GenConf->fw_cmp_tbl_base[0], 0, g_GenConf->fw_sess_tbl_num[0]* sizeof(struct fw_compare_hash_auto_ipv4));
		for(i = 0; i < g_GenConf->fw_sess_tbl_num[0] ; i++ ) {
			if(i < g_GenConf->fw_sess_tbl_num[0] -1)
				((struct fw_compare_hash_auto_ipv4 *)(g_GenConf->fw_cmp_tbl_base[0] + (i * sizeof(struct fw_compare_hash_auto_ipv4))))->valid=0;
			else
				((struct fw_compare_hash_auto_ipv4 *)(g_GenConf->fw_cmp_tbl_base[0] + (i * sizeof(struct fw_compare_hash_auto_ipv4))))->valid=1;
			((struct fw_compare_hash_auto_ipv4 *)(g_GenConf->fw_cmp_tbl_base[0] + (i * sizeof(struct fw_compare_hash_auto_ipv4))))->nxt_ptr= g_GenConf->fw_sess_tbl_num[0] - 1;
			((struct fw_compare_hash_auto_ipv4 *)(g_GenConf->fw_cmp_tbl_base[0] + (i * sizeof(struct fw_compare_hash_auto_ipv4))))->first_ptr= g_GenConf->fw_sess_tbl_num[0] - 1;
			((struct fw_compare_hash_auto_ipv4 *)(g_GenConf->fw_cmp_tbl_base[0] + (i * sizeof(struct fw_compare_hash_auto_ipv4))))->act=0;

		}
		g_session_idx_table[0].size = ((MAX_FW_SESSION_NUM + 1) >> IDX_MAP_SHIFT);
		g_session_idx_table[0].base = (uint32_t *)kzalloc((g_session_idx_table[0].size * sizeof(uint32_t)), GFP_KERNEL);
		if (!g_session_idx_table[0].base) {
			ppa_debug(DBG_ENABLE_MASK_ERR, "failed to allocate IPv4 session index table!\n");
			return PPA_FAILURE;
		}
		mpe_hal_set_session_index(0, (g_GenConf->fw_sess_tbl_num[0] - 1));
		mpe_hal_set_session_index(0, g_GenConf->fw_sess_tbl_num[0]);
	}


	/* Compare Table for IPv6 session */
	g_GenConf->fw_sess_tbl_type[1] = 2; /*IPv6 table */
	g_GenConf->fw_sess_tbl_num[1] = MAX_HW_SESSION_NUM;
	g_GenConf->fw_sess_tbl_iterate[1] = MAX_SEARCH_ITRN;
	g_GenConf->fw_cmp_tbl_base[1] = (uint32_t)kmalloc(g_GenConf->fw_sess_tbl_num[1]* sizeof(struct fw_compare_hash_auto_ipv6), GFP_DMA);
	if (!g_GenConf->fw_cmp_tbl_base[1]) {
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Failed to allocate memory for IPv6 compare table\n");
		return PPA_FAILURE;
	} else {
		memset((void *)g_GenConf->fw_cmp_tbl_base[1], 0, g_GenConf->fw_sess_tbl_num[1]* sizeof(struct fw_compare_hash_auto_ipv6));
		for(i = 0; i < g_GenConf->fw_sess_tbl_num[1]; i++ ) {
			if(i < g_GenConf->fw_sess_tbl_num[1] -1)
				((struct fw_compare_hash_auto_ipv6 *)(g_GenConf->fw_cmp_tbl_base[1] + (i * sizeof(struct fw_compare_hash_auto_ipv6))))->valid=0;
			else
				((struct fw_compare_hash_auto_ipv6 *)(g_GenConf->fw_cmp_tbl_base[1] + (i * sizeof(struct fw_compare_hash_auto_ipv6))))->valid=1;
			((struct fw_compare_hash_auto_ipv6 *)(g_GenConf->fw_cmp_tbl_base[1] + (i * sizeof(struct fw_compare_hash_auto_ipv6))))->nxt_ptr= g_GenConf->fw_sess_tbl_num[1] - 1;
			((struct fw_compare_hash_auto_ipv6 *)(g_GenConf->fw_cmp_tbl_base[1] + (i * sizeof(struct fw_compare_hash_auto_ipv6))))->first_ptr= g_GenConf->fw_sess_tbl_num[1] - 1;
			((struct fw_compare_hash_auto_ipv6 *)(g_GenConf->fw_cmp_tbl_base[1] + (i * sizeof(struct fw_compare_hash_auto_ipv6))))->act=0;
		}
		g_session_idx_table[1].size = (MAX_HW_SESSION_NUM >> IDX_MAP_SHIFT);
		g_session_idx_table[1].base = (uint32_t *)kzalloc((g_session_idx_table[1].size * sizeof(uint32_t)), GFP_KERNEL);
		if (!g_session_idx_table[1].base) {
			ppa_debug(DBG_ENABLE_MASK_ERR, "failed to allocate IPv6 session index table!\n");
			return PPA_FAILURE;
		}
		mpe_hal_set_session_index(1, (g_GenConf->fw_sess_tbl_num[1] - 1));
	}

	/* Complementary table */
	g_GenConf->hw_act_num = MAX_HW_SESSION_NUM;
	g_GenConf->hw_act_tbl_base = (uint32_t)kmalloc(g_GenConf->hw_act_num * sizeof(struct hw_act_ptr), GFP_DMA);
	if (!g_GenConf->hw_act_tbl_base) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate memory for hardware complementary table\n");
		return PPA_FAILURE;
	}
	memset((void *)g_GenConf->hw_act_tbl_base, 0 , g_GenConf->hw_act_num * sizeof(struct hw_act_ptr));

	/* Multicast VAP table base */
	for(i=0; i<MAX_PMAC_PORT; i++ ) {
		/* Fixed Port 0: CPU 1-6: LAN Port 15: WAN Port
			 Port 7-14 are dynamic ports */
		if(i == 0 || i == 15)
			g_GenConf->mc_vap_num[i] = 0 ; /* No Multicast VAP support for this PMAC port*/
		else {
			g_GenConf->mc_vap_num[i] = MAX_MC_NUM;
			g_GenConf->mc_vap_tbl_base[i] = (uint32_t)kmalloc(g_GenConf->mc_vap_num[i] * sizeof(struct vap_entry), GFP_DMA);
			if (!g_GenConf->mc_vap_tbl_base[i]) {
				ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate memory for Multicast VAP table for PMAC port\n");
				return PPA_FAILURE;
			}
			memset((void *)g_GenConf->mc_vap_tbl_base[i], 0 , (g_GenConf->mc_vap_num[i] * sizeof(struct vap_entry)));
		}
	}

	/** Session Based Hit and MIB counters allocation */
	for(i=0; i< MAX_CMP_TABLE_SUPPORTED; i++) {
		for(j=0; j< MAX_WORKER_NUM; j++) {
			g_GenConf->fw_sess_hit_tbl_base[i][j] = (uint32_t ) kmalloc((g_GenConf->fw_sess_tbl_num[i] * sizeof(uint8_t)), GFP_DMA);
			if (!g_GenConf->fw_sess_hit_tbl_base[i][j]) {
				ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate memory for Session HIT table for CMP table index %d and Worker %d\n",i,j);
				return PPA_FAILURE;
			}
			memset((void *)g_GenConf->fw_sess_hit_tbl_base[i][j], 0, (g_GenConf->fw_sess_tbl_num[i] * sizeof(uint8_t)));
		}
	}

	for(i=0; i< MAX_CMP_TABLE_SUPPORTED; i++) {
		for(j=0; j< MAX_WORKER_NUM; j++) {
			g_GenConf->fw_sess_mib_tbl_base[i][j] = (uint32_t )kmalloc((g_GenConf->fw_sess_tbl_num[i] * sizeof(struct session_mib)), GFP_DMA);
			if (!g_GenConf->fw_sess_mib_tbl_base[i][j]) {
				ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate memory for Session MIB table for CMP table index %d and Worker %d\n",i,j);
				return PPA_FAILURE;
			}
			memset((void *)g_GenConf->fw_sess_mib_tbl_base[i][j], 0, (g_GenConf->fw_sess_tbl_num[i] * sizeof(struct session_mib)));
		}
	}

	/** MIB interface table base address per Worker TC	*/
	for(i=0; i< MAX_WORKER_NUM; i++) {
		g_GenConf->mib_itf_tbl_base[i] = (uint32_t )kmalloc((g_GenConf->mib_itf_num * sizeof(struct mpe_itf_mib)), GFP_DMA);
		if (!g_GenConf->mib_itf_tbl_base[i]) {
			ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate memory for Session MIB table for Worker %d\n",i);
			return PPA_FAILURE;
		}
		memset((void *)g_GenConf->mib_itf_tbl_base[i], 0, g_GenConf->mib_itf_num * sizeof(struct mpe_itf_mib));
	}

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	/** IPSEC Inbound MIB table base address per Worker TC	*/
	for(i=0; i< MAX_WORKER_NUM; i++) {
		g_GenConf->mib_e97_dec_base[i] = (uint32_t )kmalloc((IPSEC_TUN_MAX * sizeof(struct mib_info)), GFP_DMA);
		if (!g_GenConf->mib_e97_dec_base[i]) {
			ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate memory for IPSEC Inbound Session MIB table for Worker %d\n",i);
			return PPA_FAILURE;
		}
		memset((void *)g_GenConf->mib_e97_dec_base[i], 0, IPSEC_TUN_MAX * sizeof(struct mib_info));
	}
#endif
	g_HAL_State = MPE_HAL_FW_RESOURCE_ALLOC;
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"MPE HAL Allocate FW Data Success.\n");

	return PPA_SUCCESS;

}

static int32_t mpe_hal_free_fw_table(void)
{
	int32_t i=0, j=0;
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> ---> Enter <-----.\n",__FUNCTION__);

	if(g_Dispatch_buffer)
		kfree(g_Dispatch_buffer);

	if(g_Dl_dispatch_buffer)
		kfree(g_Dl_dispatch_buffer);

	for(i=0; i< MAX_CMP_TABLE_SUPPORTED; i++) {
		if (g_session_idx_table[i].base)
			kfree(g_session_idx_table[i].base);

		if(g_GenConf->fw_cmp_tbl_base[i] != 0)
			g_GenConf->fw_cmp_tbl_base[i] = 0;
	}
	if(g_GenConf->hw_act_tbl_base)
		g_GenConf->hw_act_tbl_base = 0;

	for(i=0; i<MAX_PMAC_PORT; i++ ) {
		if(i > 0 && i < 15)
			g_GenConf->mc_vap_tbl_base[i] = 0;
	}

	for(i=0; i< MAX_CMP_TABLE_SUPPORTED; i++) {
		for(j=0; j< MAX_WORKER_NUM; j++) {
			if (g_GenConf->fw_sess_hit_tbl_base[i][j])
				g_GenConf->fw_sess_hit_tbl_base[i][j] = 0;
		}
	}
	for(i=0; i< MAX_CMP_TABLE_SUPPORTED; i++) {
		for(j=0; j< MAX_WORKER_NUM; j++) {
			if (g_GenConf->fw_sess_mib_tbl_base[i][j])
				g_GenConf->fw_sess_mib_tbl_base[i][j] = 0;
		}
	}
	for(i=0; i< MAX_WORKER_NUM; i++) {
		if (g_GenConf->mib_itf_tbl_base[i])
			g_GenConf->mib_itf_tbl_base[i] = 0;
	}
	g_HAL_State = MPE_HAL_FW_LOADED;
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> ---> Exit <-----.\n",__FUNCTION__);

	return PPA_SUCCESS;
}

static int mpe_hal_get_MpeDebugRespRegIrq(uint8_t cpu)
{
	int32_t ret=0;
	struct device_node *np;
	struct resource irqres;
	char str1[50];
	uint32_t dbgirq = 0;
	memset(str1, '\0', sizeof(str1));
	sprintf(str1, "%s%d", "/ssx7@a0000000/mpe@", ret);
	//np = of_find_node_by_path("/ssx7@a0000000/mpe@0");
	np = of_find_node_by_path("/ssx7@a0000000/mpe@1000000");
	if (!np)
		return -ENODEV;
	ret = of_irq_to_resource_table(np, &irqres, 1);
	if (ret != 1) {
		pr_info("failed to get irq for mpe dbg since ret = %d\n", ret);
		pr_info("irqres.start = %d\n", irqres.start);
		return -ENODEV;
	}
	dbgirq = irqres.start;
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"MpeDebugRespRegIrq : %d\n",dbgirq);

	return dbgirq;
}

static int mpe_hal_run_fw(uint8_t ucCpu, uint8_t ucNum_worker)
{
	int32_t ret = PPA_SUCCESS;
	uint8_t tc_num;
	int8_t ucCpuNum = -1;
	uint32_t i=0, j;
	uint32_t status = 0;
	int pages;
	u32 phy_addr ;
	int err = 0;

	struct CPU_launch_t c_lunch;
	struct TC_launch_t *tc_launch=NULL;

	/* Get the CPU number from VMB */
	ucCpuNum = vmb_cpu_alloc(ucCpu, "MPEFW");
	if( (ucCpuNum == -VMB_EBUSY) || (ucCpuNum == -VMB_EAVAIL) ) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"EBUSY !!!!\n");
		ucCpuNum = vmb_cpu_alloc(MAX_CPU, "MPEFW");
		if( (ucCpuNum == -VMB_EBUSY) || (ucCpuNum == -VMB_EAVAIL) ) {
			ppa_debug(DBG_ENABLE_MASK_ERR,"No CPU is free\n");
			ret = -VMB_EAVAIL;
			goto MPE_HAL_RUN_FW_FAILURE_HANDLER;
		}
	}
	g_MPELaunch_CPU = ucCpuNum;

	/*	Find the free hw resource(6-7) for the TC */
	for (j=MAX_WORKER_NUM; j< (MAX_WORKER_NUM+1); j++) {
		if(g_GenConf->hw_res[j].flag == 0) {
			break;
		}
	}

	g_GenConf->ddr_address = 0x20000000;
	g_GenConf->vmb_fw_msg_base[ucCpuNum]= (uint32_t ) VMB_get_msg_addr(ucCpuNum,0);
	g_GenConf->fw_vmb_msg_base[ucCpuNum]= (uint32_t ) VMB_get_msg_addr(ucCpuNum,1);
	g_GenConf->g_mpe_dbg_enable = 0;
	g_GenConf->cbm_buffer_req_port = 0;


	g_VpeInfo.vpe[j-MAX_WORKER_NUM].ucState = 1;
	g_VpeInfo.vpe[j-MAX_WORKER_NUM].ucActualVpeNo = ucCpuNum;
	tc_num = get_tm_from_vpe(ucCpuNum);
	g_GenConf->e97_mpe_en =0;
	g_GenConf->e97_init_flag = 1;

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	for(i=0; i<MAX_RING;i++) {
		ring_id_pool[i] = -1;
	}
	ring_id_pool[0] = 0; /*used by Linux*/
	ring_id_pool[1] = 1; /*used by Linux*/
	mpe_hal_alloc_cdr_rdr();
	g_GenConf->e97_mpe_en =1;
	g_GenConf->e97_init_flag = 1;
#endif
	/* Allocate a TC bound to a particular CPU */
	logic_tc_mapping[j] = tc_num;
	mpe_hal_update_tc_hw_info(ucCpuNum, tc_num, TYPE_TM, &g_GenConf->hw_res[j]);

	/*	Prepare the c_lunch */
	memset(&c_lunch, 0, sizeof(struct CPU_launch_t));

#ifndef FIRMWARE_REQUEST
	if( (mpe_fw_len % TLB_PAGE_SIZE) != 0)
		pages = (mpe_fw_len / TLB_PAGE_SIZE) + 1;
	else
		pages = (mpe_fw_len / TLB_PAGE_SIZE) ;
#else
	if( (gImage_size % TLB_PAGE_SIZE) != 0)
		pages = (gImage_size / TLB_PAGE_SIZE) + 1;
	else
		pages = (gImage_size / TLB_PAGE_SIZE) ;
#endif
	phy_addr = VIR_TO_PHY((uint32_t)g_MpeFw_load_addr);

	g_GenConf->buffer_free_tbl_base = (uint32_t)g_Dispatch_buffer;
	g_GenConf->max_tm_deq_pkt_num = 1;
	g_GenConf->dispatch_q_buf_num = 10;
	g_GenConf->pmac_len_for_csum_offload = 8;

	err = request_irq(mpe_hal_get_MpeDebugRespRegIrq(ucCpuNum) , (irq_handler_t)print_content, 0x0, "mpe_dbg", NULL);
	if (err)
		ppa_debug(DBG_ENABLE_MASK_ERR, "request_irq for IRQ mpe_dbg = %d failed !!! \n", mpe_hal_get_MpeDebugRespRegIrq(ucCpuNum));

	c_lunch.start_addr = CKSEG1ADDR((unsigned long)g_MpeFw_load_addr);

	c_lunch.sp = (uint32_t)(g_MpeFw_stack_addr + (g_GenConf->fw_hdr.fw_stack_priv_data_size * (j+1)));

	c_lunch.a0 =(uint32_t) &tlb_info;
	c_lunch.priv_info = j; /*only the hw_res index has to be passed*/

	tc_launch = (struct TC_launch_t *) kmalloc(ucNum_worker * sizeof(struct TC_launch_t), GFP_KERNEL);
	if (tc_launch == NULL) {
		free_irq(mpe_hal_get_MpeDebugRespRegIrq(ucCpuNum), NULL);
		ret = -VMB_EAVAIL;
		goto MPE_HAL_RUN_FW_FAILURE_HANDLER;
	}
	/* Find a free worker TC (0-5). For all the ucNum_worker worker TC's*/
	for (i=0; i< ucNum_worker; i++) {
		tc_num = vmb_tc_alloc(ucCpuNum);

		if(tc_num == -VMB_ERROR){
			ppa_debug(DBG_ENABLE_MASK_ERR,"Failed to allocate TC for the CPU %d\n", ucCpu );
			ret = VMB_EAVAIL;
			goto MPE_HAL_RUN_FW_FAILURE_HANDLER;
		}else {
			logic_tc_mapping[i] = tc_num;
			mpe_hal_update_tc_hw_info(ucCpuNum, tc_num, TYPE_WORKER, &g_GenConf->hw_res[i]);
			mpe_hal_prepare_tc_launch(tc_num, TYPE_WORKER, &g_GenConf->hw_res[i], &tc_launch[i]);
		}
	}

	/* Register the callback handler to VMB */
	vmb_register_callback(ucCpuNum, (void *)mpe_hal_to_vmb_callback_hdlr(status));

	ppa_memcpy((void *)c_lunch.start_addr, g_MpeFw_load_addr, (pages * TLB_PAGE_SIZE));

	/* Start the CPU*/
	pr_info("Starting cpu\n");
	ret = vmb_cpu_start(ucCpuNum, c_lunch, tc_launch, ucNum_worker, 0);

	if(ret == VMB_SUCCESS) {
		for(i=0;i < MAX_MPE_TC_NUM;i++) {
			if(!g_GenConf->hw_res[i].flag)
				continue;
			if(g_GenConf->hw_res[i].state != STATE_IN_PROGRESS) {
				pr_err("TC_%d is not in running state yet\n", i);
			}
		}
		mpe_hal_set_fw_connectivity(0);
		dp_set_gsw_parser(3,2,2,0,0);
		g_HAL_State = MPE_HAL_FW_RUNNING;
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"MPE HAL Run FW success .\n");
		kfree(tc_launch);
		return PPA_SUCCESS;
	}

MPE_HAL_RUN_FW_FAILURE_HANDLER:
	if(ret == -VMB_EAVAIL)	{
		ppa_debug(DBG_ENABLE_MASK_ERR,"CPU is not available.!!!\n");
		if(ucCpuNum >=0)
			vmb_cpu_free(ucCpuNum);
	}
	if((ret == -VMB_ETIMEOUT) ||(ret == -VMB_ENACK)) {
		int j;
		ppa_debug(DBG_ENABLE_MASK_ERR,"CPU Start is failing.!!!\n");
		vmb_tc_free(ucCpuNum, -1);
		vmb_cpu_free(ucCpuNum);

		/* For all the ucNum_worker worker TC's*/
		for (j=0; j< MAX_MPE_TC_NUM; j++) {
			logic_tc_mapping[j] = 0;
			g_GenConf->hw_res[j].flag = 0;
			g_GenConf->hw_res[j].state = STATE_INACTIVE;
		}
		ppa_debug(DBG_ENABLE_MASK_ERR,"Start VMB CPU Failure !!!\n");
		ppa_debug(DBG_ENABLE_MASK_ERR,"eva_cfg_pa = %x eva_cfg_va=%x\n", g_GenConf->eva_cfg_pa, g_GenConf->eva_cfg_va);
		free_irq(mpe_hal_get_MpeDebugRespRegIrq(ucCpuNum), NULL);
	}
	kfree(tc_launch);
	return PPA_FAILURE;
}

static int mpe_hal_stop_fw(uint8_t ucCpu)
{
	uint32_t j;
	/*	Free all the hardware resources which are assiciated to this CPU */
	for (j=0; j< MAX_MPE_TC_NUM; j++) {
		g_GenConf->hw_res[j].flag = 0; /* Free this hardware resource*/
		g_GenConf->hw_res[j].state = STATE_INACTIVE;
		logic_tc_mapping[j] = 0;
		if((g_GenConf->hw_res[j].CpuNum == ucCpu) && (g_GenConf->hw_res[j].tcType == TYPE_WORKER)) {
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> Delete CPU->TC %d->%d\n",__FUNCTION__,ucCpu, g_GenConf->hw_res[j].TcNum);
			mpe_hal_free_yield(ucCpu, 1);
			vmb_tc_stop(ucCpu, g_GenConf->hw_res[j].TcNum);
		} else	if((g_GenConf->hw_res[j].CpuNum == ucCpu) && (g_GenConf->hw_res[j].tcType == TYPE_TM)) {
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Stopping the TM !!!\n");
			vmb_cpu_stop(ucCpu);
			mpe_hal_free_semid(g_GenConf->hw_res[j].disp_q_semid);
			mpe_hal_free_semid(g_GenConf->hw_res[j].free_list_semid);
			mpe_hal_free_semid(g_GenConf->hw_res[j].cbm_alloc_semid);
			mpe_hal_free_semid(g_GenConf->hw_res[j].dispatch_q_cnt_semid);
		}
	}
	for (j=0; j< MAX_VPE_NUM; j++) {
		if(g_VpeInfo.vpe[j].ucActualVpeNo == ucCpu) {
			g_VpeInfo.vpe[j].ucState = 0;
		}
	}
	free_irq(mpe_hal_get_MpeDebugRespRegIrq(ucCpu), NULL);
	mpe_hal_remove_fw_connectivity();
	dp_set_gsw_parser(3,0,0,0,0);
	g_HAL_State = MPE_HAL_FW_RESOURCE_ALLOC;
	return PPA_SUCCESS;
}

static int32_t mpe_hal_deregister_caps(void)
{
	ppa_drv_deregister_cap(SESS_IPV4,MPE_HAL);
	ppa_drv_deregister_cap(SESS_IPV6,MPE_HAL);
	ppa_drv_deregister_cap(TUNNEL_6RD, MPE_HAL);
	ppa_drv_deregister_cap(TUNNEL_DSLITE, MPE_HAL);
	ppa_drv_deregister_cap(TUNNEL_L2TP_US,MPE_HAL);
	ppa_drv_deregister_cap(TUNNEL_L2TP_DS, MPE_HAL);
	ppa_drv_deregister_cap(TUNNEL_GRE_US,MPE_HAL);
	ppa_drv_deregister_cap(TUNNEL_GRE_DS, MPE_HAL);
	ppa_drv_deregister_cap(SESS_MC_DS, MPE_HAL);
	ppa_drv_deregister_cap(SESS_MC_DS_VAP,MPE_HAL);

#if IS_ENABLED(CONFIG_PPA_NAT_LOOP_BACK)
        ppa_drv_deregister_cap(SESS_NAT_LOOPBACK,MPE_HAL);
#endif

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	ppa_drv_deregister_cap(TUNNEL_IPSEC_US,MPE_HAL);
	ppa_drv_deregister_cap(TUNNEL_IPSEC_DS,MPE_HAL);
	ppa_drv_deregister_cap(TUNNEL_IPSEC_MIB,MPE_HAL);
#endif
#if IS_ENABLED(CONFIG_INTEL_IPQOS_MPE_DS_ACCEL)
        ppa_drv_deregister_cap(MPE_DS_QOS,MPE_HAL);
#endif

	return PPA_SUCCESS;
}

static void mpe_register_hal(void)
{
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Register MPE HAL to PPA.\n");
	ppa_drv_generic_hal_register(MPE_HAL, mpe_hal_generic_hook);
}

static int mpe_xrx500_probe(struct platform_device *pdev)
{
	g_Mpedev = &(pdev->dev);
	return 0;
}

static int	mpe_xrx500_release(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id mpe_xrx500_match[] = {
	{ .compatible = "lantiq,mpe-xrx500" },
	{},
};

static struct platform_driver mpe_xrx500_driver = {
	.probe = mpe_xrx500_probe,
	.remove = mpe_xrx500_release,
	.driver = {
		.name = "mpe-xrx500",
		.owner = THIS_MODULE,
		.of_match_table = mpe_xrx500_match,
	},
};

static int32_t hal_init(void)
{
	int32_t ret;

	platform_driver_register(&mpe_xrx500_driver);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"MPE HAL FW State : %d\n",g_HAL_State);

	if(g_HAL_State < MPE_HAL_FW_LOADED)
		goto LOAD_FW;
	else if (g_HAL_State < MPE_HAL_FW_RESOURCE_ALLOC)
		goto ALLOCATE_FW_DATA;
	else if (g_HAL_State < MPE_HAL_FW_RUNNING)
		goto RUN_FW;

LOAD_FW:
#ifndef NO_FW_HDR
	if(mpe_hal_read_fw_hdr() == PPA_FAILURE) {
		pr_err("File not found.\n");
		ret = PPA_FAILURE;
		goto CLEANUP;
	}
#endif
	if(mpe_hal_load_fw( MPE_FILE_PATH) == PPA_FAILURE) {
		pr_err("Insufficient memory for MPE FW.\n");
		ret = PPA_FAILURE;
		goto CLEANUP;
	}
ALLOCATE_FW_DATA:
	if(mpe_hal_allocate_fw_table() == PPA_FAILURE) {
		pr_err("Insufficient memory for MPE FW tables allocation\n");
		ret = PPA_FAILURE;
		goto CLEANUP;
	}
RUN_FW:
#ifndef NO_FW_HDR
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"Min TC:%d Max TC:%d\n",g_MpeFwHdr.worker_info.min_tc_num, g_MpeFwHdr.worker_info.max_tc_num);
	if (mpe_hal_run_fw(MAX_CPU, (uint8_t)g_ucNum_worker) == PPA_FAILURE)
#else
	if(mpe_hal_run_fw( MAX_CPU, 0) == PPA_FAILURE)
#endif
	{
		ppa_debug(DBG_ENABLE_MASK_ERR, "Cannot run MPE FW.\n");
		ret = PPA_FAILURE;
		goto CLEANUP;
	}
	mpe_register_hal();
	return 0;

CLEANUP:
	platform_driver_unregister(&mpe_xrx500_driver);

	return ret;
}

int32_t mpe_hal_fw_load(void)
{
	hal_init();
	return 0;
}

static int __init mpe_hal_init(void)
{
	on_each_cpu(itc_init, NULL, 1);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"MPE FW Init.\n");
	if(hal_init() == PPA_FAILURE) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"HAL Init Failed !!!!!\n");
		return PPA_FAILURE;
	}
	mpe_hal_set_checksum_queue_map_hook_fn = mpe_hal_set_checksum_queue_map;
	mpe_hal_debugfs_create();

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	mpe_hal_set_ipsec_loopback_connectivity();
#endif

#ifdef MPE_HAL_TEST
	int32_t tc;
	tc = mpe_hal_add_tc(g_MPELaunch_CPU, TYPE_WORKER);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> Added TC %d\n",__FUNCTION__,tc);
	mpe_hal_delete_tc(g_MPELaunch_CPU, tc);
#endif
	init_class_mgmt();
	init_pae_flows();
	ppa_mpe_session_list_lock_init();
	return 0;
}

static int32_t hal_uninit(void)
{
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> Unregister platform driver \n",__FUNCTION__);
	platform_driver_unregister(&mpe_xrx500_driver);
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"<%s> Deregister HAL driver \n",__FUNCTION__);
	ppa_drv_generic_hal_deregister(MPE_HAL);

	return 0;
}

int32_t mpe_hal_fw_unload(void)
{

	mpe_hal_free_fw_table();
	mpe_hal_stop_fw(g_MPELaunch_CPU);
#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	mpe_hal_free_cdr_rdr();
	mpe_hal_remove_ipsec_loopback_connectivity();
#endif
	hal_uninit();
	kfree(g_MpeFw_stack_addr);
	kfree(g_MpeFw_load_addr);

	g_HAL_State = MPE_HAL_FW_NOT_LOADED;
	return PPA_SUCCESS;
}

static void __exit mpe_hal_exit(void)
{
	uninit_pae_flows();
	uninit_class_mgmt();
	mpe_hal_set_checksum_queue_map_hook_fn = NULL;
	mpe_hal_remove_mpe_netdev();
	hal_uninit();
	mpe_hal_debugfs_destroy();
	ppa_mpe_session_list_lock_destroy();
}

typedef enum {
	SHIFT_RIGHT=0,
	SHIFT_LEFT
} shift_direction_t;

const static struct pce_cat_conf g_gswr_cat_conf[] = {
							{ 1, 0},
							{ GSWR_CAT_FILTER_MAX, GSWR_CAT_FILTER_START } ,
							{ GSWR_CAT_INGQOS_MAX, GSWR_CAT_INGQOS_START } ,
							{ GSWR_CAT_VLAN_MAX, GSWR_CAT_VLAN_START },
							{ GSWR_CAT_FWD_MAX, GSWR_CAT_FWD_START},
							{ GSWR_CAT_USQOS_MAX, GSWR_CAT_USQOS_START },
							{ GSWR_CAT_DSQOS_MAX, GSWR_CAT_DSQOS_START },
							{ GSWR_CAT_MGMT_MAX, GSWR_CAT_MGMT_START },
							{ GSWR_CAT_LRO_MAX, GSWR_CAT_LRO_START },
							{ GSWR_CAT_TUN_MAX, GSWR_CAT_TUN_START }
							};

static struct switch_dev_class class_dev[1]={{0}};
spinlock_t	g_class_lock;
static uint16_t g_pce_rtrule_next = 1;

int32_t pae_hal_add_class_rule(PPA_CLASS_RULE*);
int32_t pae_hal_del_class_rule(PPA_CLASS_RULE*);
int32_t pae_hal_get_class_rule(PPA_CLASS_RULE*);
int32_t pae_hal_mod_class_rule(PPA_CLASS_RULE*);

static int32_t init_pae_flows(void)
{
	PPA_CLASS_RULE rule;
	int ret = 0;
	const char *end;

#if IS_ENABLED(CONFIG_CBM_LS_ENABLE) && CONFIG_CBM_LS_ENABLE
	/* pce rule for tcp load spreader*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));
	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_MGMT;

	rule.pattern.bEnable = 1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_TCP;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_TCP);

	rule.pattern.bPortIdEnable = 1;
	rule.pattern.nPortId = 0;
	rule.pattern.bPortId_Exclude = 1;

	rule.action.qos_action.flowid_enabled = 1;
	rule.action.qos_action.flowid = 0x40;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}
#endif
	/* port 0 exclude*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_MGMT;

	rule.pattern.bEnable = 1;
	rule.pattern.bPortIdEnable = 1;
	rule.pattern.nPortId = 0;

	rule.action.fwd_action.rtaccelenable = 0;
	rule.action.fwd_action.rtctrlenable = 1;

	rule.action.fwd_action.processpath = 4; /* CPU	*/

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_CPU_ING_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
	ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
	return PPA_FAILURE;
	}

	/* tcp unicast*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_FWD;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_TCP;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_IP_FRAGMT | PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IPV4_OPTNS |
					PCE_PARSER_MSB_TCP | PCE_PARSER_MSB_RT_EXCEP |	PCE_PARSER_MSB_INNR_IPV6 | PCE_PARSER_MSB_INNR_IPV4);

	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB_Mask = ~(PCE_PARSER_LSB_GRE | PCE_PARSER_LSB_CAPWAP);

	rule.action.fwd_action.rtdestportmaskcmp = 1;
	rule.action.fwd_action.rtsrcportmaskcmp = 1;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_TCP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1	*/

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_TCP_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
	ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
	return PPA_FAILURE;
	}

	/* multicast v4 */
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_FWD;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_UDP_HDR_AFTR_FST_IP_HDR;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_IP_FRAGMT | PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IPV4_OPTNS |
					PCE_PARSER_MSB_UDP_HDR_AFTR_FST_IP_HDR | PCE_PARSER_MSB_RT_EXCEP | PCE_PARSER_MSB_INNR_IPV6 | PCE_PARSER_MSB_INNR_IPV4);

	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB = PCE_PARSER_LSB_OUTR_IPV4;
	rule.pattern.nParserFlagLSB_Mask = (uint16_t)(~(PCE_PARSER_LSB_OUTR_IPV4 | PCE_PARSER_LSB_GRE | PCE_PARSER_LSB_CAPWAP | PCE_PARSER_LSB_WOL));

	rule.pattern.eDstIP_Select = 1;
	rule.pattern.nDstIP.nIPv4 = in_aton("224.0.0.0");
	rule.pattern.nDstIP_Mask= PCE_IPV4_MCAST_MASK;	 /* 8 bit mask for ipv4 each bit used to mask a nibble*/

	rule.action.fwd_action.rtdestportmaskcmp = 0;
	rule.action.fwd_action.rtsrcportmaskcmp = 0;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_UDP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1 */

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_MCAST_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
	ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
	return PPA_FAILURE;
	}

	/*multicast v6*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_FWD;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_UDP_HDR_AFTR_FST_IP_HDR | PCE_PARSER_MSB_OUTR_IPV6;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_IP_FRAGMT | PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IPV4_OPTNS |
				PCE_PARSER_MSB_UDP_HDR_AFTR_FST_IP_HDR | PCE_PARSER_MSB_RT_EXCEP | PCE_PARSER_MSB_INNR_IPV6 |
				PCE_PARSER_MSB_INNR_IPV4 | PCE_PARSER_MSB_OUTR_IPV6);

	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB = 0x0000;
	rule.pattern.nParserFlagLSB_Mask = ~( PCE_PARSER_LSB_GRE | PCE_PARSER_LSB_CAPWAP | PCE_PARSER_LSB_WOL);

	rule.pattern.eDstIP_Select = 2;
	in6_pton("ff00:0:0:0:0:0:0:0",INET6_ADDRSTRLEN,(void*)&rule.pattern.nDstIP.nIPv6,-1,&end);
	rule.pattern.nDstIP_Mask= PCE_IPV6_MCAST_MASK;	/*32 bit mask for 128 bit ipv6 address one bit per nibble*/

	rule.action.fwd_action.rtdestportmaskcmp = 0;
	rule.action.fwd_action.rtsrcportmaskcmp = 0;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_UDP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1 */

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_MCAST_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
	ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
	return PPA_FAILURE;
	}

	/* udp unicast v4*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_FWD;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_UDP_HDR_AFTR_FST_IP_HDR;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_IP_FRAGMT | PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IPV4_OPTNS |
				PCE_PARSER_MSB_UDP_HDR_AFTR_FST_IP_HDR | PCE_PARSER_MSB_RT_EXCEP |	PCE_PARSER_MSB_INNR_IPV6 | PCE_PARSER_MSB_INNR_IPV4);

	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB = PCE_PARSER_LSB_OUTR_IPV4;
	rule.pattern.nParserFlagLSB_Mask = (uint16_t)(~(PCE_PARSER_LSB_OUTR_IPV4 | PCE_PARSER_LSB_GRE | PCE_PARSER_LSB_CAPWAP | PCE_PARSER_LSB_WOL));

	rule.pattern.eDstIP_Select = 1;
	rule.pattern.nDstIP.nIPv4 = in_aton("224.0.0.0");
	rule.pattern.nDstIP_Mask= PCE_IPV4_MCAST_MASK;	 /* 8 bit mask for ipv4 each bit used to mask a nibble*/
	rule.pattern.bDstIP_Exclude= 1;

	rule.action.fwd_action.rtdestportmaskcmp = 1;
	rule.action.fwd_action.rtsrcportmaskcmp = 1;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_UDP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1	*/

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_UDP_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
	ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
	return PPA_FAILURE;
	}

	/* udp unicast v6 */
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_FWD;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_UDP_HDR_AFTR_FST_IP_HDR | PCE_PARSER_MSB_OUTR_IPV6;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_IP_FRAGMT | PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IPV4_OPTNS |
					PCE_PARSER_MSB_UDP_HDR_AFTR_FST_IP_HDR | PCE_PARSER_MSB_RT_EXCEP |	PCE_PARSER_MSB_INNR_IPV6 |
					PCE_PARSER_MSB_INNR_IPV4 | PCE_PARSER_MSB_OUTR_IPV6);
	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB = 0x0000;
	rule.pattern.nParserFlagLSB_Mask = ~( PCE_PARSER_LSB_GRE | PCE_PARSER_LSB_CAPWAP | PCE_PARSER_LSB_WOL);

	rule.action.fwd_action.rtdestportmaskcmp = 1;
	rule.action.fwd_action.rtsrcportmaskcmp = 1;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_UDP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1 */

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_UDP_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}

	/* 6rd Downstream TCP*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_TCP | PCE_PARSER_MSB_INNR_IPV6;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_INNR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IP_FRAGMT |
					PCE_PARSER_MSB_IPV4_OPTNS | PCE_PARSER_MSB_TCP | PCE_PARSER_MSB_RT_EXCEP | PCE_PARSER_MSB_INNR_IPV6);
	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB = PCE_PARSER_LSB_OUTR_IPV4;
	rule.pattern.nParserFlagLSB_Mask = (uint16_t)(~(PCE_PARSER_LSB_GRE | PCE_PARSER_LSB_OUTR_IPV4));

	rule.action.fwd_action.rtdestportmaskcmp = 1;
	rule.action.fwd_action.rtsrcportmaskcmp = 1;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_TCP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;
	rule.action.fwd_action.rtinneripaskey = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1	*/

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_6RD_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}

	/* 6rd Downstream UDP Multicast*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR | PCE_PARSER_MSB_INNR_IPV6;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR | PCE_PARSER_MSB_INNR_IPV6_WITH_EXTN_HDR |
					PCE_PARSER_MSB_IP_FRAGMT | PCE_PARSER_MSB_IPV4_OPTNS | PCE_PARSER_MSB_RT_EXCEP | PCE_PARSER_MSB_INNR_IPV6);
	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB = PCE_PARSER_LSB_OUTR_IPV4;
	rule.pattern.nParserFlagLSB_Mask = (uint16_t)(~(PCE_PARSER_LSB_OUTR_IPV4 | PCE_PARSER_LSB_GRE | PCE_PARSER_LSB_CAPWAP));

	rule.pattern.eInnerDstIP_Select= 2;
	in6_pton("ff00:0:0:0:0:0:0:0",INET6_ADDRSTRLEN,(void*)&rule.pattern.nInnerDstIP.nIPv6,-1,&end);
	rule.pattern.nInnerDstIP_Mask= PCE_IPV6_MCAST_MASK;

	rule.action.fwd_action.rtdestportmaskcmp = 0;
	rule.action.fwd_action.rtsrcportmaskcmp = 0;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_UDP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;
	rule.action.fwd_action.rtinneripaskey = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1	*/

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_6RD_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}

	/* 6rd Downstream UDP*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_INNR_IPV6;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR | PCE_PARSER_MSB_INNR_IPV6_WITH_EXTN_HDR |
					PCE_PARSER_MSB_IP_FRAGMT | PCE_PARSER_MSB_IPV4_OPTNS | PCE_PARSER_MSB_RT_EXCEP | PCE_PARSER_MSB_INNR_IPV6);

	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB = PCE_PARSER_LSB_OUTR_IPV4;
	rule.pattern.nParserFlagLSB_Mask = (uint16_t)(~(PCE_PARSER_LSB_OUTR_IPV4 | PCE_PARSER_LSB_GRE | PCE_PARSER_LSB_CAPWAP));

	rule.action.fwd_action.rtdestportmaskcmp = 1;
	rule.action.fwd_action.rtsrcportmaskcmp = 1;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_UDP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;
	rule.action.fwd_action.rtinneripaskey = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1	*/

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_6RD_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}

	/* dslite Downstream TCP */
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_TCP | PCE_PARSER_MSB_INNR_IPV4 | PCE_PARSER_MSB_OUTR_IPV6;
	rule.pattern.nParserFlagMSB_Mask = ~( PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_INNR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IP_FRAGMT |
					PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IPV4_OPTNS | PCE_PARSER_MSB_TCP |
					PCE_PARSER_MSB_RT_EXCEP | PCE_PARSER_MSB_INNR_IPV4 | PCE_PARSER_MSB_OUTR_IPV6);

	rule.action.fwd_action.rtdestportmaskcmp = 1;
	rule.action.fwd_action.rtsrcportmaskcmp = 1;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_TCP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;
	rule.action.fwd_action.rtinneripaskey = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1	*/

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_DSLITE_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}

	/* dslite Downstream UDP Multicast*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR | PCE_PARSER_MSB_INNR_IPV4 | PCE_PARSER_MSB_OUTR_IPV6;
	rule.pattern.nParserFlagMSB_Mask = ~( PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR | PCE_PARSER_MSB_INNR_IPV6_WITH_EXTN_HDR |
					PCE_PARSER_MSB_IP_FRAGMT | PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_RT_EXCEP |
					PCE_PARSER_MSB_INNR_IPV4 | PCE_PARSER_MSB_OUTR_IPV6);

	rule.pattern.eInnerDstIP_Select= 1;
	rule.pattern.nInnerDstIP.nIPv4 = in_aton("224.0.0.0");
	rule.pattern.nInnerDstIP_Mask= PCE_IPV4_MCAST_MASK;

	rule.action.fwd_action.rtdestportmaskcmp = 0;
	rule.action.fwd_action.rtsrcportmaskcmp = 0;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_UDP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;
	rule.action.fwd_action.rtinneripaskey = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1	*/

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_DSLITE_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}

	/* dslite Downstream UDP*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_INNR_IPV4 | PCE_PARSER_MSB_OUTR_IPV6;
	rule.pattern.nParserFlagMSB_Mask = ~( PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR | PCE_PARSER_MSB_INNR_IPV6_WITH_EXTN_HDR |
					PCE_PARSER_MSB_IP_FRAGMT | PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_RT_EXCEP |
					PCE_PARSER_MSB_INNR_IPV4 | PCE_PARSER_MSB_OUTR_IPV6);

	rule.action.fwd_action.rtdestportmaskcmp = 1;
	rule.action.fwd_action.rtsrcportmaskcmp = 1;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_UDP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;
	rule.action.fwd_action.rtinneripaskey = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1 */

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_DSLITE_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}

	/* L2TP Downstream TCP */
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_TCP;
	rule.pattern.nParserFlagMSB_Mask = ~( PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_INNR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IP_FRAGMT |
					PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IPV4_OPTNS | PCE_PARSER_MSB_TCP |
					PCE_PARSER_MSB_RT_EXCEP);

	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB_Mask = ~(PCE_PARSER_LSB_GRE);

	rule.action.fwd_action.rtdestportmaskcmp = 1;
	rule.action.fwd_action.rtsrcportmaskcmp = 1;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_TCP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;
	rule.action.fwd_action.rtinneripaskey = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1	*/

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_L2TP_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}

	/* L2TP Downstream UDP Multicast inner ipv6*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR | PCE_PARSER_MSB_INNR_IPV6;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR | PCE_PARSER_MSB_INNR_IPV6_WITH_EXTN_HDR |
					PCE_PARSER_MSB_IP_FRAGMT | PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IPV4_OPTNS |
					PCE_PARSER_MSB_RT_EXCEP | PCE_PARSER_MSB_RT_EXCEP);

	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB_Mask = ~(PCE_PARSER_LSB_GRE | PCE_PARSER_LSB_CAPWAP);

	rule.pattern.eInnerDstIP_Select= 2;
	in6_pton("ff00:0:0:0:0:0:0:0",INET6_ADDRSTRLEN,(void*)&rule.pattern.nInnerDstIP.nIPv6,-1,&end);
	rule.pattern.nInnerDstIP_Mask= PCE_IPV6_MCAST_MASK;

	rule.action.fwd_action.rtdestportmaskcmp = 0;
	rule.action.fwd_action.rtsrcportmaskcmp = 0;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_UDP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;
	rule.action.fwd_action.rtinneripaskey = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1	*/

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_L2TP_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}

 	/* L2TP Downstream UDP Multicast inner ipv4*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR | PCE_PARSER_MSB_INNR_IPV4;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR | PCE_PARSER_MSB_IP_FRAGMT |
					PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IPV4_OPTNS | PCE_PARSER_MSB_RT_EXCEP |
					PCE_PARSER_MSB_INNR_IPV4);


	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB_Mask = ~(PCE_PARSER_LSB_GRE | PCE_PARSER_LSB_CAPWAP);

	rule.pattern.eInnerDstIP_Select= 1;
	rule.pattern.nInnerDstIP.nIPv4 = in_aton("224.0.0.0");
	rule.pattern.nInnerDstIP_Mask= PCE_IPV4_MCAST_MASK;

	rule.action.fwd_action.rtdestportmaskcmp = 0;
	rule.action.fwd_action.rtsrcportmaskcmp = 0;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_UDP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;
	rule.action.fwd_action.rtinneripaskey = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1 */

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_L2TP_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
	ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
	return PPA_FAILURE;
	}

	/* L2TP downstream UDP inner ipv6*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR | PCE_PARSER_MSB_INNR_IPV6;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR | PCE_PARSER_MSB_INNR_IPV6_WITH_EXTN_HDR |
					PCE_PARSER_MSB_IP_FRAGMT | PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IPV4_OPTNS |
					PCE_PARSER_MSB_RT_EXCEP | PCE_PARSER_MSB_RT_EXCEP);

	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB_Mask = ~(PCE_PARSER_LSB_GRE | PCE_PARSER_LSB_CAPWAP);

	rule.action.fwd_action.rtdestportmaskcmp = 1;
	rule.action.fwd_action.rtsrcportmaskcmp = 1;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_UDP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;
	rule.action.fwd_action.rtinneripaskey = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1 */

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_L2TP_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}

	/* L2TP downstream UDP inner ipv4*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR | PCE_PARSER_MSB_INNR_IPV4;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_L2TP_DATA | PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR | PCE_PARSER_MSB_IP_FRAGMT |
					PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IPV4_OPTNS | PCE_PARSER_MSB_RT_EXCEP |
					PCE_PARSER_MSB_INNR_IPV4);

	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB_Mask = ~(PCE_PARSER_LSB_GRE | PCE_PARSER_LSB_CAPWAP);

	rule.action.fwd_action.rtdestportmaskcmp = 1;
	rule.action.fwd_action.rtsrcportmaskcmp = 1;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_UDP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;
	rule.action.fwd_action.rtinneripaskey = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1 */

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_L2TP_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
	ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
	return PPA_FAILURE;
	}

	/* CAPWAP downstream traffic */
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB = PCE_PARSER_LSB_CAPWAP;
	rule.pattern.nParserFlagLSB_Mask = ~(PCE_PARSER_LSB_GRE | PCE_PARSER_LSB_CAPWAP);

	rule.action.fwd_action.portmap = 4;
	rule.action.fwd_action.forward_portmap = 0x2000;
	rule.action.fwd_action.rtaccelenable = 0;
	rule.action.fwd_action.rtctrlenable = 1;

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_CAPWAP_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add capwap rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}

	/* GRE traffic - TCP*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_TCP;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_IP_FRAGMT |
				PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IPV4_OPTNS |
				PCE_PARSER_MSB_RT_EXCEP | PCE_PARSER_MSB_TCP );

	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB = PCE_PARSER_LSB_GRE;
	rule.pattern.nParserFlagLSB_Mask = ~(PCE_PARSER_LSB_GRE);

	rule.action.fwd_action.rtinneripaskey = 1;

	rule.action.fwd_action.rtdestportmaskcmp = 1;
	rule.action.fwd_action.rtsrcportmaskcmp = 1;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_TCP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1 */

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_GRE_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add tcp gre rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}

	/* GRE Downstream Multicast*/
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_IP_FRAGMT |
				PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IPV4_OPTNS |
				PCE_PARSER_MSB_RT_EXCEP | PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR );

	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB = PCE_PARSER_LSB_GRE;
	rule.pattern.nParserFlagLSB_Mask = ~(PCE_PARSER_LSB_GRE|PCE_PARSER_LSB_CAPWAP);

	rule.pattern.eInnerDstIP_Select= 1;
	rule.pattern.nInnerDstIP.nIPv4 = in_aton("224.0.0.0");
	rule.pattern.nInnerDstIP_Mask= PCE_IPV4_MCAST_MASK;

	rule.action.fwd_action.rtinneripaskey = 1;

	rule.action.fwd_action.rtdestportmaskcmp = 0;
	rule.action.fwd_action.rtsrcportmaskcmp = 0;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_UDP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1 */

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_GRE_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add multicast gre rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}

	/* GRE traffic - UDP */
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB = PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_IP_FRAGMT |
				PCE_PARSER_MSB_OUTR_IPV6_WITH_EXTN_HDR | PCE_PARSER_MSB_IPV4_OPTNS |
				PCE_PARSER_MSB_RT_EXCEP | PCE_PARSER_MSB_UDP_HDR_AFTR_SEC_IP_HDR );

	rule.pattern.bParserFlagLSB_Enable = 1;
	rule.pattern.nParserFlagLSB = PCE_PARSER_LSB_GRE;
	rule.pattern.nParserFlagLSB_Mask = ~(PCE_PARSER_LSB_GRE|PCE_PARSER_LSB_CAPWAP);

	rule.action.fwd_action.rtinneripaskey = 1;

	rule.action.fwd_action.rtdestportmaskcmp = 1;
	rule.action.fwd_action.rtsrcportmaskcmp = 1;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;

	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_UDP;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.rtctrlenable = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1 */

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_GRE_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "add udp gre rule returned failure %d\n",ret);
		return PPA_FAILURE;
	}

	/* Send PON INGRESS Traffic for MPE Processing */
	ppa_memset(&rule, 0, sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_MGMT;

	rule.pattern.bEnable = 1;
	rule.pattern.bPortIdEnable = 1;
	rule.pattern.nPortId = 2; 				/* PON */

	rule.action.fwd_action.processpath = 1;	/* MPE */

	if (pae_hal_add_class_rule(&rule) != PPA_SUCCESS) {
	ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n", ret);
	return PPA_FAILURE;
	}

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	/* IPSec Downstream */
	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));

	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_TUN;

	rule.pattern.bEnable=1;
	rule.pattern.bProtocolEnable=1;
	rule.pattern.nProtocol = PCE_PROTO_ESP;
	rule.pattern.nProtocolMask =(u8) ~(0xFF);

	rule.pattern.bParserFlagMSB_Enable = 1;
	rule.pattern.nParserFlagMSB_Mask = ~(PCE_PARSER_MSB_IP_FRAGMT | PCE_PARSER_MSB_RT_EXCEP);

	rule.action.fwd_action.rtctrlenable = 1;
	rule.action.fwd_action.rtaccelenable = 1;
	rule.action.fwd_action.routextid_enable = 1;
	rule.action.fwd_action.routextid = RT_EXTID_IPSEC;
	rule.action.fwd_action.rtdstipmaskcmp = 1;
	rule.action.fwd_action.rtsrcipmaskcmp = 1;
	rule.action.fwd_action.rtdestportmaskcmp = 1;
	rule.action.fwd_action.rtsrcportmaskcmp = 1;

	rule.action.fwd_action.processpath = 1; /* MPE1	*/

	rule.action.rmon_action = 1;
	rule.action.rmon_id = RMON_IPSEC_CNTR;

	if(pae_hal_add_class_rule(&rule)!=PPA_SUCCESS) {
	ppa_debug(DBG_ENABLE_MASK_ERR, "add pce rule returned failure %d\n",ret);
	return PPA_FAILURE;
	}
#endif

	return PPA_SUCCESS;
}

static int32_t uninit_pae_flows(void)
{
	int i, ret=PPA_SUCCESS;
	PPA_CLASS_RULE rule;

	ppa_memset(&rule,0,sizeof(PPA_CLASS_RULE));
	rule.in_dev = GSWR_INGRESS;
	rule.category = CAT_MGMT;
	for(i=class_dev[GSWR_INGRESS].cat_map[CAT_MGMT].cat_last_ordr; i >= 0; i--) {
		rule.order = i+1;
		pae_hal_del_class_rule(&rule);
	}
	rule.category = CAT_FWD;
	for(i=class_dev[GSWR_INGRESS].cat_map[CAT_FWD].cat_last_ordr; i >= 0; i--) {
		rule.order = i+1;
		pae_hal_del_class_rule(&rule);
	}
	rule.category = CAT_TUN;
	for(i=class_dev[GSWR_INGRESS].cat_map[CAT_TUN].cat_last_ordr; i >= 0; i--) {
		rule.order = i+1;
		pae_hal_del_class_rule(&rule);
	}
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"PCE rule disable returned success\n");

	return ret;
}

static int32_t uninit_class_mgmt(void)
{
	int32_t ret= PPA_SUCCESS, i;

	spin_lock_bh(&g_class_lock );
	for(i=0; i< GSWR_PCE_MAX; i++) {
		if( class_dev[GSWR_INGRESS].cat_ordr_vect[i].usage_flg) {
		/* call the pae flow disable function in index*/
		}
	}

	ppa_free(class_dev[GSWR_INGRESS].cat_ordr_vect);
	ppa_free(class_dev[GSWR_INGRESS].pce_tbl_bitmap);

	for( i=0; i < CAT_MAX; i++) {
		ppa_free(class_dev[GSWR_INGRESS].cat_map[i].cat_idx_vect);
	}

	spin_unlock_bh(&g_class_lock );

	return ret;
}
static int32_t init_class_mgmt(void)
{
	int32_t ret= PPA_SUCCESS, i;

	spin_lock_init(&g_class_lock);

	ppa_memset(class_dev,0,sizeof(struct switch_dev_class));


	class_dev[GSWR_INGRESS].tot_max = GSWR_PCE_MAX;
	class_dev[GSWR_INGRESS].tot_used = 0;

	for( i=0; i < CAT_MAX; i++) {
		class_dev[GSWR_INGRESS].cat_map[i].cat_id = i;
		class_dev[GSWR_INGRESS].cat_map[i].cat_max = g_gswr_cat_conf[i].cat_max;
		class_dev[GSWR_INGRESS].cat_map[i].cat_start_idx = g_gswr_cat_conf[i].cat_start_idx;
		if(g_gswr_cat_conf[i].cat_max) {
			class_dev[GSWR_INGRESS].cat_map[i].cat_idx_vect = (cat_idx_map_t *) kmalloc ( sizeof(cat_idx_map_t) * g_gswr_cat_conf[i].cat_max, GFP_KERNEL);
			ppa_memset(class_dev[GSWR_INGRESS].cat_map[i].cat_idx_vect,0x0000FFFF,sizeof(cat_idx_map_t) * g_gswr_cat_conf[i].cat_max);
		}

		class_dev[GSWR_INGRESS].cat_map[i].cat_used = 0;
		class_dev[GSWR_INGRESS].cat_map[i].cat_last_ordr = -1;

	}

	/*Kamal hardcoded for the time being with subcat GSWR_CAT_FILTER under CAT_FILTER*/
	/*subcat setup PAE*/
	class_dev[GSWR_INGRESS].subcat_map[0].cat_id = CAT_NONE;
	class_dev[GSWR_INGRESS].subcat_map[0].subcat_id = SUBCAT_NONE;
	class_dev[GSWR_INGRESS].subcat_map[0].subcat_max = GSWR_PCE_MAX;
	class_dev[GSWR_INGRESS].subcat_map[0].subcat_used = 0;

	class_dev[GSWR_INGRESS].subcat_map[1].cat_id = CAT_FILTER;
	class_dev[GSWR_INGRESS].subcat_map[1].subcat_id = SUBCAT_WLAN_FILTER;
	class_dev[GSWR_INGRESS].subcat_map[1].subcat_max = GSWR_CAT_FILTER_MAX/2;
	class_dev[GSWR_INGRESS].subcat_map[1].subcat_used = 0;

	class_dev[GSWR_INGRESS].pce_tbl_bitmap = (uint32_t*) kmalloc(sizeof(uint32_t)*(GSWR_PCE_MAX/32), GFP_KERNEL);
	ppa_memset(class_dev[GSWR_INGRESS].pce_tbl_bitmap,0,sizeof(uint32_t)*(GSWR_PCE_MAX/32));
	class_dev[GSWR_INGRESS].cat_ordr_vect = (cat_ordr_vect_t*) kmalloc(sizeof(cat_ordr_vect_t)*GSWR_PCE_MAX, GFP_KERNEL);
	ppa_memset(class_dev[GSWR_INGRESS].cat_ordr_vect, 0, sizeof(cat_ordr_vect_t)*GSWR_PCE_MAX);

	return ret;
}

static uint8_t bitmap_isset( ppa_class_devingress_t indev, uint16_t index)
{
	int idx = index/32, offset=index%32;

	if (!offset) { idx-=1; offset = 31;} else { offset-=1;}
	if (indev <= GSWR_INGRESS) {
		return ((class_dev[indev].pce_tbl_bitmap[idx] >> offset) & 0x1);
	}

	return 1;
}

static int32_t set_bitmap(ppa_class_devingress_t indev, uint16_t index)
{
	int idx = index/32, offset=index%32;

	if(!offset) { idx-=1; offset = 31;} else { offset-=1;}
	if(indev <= GSWR_INGRESS) {
		if(!((class_dev[indev].pce_tbl_bitmap[idx] >> offset) & 0x1)) {
			class_dev[indev].pce_tbl_bitmap[idx] |= (1 << offset);
			return PPA_SUCCESS;
		}
	}
	return PPA_FAILURE;
}

static int32_t clear_bitmap(ppa_class_devingress_t indev, uint16_t index)
{
	int idx = index/32, offset=index%32;

	if(!offset) { idx-=1; offset = 31;} else { offset-=1;}
	if(indev <= GSWR_INGRESS) {
		if((class_dev[indev].pce_tbl_bitmap[idx] >> offset) & 0x1) {
			class_dev[indev].pce_tbl_bitmap[idx] &= ~(1 << offset);
			return PPA_SUCCESS;
		}
	}
	return PPA_FAILURE;
}

static int32_t pce_rule_read(GSW_API_HANDLE* gsw_handle, GSW_PCE_rule_t* pcerule, uint16_t idx)
{
	int32_t ret = PPA_SUCCESS;

	pcerule->pattern.nIndex = idx;

	if((gsw_api_kioctl(*gsw_handle, GSW_PCE_RULE_READ, pcerule)) < GSW_statusOk) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"read_routing_entry returned Failure \n");
		ret=PPA_FAILURE;
	}

	return ret;
}


static int32_t pce_rule_write(GSW_API_HANDLE* gsw_handle, GSW_PCE_rule_t* pcerule, uint16_t idx)
{
	int32_t ret = PPA_SUCCESS;

	pcerule->pattern.nIndex = idx;

	if((gsw_api_kioctl(*gsw_handle, GSW_PCE_RULE_WRITE, pcerule)) < GSW_statusOk) {
		ppa_debug(DBG_ENABLE_MASK_ERR,"read_routing_entry returned Failure \n");
	ret=PPA_FAILURE;
	}

	return ret;
}

static int32_t open_switch_dev(ppa_class_devingress_t ing_dev, GSW_API_HANDLE* gsw_handle)
{
	if(ing_dev==GSWR_INGRESS) {
		*gsw_handle = gsw_api_kopen("/dev/switch_api/0");
	}
	if (*gsw_handle == 0) {
		ppa_debug(DBG_ENABLE_MASK_ERR, "%s: Open SWAPI device FAILED !!\n", __func__ );
		return PPA_FAILURE;
	}
	return PPA_SUCCESS;
}

void copy_class_to_pce(GSW_PCE_rule_t* pcerule, PPA_CLASS_RULE* classrule)
{
	/*copy the pattern */
	ppa_memcpy(&pcerule->pattern,&classrule->pattern, sizeof(GSW_PCE_pattern_t));

	/*copy the actions*/
	/*filter actions*/
	pcerule->action.ePortFilterType_Action = classrule->action.filter_action.portfilter;
	pcerule->action.eCrossStateAction = classrule->action.filter_action.crossstate;
	/*vlan actions*/
	pcerule->action.nFId = classrule->action.vlan_action.fid;
	pcerule->action.eVLAN_Action = classrule->action.vlan_action.cvlan;
	pcerule->action.nVLAN_Id = classrule->action.vlan_action.vlan_id;
	pcerule->action.eSVLAN_Action = classrule->action.vlan_action.svlan;
	pcerule->action.nSVLAN_Id = classrule->action.vlan_action.svlan_id;
	pcerule->action.eVLAN_CrossAction = classrule->action.vlan_action.cross_vlan;
	pcerule->action.bCVLAN_Ignore_Control = classrule->action.vlan_action.cvlan_ignore;
	/*fwd actions*/
	pcerule->action.eLearningAction = classrule->action.fwd_action.learning;
	pcerule->action.bPortTrunkAction = classrule->action.fwd_action.port_trunk;
	pcerule->action.ePortMapAction = classrule->action.fwd_action.portmap;
	pcerule->action.nForwardPortMap[0] = classrule->action.fwd_action.forward_portmap;
	pcerule->action.nForwardSubIfId = classrule->action.fwd_action.forward_subifid;
	pcerule->action.bRoutExtId_Action = classrule->action.fwd_action.routextid_enable;
	pcerule->action.nRoutExtId = classrule->action.fwd_action.routextid;
	pcerule->action.bRtDstPortMaskCmp_Action = classrule->action.fwd_action.rtdestportmaskcmp;
	pcerule->action.bRtSrcPortMaskCmp_Action = classrule->action.fwd_action.rtsrcportmaskcmp;
	pcerule->action.bRtDstIpMaskCmp_Action = classrule->action.fwd_action.rtdstipmaskcmp;
	pcerule->action.bRtSrcIpMaskCmp_Action = classrule->action.fwd_action.rtsrcipmaskcmp;
	pcerule->action.bRtInnerIPasKey_Action = classrule->action.fwd_action.rtinneripaskey;
	pcerule->action.bRtAccelEna_Action = classrule->action.fwd_action.rtaccelenable;
	pcerule->action.bRtCtrlEna_Action = classrule->action.fwd_action.rtctrlenable;
	pcerule->action.eProcessPath_Action = classrule->action.fwd_action.processpath;
	/*QoS actions*/
	pcerule->action.eTrafficClassAction = classrule->action.qos_action.trafficclass;
	pcerule->action.nTrafficClassAlternate = classrule->action.qos_action.alt_trafficclass;
	pcerule->action.eMeterAction = classrule->action.qos_action.meter;
	pcerule->action.nMeterId = classrule->action.qos_action.meterid;
	pcerule->action.eCritFrameAction = classrule->action.qos_action.criticalframe;
	pcerule->action.bRemarkAction = classrule->action.qos_action.remark;
	pcerule->action.bRemarkPCP = classrule->action.qos_action.remarkpcp;
	pcerule->action.bRemarkSTAG_PCP = classrule->action.qos_action.remark_stagpcp;
	pcerule->action.bRemarkSTAG_DEI = classrule->action.qos_action.remark_stagdei;
	pcerule->action.bRemarkDSCP = classrule->action.qos_action.remark_dscp;
	pcerule->action.bRemarkClass = classrule->action.qos_action.remark_class;
	pcerule->action.bFlowID_Action = classrule->action.qos_action.flowid_enabled;
	pcerule->action.nFlowID = classrule->action.qos_action.flowid;
	/*Mgmt actions*/
	pcerule->action.eIrqAction = classrule->action.mgmt_action.irq;
	pcerule->action.eTimestampAction = classrule->action.mgmt_action.timestamp;
	/*Rmon Action*/
	pcerule->action.bRMON_Action = classrule->action.rmon_action;
	pcerule->action.nRMON_Id = classrule->action.rmon_id;
}

void copy_pce_to_class(PPA_CLASS_RULE* classrule, GSW_PCE_rule_t* pcerule)
{
	/*copy the pattern */
	ppa_memcpy(&classrule->pattern,&pcerule->pattern, sizeof(GSW_PCE_pattern_t));

	/*copy the actions
	filter actions*/
	classrule->action.filter_action.portfilter = pcerule->action.ePortFilterType_Action;
	classrule->action.filter_action.crossstate = pcerule->action.eCrossStateAction;
	/*vlan actions*/
	classrule->action.vlan_action.fid = pcerule->action.nFId;
	classrule->action.vlan_action.cvlan = pcerule->action.eVLAN_Action;
	classrule->action.vlan_action.vlan_id = pcerule->action.nVLAN_Id;
	classrule->action.vlan_action.svlan = pcerule->action.eSVLAN_Action;
	classrule->action.vlan_action.svlan_id = pcerule->action.nSVLAN_Id;
	classrule->action.vlan_action.cross_vlan = pcerule->action.eVLAN_CrossAction;
	classrule->action.vlan_action.cvlan_ignore = pcerule->action.bCVLAN_Ignore_Control;
	/*fwd actions*/
	classrule->action.fwd_action.learning = pcerule->action.eLearningAction;
	classrule->action.fwd_action.port_trunk = pcerule->action.bPortTrunkAction;
	classrule->action.fwd_action.portmap = pcerule->action.ePortMapAction;
	classrule->action.fwd_action.forward_portmap = pcerule->action.nForwardPortMap[0];
	classrule->action.fwd_action.forward_subifid = pcerule->action.nForwardSubIfId;
	classrule->action.fwd_action.routextid_enable = pcerule->action.bRoutExtId_Action;
	classrule->action.fwd_action.routextid = pcerule->action.nRoutExtId;
	classrule->action.fwd_action.rtdestportmaskcmp = pcerule->action.bRtDstPortMaskCmp_Action;
	classrule->action.fwd_action.rtsrcportmaskcmp = pcerule->action.bRtSrcPortMaskCmp_Action;
	classrule->action.fwd_action.rtdstipmaskcmp = pcerule->action.bRtDstIpMaskCmp_Action;
	classrule->action.fwd_action.rtsrcipmaskcmp = pcerule->action.bRtSrcIpMaskCmp_Action;
	classrule->action.fwd_action.rtinneripaskey = pcerule->action.bRtInnerIPasKey_Action;
	classrule->action.fwd_action.rtaccelenable = pcerule->action.bRtAccelEna_Action;
	classrule->action.fwd_action.rtctrlenable = pcerule->action.bRtCtrlEna_Action;
	classrule->action.fwd_action.processpath = pcerule->action.eProcessPath_Action;
	/*QoS actions*/
	classrule->action.qos_action.trafficclass = pcerule->action.eTrafficClassAction;
	classrule->action.qos_action.alt_trafficclass = pcerule->action.nTrafficClassAlternate;
	classrule->action.qos_action.meter = pcerule->action.eMeterAction;
	classrule->action.qos_action.meterid = pcerule->action.nMeterId;
	classrule->action.qos_action.criticalframe = pcerule->action.eCritFrameAction;
	classrule->action.qos_action.remark = pcerule->action.bRemarkAction;
	classrule->action.qos_action.remarkpcp = pcerule->action.bRemarkPCP;
	classrule->action.qos_action.remark_stagpcp = pcerule->action.bRemarkSTAG_PCP;
	classrule->action.qos_action.remark_stagdei = pcerule->action.bRemarkSTAG_DEI;
	classrule->action.qos_action.remark_dscp = pcerule->action.bRemarkDSCP;
	classrule->action.qos_action.remark_class = pcerule->action.bRemarkClass;
	classrule->action.qos_action.flowid_enabled = pcerule->action.bFlowID_Action;
	classrule->action.qos_action.flowid = pcerule->action.nFlowID;
	/*Mgmt actions*/
	classrule->action.mgmt_action.irq = pcerule->action.eIrqAction;
	classrule->action.mgmt_action.timestamp = pcerule->action.eTimestampAction;
	/*Rmon Action*/
	classrule->action.rmon_action = pcerule->action.bRMON_Action;
	classrule->action.rmon_id = pcerule->action.nRMON_Id;
}

static uint16_t find_ordr_from_uid(ppa_class_devingress_t ing_dev, ppa_class_category_t cat, uint16_t uid)
{
	uint16_t ordr=0xFFFF, i;

	for(i=0; i<=class_dev[ing_dev].cat_map[cat].cat_last_ordr; i++) {
		if(class_dev[ing_dev].cat_map[cat].cat_idx_vect[i].uid == uid) {
			ordr = i;
			break;
		}
	}
	return ordr;
}

uint16_t find_free_index(ppa_class_devingress_t ing_dev, ppa_class_category_t cat)
{
	uint16_t index = 0xFFFF;

	for(index = class_dev[ing_dev].cat_map[cat].cat_start_idx; index < class_dev[ing_dev].tot_max; index++) {
		if(!bitmap_isset(ing_dev, index)) {
			/*set the occupancy bitmap*/
			if(set_bitmap(ing_dev, index) == PPA_SUCCESS) {
				break;
			}
		}
	}
	return index;
}

int32_t	swap_pce_rules(ppa_class_devingress_t ing_dev, ppa_class_category_t cat, uint16_t ordr, uint16_t* index)
{
	int32_t ret = PPA_SUCCESS;
	uint16_t t_idx=0xFFFF;
	GSW_PCE_rule_t pcerule;
	GSW_API_HANDLE gsw_handle=0;

	if(open_switch_dev(ing_dev,&gsw_handle)!=PPA_SUCCESS)
		return PPA_FAILURE;

	ppa_memset(&pcerule,0,sizeof(GSW_PCE_rule_t));

	if(ordr < class_dev[ing_dev].cat_map[cat].cat_max) {
		t_idx = class_dev[ing_dev].cat_map[cat].cat_idx_vect[ordr].index;
		pce_rule_read(&gsw_handle, &pcerule, t_idx);
		if(pcerule.action.nFId){
			pcerule.action.eVLAN_Action = 2; //VLAN_ALTERNATIVE
		}
		ret=pce_rule_write(&gsw_handle, &pcerule, *index);
		class_dev[ing_dev].cat_map[cat].cat_idx_vect[ordr].index=*index;
		class_dev[ing_dev].cat_ordr_vect[*index] = class_dev[ing_dev].cat_ordr_vect[t_idx];
		class_dev[ing_dev].cat_ordr_vect[t_idx].usage_flg=0;
		*index = t_idx;
	}

	gsw_api_kclose(gsw_handle);
	return ret;
}

int32_t update_class_tables( PPA_CLASS_RULE* rule, uint16_t index)
{
	int32_t ret=PPA_SUCCESS;
	GSW_PCE_rule_t pcerule;
	GSW_API_HANDLE gsw_handle=0;

	if(open_switch_dev(rule->in_dev,&gsw_handle)!=PPA_SUCCESS)
	return PPA_FAILURE;

	ppa_memset(&pcerule,0,sizeof(GSW_PCE_rule_t));
	/* copy values to the switch datastructure */
	copy_class_to_pce(&pcerule, rule);

	/*show_pce_rule(&pcerule);*/

	ret=pce_rule_write(&gsw_handle, &pcerule, index);
	class_dev[rule->in_dev].cat_map[rule->category].cat_idx_vect[rule->order-1].index = index;
	class_dev[rule->in_dev].cat_map[rule->category].cat_idx_vect[rule->order-1].uid = g_pce_rtrule_next++;

	class_dev[rule->in_dev].cat_map[rule->category].cat_used++;
	class_dev[rule->in_dev].subcat_map[rule->subcategory].subcat_used++;
	class_dev[rule->in_dev].tot_used++;

	class_dev[rule->in_dev].cat_ordr_vect[index].cat_id = rule->category;
	class_dev[rule->in_dev].cat_ordr_vect[index].subcat_id = rule->subcategory;
	class_dev[rule->in_dev].cat_ordr_vect[index].cat_ordr = rule->order-1;
	class_dev[rule->in_dev].cat_ordr_vect[index].usage_flg = 1;

	/* return the unique index */
	rule->uidx = class_dev[rule->in_dev].cat_map[rule->category].cat_idx_vect[rule->order-1].uid;
	rule->pattern.nIndex = pcerule.pattern.nIndex;
	gsw_api_kclose(gsw_handle);

	return ret;
}

int32_t shift_cat_idx_vect(ppa_class_devingress_t ing_dev, ppa_class_category_t cat, uint16_t ordr, shift_direction_t dir)
{
	int i;
	if(dir == SHIFT_RIGHT) {
		class_dev[ing_dev].cat_map[cat].cat_last_ordr++;
		for(i=class_dev[ing_dev].cat_map[cat].cat_last_ordr; i>ordr; i--) {
			class_dev[ing_dev].cat_map[cat].cat_idx_vect[i]=class_dev[ing_dev].cat_map[cat].cat_idx_vect[i-1];
		}
		class_dev[ing_dev].cat_map[cat].cat_idx_vect[ordr].index = 0xFFFF;
		class_dev[ing_dev].cat_map[cat].cat_idx_vect[ordr].uid = 0;
	} else {
		if(ordr < class_dev[ing_dev].cat_map[cat].cat_last_ordr) {
			for(i=ordr; i<class_dev[ing_dev].cat_map[cat].cat_last_ordr; i++) {
				class_dev[ing_dev].cat_map[cat].cat_idx_vect[i]=class_dev[ing_dev].cat_map[cat].cat_idx_vect[i+1];
			}
		}
		class_dev[ing_dev].cat_map[cat].cat_idx_vect[class_dev[ing_dev].cat_map[cat].cat_last_ordr].index = 0xFFFF;
		class_dev[ing_dev].cat_map[cat].cat_idx_vect[class_dev[ing_dev].cat_map[cat].cat_last_ordr].uid = 0;
		class_dev[ing_dev].cat_map[cat].cat_last_ordr--;
	}

	return PPA_SUCCESS;
}
int32_t pae_hal_add_class_rule(PPA_CLASS_RULE* rule)
{
	int32_t ret= PPA_SUCCESS;
	uint16_t idx=0xFFFF, ordr=0;

	/* validate the inputs */
	if (rule->in_dev > GSWR_INGRESS || rule->category >= CAT_MAX || rule->subcategory >= SUBCAT_MAX ) {
		return PPA_FAILURE;
	}

	spin_lock_bh(&g_class_lock );

	if(class_dev[rule->in_dev].tot_used < class_dev[rule->in_dev].tot_max) {
		if( (rule->category < CAT_MAX) && class_dev[rule->in_dev].cat_map[rule->category].cat_used < class_dev[rule->in_dev].cat_map[rule->category].cat_max) {
			if( (rule->subcategory < SUBCAT_MAX) &&
				class_dev[rule->in_dev].subcat_map[rule->subcategory].subcat_used < class_dev[rule->in_dev].subcat_map[rule->subcategory].subcat_max) {

				/*if rule->order=0 then we assign the cat_last_ordr + 1*/
				if(!rule->order) {
					rule->order = class_dev[rule->in_dev].cat_map[rule->category].cat_last_ordr + 2;
				}

				if(rule->order-1 < class_dev[rule->in_dev].cat_map[rule->category].cat_max) {

				/*if order passed is far beyond the cat_last_order reset the order to cat_last_ordr + 1*/
				if((class_dev[rule->in_dev].cat_map[rule->category].cat_last_ordr + 1) < (rule->order - 1)) {
					rule->order = class_dev[rule->in_dev].cat_map[rule->category].cat_last_ordr + 2;
				}

				idx = find_free_index(rule->in_dev, rule->category);
				if (idx < class_dev[rule->in_dev].tot_max) {

					/*find 'ordr' where cat_idx_vect[ordr] < idx*/
					for(ordr=0; (ordr <= class_dev[rule->in_dev].cat_map[rule->category].cat_last_ordr) &&
						(class_dev[rule->in_dev].cat_map[rule->category].cat_idx_vect[ordr].index < idx); ordr ++);
					while (ordr < rule->order-1) {
						if(swap_pce_rules(rule->in_dev, rule->category, ordr, &idx)!=PPA_SUCCESS) {
							ppa_debug(DBG_ENABLE_MASK_ERR,"PCE rule swap failed in dev %d index=%d...\n", rule->in_dev, idx);
							clear_bitmap(rule->in_dev,idx);
							ret = PPA_FAILURE;
							goto ADD_FINISH;
						}
						ordr++;
					}

					/*while ordr > rule->order-1 swap*/
					while(ordr > rule->order-1) {
						ordr--;
						if(swap_pce_rules(rule->in_dev, rule->category, ordr, &idx)!=PPA_SUCCESS) {
							ppa_debug(DBG_ENABLE_MASK_ERR,"PCE rule swap failed in dev %d index=%d...\n", rule->in_dev, idx);
							clear_bitmap(rule->in_dev,idx);
							ret = PPA_FAILURE;
							goto ADD_FINISH;
						}
					}

					/*now ordr == order -1 */
					if( ordr > class_dev[rule->in_dev].cat_map[rule->category].cat_last_ordr) {
						class_dev[rule->in_dev].cat_map[rule->category].cat_last_ordr = ordr;
					} else {
						ret = shift_cat_idx_vect(rule->in_dev, rule->category, ordr, SHIFT_RIGHT);
					}
					/*Write the new rule in idx and update the tables*/
					ret = update_class_tables(rule, idx);
				} else {
					ppa_debug(DBG_ENABLE_MASK_ERR,"No free index found ... \n");
					ret = PPA_FAILURE;
				}
				} else {
					ppa_debug(DBG_ENABLE_MASK_ERR,"Order cannot be more than category max %d...\n", class_dev[rule->in_dev].cat_map[rule->category].cat_max);
					ret = PPA_FAILURE;
				}
			} else {
				ppa_debug(DBG_ENABLE_MASK_ERR,"MAX limit %d reached in for subcategory %d...\n", class_dev[rule->in_dev].subcat_map[rule->subcategory].subcat_max, rule->subcategory);
				ret = PPA_FAILURE;
			}
		} else {
			ppa_debug(DBG_ENABLE_MASK_ERR,"MAX limit %d reached in for category %d...\n", class_dev[rule->in_dev].cat_map[rule->category].cat_max, rule->category);
			ret = PPA_FAILURE;
		}
	} else {
		ppa_debug(DBG_ENABLE_MASK_ERR,"MAX PCE rule limit reached in dev %d...\n", rule->in_dev);
		ret = PPA_FAILURE;
	}
ADD_FINISH:
	spin_unlock_bh(&g_class_lock );
	return ret;
}
EXPORT_SYMBOL(pae_hal_add_class_rule);

int32_t pae_hal_del_class_rule(PPA_CLASS_RULE* rule)
{
	int32_t ret= PPA_SUCCESS;
	uint16_t idx=0xFFFF, ordr=0;
	GSW_PCE_rule_t pcerule;
	GSW_API_HANDLE gsw_handle=0;

	if (open_switch_dev(rule->in_dev,&gsw_handle)!=PPA_SUCCESS || rule->subcategory >= SUBCAT_MAX || rule->category >= CAT_MAX)
		return PPA_FAILURE;

	ppa_memset(&pcerule,0,sizeof(GSW_PCE_rule_t));

	spin_lock_bh(&g_class_lock );
	/*if the caller has passed the order to delete.. it is assumed that the caller has maintained the relative order properly*/
	if(rule->order) {
		ordr = rule->order-1;
	} else {
		ordr = find_ordr_from_uid(rule->in_dev, rule->category, rule->uidx);
	}

	if( ordr <= class_dev[rule->in_dev].cat_map[rule->category].cat_last_ordr) {
		idx = class_dev[rule->in_dev].cat_map[rule->category].cat_idx_vect[ordr].index;
		if(class_dev[rule->in_dev].cat_ordr_vect[idx].usage_flg) {
			ret = pce_rule_write(&gsw_handle, &pcerule, idx);
			class_dev[rule->in_dev].cat_ordr_vect[idx].usage_flg=0;
			clear_bitmap(rule->in_dev,idx);

			ret = shift_cat_idx_vect(rule->in_dev, rule->category, ordr, SHIFT_LEFT);

			class_dev[rule->in_dev].cat_map[rule->category].cat_used--;
			class_dev[rule->in_dev].subcat_map[rule->subcategory].subcat_used--;
			class_dev[rule->in_dev].tot_used--;
		} else {
			ppa_debug(DBG_ENABLE_MASK_ERR,"Device=%d Category=%d Order=%d PCE table Index=%d is empty...\n",rule->in_dev, rule->category, rule->order, idx);
			ret = PPA_FAILURE;
		}
	} else {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Invalid order %d for categoty %d...\n", rule->order, rule->category);
		ret = PPA_FAILURE;
	}
	spin_unlock_bh(&g_class_lock );
	gsw_api_kclose(gsw_handle);
	return ret;
}
EXPORT_SYMBOL(pae_hal_del_class_rule);

int32_t pae_hal_mod_class_rule(PPA_CLASS_RULE* rule)
{
	int32_t ret= PPA_SUCCESS;
	uint16_t idx=0xFFFF, ordr=0;
	GSW_PCE_rule_t pcerule;
	GSW_API_HANDLE gsw_handle=0;

	if (open_switch_dev(rule->in_dev,&gsw_handle)!=PPA_SUCCESS || rule->category >= CAT_MAX)
		return PPA_FAILURE;

	ppa_memset(&pcerule,0,sizeof(GSW_PCE_rule_t));

	spin_lock_bh(&g_class_lock );
/*if the caller has passed the order to delete.. it is assumed that the caller has maintained the relative order properly*/
	if(rule->order) {
		ordr = rule->order-1;
	} else {
		ordr = find_ordr_from_uid(rule->in_dev, rule->category, rule->uidx);
	}

	if( ordr <= class_dev[rule->in_dev].cat_map[rule->category].cat_last_ordr) {
		idx = class_dev[rule->in_dev].cat_map[rule->category].cat_idx_vect[ordr].index;
		if(class_dev[rule->in_dev].cat_ordr_vect[idx].usage_flg) {
			pce_rule_read(&gsw_handle, &pcerule, idx);
			/*modify the pce rule*/
			copy_class_to_pce(&pcerule, rule);
			ret = pce_rule_write(&gsw_handle, &pcerule, idx);
		} else {
			ppa_debug(DBG_ENABLE_MASK_ERR,"Device=%d Category=%d Order=%d PCE table Index=%d is empty...\n",rule->in_dev, rule->category, rule->order, idx);
			ret = PPA_FAILURE;
		}
	} else {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Invalid order %d for categoty %d...\n", rule->order, rule->category);
		ret = PPA_FAILURE;
	}
	spin_unlock_bh(&g_class_lock );
	gsw_api_kclose(gsw_handle);
	return ret;
}
EXPORT_SYMBOL(pae_hal_mod_class_rule);

int32_t pae_hal_get_class_rule(PPA_CLASS_RULE* rule)
{
	int32_t ret= PPA_SUCCESS;
	uint16_t idx=0xFFFF, ordr=0;
	GSW_PCE_rule_t pcerule;
	GSW_API_HANDLE gsw_handle=0;

	if (open_switch_dev(rule->in_dev,&gsw_handle)!=PPA_SUCCESS || rule->category >= CAT_MAX)
		return PPA_FAILURE;

	ppa_memset(&pcerule,0,sizeof(GSW_PCE_rule_t));

	spin_lock_bh(&g_class_lock );
	/*if the caller has passed the order to delete.. it is assumed that the caller has maintained the relative order properly*/
	if(rule->order) {
		ordr = rule->order-1;
	} else {
		ordr = find_ordr_from_uid(rule->in_dev, rule->category, rule->uidx);
	}

	if( ordr <= class_dev[rule->in_dev].cat_map[rule->category].cat_last_ordr) {
		idx = class_dev[rule->in_dev].cat_map[rule->category].cat_idx_vect[ordr].index;
		if(class_dev[rule->in_dev].cat_ordr_vect[idx].usage_flg) {
			pce_rule_read(&gsw_handle, &pcerule, idx);
			copy_pce_to_class(rule, &pcerule);
		} else {
			ppa_debug(DBG_ENABLE_MASK_ERR,"Device=%d Category=%d Order=%d PCE table Index=%d is empty...\n",rule->in_dev, rule->category, rule->order, idx);
			ret = PPA_FAILURE;
		}
	} else {
		ppa_debug(DBG_ENABLE_MASK_ERR,"Invalid order %d for categoty %d...\n", rule->order, rule->category);
		ret = PPA_FAILURE;
	}
	/*show_pce_rule(&pcerule);	*/

	spin_unlock_bh(&g_class_lock );
	gsw_api_kclose(gsw_handle);
	return ret;
}
EXPORT_SYMBOL(pae_hal_get_class_rule);

module_init(mpe_hal_init);
module_exit(mpe_hal_exit);

MODULE_LICENSE("GPL");
