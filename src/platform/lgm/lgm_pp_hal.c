/******************************************************************************
**
** FILE NAME	: lgm_pp_hal.c
** PROJECT	: LGM
** MODULES	: PPA PPv4 HAL
**
** DATE		: 29 Oct 2018
** AUTHOR	: Kamal Eradath
** DESCRIPTION	: PPv4 hardware abstraction layer
** COPYRIGHT	: Copyright (c) 2020-2024 MaxLinear, Inc.
**                Copyright (c) 2014, Intel Corporation.
**
**	 For licensing information, see the file 'LICENSE' in the root folder of
**	 this software module.
**
** HISTORY
** $Date		$Author		 	$Comment
** 29 Oct 2018		Kamal Eradath		Initial Version
** 13 JUN 2022		Gaurav Sharma		Moved Litepath code to separate file.
*******************************************************************************/
/*
 * ####################################
 *		Head File
 * ####################################
 */
/*
 *	Common Head File
 */
#include <linux/version.h>
#include <generated/autoconf.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/udp.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <linux/clk.h>
#include <net/ip_tunnels.h>
#include <linux/if_arp.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/timer.h>
#include <asm/uaccess.h>
#include <net/ipv6.h>
#include <net/ip6_tunnel.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_pppox.h>
#include <linux/net.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/route.h>
#include <net/inet6_hashtables.h>
#include <linux/bitops.h>
#include <linux/bitmap.h>

/*
 *	Chip Specific Head File
 */
#include <linux/pp_api.h>
#include <linux/pktprs.h>
#include <net/datapath_api.h>
#if IS_ENABLED(CONFIG_LGM_TOE)
#if IS_ENABLED(CONFIG_SOC_LGM)
#include <net/toe_np_lro.h>
#else
#include <net/intel_np_lro.h>
#endif
#endif /* CONFIG_LGM_TOE */
#include <net/datapath_api_qos.h>
#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
#include <net/datapath_api_vpn.h>
#endif
#include <net/datapath_api_gswip32.h>
#if IS_ENABLED(CONFIG_MCAST_HELPER)
#include <net/mcast_helper_api.h>
#endif
#include <net/ppa/ppa_api.h>
#include <net/ppa/ppa_hal_api.h>
#include <net/ppa/ppa_drv_wrapper.h>
#include "../../ppa_api/ppa_api_netif.h"
#include "../../ppa_api/ppa_api_session.h"
#include "lgm_pp_hal.h"
#include "lgm_lro_hal.h"

#include "lgm_hw_litepath.h"

#include <soc/mxl/mxl_skb_ext.h>
#if IS_ENABLED(CONFIG_SGAM)
#include <net/sgam/sgam_api.h>
#endif /* CONFIG_SGAM */

/*
 * ####################################
 *			Version No.
 * ####################################
 */
#define VER_FAMILY	0x10
#define VER_DRTYPE	0x04 /* 4: Stack/System Adaption Layer driver*/
#define VER_INTERFACE	0x1 /*	bit 0: MII 1 */
#define VER_ACCMODE	0x11 /*	bit 0: Routing &Bridging */

#define VER_MAJOR	1
#define VER_MID		0
#define VER_MINOR	0

#define SESSION_RETRY_MAX	 8
#define ETH_MTU	1500
#define PPA_MAX_DSCP 64
/*
 *	Compilation Switch
 */
/*!
	\brief Turn on/off debugging message and disable inline optimization.
 */
#define ENABLE_DEBUG			1
/*!
	\brief Turn on/off ASSERT feature, print message while condition is not fulfilled.
 */
#define ENABLE_ASSERT			1
/*@}*/

#if defined(ENABLE_DEBUG) && ENABLE_DEBUG
	#define ENABLE_DEBUG_PRINT	1
	#define DISABLE_INLINE		1
#endif

#if defined(DISABLE_INLINE) && DISABLE_INLINE
	#define INLINE
#else
	#define INLINE			inline
#endif

#if defined(ENABLE_DEBUG_PRINT) && ENABLE_DEBUG_PRINT
	#undef	dbg
	static unsigned int lgm_pp_hal_dbg_enable = 0;
	#define dbg(format, arg...) do { if ( lgm_pp_hal_dbg_enable ) printk(KERN_WARNING ":%d:%s: " format "\n", __LINE__, __FUNCTION__, ##arg); } while ( 0 )
#else
	#if !defined(dbg)
	#define dbg(format, arg...)
	#endif
#endif

#if defined(ENABLE_ASSERT) && ENABLE_ASSERT
	#define ASSERT(cond, format, arg...) do { if ( !(cond) ) printk(KERN_ERR __FILE__ ":%d:%s: " format "\n", __LINE__, __FUNCTION__, ##arg); } while ( 0 )
#else
	#define ASSERT(cond, format, arg...)
#endif

#ifndef NUM_ENTITY
#define NUM_ENTITY(x)	(sizeof(x) / sizeof(*(x)))
#endif

#define PPA_API_PROC 		1

#define DEFAULT_WQ_TIME			(4) /* 4 seconds */
#define DEFAULT_DB_SLICE		(1024U) /*number of db entries polled per iteration*/
#define DEFAULT_INACT_ARRAY_SIZE	(8192U) /*8K*/

#define ETH_HLEN		14	/* Total octets in header.	 */
#define IPV4_HLEN		20
#define IPV6_HLEN		40
#define VLAN_HLEN		4
#define PPPOE_HLEN		8
#define ESP_HLEN		8
#define ESP_IV			16
#define PPPOE_IPV4_TAG		0x0021
#define PPPOE_IPV6_TAG		0x0057

#define COPY_16BYTES 16
#define COPY_32BYTES 32
#define CPU_PORT_WLAN_BIT_MODE	9

/* FBM - Fast buffer monitoring
 * used to reduce the DDR load for short packets 10G-10G BiDir
 * by using fast (internal memory) buffers (SSB) on a single port (10G LAN by
 * default) the PMB is monitoring the buffer manager pool allocation and all
 * the accelerated traffic transmited to the port (rate and average packet
 * size) for shaping the traffic by TBM according to the pool fill level
 */
/* 9.98G[bps] in bytes per second */
#define FBM_HIGH_RATE_BPS (9980000000ULL / 8)
/* 8.3G[bps] in bytes per second */
#define FBM_LOW_RATE_BPS  (8300000000ULL / 8)
/* 10G[bps] in bytes per second */
#define FBM_MAX_RATE_BPS  (10000000000ULL / 8)
/* Ethernet L1 bytes: 12 Bytes IFG + 7 Bytes Preamble + 1 Byte SFD */
#define FBM_L1_BYTES   (20)
/* FBM is used only for short packets [60-128] */
#define FBM_MIN_PKT_SZ (60)
#define FBM_MAX_PKT_SZ (128)
/* CIR step in Bytes, 20M[Bps] * 8 == 160M[bps] */
#define FBM_CIR_STEP   (20000000)
/* CIR small step in Bytes, 250K[Bps] * 8 == 2M[bps] */
#define FBM_CIR_SSTEP  (250000)
/* PPS threshold, Calc for: 10G and max size of "short packets" [128] */
#define FBM_PPS_THR    (FBM_MAX_RATE_BPS / (FBM_MAX_PKT_SZ + FBM_L1_BYTES))
/* Tailroom for disable FBM = buf size - headroom - min pkt size + 4 */
#define FBM_DIS_TR_SZ(hr) (256 - (hr) - FBM_MIN_PKT_SZ + 4)
/* Fast buffer monitor interface */
#define FBM_IF "eth0_1"
/* Timer interval for fast response */
#define FBM_FAST_TIMER      (MSEC_PER_SEC)
/* Timer interval for slower response */
#define FBM_SLOW_TIMER      (5 * MSEC_PER_SEC)
/* Default TBM cbs value */
#define FBM_TBM_CBS_DFLT    (0x2800)
/* Default threshold for max consecutive iterations of lowest rate shaping */
#define FBM_MIN_RATE_IT_CNT (3)

#if IS_ENABLED(CONFIG_PPA_BBF247_MODE1)
#define BBF247_MAX_SESS_ID		20
#define BBF247_INVALID_SESS_ID	U32_MAX
#endif /*CONFIG_PPA_BBF247_MODE1*/


/*
 * ####################################
 *		Declaration
 * ####################################
 */

#if defined(PPA_API_PROC)
static int proc_read_ppv4_tdox_enable(struct inode *inode, struct file *file);
static ssize_t proc_set_ppv4_tdox_enable(struct file *file, const char __user *buf, size_t count, loff_t *data);

static int proc_read_ppv4_ifstats_seq_open(struct inode *, struct file *);

static int proc_read_ppv4_rtstats_seq_open(struct inode *, struct file *);
static ssize_t proc_clear_ppv4_rtstats(struct file *, const char __user *, size_t , loff_t *);

static int proc_read_ppv4_accel_seq_open(struct inode *, struct file *);
static int proc_read_support_ppv4_accel_seq_open(struct inode *,
		struct file *);
static ssize_t proc_set_ppv4_accel(struct file *, const char __user *, size_t,
		loff_t *);
static ssize_t proc_set_support_ppv4_accel(struct file *, const char __user *,
		size_t, loff_t *);

#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
static int proc_read_ppv4_vpn_tunn_open(struct inode *, struct file *);
#endif /* CONFIG_INTEL_VPN || CONFIG_MXL_VPN */

static int proc_read_ppv4_debug_seq_open(struct inode *, struct file *);
static ssize_t proc_set_ppv4_debug(struct file *, const char __user *, size_t , loff_t *);

#if IS_ENABLED(CONFIG_PPA_BBF247_MODE1)
static int ppa_run_cmd(const char *cmd);
static int32_t ppa_add_bbf247_mode1_us_session(PPA_NETIF *rxif, PPA_NETIF *txif,
					       uint32_t *session_id);
static int32_t ppa_add_bbf247_mode1_ds_session(PPA_NETIF *rxif, PPA_NETIF *txif,
					       u32 class, uint32_t *session_id);
static int32_t ppa_pp_update_ports(PPA_NETIF *lan_if, PPA_NETIF *vuni_if);
static void ppa_bbf247_mode1(PPA_IFNAME vani_netif_name[PPA_IF_NAME_SIZE],
			     PPA_IFNAME vuni_netif_name[PPA_IF_NAME_SIZE],
			     PPA_IFNAME lan_netif_name[PPA_IF_NAME_SIZE],
			     bool enable);
static int proc_read_ppv4_bbf247_hgu(struct seq_file *seq, void *v);
static int proc_read_ppv4_bbf247_hgu_seq_open(struct inode *inode,
					      struct file *file);
static ssize_t proc_set_ppv4_bbf247_hgu(struct file *file,
					const char __user *buf,
					size_t count, loff_t *data);
#endif /*CONFIG_PPA_BBF247_MODE1*/
#endif /*defined(PPA_API_PROC)*/
struct client_info{
	uint32_t sess_id;		/* Client session id */
	struct net_device *netdev;	/* tx netdevice */
	struct pp_hash sess_hash;	/* HW hash of the dst */
};

/*Each client will have one session in pp*/
typedef struct mc_db_nod {
	bool		used;	/*index is in use*/
	struct pp_stats	stats;	/*statistics per group*/
	struct pp_hash  grp_sess_hash; /*HW hash of the group session*/
	struct client_info dst[MAX_MC_CLIENT_PER_GRP]; /* mc clients*/
} MC_DB_NODE;


/*Each unicast entry in pp will need following information kept in hal*/
typedef struct uc_db_node {
	bool			used;	/*index is in use*/
	struct pp_stats		stats;	/*statistics*/
	void 			*node; 	/*unicast session node pointer*/
#if IS_ENABLED(LITEPATH_HW_OFFLOAD)
	struct lp_info		*lp_rxinfo; /*litepath rx packet info*/
#endif /*IS_ENABLED(LITEPATH_HW_OFFLOAD)*/
	bool			lro;	/*lro session*/
} PP_HAL_DB_NODE;


typedef struct ipsec_tun {
	bool valid;
	bool trns_mode;			/* Transport mode */
	bool is_inbound;		/* Inbound dir */
	bool ipv6;			/* ESP packet packet is IPv6*/
	bool pppoe;			/* PPPoE header */
	uint8_t hdr_len;		/* Total header length of the ESP packet */
	uint8_t esp_hdr_len;		/* ESP header + IV length*/
	uint8_t ip_offset;		/* Offset of the IP header in the ESP packet */
	uint8_t strip_sz;		/* Specify number of bytes to strip when rebuilding the ESP header */
	uint8_t esp_offset;		/* Offset of the ESP header in the ESP packet */
	uint8_t org_nexthdr;		/* next header of the outer ip */
	uint32_t iv_sz;			/* tunnel IV size */
	uint32_t seq;
	void *hdr;			/* Backed up ESP header */
	struct list_head sessions;	/* PPA related sessions list(p_item) */
} PP_IPSEC_TUN_NODE;

struct mc_dev_priv{
	struct module	*owner;
};

#if IS_ENABLED(CONFIG_PPA_BBF247_MODE1)
struct BBF247_Session_Info {
	uint32_t sess_id[BBF247_MAX_SESS_ID];
	uint32_t sess_cnt;
	char *eth_arr[BBF247_MAX_SESS_ID];
};
#endif /*CONFIG_PPA_BBF247_MODE1*/

#if IS_ENABLED(CONFIG_LGM_TOE)
extern int32_t ppa_bypass_lro(PPA_BUF *ppa_buf);
#endif /*IS_ENABLED(CONFIG_LGM_TOE)*/

#if !IS_ENABLED(CONFIG_SGAM)
enum pp_sgc_lvl {
	PP_SGC_LVL_0 = 0, /* Group 0 used for FBM(SSB) monitoring */
	PP_SGC_LVL_1, /* Used by SGAM */
	PP_SGC_LVL_2, /* Used for interface stats */
	PP_SGC_LVL_3, /* Used for interface stats */
	PP_SGC_LVL_4, /* Used for interface stats */
	PP_SGC_LVL_5, /* Used for interface stats */
	PP_SGC_LVL_6, /* Used for interface stats */
	PP_SGC_LVL_7, /* Used by SGAM */
	PP_SGC_LVL_MAX = PP_SGC_LVL_7
};
#endif /* !IS_ENABLED(CONFIG_SGAM) */

#define PP_HAL_MAX_IFS_NUM 63
struct if_stats {
	struct if_info {
		PPA_NETIF *dev;
		struct sgc_info {
			uint8_t		grp:3;
			uint8_t		res:5;
			uint16_t	rx_id;
			uint16_t	tx_id;
		} sgc[2];
		refcount_t	ref_cnt;
	} if_info[PP_HAL_MAX_IFS_NUM];
	DECLARE_BITMAP(if_bitmap, PP_HAL_MAX_IFS_NUM);
	spinlock_t lock;
};
static int init_if_stats(void);
static void uninit_if_stats(void);
static int alloc_if_stats_idx(int indx, PPA_NETIF *dev);
static void free_if_stats_idx(int indx);
static inline int get_if_stats_idx(PPA_NETIF *dev);
static inline void put_if_stats_idx(PPA_NETIF *dev);
static int pp_hal_sgc_alloc(PPA_NETIF *dev, struct sgc_info *sgc, int count);
static int pp_hal_sgc_get(struct sgc_info *sgc, int count,
			  struct pp_stats *tx_stats, struct pp_stats *rx_stats);
static void pp_hal_sgc_free(struct sgc_info *sgc, int count);
static int test_and_attach_sgc(uint16_t sgc[PP_SI_SGC_MAX],
			       int indx, bool is_tx);
static int attach_sgc(PPA_NETIF *rxif, PPA_NETIF *txif,
		      uint16_t sgc[PP_SI_SGC_MAX]);
static void detach_sgc(PPA_NETIF *rxif, PPA_NETIF *txif);
static int add_interface(struct netif_info *ifinfo);
static int del_interface(struct netif_info *ifinfo);
static int get_if_stats(PPA_NETIF *dev, struct intf_mib *ifmib);

static DEFINE_PER_CPU(PPA_HAL_STATS, rtstats);
#define PPA_HAL_RTSTATS_INC(field) raw_cpu_inc(rtstats.field)
#define PPA_HAL_RTSTATS_DEC(field) raw_cpu_dec(rtstats.field)

/*
 * ####################################
 *	 Global Variable
 * ####################################
 */

/**
 * @struct pphal_fbm
 * @brief Fast Buffer Monitor
 */
struct pphal_fbm {
	/*! FBM enable */
	bool enable;
	/*! FBM pp port configuration */
	struct pp_port_cfg pcfg;
	/*! Original pp port tailroom */
	uint16_t orig_tr;
	/*! FBM gpid */
	uint16_t gpid;
	/*! FBM timer */
	struct timer_list timer;
	/*! FBM pp TBM ID */
	uint16_t tbm_id;
	/*! FBM pp SGC ID */
	uint16_t sgc_id;
	/*! FBM pp SGC group ID */
	uint16_t sgc_grp;
	/*! Fast BM pool ID */
	uint16_t pool_id;
	/*! Fast BM pool fill threshold
	 *  above this threshold the pool is consider as full
	 */
	uint16_t pool_fill_thr;
	/*! Single step for updating the shaping value */
	uint64_t shaping_step;
	/*! Single small step for updating the shaping value */
	uint64_t shaping_small_step;
	/*! Lowest rate limit for shaping */
	uint64_t shaping_low;
	/*! High rate limit for shaping, above this threshold,
	 *  rate increasing can be done only by small steps
	 */
	uint64_t shaping_high;
	/*! Maximum rate limit */
	uint64_t shaping_max;
	/*! Count number of consecutive iterations of lowest rate shaping */
	uint32_t min_cir_cnt;
	/*! Threshold for max consecutive iterations of lowest rate shaping,
	 *  above this threshold the FBM will be disabled
	 */
	uint32_t min_cir_cnt_thr;
	/*! FBM pp TBM */
	struct pp_dual_tbm tbm;
	/*! FBM timer interval */
	uint32_t interval;
};

static struct pphal_fbm fbm;
static void pphal_fbm_tbm_timer_update(struct timer_list *timer);
static void pphal_fbm_enable(bool en);
static int32_t pphal_fbm_gpid_update(uint32_t gpid);

/* gswip port bitmap map */
static uint32_t g_port_map = 0xFFFF; /*{ 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 }*/
static uint32_t g_us_accel_enabled = 1;
static uint32_t g_supp_accel_enabled = 1;
static uint32_t g_ds_accel_enabled = 1;
static uint32_t g_max_hw_sessions = MAX_UC_SESSION_ENTRIES;
#if IS_ENABLED(CONFIG_PPA_BBF247_MODE1)
static struct BBF247_Session_Info *bbf247_sess;
#endif /*CONFIG_PPA_BBF247_MODE1*/

/* Gswip logical qid*/
static uint16_t g_gswip_qid;
static struct nf_node g_mcast_nf = {0};
static struct nf_node g_frag_nf = {0};
static struct nf_node g_reas_nf = {0};
static struct nf_node g_tdox_nf = {0};
static struct nf_node g_remrk_nf = {0};
#if !IS_ENABLED(CONFIG_INTEL_VPN) && !IS_ENABLED(CONFIG_MXL_VPN)
static struct nf_node g_lld_nf = {0};
#endif

#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
static struct nf_node g_vpna_conn = {0};
static struct nf_node g_vpn_nf = {0};
static spinlock_t g_tun_db_lock;
static PP_IPSEC_TUN_NODE ipsec_tun_db[MAX_TUN_ENTRIES]={0};
#endif /* CONFIG_INTEL_VPN || CONFIG_MXL_VPN */

/*multicast group DB*/
static MC_DB_NODE mc_db[MAX_MC_GROUP_ENTRIES]={0};
/*DB to maintain pp status in pp hal */
static PP_HAL_DB_NODE	*pp_hal_db=NULL;
/*DB to maintain IPSec tunnel entries*/

/*Session delete callback */
static void (*del_routing_session_cb)(void *p_item)=NULL;

static spinlock_t		g_hal_db_lock;
static spinlock_t		g_hal_mc_db_lock;
static uint32_t		g_sess_timeout_thr = 0;

/* Global ppv4 hal counters */
static uint64_t nsess_add=0;
static uint64_t nsess_del=0;
static uint64_t nsess_del_fail=0;
static uint64_t nsess_add_succ=0;
static uint64_t nsess_add_fail_rt_tbl_full=0;
static uint64_t nsess_add_fail_coll_full=0;
static uint32_t nsess_add_fail_oth=0;

#if defined(PPA_API_PROC)
static struct dentry *ppa_ppv4hal_debugfs_dir;
static struct dentry *ppa_fbm_debugfs_dir;

static const struct file_operations dbgfs_file_ppv4_ifstats_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_ppv4_ifstats_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations dbgfs_file_ppv4_rtstats_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_ppv4_rtstats_seq_open,
	.read		= seq_read,
	.write		= proc_clear_ppv4_rtstats,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static const struct file_operations dbgfs_file_ppv4_accel_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_ppv4_accel_seq_open,
	.read		= seq_read,
	.write		= proc_set_ppv4_accel,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static const struct file_operations dbgfs_file_ppv4_support_accel_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_support_ppv4_accel_seq_open,
	.read		= seq_read,
	.write		= proc_set_support_ppv4_accel,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
static const struct file_operations dbgfs_file_ppv4_vpn_tunn_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_ppv4_vpn_tunn_open,
	.read		= seq_read,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};
#endif

static const struct file_operations dbgfs_file_ppv4_debug_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_ppv4_debug_seq_open,
	.read		= seq_read,
	.write		= proc_set_ppv4_debug,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static const struct file_operations dbgfs_file_ppv4_tdox_enable_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_ppv4_tdox_enable,
	.read		= seq_read,
	.write		= proc_set_ppv4_tdox_enable,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int dbgfs_fbm_status_read(struct seq_file *seq, void *v)
{
	if (!capable(CAP_SYSLOG)) {
		pr_err("Read Permission denied\n");
		return 0;
	}
	seq_puts(seq, "Fast Buffer Monitor:\n");
	seq_puts(seq, "====================\n");
	seq_printf(seq, "Status                    : %s\n",
		   fbm.enable ? "Enabled" : "Disabled");
	seq_printf(seq, "GPID                      : %u\n", fbm.gpid);
	seq_printf(seq, "GPID tailroom             : %u\n",
		   fbm.pcfg.tx.tailroom_size);
	seq_printf(seq, "Policy id                 : %u\n",
		   fbm.pcfg.tx.base_policy);
	seq_printf(seq, "Pool id                   : %u\n",
		   fbm.pool_id);
	seq_printf(seq, "Pool fill threshold       : %u\n", fbm.pool_fill_thr);
	seq_printf(seq, "Interval[mSEC]            : %u\n", fbm.interval);
	seq_puts(seq,   "Shaping [bps]:\n");
	seq_printf(seq, "   Step                   : %llu\n",
		   fbm.shaping_step << 3);
	seq_printf(seq, "   Small step             : %llu\n",
		   fbm.shaping_small_step << 3);
	seq_printf(seq, "   Rate low               : %llu\n",
		   fbm.shaping_low << 3);
	seq_printf(seq, "   Rate high              : %llu\n",
		   fbm.shaping_high << 3);
	seq_printf(seq, "   Rate max               : %llu\n",
		   fbm.shaping_max << 3);
	seq_printf(seq, "   Min Rate cnt           : %u\n", fbm.min_cir_cnt);
	seq_printf(seq, "   Min Rate cnt threshold : %u\n",
		   fbm.min_cir_cnt_thr);
	seq_puts(seq,   "TBM Info:\n");
	seq_printf(seq, "   Status                 : %s\n",
		   fbm.tbm.enable ? "Enabled" : "Disabled");
	seq_printf(seq, "   ID                     : %hu\n", fbm.tbm_id);
	seq_printf(seq, "   cir[bps]               : %llu\n", fbm.tbm.cir << 3);
	seq_printf(seq, "   cbs[bps]               : %u\n", fbm.tbm.cbs << 3);

	return 0;
}

static int dbgfs_fbm_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, dbgfs_fbm_status_read, NULL);
}

static const struct file_operations dbgfs_file_fbm_status_seq_fops = {
	.owner   = THIS_MODULE,
	.open    = dbgfs_fbm_status_open,
	.read    = seq_read,
	.release = single_release,
};

static int dbgfs_fbm_gpid_write(void *data, u64 val)
{
	int32_t ret;

	if (!capable(CAP_NET_ADMIN)) {
		pr_err("Write Permission denied\n");
		return 0;
	}

	ret = pphal_fbm_gpid_update((uint32_t)val);
	if (ret)
		pr_err("Failed to update FBM GPID\n");

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(dbgfs_file_fbm_gpid_seq_fops, NULL,
			 dbgfs_fbm_gpid_write, "%llu\n");

static int dbgfs_fbm_step_write(void *data, u64 val)
{
	if (!capable(CAP_NET_ADMIN)) {
		pr_err("Write Permission denied\n");
		return 0;
	}
	/* Convert from bits to bytes */
	fbm.shaping_step = val >> 3;

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(dbgfs_file_fbm_step_seq_fops, NULL,
			 dbgfs_fbm_step_write, "%llu\n");

static int dbgfs_fbm_sstep_write(void *data, u64 val)
{
	if (!capable(CAP_NET_ADMIN)) {
		pr_err("Write Permission denied\n");
		return 0;
	}
	/* Convert from bits to bytes */
	fbm.shaping_small_step = val >> 3;

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(dbgfs_file_fbm_sstep_seq_fops, NULL,
			 dbgfs_fbm_sstep_write, "%llu\n");

static int dbgfs_fbm_pool_thr_write(void *data, u64 val)
{
	if (!capable(CAP_NET_ADMIN)) {
		pr_err("Write Permission denied\n");
		return 0;
	}
	fbm.pool_fill_thr = (uint16_t)val;

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(dbgfs_file_fbm_pool_thr_seq_fops, NULL,
			 dbgfs_fbm_pool_thr_write, "%llu\n");

static int dbgfs_fbm_min_cnt_thr_write(void *data, u64 val)
{
	if (!capable(CAP_NET_ADMIN)) {
		pr_err("Write Permission denied\n");
		return 0;
	}
	fbm.min_cir_cnt_thr = (uint32_t)val;

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(dbgfs_file_fbm_min_cnt_seq_fops, NULL,
			 dbgfs_fbm_min_cnt_thr_write, "%llu\n");

static int dbgfs_fbm_hcir_write(void *data, u64 val)
{
	if (!capable(CAP_NET_ADMIN)) {
		pr_err("Write Permission denied\n");
		return 0;
	}
	/* Convert from bits to bytes */
	fbm.shaping_high = val >> 3;

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(dbgfs_file_fbm_hcir_seq_fops, NULL,
			 dbgfs_fbm_hcir_write, "%llu\n");

static int dbgfs_fbm_lcir_write(void *data, u64 val)
{
	if (!capable(CAP_NET_ADMIN)) {
		pr_err("Write Permission denied\n");
		return 0;
	}
	/* Convert from bits to bytes */
	fbm.shaping_low = val >> 3;

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(dbgfs_file_fbm_lcir_seq_fops, NULL,
			 dbgfs_fbm_lcir_write, "%llu\n");

static int dbgfs_fbm_mcir_write(void *data, u64 val)
{
	if (!capable(CAP_NET_ADMIN)) {
		pr_err("Write Permission denied\n");
		return 0;
	}
	/* Convert from bits to bytes */
	fbm.shaping_max = val >> 3;

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(dbgfs_file_fbm_mcir_seq_fops, NULL,
			 dbgfs_fbm_mcir_write, "%llu\n");

static int dbgfs_fbm_enable_write(void *data, u64 val)
{
	if (!capable(CAP_NET_ADMIN))
		return 0;

	if (!val) {
		if (fbm.enable) {
			fbm.enable = false;
			del_timer(&fbm.timer);
			pphal_fbm_enable(false);
			pp_dual_tbm_set(fbm.tbm_id, &fbm.tbm);
		}
		pr_info("FBM Momitor Disbled\n");
	} else {
		if (!fbm.enable) {
			fbm.enable = true;
			/* Init FBM TBM timer */
			timer_setup(&fbm.timer, pphal_fbm_tbm_timer_update, 0);
			mod_timer(&fbm.timer,
				  jiffies + msecs_to_jiffies(fbm.interval));
		}
		pr_info("FBM Momitor Enabled\n");
	}

	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(dbgfs_file_fbm_enable_seq_fops, NULL,
			 dbgfs_fbm_enable_write, "%llu\n");

#if IS_ENABLED(CONFIG_PPA_BBF247_MODE1)
static const struct file_operations dbgfs_file_ppv4_bbf247_hgu_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_ppv4_bbf247_hgu_seq_open,
	.read		= seq_read,
	.write		= proc_set_ppv4_bbf247_hgu,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};
#endif /*CONFIG_PPA_BBF247_MODE1*/

#endif /*defined(PPA_API_PROC)*/

static struct if_stats *if_stats_db;

/*
 * ####################################
 *		Extern Variable
 * ####################################
 */

/*
 * ####################################
 *		Extern Function
 * ####################################
 */

extern uint32_t ppa_drv_generic_hal_register(uint32_t hal_id, ppa_generic_hook_t generic_hook);
extern void ppa_drv_generic_hal_deregister(uint32_t hal_id);

extern uint32_t ppa_drv_register_cap(PPA_API_CAPS cap, uint8_t wt, PPA_HAL_ID hal_id);
extern uint32_t ppa_drv_deregister_cap(PPA_API_CAPS cap, PPA_HAL_ID hal_id);

/*
 * ####################################
 *			Local Function
 * ####################################
 */
#define PRINT_SKB 1
#if IS_ENABLED(PRINT_SKB)
static int p_flg = 0;
#endif /*IS_ENABLED(PRINT_SKB)*/

static int get_soc_rev(void)
{
	struct cbm_ops *cqm_ops = NULL;

	cqm_ops = (struct cbm_ops *)dp_get_ops(0, DP_OPS_CQM);
	if (cqm_ops && cqm_ops->cqm_get_version)
		return cqm_ops->cqm_get_version();

	return -1;
}

static inline void dumpskb(uint8_t *ptr, int len, int flag)
{
#if IS_ENABLED(PRINT_SKB)
	p_flg++;

	if (!lgm_pp_hal_dbg_enable)
		return;

	if (flag || ((p_flg % 10) == 0)) {
		print_hex_dump(KERN_ERR, "", DUMP_PREFIX_NONE, 16, 1,
			       ptr, len, false);
		p_flg = 0;
	}
#endif
}

static inline uint32_t is_valid_session(uint32_t session_id)
{
	if (session_id && (session_id <= g_max_hw_sessions)) {
		return 1;
	}
	return 0;
}

static inline uint32_t is_lansession(uint32_t flags)
{
	return ((flags & SESSION_LAN_ENTRY) ? 1 : 0);
}

int32_t is_lgm_special_netif(struct net_device *netif)
{
	/* multicast netif */
	if (ppa_is_netif_equal(netif, g_mcast_nf.dev)) {
		return 1;
#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
	} else if (ppa_is_netif_equal(netif, g_vpn_nf.dev)) {
	/* vpnnf_netif */
		return 1;
#endif /* CONFIG_INTEL_VPN || CONFIG_MXL_VPN */
	} else if (ppa_is_netif_equal(netif, ppa_get_lp_dev())) {
	 /*litepath netif*/
		return 1;
#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
	} else if (ppa_is_netif_equal(netif, g_vpna_conn.dev)) {
		/* vpn_adapter netif*/
		return 1;
#endif
	}
	return 0;
}
EXPORT_SYMBOL(is_lgm_special_netif);

static inline uint16_t get_gswip_qid(struct dp_spl_cfg *dpcon)
{
	struct dp_qos_q_logic q_logic = {0};

	if (!g_gswip_qid) {
		/* Qid to be used from NF to send the backet back to Gswip */
		ppa_memset(&q_logic, 0, sizeof(q_logic));
		q_logic.q_id = dpcon->egp[1].qid;
		/* physical to logical qid */
		if (dp_qos_get_q_logic(&q_logic, 0) == DP_FAILURE) {
			dbg("%s:%d ERROR Failed to Logical Queue Id\n", __func__, __LINE__);
			return PPA_FAILURE;
		}
		g_gswip_qid = q_logic.q_logic_id;
	}
	return g_gswip_qid;
}

static inline uint32_t lgm_get_session_color(struct uc_session_node *p_item)
{
	return PP_COLOR_GREEN;; /*FIXME: 1 = green, 2 = orange, 3 = red */
}

static inline uint16_t get_cpu_portinfo(void)
{
	/*TBD: this api will be implemented by dp later to return all the 8 CPU GPIds and qids*/
	return 16;
}

static inline uint16_t get_cpu_qid(void)
{
	/*TBD: this api shall call dp to retrieve the correct CPU queueid*/
	return 2;
}

static int mcdev_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	consume_skb(skb);
	return NETDEV_TX_OK;
}

static struct net_device_ops mcdev_ops = {
	.ndo_start_xmit	= mcdev_xmit,

};

static void mcdev_setup(struct net_device *dev)
{
	ether_setup(dev);/* assign some members */
	return;
}

/*Calback invoked by dp when packets are received on g_mc_gpid */
int32_t mc_dp_rx_handler(struct net_device *rxif, struct net_device *txif,
	struct sk_buff *skb, int32_t len)
{
	struct pp_desc *ppdesc = NULL;
	int16_t groupid = -1, dev_idx = -1;
	PPA_NETIF *tx_netif = NULL;

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);

	/*1. Call the parsing RX hook for the skb*/
	pktprs_do_parse(skb, NULL, PKTPRS_ETH_RX);

	/*2. Read the ud parameters from the descriptor*/
	/* Based on the mc groupid and dev_idx we need to find the eg_netdev from the mc_db*/
	ppdesc = pp_pkt_desc_get(skb);
	if (ppdesc) {
		groupid = ppdesc->ps & MC_GRP_MASK; /*BITS: [8:0] */
		dev_idx = (ppdesc->ps & MC_DST_MASK) >> 18; /* BITS: [18:21] */
	}

	spin_lock_bh(&g_hal_mc_db_lock);
	if (((groupid > 0) && (groupid < MAX_MC_GROUP_ENTRIES)) && mc_db[groupid].used
		&& ((dev_idx >= 0) && (dev_idx < MAX_MC_CLIENT_PER_GRP))) {
			tx_netif = mc_db[groupid].dst[dev_idx].netdev;
	}
	spin_unlock_bh(&g_hal_mc_db_lock);

	/*3. set skb->dev as the eg_netdev and call dev_queue_xmit*/
	/* parsing driver's TX hook will be invoked automatically*/
	if (tx_netif) {
		skb->dev = tx_netif;
		skb->pkt_type = PACKET_OUTGOING;
#if IS_ENABLED(CONFIG_MCAST_HELPER)
		mcast_helper_set_skb_gid(skb, groupid);
#endif
		dev_queue_xmit(skb);
	} else {
		consume_skb(skb);
	}

	return PPA_SUCCESS;
}

static dp_cb_t mc_dp_cb = {
	.rx_fn = mc_dp_rx_handler,
};

static inline int32_t init_tdox_nf(void)
{
	int32_t ret = PPA_SUCCESS;
	struct pp_nf_info nf_info = {0};
	struct dp_spl_cfg dp_con = {0};
	struct dp_qos_q_logic q_logic = {0};

	ppa_memset(&g_tdox_nf, 0, sizeof(g_tdox_nf));

	/*dp connection for TDOX uC */
	dp_con.flag = 0;/*DP_F_REGISTER;*/
	dp_con.type = DP_SPL_PP_NF;
	dp_con.f_subif = 1;
	dp_con.f_gpid = 0;

	if ((ret = dp_spl_conn(0, &dp_con))) {
		dbg("Regsiter spl conn for TDOX failed\n");
		return PPA_FAILURE;
	}
	g_tdox_nf.uc_id = dp_con.spl_id;

	dbg("%s %d dp_spl_conn success dp_con.gpid=%d, dp_con.spl_id=%d, dp_con.egp[0].qid=%d, dp_con.igp[0].egp.qid=%d\n",
		__FUNCTION__, __LINE__,dp_con.gpid, dp_con.spl_id,
		dp_con.egp[0].qid, dp_con.egp[1].qid);
	/*******************************************************/

	g_tdox_nf.gpid = dp_con.gpid;

	/* Egress port qid */
	q_logic.q_id = dp_con.egp[0].qid;

	/* physical to logical qid */
	if (dp_qos_get_q_logic(&q_logic, 0) == DP_FAILURE) {
		dbg("%s:%d ERROR Failed to Logical Queue Id\n",
			__func__, __LINE__);
		return PPA_FAILURE;
	}

	nf_info.pid = g_tdox_nf.gpid;
	nf_info.q = g_tdox_nf.qid = q_logic.q_logic_id;

#if IS_ENABLED(LITEPATH_HW_OFFLOAD)
	nf_info.pid = ppa_get_lp_gpid();
	nf_info.subif = ppa_get_lp_subif();

	/* cpu qid for lro */
	q_logic.q_id = get_cpu_qid();

	/* physical to logical qid */
	if (dp_qos_get_q_logic(&q_logic, 0) == DP_FAILURE) {
		pr_info("%s:%d ERROR Failed to Logical Queue Id\n", __func__, __LINE__);
		return PPA_FAILURE;
	}

	nf_info.cycl2_q = q_logic.q_logic_id;
#endif

	dbg("%s %d calling pp_nf_set gpid=%d qid=%d cycl2_q=%d\n",
		__FUNCTION__, __LINE__, nf_info.pid, nf_info.q, nf_info.cycl2_q);

	/*Setup the uC path */
	if ((ret = pp_nf_set(PP_NF_TURBODOX, &nf_info, NULL)))
		dbg("pp_nf_set failed for PP_NF_TURBODOX\n");

	return ret;
}

static inline int32_t init_mc_nf(void)
{
	int32_t ret = PPA_SUCCESS;
	struct pp_nf_info nf_info = {0};
	struct dp_spl_cfg dp_con = {0};
	struct dp_qos_q_logic q_logic = {0};
	struct pp_port_cfg pcfg = {0};
	struct mc_dev_priv *priv = NULL;

	dbg("%s %d\n",__FUNCTION__,__LINE__);

	ppa_memset(&g_mcast_nf, 0, sizeof(g_mcast_nf));
	/*Allocate netdevice */

	g_mcast_nf.dev = alloc_netdev(sizeof(struct mc_dev_priv),
				"mcdev0", NET_NAME_UNKNOWN, mcdev_setup);
	if (!g_mcast_nf.dev) {
		dbg("alloc_netdev failed for mcdev0\n");
		return PPA_FAILURE;
	}

	priv = netdev_priv(g_mcast_nf.dev);
	priv->owner = THIS_MODULE;

	g_mcast_nf.dev->netdev_ops = &mcdev_ops;
	/*Register netdevice*/
	if (register_netdev(g_mcast_nf.dev)) {
		free_netdev(g_mcast_nf.dev);
		g_mcast_nf.dev = NULL;
		dbg("register device \"mcdev0\" failed\n");
		return PPA_FAILURE;
	}
	/*call the dp to allocate special connection */
	/*******************************************************/

	/*dp connection for multicast uC */
	dp_con.flag = 0;/*DP_F_REGISTER;*/
	dp_con.type = DP_SPL_PP_NF;
	dp_con.f_subif = 1;
	dp_con.f_gpid = 1;

	/*assign the netdevice */
	dp_con.dev = g_mcast_nf.dev;

	/*callback to be invoked by dp when packet is received for this GPID*/
	dp_con.dp_cb = &mc_dp_cb;

	if ((ret = dp_spl_conn(0, &dp_con))) {
		dbg("Regsiter spl conn for mc failed\n");
		return PPA_FAILURE;
	}

	/*enable rp_rx*/
	if ((ret = dp_rx_enable(g_mcast_nf.dev, g_mcast_nf.dev->name, 1))) {
		dbg("Enable rx_fn for mc failed\n");
		return PPA_FAILURE;
	}

	/*******************************************************/
	dbg("%s %d dp_spl_conn success dp_con.gpid=%d, dp_con.subif=%d dp_con.spl_id=%d, dp_con.egp[0].qid=%d, dp_con.egp[1].qid=%d\n",
		__FUNCTION__, __LINE__,dp_con.gpid, dp_con.subif, dp_con.spl_id, dp_con.egp[0].qid, dp_con.egp[1].qid);

	/*Store the gpid and uc_id*/
	g_mcast_nf.uc_id = dp_con.spl_id;
	g_mcast_nf.gpid = dp_con.gpid;
	g_mcast_nf.subif = (dp_con.subif >> CPU_PORT_WLAN_BIT_MODE) & 0X0F; /*remove 9 bits of mc groupid*/

	/*Get the port settings and change the ingress classification parameters*/
	if ((ret=pp_port_get(g_mcast_nf.gpid, &pcfg))) {
		dbg("pp_port_get failed in %s %d\n", __FUNCTION__, __LINE__);
		return PPA_FAILURE;
	}

	/*Fields to copy from STW*/
	pcfg.rx.cls.n_flds = 2;
	pcfg.rx.cls.cp[0].stw_off = 0;/* multicast group index in ps0 form bit 0*/
	pcfg.rx.cls.cp[0].copy_size = 9;/* 9 bits field */
	pcfg.rx.cls.cp[1].stw_off = 18;/* multicast dst bitmap in ps0 from bit 18 */
	pcfg.rx.cls.cp[1].copy_size = 4;/* 4 bits field */

	/*Set the modified port configuration */
	if ((ret=pp_port_update(g_mcast_nf.gpid, &pcfg))) {
		dbg("pp_port_update failed in %s %d\n", __FUNCTION__, __LINE__);
		return PPA_FAILURE;
	}

	/*Egress port qid*/;
	q_logic.q_id = dp_con.egp[0].qid;

	/* physical to logical qid */
	if (dp_qos_get_q_logic(&q_logic, 0) == DP_FAILURE) {
		dbg("%s:%d ERROR Failed to Logical Queue Id\n", __func__, __LINE__);
		return PPA_FAILURE;
	}

	/*Store the logical qid */
	g_mcast_nf.qid = q_logic.q_logic_id;

	nf_info.cycl2_q = get_gswip_qid(&dp_con);
	nf_info.pid = g_mcast_nf.gpid;
	nf_info.q = g_mcast_nf.qid;

	dbg("%s %d calling pp_nf_set gpid=%d qid=%d cycl2_qid=%d\n", __FUNCTION__, __LINE__, nf_info.pid, nf_info.q, nf_info.cycl2_q);

	/*Setup the uC path */
	if ((ret = pp_nf_set(PP_NF_MULTICAST, &nf_info, NULL)))
		dbg("pp_nf_set failed for PP_NF_MULTICAST\n");

	dbg("%s %d g_mcast_nf.gpid=%d, dp_con.subif=%d, dp_con.spl_id=%d, g_mcast_nf.qid=%d, g_gswip_qid=%d\n",
		__FUNCTION__, __LINE__, g_mcast_nf.gpid, dp_con.subif, dp_con.spl_id, g_mcast_nf.qid, g_gswip_qid);

	return ret;
}

static int init_frag_nf(void)
{
	int32_t ret = PPA_SUCCESS;
	struct pp_nf_info nf_info = {0};
	struct dp_spl_cfg dp_con = {0};
	struct dp_qos_q_logic q_logic = {0};

	/*TBD: remove next line when fragmentor in implemented in pp*/
	ppa_memset(&g_frag_nf, 0, sizeof(g_frag_nf));

	/*dp connection for fragmenter uC */
	dp_con.flag = 0;/*DP_F_REGISTER;*/
	dp_con.type = DP_SPL_PP_NF;
	dp_con.f_subif = 1;
	dp_con.f_gpid = 0;

	if ((ret = dp_spl_conn(0, &dp_con))) {
		dbg("Regsiter spl conn for fragmenter failed\n");
		return PPA_FAILURE;
	}
	g_frag_nf.uc_id = dp_con.spl_id;

	dbg("%s %d dp_spl_conn success dp_con.gpid=%d, dp_con.spl_id=%d, dp_con.egp[0].qid=%d, dp_con.igp[0].egp.qid=%d\n",
		__FUNCTION__, __LINE__,dp_con.gpid, dp_con.spl_id, dp_con.egp[0].qid, dp_con.egp[1].qid);
	/*******************************************************/

	g_frag_nf.gpid = dp_con.gpid;

	/*Egress port qid*/
	q_logic.q_id = dp_con.egp[0].qid;

	/* physical to logical qid */
	if (dp_qos_get_q_logic(&q_logic, 0) == DP_FAILURE) {
		dbg("%s:%d ERROR Failed to Logical Queue Id\n", __func__, __LINE__);
		return PPA_FAILURE;
	}

	nf_info.pid = g_frag_nf.gpid;
	nf_info.q = g_frag_nf.qid = q_logic.q_logic_id;

	nf_info.cycl2_q = get_gswip_qid(&dp_con);
	dbg("%s %d calling pp_nf_set gpid=%d qid=%d cycl2_qid=%d\n", __FUNCTION__, __LINE__, nf_info.pid, nf_info.q, nf_info.cycl2_q);

	/*Setup the uC path */
	if ((ret = pp_nf_set(PP_NF_FRAGMENTER, &nf_info, NULL)))
		dbg("pp_nf_set failed for PP_NF_FRAGMENTER\n");

	ppa_memset(&g_reas_nf, 0, sizeof(g_reas_nf));
	ppa_memset(&dp_con, 0, sizeof(dp_con));
	ppa_memset(&q_logic, 0, sizeof(q_logic));
	ppa_memset(&nf_info, 0, sizeof(nf_info));

	/*dp connection for reassembler uC */
	dp_con.flag = 0;/*DP_F_REGISTER;*/
	dp_con.type = DP_SPL_PP_NF;
	dp_con.f_subif = 1;
	dp_con.f_gpid = 0;

	if ((ret = dp_spl_conn(0, &dp_con))) {
		dbg("Regsiter spl conn for reassmbler failed\n");
		return PPA_FAILURE;
	}
	g_reas_nf.uc_id = dp_con.spl_id;

	dbg("%s %d dp_spl_conn success dp_con.gpid=%d, dp_con.spl_id=%d, dp_con.egp[0].qid=%d, dp_con.igp[0].egp.qid=%d\n",
		__FUNCTION__, __LINE__,dp_con.gpid, dp_con.spl_id, dp_con.egp[0].qid, dp_con.egp[1].qid);
	/*******************************************************/

	g_reas_nf.gpid = dp_con.gpid;

	/*Egress port qid*/
	q_logic.q_id = dp_con.egp[0].qid;

	/* physical to logical qid */
	if (dp_qos_get_q_logic(&q_logic, 0) == DP_FAILURE) {
		dbg("%s:%d ERROR Failed to Logical Queue Id\n", __func__, __LINE__);
		return PPA_FAILURE;
	}

	nf_info.pid = g_reas_nf.gpid;
	nf_info.q = g_reas_nf.qid = q_logic.q_logic_id;

	nf_info.cycl2_q = get_gswip_qid(&dp_con);
	dbg("%s %d calling pp_nf_set gpid=%d qid=%d cycl2_qid=%d\n", __FUNCTION__, __LINE__, nf_info.pid, nf_info.q, nf_info.cycl2_q);

	/*Setup the uC path */
	if ((ret = pp_nf_set(PP_NF_REASSEMBLY, &nf_info, NULL)))
		dbg("pp_nf_set failed for PP_NF_REASSEMBLY\n");

	return ret;
}

static int init_remarking_nf(void)
{
	int32_t ret = PPA_SUCCESS;
	struct pp_nf_info nf_info = {0};
	struct dp_spl_cfg dp_con = {0};
	struct dp_qos_q_logic q_logic = {0};

	ppa_memset(&g_remrk_nf, 0, sizeof(g_remrk_nf));

	/* dp connection for remarking uC */
	dp_con.flag = 0;/*DP_F_REGISTER;*/
	dp_con.type = DP_SPL_PP_NF;
	dp_con.f_subif = 1;
	dp_con.f_gpid = 0;

	if ((ret = dp_spl_conn(0, &dp_con))) {
		dbg("Regsiter spl conn for remarking failed\n");
		return PPA_FAILURE;
	}
	g_remrk_nf.uc_id = dp_con.spl_id;

	dbg("%s %d dp_spl_conn success dp_con.gpid=%d, dp_con.spl_id=%d, dp_con.egp[0].qid=%d, dp_con.igp[0].egp.qid=%d\n",
		__FUNCTION__, __LINE__,dp_con.gpid, dp_con.spl_id,
		dp_con.egp[0].qid, dp_con.egp[1].qid);
	/*******************************************************/

	g_remrk_nf.gpid = dp_con.gpid;

	/* Egress port qid*/
	q_logic.q_id = dp_con.egp[0].qid;

	/* physical to logical qid */
	if (dp_qos_get_q_logic(&q_logic, 0) == DP_FAILURE) {
		dbg("%s:%d ERROR Failed to Logical Queue Id\n",
		    __func__, __LINE__);
		return PPA_FAILURE;
	}

	nf_info.pid = g_remrk_nf.gpid;
	nf_info.q = g_remrk_nf.qid = q_logic.q_logic_id;

	dbg("%s %d calling pp_nf_set gpid=%d qid=%d\n", __FUNCTION__, __LINE__,
 	    nf_info.pid, nf_info.q);

	/*Setup the uC path */
	if ((ret = pp_nf_set(PP_NF_REMARKING, &nf_info, NULL)))
		dbg("pp_nf_set failed for PP_NF_REMARKING\n");

	return ret;
}

#if !IS_ENABLED(CONFIG_INTEL_VPN) && !IS_ENABLED(CONFIG_MXL_VPN)
static int init_ipsec_lld_nf(void)
{
	int32_t ret = PPA_SUCCESS;
	struct pp_nf_info nf_info = {0};
	struct dp_spl_cfg dp_con = {0};
	struct dp_qos_q_logic q_logic = {0};

	ppa_memset(&g_lld_nf, 0, sizeof(g_lld_nf));

	/* dp connection for lld uC */
	dp_con.flag = 0;/*DP_F_REGISTER;*/
	dp_con.type = DP_SPL_PP_NF;
	dp_con.f_subif = 1;
	dp_con.f_gpid = 0;

	if ((ret = dp_spl_conn(0, &dp_con))) {
		dbg("Regsiter spl conn for ipsec_lld failed\n");
		return PPA_FAILURE;
	}
	g_lld_nf.uc_id = dp_con.spl_id;

	dbg("%s %d dp_spl_conn success dp_con.gpid=%d, dp_con.spl_id=%d, dp_con.egp[0].qid=%d, dp_con.igp[0].egp.qid=%d\n",
		__FUNCTION__, __LINE__,dp_con.gpid, dp_con.spl_id,
		dp_con.egp[0].qid, dp_con.egp[1].qid);
	/*******************************************************/

	g_lld_nf.gpid = dp_con.gpid;

	/* Egress port qid*/
	q_logic.q_id = dp_con.egp[0].qid;

	/* physical to logical qid */
	if (dp_qos_get_q_logic(&q_logic, 0) == DP_FAILURE) {
		dbg("%s:%d ERROR Failed to Logical Queue Id\n",
		    __func__, __LINE__);
		return PPA_FAILURE;
	}

	nf_info.pid = g_lld_nf.gpid;
	nf_info.q = g_lld_nf.qid = q_logic.q_logic_id;

	dbg("%s %d calling pp_nf_set gpid=%d qid=%d\n", __FUNCTION__, __LINE__,
 	    nf_info.pid, nf_info.q);

	/*Setup the uC path */
	if ((ret = pp_nf_set(PP_NF_IPSEC_LLD, &nf_info, NULL)))
		dbg("pp_nf_set failed for PP_NF_IPSEC_LLD\n");

	return ret;
}
#endif

#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
static inline int32_t ppa_vpn_parse_rx(struct sk_buff *skb,
				       struct net_device *dev,
				       uint16_t tunnel_id)
{
	PP_IPSEC_TUN_NODE *tunn_info;
	int32_t ret = PPA_SUCCESS;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct pppoe_hdr *ppphdr = NULL;
	struct pktprs_hdr *rx_hdr;
	struct ip_esp_hdr *esphdr;
	uint16_t offset = 0;
	uint16_t totlen = 0;
	uint8_t strip_sz = 0;
	uint8_t nhdr_sz = 0;

	dbg("received skb====> dev=%s",dev?dev->name:"null");
	dumpskb(skb->data, 64, 1);

	spin_lock_bh(&g_tun_db_lock);
	tunn_info = &ipsec_tun_db[tunnel_id];
	if (!(!list_empty(&tunn_info->sessions) && tunn_info->is_inbound))
		goto exit;

	skb_reset_mac_header(skb);
	skb->dev = dev;

	/* Call learning ingress for 2nd round session rx packet */
	pktprs_do_parse(skb, dev, PKTPRS_ETH_RX);
	rx_hdr = pktprs_skb_hdr_get(skb);
	if (!rx_hdr) {
		pr_err_ratelimited("Failed to get RX pktprs header\n");
		ret = PPA_FAILURE;
		goto exit;
	}

	/* is this really possible??, the VPN FW always removes that! */
	if (PKTPRS_IS_ESP(rx_hdr, PKTPRS_HDR_LEVEL0)) {
		pr_err_ratelimited("ESP header back from VPN FW, aborting packet\n");
		ret = PPA_FAILURE;
		goto exit;
	}

	if (!PKTPRS_IS_IP(rx_hdr, PKTPRS_HDR_LEVEL0)) {
		pr_err_ratelimited("NO valid IP header in packet, aborting packet\n");
		ret = PPA_FAILURE;
		goto exit;
	}

	/* in trasport mode the ip total length is wrong cause it
	 * wasn't updated after being decrypted by VPN FW
	 * so we calculate it with the skb->len and the ip header
	 * offset which is true for all cases.
	 */
	totlen = skb->len;
	/* Get the ingress ip length */
	if (PKTPRS_IS_IPV6(rx_hdr, PKTPRS_HDR_LEVEL0))
		totlen -= pktprs_ip_hdr_sz(rx_hdr, PKTPRS_HDR_LEVEL0);
	else if (PKTPRS_IS_IPV4(rx_hdr, PKTPRS_HDR_LEVEL0))
		totlen -= pktprs_ip_hdr_off(rx_hdr, PKTPRS_HDR_LEVEL0);

	/* 2. Restore the original ESP header
	 * The skb->data is currently pointing to the begining of
	 * Ethernet header.
	 * Set the skb->data to the point where the ESP header
	 * can be copied
	 */

	/* header size to restore */
	nhdr_sz = tunn_info->hdr_len + tunn_info->iv_sz;
	/* size to strip from current header */
	if (tunn_info->trns_mode)
		/* in transport mode we string the outer IP and ETH */
		strip_sz = pktprs_ip_hdr_sz(rx_hdr, PKTPRS_HDR_LEVEL0);
	else
		/* in tunnel mode we strip only the ETH header */
		strip_sz = pktprs_ip_hdr_off(rx_hdr, PKTPRS_HDR_LEVEL0);

	/* total size to add to the packet */
	offset = nhdr_sz - strip_sz;

	dbg("skb->len %u, totlen %u, tunn_info->hdr_len %u, tunn_info->iv_sz %u, nhdr_sz %u, strip_sz %u, offset %u",
	    skb->len, totlen, tunn_info->hdr_len, tunn_info->iv_sz, nhdr_sz,
	    strip_sz, offset);

	/* Verify the skb has enough headroom */
	if (offset > 0) {
		if (skb_headroom(skb) > offset) {
			skb_push(skb, offset);
		} else {
			pr_err_ratelimited("%s:%d: Not enough headroom %d!!\n",
				__func__, __LINE__, offset);
			ret = PPA_FAILURE;
			goto exit;
		}
	}

	/*Copy the stored ESP header */
	ppa_memcpy(skb->data, tunn_info->hdr, tunn_info->hdr_len);
	/*Set the IV field to 0*/
	ppa_memset(skb->data + tunn_info->hdr_len, 0, tunn_info->iv_sz);

	skb_set_mac_header(skb, 0);
	skb_set_network_header(skb, tunn_info->ip_offset);

	totlen += (nhdr_sz - tunn_info->strip_sz);
	if (tunn_info->ipv6) {
		ip6h = ipv6_hdr(skb);
		ip6h->payload_len = htons(totlen);
	} else {
		iph = ip_hdr(skb);
		iph->tot_len = htons(totlen);

		/* calculate header checksum*/
		iph->check = 0;
		iph->check = ip_fast_csum((const void *)iph, iph->ihl);
	}

	/* update the sequence number so xfrm will not drop the packet */
	esphdr = (struct ip_esp_hdr *)(skb_mac_header(skb) +
					tunn_info->esp_offset);
	esphdr->seq_no = htonl(tunn_info->seq++);

	if (tunn_info->pppoe) {
		/* update ppp header with length of the ppp payload */
		ppphdr = (struct pppoe_hdr *)(skb_network_header(skb) -
						PPPOE_HLEN);
		/* add the outer ipv6 header length as it is not
		 * included in the totlen
		 */
		if (tunn_info->ipv6)
			totlen += sizeof(struct ipv6hdr);
		/* ip payload length + ppp header length */
		ppphdr->length = htons(totlen + 2);
	}

	dbg("transmit skb====> dev=%s", dev ? dev->name : "null");
	dumpskb(skb->data, 128, 1);

exit:
	spin_unlock_bh(&g_tun_db_lock);
	return ret;
}

static inline int32_t ppa_vpn_tunn_del(uint16_t tunnel_id)
{
	struct uc_session_node *p_item, *p;

	/*check if the tunnel table entry is free */
	spin_lock_bh(&g_tun_db_lock);
	/* delete all related sessions */
	list_for_each_entry_safe(p_item, p, &ipsec_tun_db[tunnel_id].sessions, tun_node) {
		list_del_init(&p_item->tun_node);
		del_routing_session_cb(p_item);
	}
	INIT_LIST_HEAD(&ipsec_tun_db[tunnel_id].sessions);
	ipsec_tun_db[tunnel_id].valid = false;
	spin_unlock_bh(&g_tun_db_lock);

	return PPA_SUCCESS;
}

static int init_vpn_offload(void)
{
	struct pp_nf_info nf_info = {0};
	struct dp_spl_cfg dp_con = {0};
	struct dp_spl_cfg vpn_con = {0};
	struct dp_qos_q_logic q_logic = {0};
	int i, ret = PPA_SUCCESS;
	struct mc_dev_priv *priv = NULL;
	struct dp_queue_map_set q_map = {0};
	uint16_t vpn_gpid;
#if IS_ENABLED(CONFIG_INTEL_VPN)
	struct intel_vpn_ops *vpn_ops = dp_get_vpn_ops(0);
#elif IS_ENABLED(CONFIG_MXL_VPN)
	struct mxl_vpn_ops *vpn_ops = dp_get_vpn_ops(0);
#endif

	if (!vpn_ops)
		return PPA_FAILURE;

	/* initialize the VPN assist */
	ppa_memset(&g_vpn_nf, 0, sizeof(g_vpn_nf));

	/*Allocate netdevice */
	/*using lpdev structures as this is a dummy net device */
	g_vpn_nf.dev = alloc_netdev(sizeof(struct mc_dev_priv),
			"vpnnf_dev0", NET_NAME_UNKNOWN, mcdev_setup);
	if (!g_vpn_nf.dev) {
		dbg("alloc_netdev failed for vpnnf_dev0\n");
		return PPA_FAILURE;
	}

	priv = netdev_priv(g_vpn_nf.dev);
	priv->owner = THIS_MODULE;

	g_vpn_nf.dev->netdev_ops = &mcdev_ops;
	/*Register netdevice*/
	if (register_netdev(g_vpn_nf.dev)) {
		free_netdev(g_vpn_nf.dev);
		g_vpn_nf.dev = NULL;
		dbg("register device \"vpnnf_dev0\" failed\n");
		return PPA_FAILURE;
	}

	/*Get the VPNA connection parameters */
	dp_spl_conn_get(0, DP_SPL_VPNA, &vpn_con, 1);
	g_vpna_conn.dev = vpn_con.dev;
	q_logic.q_id = vpn_con.egp[0].qid;

	if (dp_qos_get_q_logic(&q_logic, 0) == DP_SUCCESS) {
		g_vpna_conn.subif = vpn_con.subif >> 9;
		g_vpna_conn.gpid = vpn_con.gpid;
		g_vpna_conn.qid = q_logic.q_logic_id;
	} else {
		dbg("%s:%d ERROR Failed to VPN Q id\n", __func__, __LINE__);
	}

	/*assign the netdevice */
	dp_con.dev = g_vpn_nf.dev;

	/*callback to be invoked by dp when packet is received for this GPID*/
	/*register the callback registered by the VPN adaptor driver */
	dp_con.dp_cb = vpn_con.dp_cb;

	/*dp connection for vpn assist uC */
	dp_con.flag = 0;/*DP_F_REGISTER;*/
	dp_con.type = DP_SPL_PP_NF;
	dp_con.f_subif = 1;
	dp_con.f_gpid = 1;

	if ((ret = dp_spl_conn(0, &dp_con))) {
		dbg("Regsiter spl conn for mc failed\n");
		return PPA_FAILURE;
	}
	g_vpn_nf.uc_id = dp_con.spl_id;

	dbg("%s %d dp_spl_conn success dp_con.gpid=%d, dp_con.spl_id=%d, dp_con.egp[0].qid=%d, dp_con.igp[0].egp.qid=%d\n",
		__FUNCTION__, __LINE__,dp_con.gpid, dp_con.spl_id, dp_con.egp[0].qid, dp_con.egp[1].qid);
	/*******************************************************/

	g_vpn_nf.gpid = dp_con.gpid;
	g_vpn_nf.subif = dp_con.subif >> 9;

	/* Setup Queue map table for vpn assist tx */
	q_map.q_id = dp_con.egp[0].qid;		/* Gswip Qid */
	q_map.map.dp_port = dp_con.dp_port;	/*CPU portid*/
	q_map.map.subif = dp_con.subif;		/*Subif id */
	q_map.mask.flowid = 1;			/* Flowid dont care*/
	q_map.mask.egflag = 1;			/* Egress flag dont care*/

	if (dp_queue_map_set(&q_map, 0) == DP_FAILURE)
		dbg("dp_queue_map_set failed for Queue [%d]\n", dp_con.egp[1].qid);

	/*Egress port qid*/
	q_logic.q_id = dp_con.egp[0].qid;

	/* physical to logical qid */
	if (dp_qos_get_q_logic(&q_logic, 0) == DP_FAILURE) {
		dbg("%s:%d ERROR Failed to Logical Queue Id\n", __func__, __LINE__);
		return PPA_FAILURE;
	}

	/* PP egress uC should send the ESP packets to a 2nd round in PP
	 * over the VPN FW gpid and subif
	 */
	nf_info.pid = vpn_con.gpid;
	nf_info.subif = vpn_con.subif >> 9;
	nf_info.q = g_vpn_nf.qid = q_logic.q_logic_id;
	vpn_gpid = g_vpn_nf.gpid;

	nf_info.cycl2_q = get_gswip_qid(&dp_con);
	dbg("%s %d calling pp_nf_set gpid=%d qid=%d cycl2_qid=%d, vpn_gpid=%d\n",
	    __FUNCTION__, __LINE__, nf_info.pid, nf_info.q, nf_info.cycl2_q,
	    vpn_gpid);

	/*Setup the uC path */
	if ((ret = pp_nf_set(PP_NF_IPSEC_LLD, &nf_info, &vpn_gpid)))
		dbg("pp_nf_set failed for PP_NF_IPSEC_LLD\n");

	/*initalize the tunnel_db*/
	spin_lock_init(&g_tun_db_lock);
	ppa_memset(&ipsec_tun_db, 0, sizeof(ipsec_tun_db));

	ppa_vpn_ig_lrn_hook   = ppa_vpn_parse_rx;
	ppa_vpn_tunn_del_hook = ppa_vpn_tunn_del;

	for (i = 0; i < ARRAY_SIZE(ipsec_tun_db); i++)
		INIT_LIST_HEAD(&ipsec_tun_db[i].sessions);

	return ret;
}

static inline void uninit_vpn_offload(void)
{
	struct dp_spl_cfg dp_con={0};

	dp_con.flag = DP_F_DEREGISTER;
	dp_con.type = DP_SPL_PP_NF;
	dp_con.spl_id = g_vpn_nf.uc_id;

	if (dp_spl_conn(0, &dp_con)) {
		dbg("Deregister of dp spl conn for vpn failed\n");
	}

	ppa_vpn_ig_lrn_hook   = NULL;
	ppa_vpn_tunn_del_hook = NULL;
}
#endif /* CONFIG_INTEL_VPN || CONFIG_MXL_VPN */

static inline void uninit_mc_nf(void)
{
	/*******************************************************/
	struct dp_spl_cfg dp_con={0};

	dp_con.flag = DP_F_DEREGISTER;
	dp_con.type = DP_SPL_PP_NF;
	dp_con.spl_id = g_mcast_nf.uc_id;

	if (dp_spl_conn(0, &dp_con)) {
		dbg("Deregister of dp spl conn for mc failed\n");
	}
	/*******************************************************/
}

static inline void uninit_tdox_nf(void)
{
	struct dp_spl_cfg dp_con={0};

	dp_con.flag = DP_F_DEREGISTER;
	dp_con.type = DP_SPL_PP_NF;
	dp_con.spl_id = g_tdox_nf.uc_id;

	if (dp_spl_conn(0, &dp_con))
		dbg("Deregister of dp spl conn for mc failed\n");

}

static inline void uninit_remarking_nf(void)
{
	struct dp_spl_cfg dp_con={0};

	dp_con.flag = DP_F_DEREGISTER;
	dp_con.type = DP_SPL_PP_NF;
	dp_con.spl_id = g_remrk_nf.uc_id;

	if (dp_spl_conn(0, &dp_con))
		dbg("Deregister of dp spl conn for remarking failed\n");
}

#if !IS_ENABLED(CONFIG_INTEL_VPN) && !IS_ENABLED(CONFIG_MXL_VPN)
static inline void uninit_ipsec_lld_nf(void)
{
	struct dp_spl_cfg dp_con={0};

	dp_con.flag = DP_F_DEREGISTER;
	dp_con.type = DP_SPL_PP_NF;
	dp_con.spl_id = g_lld_nf.uc_id;

	if (dp_spl_conn(0, &dp_con))
		dbg("Deregister of dp spl conn for lld failed\n");
}
#endif

static inline void uninit_frag_nf(void)
{
	struct dp_spl_cfg dp_con={0};

	dp_con.flag = DP_F_DEREGISTER;
	dp_con.type = DP_SPL_PP_NF;
	dp_con.spl_id = g_frag_nf.uc_id;

	/*Workaround to disable the fragmenter and reassembler
	until the performance issue is fixed*/
	return;

	if (dp_spl_conn(0, &dp_con)) {
		dbg("Deregister of dp spl conn for fragmenter failed\n");
	}

	dp_con.spl_id = g_reas_nf.uc_id;

	if (dp_spl_conn(0, &dp_con)) {
		dbg("Deregister of dp spl conn for reassembly failed\n");
	}
/*******************************************************/
}

static int init_if_stats(void)
{
	/*initialize the if_stats DB */
	if_stats_db = ppa_malloc(sizeof(struct if_stats));
	if (!if_stats_db) {
		pr_err("Failed to allocate if_stats db\n");
		return PPA_FAILURE;
	}
	memset(if_stats_db, 0, sizeof(struct if_stats));

	/*Init the if_stats db lock*/
	spin_lock_init(&if_stats_db->lock);
	return PPA_SUCCESS;
}

static void uninit_if_stats(void)
{
	int indx;
	struct if_info *ifinfo;

	spin_lock_bh(&if_stats_db->lock);
	for_each_set_bit(indx, if_stats_db->if_bitmap, PP_HAL_MAX_IFS_NUM) {
		ifinfo = &if_stats_db->if_info[indx];
		if (!refcount_dec_and_test(&ifinfo->ref_cnt)) {
			dbg("if_stats_db force cleanup for dev:%s refcnt:%d\n",
			    ppa_get_netif_name(ifinfo->dev),
			    refcount_read(&ifinfo->ref_cnt));
		}
		free_if_stats_idx(indx);
	}
	spin_unlock_bh(&if_stats_db->lock);

	ppa_free(if_stats_db);
	if_stats_db = NULL;
}

#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
#if IS_ENABLED(CONFIG_INTEL_VPN)
static inline bool is_vpn_assist(struct intel_vpn_tunnel_info *tun_info)
#elif IS_ENABLED(CONFIG_MXL_VPN)
static inline bool is_vpn_assist(struct mxl_vpn_tunnel_info *tun_info)
#endif
{
	return tun_info->mode == VPN_MODE_TRANSPORT;
}

/**
 * @brief adding the ipsec tunnel to the local database
 *        1. update the ref count if entry already exist
 *        2. free the old header if exist
 *        3. reset the entry
 *        4. increment the ref count
 *        5. save the related p_item
 * @param p_item session ndoe
 */
static void ipsec_tunn_db_add(struct uc_session_node *p_item)
{
	/* if the tunnel already created, do nothing */
	if (!list_empty(&ipsec_tun_db[p_item->tunnel_idx].sessions))
		return;

	/*if this index was in use earlier free it*/
	if (ipsec_tun_db[p_item->tunnel_idx].hdr)
		ppa_free(ipsec_tun_db[p_item->tunnel_idx].hdr);

	ppa_memset(&ipsec_tun_db[p_item->tunnel_idx], 0,
		   sizeof(PP_IPSEC_TUN_NODE));

	INIT_LIST_HEAD(&ipsec_tun_db[p_item->tunnel_idx].sessions);
	ipsec_tun_db[p_item->tunnel_idx].valid = true;
}

#if IS_ENABLED(CONFIG_INTEL_VPN)
static void store_esp_tunnel_header(struct uc_session_node *p_item,
				    struct pktprs_desc *desc,
				    struct intel_vpn_tunnel_info *tunn_info)
#elif IS_ENABLED(CONFIG_MXL_VPN)
static void store_esp_tunnel_header(struct uc_session_node *p_item,
				    struct pktprs_desc *desc,
				    struct mxl_vpn_tunnel_info *tunn_info)
#endif
{
	PP_IPSEC_TUN_NODE *db_tinfo; /* db tunnel info */
	char *ptr = NULL;
	uint16_t tunnel_id = p_item->tunnel_idx;
	struct iphdr *ipv4;
	struct ipv6hdr *ipv6;
	struct ipv6_opt_hdr *ehdr;
	uint8_t nexthdr;
	uint8_t *last_nexthdr_ptr;
	uint16_t off;

	db_tinfo = &ipsec_tun_db[tunnel_id];

	spin_lock_bh(&g_tun_db_lock);
	if (db_tinfo->hdr)
		goto unlock;

	db_tinfo->is_inbound = true;
	/* Update header len */
	db_tinfo->hdr_len =
		pktprs_hdr_sz(desc->rx, PKTPRS_PROTO_ESP, PKTPRS_HDR_LEVEL0);
	db_tinfo->iv_sz = tunn_info->iv_sz;
	/* Save ESP info */
	db_tinfo->esp_offset = pktprs_hdr_off(desc->rx,
					      PKTPRS_PROTO_ESP,
					      PKTPRS_HDR_LEVEL0);
	db_tinfo->esp_hdr_len = db_tinfo->hdr_len - db_tinfo->esp_offset;
	db_tinfo->seq = ntohl(pktprs_esp_hdr(desc->rx, PKTPRS_HDR_LEVEL0)->seq_no);
	db_tinfo->seq++;

	/* Allocate memory for the tunnel header */
	db_tinfo->hdr = ppa_malloc(db_tinfo->hdr_len);
	if (!db_tinfo->hdr) {
		dbg("Header allocation failed!!");
		goto unlock;
	}

	if (tunn_info->mode == VPN_MODE_TRANSPORT) {
		db_tinfo->trns_mode = 1;
		/* in transport mode we strip the outer IP and ETH */
		db_tinfo->strip_sz = pktprs_ip_hdr_sz(desc->rx, PKTPRS_HDR_LEVEL0);
	} else {
		/* in tunnel mode we strip only the ETH header */
		db_tinfo->strip_sz = pktprs_ip_hdr_off(desc->rx, PKTPRS_HDR_LEVEL0);
	}

	/*Copy the ingress tunnel header to the buffer*/
	ptr = (char *)db_tinfo->hdr;
	ppa_memcpy(ptr, desc->rx->buf, db_tinfo->hdr_len);

	/* fix the IP header and remove fragment info if exist */
	if (PKTPRS_IS_IPV4(desc->rx, PKTPRS_HDR_LEVEL0)) {
		db_tinfo->ip_offset = pktprs_hdr_off(desc->rx,
							 PKTPRS_PROTO_IPV4,
							 PKTPRS_HDR_LEVEL0);
		ipv4 = (struct iphdr *)&ptr[db_tinfo->ip_offset];

		/*
		 * - Reset ipv4 totlen and checksum - will be updated
		 *   in dp.
		 * - Remove the frag offset indication since we want to apply
		 *   this information on the reassembled packet
		 */
		ipv4->tot_len = 0;
		ipv4->frag_off &= htons(IP_DF);
		ipv4->check = 0;
		db_tinfo->org_nexthdr = ipv4->protocol;
	} else if (PKTPRS_IS_IPV6(desc->rx, PKTPRS_HDR_LEVEL0)) {
		db_tinfo->ipv6 = true;
		db_tinfo->ip_offset = pktprs_hdr_off(desc->rx,
						     PKTPRS_PROTO_IPV6,
						     PKTPRS_HDR_LEVEL0);
		ipv6 = (struct ipv6hdr *)&ptr[db_tinfo->ip_offset];

		/* Reset ipv6 payload len - will be updated in dp */
		ipv6->payload_len = 0;

		if (!PKTPRS_IS_FRAG_OPT(desc->rx, PKTPRS_HDR_LEVEL0))
			goto check_pppoe;

		/* Remove the frag extention header */
		db_tinfo->hdr_len -= sizeof(struct frag_hdr);
		last_nexthdr_ptr = &ipv6->nexthdr;
		nexthdr = *last_nexthdr_ptr;
		off = db_tinfo->ip_offset + sizeof(struct ipv6hdr);

		while (ipv6_ext_hdr(nexthdr) && nexthdr != NEXTHDR_NONE) {
			ehdr = (struct ipv6_opt_hdr *)(ptr + off);
			if (nexthdr == NEXTHDR_FRAGMENT) {
				*last_nexthdr_ptr = ehdr->nexthdr;
				memmove(ehdr,
					ptr + off + sizeof(struct frag_hdr),
					db_tinfo->hdr_len - off);
				break;
			} else if (nexthdr == NEXTHDR_AUTH) {
				off += ipv6_authlen(ehdr);
			} else {
				off += ipv6_optlen(ehdr);
			}
			last_nexthdr_ptr = &ehdr->nexthdr;
			nexthdr = *last_nexthdr_ptr;
		}
		db_tinfo->org_nexthdr = nexthdr;
	}

check_pppoe:
	if (PKTPRS_IS_PPPOE(desc->rx, PKTPRS_HDR_LEVEL0))
		db_tinfo->pppoe = 1;

	dbg("ip_offset=%d hdr_len=%d esp_hdr_len=%d, iv_sz=%u, ipv6=%u, org_nexthdr %u\n",
	    db_tinfo->ip_offset, db_tinfo->hdr_len,
	    db_tinfo->esp_hdr_len, db_tinfo->iv_sz,
	    db_tinfo->ipv6, db_tinfo->org_nexthdr);
	dumpskb(ptr, db_tinfo->hdr_len, 1);

unlock:
	spin_unlock_bh(&g_tun_db_lock);
}

static inline bool is_ipsec_tunnel_id_valid(uint32_t tunidx)
{
	return (tunidx < ARRAY_SIZE(ipsec_tun_db));
}

#if IS_ENABLED(CONFIG_INTEL_VPN)
static int get_vpn_tun_params(uint32_t spi,
			       struct intel_vpn_tunnel_info *tun_info)
#elif IS_ENABLED(CONFIG_MXL_VPN)
static int get_vpn_tun_params(uint32_t spi,
			       struct mxl_vpn_tunnel_info *tun_info)
#endif
{
	struct dp_qos_q_logic q_logic = {0};
#if IS_ENABLED(CONFIG_INTEL_VPN)
	struct intel_vpn_ops *vpn_ops = dp_get_vpn_ops(0);
#elif IS_ENABLED(CONFIG_MXL_VPN)
	struct mxl_vpn_ops *vpn_ops = dp_get_vpn_ops(0);
#endif

	int ret;

	if (!vpn_ops)
		return -EINVAL;

	ret = vpn_ops->get_tunnel_info(vpn_ops->dev, spi, tun_info);
	if (ret)
		/* failed to find tunnel with specified spi, probably
		 * bypass mode
		 */
		return ret;

	if (!g_vpna_conn.gpid) {
		g_vpna_conn.gpid = tun_info->gpid;
		g_vpna_conn.subif =
			(tun_info->subif >> CPU_PORT_WLAN_BIT_MODE) & 0X0F;

		/*Egress port qid*/
		q_logic.q_id = tun_info->qid;

		/* physical to logical qid */
		if (dp_qos_get_q_logic(&q_logic, 0) == DP_FAILURE) {
			dbg("%s:%d ERROR Failed to Logical Queue Id\n", __func__, __LINE__);
		}

		g_vpna_conn.qid = q_logic.q_logic_id;
	}

	return 0;
}

#if IS_ENABLED(CONFIG_INTEL_VPN)
static int
vpn_outbound_set_action(struct intel_vpn_tunnel_info *t,
			struct intel_vpn_ops *o)
#elif IS_ENABLED(CONFIG_MXL_VPN)
static int
vpn_outbound_set_action(struct mxl_vpn_tunnel_info *t,
			struct mxl_vpn_ops *o)
#endif
{
#if IS_ENABLED(CONFIG_INTEL_VPN)
	struct intel_vpn_ipsec_act act = {0};
#elif IS_ENABLED(CONFIG_MXL_VPN)
	struct mxl_vpn_ipsec_act act = {0};
#endif

	/* subif and tunnelid field dw0[14:0] */
	act.dw0_mask = ~((u32)GENMASK(15, 0));
	act.dw0_val = FIELD_PREP(BIT(15), 1) |
		      FIELD_PREP(GENMASK(14, 9), g_vpna_conn.subif) |
		      FIELD_PREP(GENMASK(8, 0), t->tunnel_id);

	/* gpid to bits [23:16] in dw1 */
	act.dw1_mask = ~((u32)GENMASK(23, 16));
	act.dw1_val = FIELD_PREP(GENMASK(23, 16), g_vpna_conn.gpid);

	/* enqueue in qos */
	act.enq_qos = 1;

	/* Add session in vpn FW */
	return o->add_session(o->dev, t->tunnel_id, &act);
}

static unsigned int
vpn_outbound_ps_prepare(uint8_t eip_off, uint8_t nhdr, uint8_t sess_id,
			uint8_t tunn_id, uint8_t class)
{
	ulong ps = 0;

	/* EIP Offset --> <EIP_offset> dw0[7:0] */
	ps |= FIELD_PREP(GENMASK(7, 0), eip_off);
	/*<ENCRYPT> dw0[8]*/
	set_bit(8, &ps);

	/* Next header --> dw0[16:13] */
	ps |= FIELD_PREP(GENMASK(16, 13), nhdr);

	/* TBD: rt_entry->ps third byte =
	 * (TBD:needed only in single pass << 1 ) & 0x0E;
	 */
	/* <VPN_Sess_off> dw0[19:17] */
	ps |= FIELD_PREP(GENMASK(19, 17), sess_id);
	/* Tunnel ID --> dw0[27:20] */
	ps |= FIELD_PREP(GENMASK(27, 20), tunn_id);
	/* TC/Class --> dw0[31:28] */
	ps |= FIELD_PREP(GENMASK(31, 28), class);

	return (uint32_t)ps;
}

#if IS_ENABLED(CONFIG_INTEL_VPN)
static int32_t
set_vpn_outbound_session_params(struct pp_sess_create_args *rt_entry,
				struct pktprs_desc *desc,
				struct uc_session_node *p_item,
				struct intel_vpn_tunnel_info *tun_info)
#elif IS_ENABLED(CONFIG_MXL_VPN)
static int32_t
set_vpn_outbound_session_params(struct pp_sess_create_args *rt_entry,
				struct pktprs_desc *desc,
				struct uc_session_node *p_item,
				struct mxl_vpn_tunnel_info *tun_info)
#endif
{
	/*Upstream session needs to first go to the VPN-A for encryption*/
#if IS_ENABLED(CONFIG_INTEL_VPN)
	struct intel_vpn_ops *vpn_ops = dp_get_vpn_ops(0);
#elif IS_ENABLED(CONFIG_MXL_VPN)
	struct mxl_vpn_ops *vpn_ops = dp_get_vpn_ops(0);
#endif
	struct xfrm_offload *xo = xfrm_offload(desc->skb);
	u8 eip_off, next_header = 0;
	int sess_id;

	if (!vpn_ops) {
		dbg("VPNA not initialized\n");
		return PPA_FAILURE;
	}

	if (!xo) {
		dbg("No offload found\n");
		return PPA_FAILURE;
	}

	/* 1. Set the egress port = VPNA.gpid */
	rt_entry->eg_port = g_vpna_conn.gpid;

	/* 2. Set the egress qid = VPNA.qid*/
	rt_entry->dst_q = g_vpna_conn.qid;

	/* 3. Set the dw0 and dw1 to be added egress in the VPNA */
	sess_id = vpn_outbound_set_action(tun_info, vpn_ops);
	if (sess_id < 0) {
		dbg("failed to configure tunnel %u session action, err %d\n",
		    tun_info->tunnel_id, sess_id);
		return PPA_FAILURE;
	}

	/* 4. set the dectyption parameters in the dw0 of session PSB */
	if (vpn_ops->proto_to_next_header(vpn_ops->dev,
					  xo->proto, &next_header))
		return PPA_FAILURE;

	eip_off = pktprs_ip_hdr_sz(desc->tx, PKTPRS_HDR_LEVEL0);
	rt_entry->ps = vpn_outbound_ps_prepare(eip_off, next_header, sess_id,
					       tun_info->tunnel_id,
					       p_item->pkt.priority);
	set_bit(PP_SESS_FLAG_PS_VALID_BIT, &rt_entry->flags);

	dbg("rt_entry->eg_port= %d tunnel_id=%d, dw0=%#x\n", rt_entry->eg_port,
		tun_info->tunnel_id, rt_entry->ps);

	return PPA_SUCCESS;
}
#endif /* CONFIG_INTEL_VPN || CONFIG_MXL_VPN */

static inline void set_ethtype(struct pktprs_hdr *phdr, uint16_t proto)
{
	__be16 *ethtype;
	int ip_off;

	if (!phdr || !PKTPRS_IS_IP(phdr, PKTPRS_HDR_LEVEL0))
		return;

	ip_off = pktprs_ip_hdr_off(phdr, PKTPRS_HDR_LEVEL0);
	if (ip_off < 0)
		return;

	ethtype = (__be16 *)(&phdr->buf[ip_off - 2]);
	*ethtype = htons(proto);
}

#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
#if IS_ENABLED(CONFIG_INTEL_VPN)
int vpn_inbound_set_action(struct intel_vpn_tunnel_info *t,
			   struct intel_vpn_ops *o)
#elif IS_ENABLED(CONFIG_MXL_VPN)
int vpn_inbound_set_action(struct mxl_vpn_tunnel_info *t,
			   struct mxl_vpn_ops *o)
#endif
{
#if IS_ENABLED(CONFIG_INTEL_VPN)
	struct intel_vpn_ipsec_act act = { 0 };
#elif IS_ENABLED(CONFIG_MXL_VPN)
	struct mxl_vpn_ipsec_act act = { 0 };
#endif

	if (is_vpn_assist(t)) {
		/* subif to bits [12: 9] in dw0 */
		act.dw0_val = FIELD_PREP(GENMASK(12, 9), g_vpn_nf.subif);
		/* gpid to bits [23:16] in dw1 */
		act.dw1_val = FIELD_PREP(GENMASK(23, 16), g_vpn_nf.gpid);
	} else {
		/* subif to bits [12: 9] in dw0 */
		act.dw0_val = FIELD_PREP(GENMASK(12, 9), g_vpna_conn.subif);
		/* gpid to bits [23:16] in dw1 */
		act.dw1_val = FIELD_PREP(GENMASK(23, 16), g_vpna_conn.gpid);
	}
	act.dw0_mask = ~((u32)GENMASK(12, 9));
	act.dw1_mask = ~((u32)GENMASK(23, 16));
	/* enqueue in qos */
	act.enq_qos = 1;

	return o->update_tunnel_in_act(o->dev, t->tunnel_id, &act);
}

static uint32_t
vpn_inbound_ps_prepare(uint8_t eip_off, uint8_t ip_off,
		       uint8_t tunn_id, uint8_t class)
{
	ulong ps = 0;

	/* EIP Offset --> <EIP_offset> dw0[7:0] */
	ps |= FIELD_PREP(GENMASK(7, 0), eip_off);
	/* decryption mode --> <DECRYPT> dw0[8] */
	clear_bit(8, &ps);
	/* EIP Offset --> <uC_IP_Offset> dw0[16:9] */
	ps |= FIELD_PREP(GENMASK(16, 9), ip_off);

	/* Tunnel ID --> dw0[27:20] */
	ps |= FIELD_PREP(GENMASK(27, 20), tunn_id);
	/* TC/Class --> dw0[31:28] */
	ps |= FIELD_PREP(GENMASK(31, 28), class);

	return (uint32_t)ps;
}

#if IS_ENABLED(CONFIG_INTEL_VPN)
static int32_t
set_vpn_inbound_session_params(struct pp_sess_create_args *rt_entry,
		struct pktprs_desc *desc,
		struct uc_session_node *p_item,
		struct intel_vpn_tunnel_info *tun_info)
#elif IS_ENABLED(CONFIG_MXL_VPN)
static int32_t
set_vpn_inbound_session_params(struct pp_sess_create_args *rt_entry,
		struct pktprs_desc *desc,
		struct uc_session_node *p_item,
		struct mxl_vpn_tunnel_info *tun_info)
#endif
{
#if IS_ENABLED(CONFIG_INTEL_VPN)
	struct intel_vpn_ops *vpn_ops = dp_get_vpn_ops(0);
#elif IS_ENABLED(CONFIG_MXL_VPN)
	struct mxl_vpn_ops *vpn_ops = dp_get_vpn_ops(0);
#endif
	struct iphdr *ip;
	uint16_t orig_eg_ethertype = 0;
	uint32_t hdr0 = PKTPRS_HDR_LEVEL0;
	uint8_t eip_off = 0;
	uint8_t ip_off = 0;

	if (!vpn_ops) {
		dbg("VPNA not initialized\n");
		return PPA_FAILURE;
	}

	vpn_ops->update_tunnel_in_netdev(vpn_ops->dev, tun_info->tunnel_id,
					 p_item->rx_if);

	/* 1. Set the egress port = VPNA.gpid */
	rt_entry->eg_port = g_vpna_conn.gpid;

	/* 2. Set the egress qid = VPNA.qid*/
	rt_entry->dst_q = g_vpna_conn.qid;

	/* 3. Set the dw0 and dw1 to be added egress in the VPNA */
	vpn_inbound_set_action(tun_info, vpn_ops);

	/*Get the original egress ethernet type*/
	/* handle the case internal header eth type is PPP IP/IPv6 */
	if (PKTPRS_IS_IPV4(desc->tx, hdr0))
		orig_eg_ethertype = ETH_P_IP;
	else if (PKTPRS_IS_IPV6(desc->tx, hdr0))
		orig_eg_ethertype = ETH_P_IPV6;

	/* copy ingress fv to egress fv */
	ppa_memcpy(desc->tx, desc->rx, sizeof(*desc->rx));

	/* rempve pppoe header */
	pktprs_proto_remove(desc->tx, PKTPRS_PROTO_PPPOE, hdr0);
	pktprs_proto_remove(desc->tx, PKTPRS_PROTO_VLAN0, hdr0);
	pktprs_proto_remove(desc->tx, PKTPRS_PROTO_VLAN1, hdr0);
	/* update MAC with correct eth type of the internal packet */
	set_ethtype(desc->tx, orig_eg_ethertype);

	/* 4. set the dectyption parameters in the dw0 of session PSB */
	if (!PKTPRS_IS_IP(desc->tx, hdr0))
		goto prepare_ps;

	if (tun_info->mode == VPN_MODE_TUNNEL) {
		pktprs_ip_remove(desc->tx, hdr0);
	} else if (tun_info->mode == VPN_MODE_TRANSPORT) {
		/* IP header next protocol offset */
		ip_off = pktprs_ip_hdr_off(desc->tx, hdr0);
		if (PKTPRS_IS_IPV4(desc->tx, hdr0)) {
			ip_off += offsetof(struct iphdr, protocol);
			/* remove the ip fragmentation info so the pp session
			 * manager won't think it is fragments acceleration.
			 * safe to do it as this is ESP termination session.
			 */
			ip = pktprs_ipv4_hdr(desc->tx, hdr0);
			ip->frag_off &= htons(IP_DF);
		} else if (PKTPRS_IS_IPV6(desc->tx, hdr0)) {
			ip_off += pktprs_ip6_proto_off(pktprs_ipv6_hdr(desc->tx,
								       hdr0));
			/* remove the ip fragmentation header so the pp session
			 * manager won't think it is fragments acceleration.
			 * safe to do it as this is ESP termination session.
			 */
			pktprs_proto_remove(desc->tx, PKTPRS_PROTO_FRAG_OPT,
					    hdr0);
		}
	}
	pktprs_proto_remove(desc->tx, PKTPRS_PROTO_UDP, hdr0);
	eip_off = pktprs_hdr_off(desc->tx, PKTPRS_PROTO_ESP, hdr0);

prepare_ps:
	if (ip_off >= 128) {
		/* ip offset length is 7 bits in PS, bigger values cannot
		 * be accelerated
		 */
		pr_err_ratelimited("ip_off %u too big, max supported size %u\n",
				   ip_off, 127);
		return PPA_FAILURE;
	}
	rt_entry->ps = vpn_inbound_ps_prepare(eip_off, ip_off,
					      tun_info->tunnel_id, 0);
	set_bit(PP_SESS_FLAG_PS_VALID_BIT, &rt_entry->flags);
	set_bit(PP_SESS_FLAG_OUTER_REASS_FORCE, &rt_entry->flags);

	/* ESP header to be inserted if the decrypted packet from VPNA
	 * comes back to CPU.
	 * It happens after the 1st session creation and before
	 * the 2nd session was created
	 */
	store_esp_tunnel_header(p_item, desc, tun_info);

	dbg("rt_entry->eg_port= %d tunnel_id=%d, dw0=%#x\n", rt_entry->eg_port,
	    tun_info->tunnel_id, rt_entry->ps);

	return PPA_SUCCESS;
}
#endif /* CONFIG_INTEL_VPN || CONFIG_MXL_VPN */

#if defined(PPA_API_PROC)
static int proc_read_ppv4_ifstats(struct seq_file *seq, void *v)
{
	int indx;
	struct pp_stats tx_stats[2];
	struct pp_stats rx_stats[2];
	struct sgc_info *sgc;
	uint64_t total_tx_pkts, total_rx_pkts;
	uint64_t total_tx_bytes, total_rx_bytes;

	if (!capable(CAP_SYSLOG)) {
		pr_err("Read Permission denied\n");
		return 0;
	}

	seq_puts(seq, "+------------------+------------------------------------------"
		 "--------+--------------------------------------------------+\n");
	seq_printf(seq, "|                  | %-48s | %-48s |\n",
		   "Transmit", "Receive");
	seq_printf(seq, "| %-16s +---------+-----------------+----------------------+"
		   "---------+-----------------+----------------------+\n",
		   "Interface");
	seq_printf(seq, "|                  | %-7s | %-15s | %-20s | %-7s | %-15s | %-20s |\n",
		   "Grp:Idx", "Packets", "Bytes",
		   "Grp:Idx", "Packets", "Bytes");
	seq_puts(seq, "+------------------+---------+-----------------+--------------"
		 "--------+---------+-----------------+----------------------+\n");

	spin_lock_bh(&if_stats_db->lock);
	for_each_set_bit(indx, if_stats_db->if_bitmap, PP_HAL_MAX_IFS_NUM) {
		sgc = if_stats_db->if_info[indx].sgc;
		memset(&tx_stats, 0, (2 * sizeof(struct pp_stats)));
		memset(&rx_stats, 0, (2 * sizeof(struct pp_stats)));
		pp_hal_sgc_get(sgc, 2, tx_stats, rx_stats);

		seq_printf(seq, "| %-16s | %2d:%-4d | %-15llu | %-20llu | %2d:%-4d | %-15llu"
			   " | %-20llu |\n", "",
			   sgc[0].grp, sgc[0].tx_id,
			   tx_stats[0].packets, tx_stats[0].bytes,
			   sgc[0].grp, sgc[0].rx_id,
			   rx_stats[0].packets, rx_stats[0].bytes);

		seq_printf(seq, "| %-16s | %2d:%-4d | %-15llu | %-20llu | %2d:%-4d | %-15llu"
			   " | %-20llu |\n", "",
			   sgc[1].grp, sgc[1].tx_id,
			   tx_stats[1].packets, tx_stats[1].bytes,
			   sgc[1].grp, sgc[1].rx_id,
			   rx_stats[1].packets, rx_stats[1].bytes);

		total_tx_pkts = tx_stats[0].packets + tx_stats[1].packets;
		total_rx_pkts = rx_stats[0].packets + rx_stats[1].packets;
		total_tx_bytes = tx_stats[0].bytes + tx_stats[1].bytes;
		total_rx_bytes = rx_stats[0].bytes + rx_stats[1].bytes;

		seq_puts(seq, "|                  +---------+-----------------+-------------"
			 "---------+---------+-----------------+----------------------+\n");
		seq_printf(seq, "| %-16s |  Total  | %-15llu | %-20llu |  Total  | %-15llu |"
			   " %-20llu |\n",
			   ppa_get_netif_name(if_stats_db->if_info[indx].dev),
			   total_tx_pkts, total_tx_bytes,
			   total_rx_pkts, total_rx_bytes);
		seq_puts(seq, "+------------------+---------+-----------------+-------------"
			 "---------+---------+-----------------+----------------------+\n");
	}
	spin_unlock_bh(&if_stats_db->lock);
	return 0;
}

static int proc_read_ppv4_ifstats_seq_open(struct inode *inode,
					   struct file *file)
{
	return single_open(file, proc_read_ppv4_ifstats, NULL);
}

static int proc_read_ppv4_rtstats(struct seq_file *seq, void *v)
{
	if (!capable(CAP_SYSLOG)) {
		printk ("Read Permission denied");
		return 0;
	}

	seq_printf(seq,	"=====================================================================\n");
	seq_printf(seq,	"Total Number of Routing session entrys			: %llu\n", nsess_add_succ - nsess_del + nsess_del_fail);
	seq_printf(seq,	"Total Number of Routing session add requests		: %llu\n", nsess_add);
	seq_printf(seq,	"Total Number of Routing session delete			: %llu\n", nsess_del);
	seq_printf(seq,	"Total Number of Routing session delete fail		: %llu\n", nsess_del_fail);
	seq_printf(seq,	"Total Number of Routing session add fails		: %llu\n", nsess_add_fail_rt_tbl_full + nsess_add_fail_coll_full + nsess_add_fail_oth);
	seq_printf(seq,	"Total Number of Routing session add fail rt tbl full	: %llu\n", nsess_add_fail_rt_tbl_full);
	seq_printf(seq,	"Total Number of Routing session add fail coll full	: %llu\n", nsess_add_fail_coll_full);
	seq_printf(seq,	"Total Number of Routing session add fail others	: %u\n", nsess_add_fail_oth);
	seq_printf(seq,	"=====================================================================\n");
	return 0;
}

static int proc_read_ppv4_rtstats_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_ppv4_rtstats, NULL);
}

static ssize_t proc_clear_ppv4_rtstats(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	int len;
	char str[40];
	char *p;

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}

	len = min(count, (size_t)(sizeof(str) - 1));
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if (strncmp(p, "clear", 5) == 0) {
		nsess_add = 0;
		nsess_del = 0;
		nsess_del_fail = 0;
		nsess_add_succ = 0;
		nsess_add_fail_rt_tbl_full = 0;
		nsess_add_fail_coll_full = 0;
		nsess_add_fail_oth = 0;
		printk(KERN_ERR "PPv4 HAL stats cleared!!!\n");
	} else {
		printk(KERN_ERR "usage : echo clear > /sys/kernel/debug/ppa/pp_hal/rtstats\n");
	}

	return len;
}

static int proc_read_ppv4_accel(struct seq_file *seq, void *v)
{
	if (!capable(CAP_SYSLOG)) {
		printk ("Read Permission denied");
		return 0;
	}
	seq_printf(seq,	"PPv4 Upstream Acceleration	: %s\n", g_us_accel_enabled ? "enabled" : "disabled");
	seq_printf(seq,	"PPv4 Downstream Acceleration	: %s\n", g_ds_accel_enabled ? "enabled" : "disabled");
	return 0;
}

static int proc_read_ppv4_accel_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_ppv4_accel, NULL);
}

static int proc_read_supp_ppv4_accel(struct seq_file *seq, void *v)
{
	if (!capable(CAP_SYSLOG)) {
		pr_info("Read Permission denied");
		return 0;
	}
	seq_printf(seq,	"PPv4 supportive Acceleration	: %s\n",
			g_supp_accel_enabled ? "enabled" : "disabled");
	return 0;
}

static int proc_read_support_ppv4_accel_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_supp_ppv4_accel, NULL);
}

#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
static int proc_read_ppv4_vpn_tunn_show(struct seq_file *s, void *v)
{
	static PP_IPSEC_TUN_NODE *tinfo;
	struct uc_session_node *p_item, *p;
	int i;

	if (!capable(CAP_SYSLOG)) {
		printk ("Read Permission denied");
		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(ipsec_tun_db); i++) {
		tinfo = &ipsec_tun_db[i];
		if (!tinfo->hdr)
			continue;

		seq_printf(s, " Tunnel %-3u Info\n", i);
		seq_puts(s, "=================\n");

		seq_printf(s, " Mode          : %s\n",
			   tinfo->trns_mode ? "Transport" : "Tunnel");
		seq_printf(s, " Direction     : %s\n",
			   tinfo->is_inbound ? "Inbound" : "Outbound");
		seq_printf(s, " PPPoE         : %s\n",
			   tinfo->pppoe ? "True" : "False");
		seq_printf(s, " IP            : %s\n",
			   tinfo->ipv6 ? "IPv6" : "IPv4");
		seq_printf(s, " IP Offset     : %u\n", tinfo->ip_offset);
		seq_printf(s, " Strip Size    : %u\n", tinfo->strip_sz);
		seq_printf(s, " ESP Length    : %u\n", tinfo->esp_hdr_len);
		seq_printf(s, " IV Length     : %u\n", tinfo->iv_sz);
		seq_printf(s, " Header Length : %u\n", tinfo->iv_sz);
		seq_puts(s, " Header        : ");
		seq_hex_dump(s, "", DUMP_PREFIX_NONE, 32, 1,
			     tinfo->hdr, tinfo->hdr_len, false);
		seq_puts(s, "\n");

		seq_puts(s, " Sessions      : ");
		list_for_each_entry_safe(p_item, p, &tinfo->sessions, tun_node)
			seq_printf(s, "%u, ", p_item->routing_entry);
		seq_puts(s, "\n\n");

	}

	return 0;
}

static int proc_read_ppv4_vpn_tunn_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_ppv4_vpn_tunn_show, NULL);
}
#endif /* CONFIG_INTEL_VPN || CONFIG_MXL_VPN */

static ssize_t proc_set_ppv4_accel(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	int len;
	char str[40];
	char *p;
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}

	len = min(count, (size_t)(sizeof(str) - 1));
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if (strncmp(p, "enable", 6) == 0) {
		if (len > 6) {
			if (strncmp(p + 7, "us", 2) == 0) {
				g_us_accel_enabled = 3;
			} else if (strncmp(p + 7, "ds", 2) == 0) {
				g_ds_accel_enabled = 3;
			}
		} else {
			g_us_accel_enabled = 3;
			g_ds_accel_enabled = 3;
		}
		g_supp_accel_enabled = 1;
		printk(KERN_ERR "Acceleration Enabled!!!\n");
	} else if (strncmp(p, "disable", 7) == 0) {
		if (len > 7) {
			if (strncmp(p + 8, "us", 2) == 0) {
				g_us_accel_enabled=0;
			} else if (strncmp(p + 8, "ds", 2) == 0) {
				g_ds_accel_enabled=0;
			}
		} else {
			g_us_accel_enabled = 0;
			g_ds_accel_enabled = 0;
		}
		g_supp_accel_enabled = 0;
		printk(KERN_ERR "Acceleration Disabled!!!\n");
	} else {
		printk(KERN_ERR "usage : echo <enable/disable> [us/ds] > /sys/kernel/debug/ppa/pp_hal/accel\n");
	}

	return len;
}

static ssize_t proc_set_support_ppv4_accel(struct file *file,
		const char __user *buf, size_t count, loff_t *data)
{
	int len;
	char str[40];
	char *p;

	if (!capable(CAP_NET_ADMIN)) {
		pr_info("Write Permission denied");
		return 0;
	}

	len = min(count, (size_t)(sizeof(str) - 1));
	len -= ppa_copy_from_user(str, buf, len);
	while (len && str[len - 1] <= ' ')
		len--;
	str[len] = 0;
	for (p = str; *p && *p <= ' '; p++, len--)
		;
	if (!*p)
		return count;

	if (strncmp(p, "enable", 6) == 0) {
		g_supp_accel_enabled = 1;
		pr_info("supp Acceleration Enabled!!!\n");
	} else if (strncmp(p, "disable", 7) == 0) {
		g_supp_accel_enabled = 0;
		pr_info("supp Acceleration Disabled!!!\n");
	}

	return len;
}

static int proc_read_ppv4_debug(struct seq_file *seq, void *v)
{
	if (!capable(CAP_SYSLOG)) {
		printk ("Read Permission denied");
		return 0;
	}
	seq_printf(seq,	"PPv4 Debug	: %s\n", lgm_pp_hal_dbg_enable ? "enabled" : "disabled");
	return 0;
}

static int proc_read_ppv4_debug_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_ppv4_debug, NULL);
}

static int proc_read_ppv4_tdox(struct seq_file *seq, void *v)
{
	if (!capable(CAP_SYSLOG)) {
		printk ("Read Permission denied");
		return 0;
	}
	seq_printf(seq,	"PPv4 TDOX	: %s\n", ppa_tdox_enable_get() ? "enabled" : "disabled");
	return 0;
}

static int proc_read_ppv4_tdox_enable(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_ppv4_tdox, NULL);
}

static ssize_t proc_set_ppv4_tdox_enable(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	int len;
	char str[40];
	char *p;
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}

	len = min(count, (size_t)(sizeof(str) - 1));
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if (strncmp(p, "enable", 6) == 0) {
		ppa_tdox_enable_set(true);
		pr_debug("TDOX Enabled!\n");
	} else if (strncmp(p, "disable", 7) == 0) {
		ppa_tdox_enable_set(false);
		pr_debug("TDOX Disbled!\n");
	} else {
		pr_debug("usage : echo <enable/disable> > /sys/kernel/debug/ppa/hal/pp/tdox\n");
	}

	return len;
}

static ssize_t proc_set_ppv4_debug(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	int len;
	char str[40];
	char *p;
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}

	len = min(count, (size_t)(sizeof(str) - 1));
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if (strncmp(p, "enable", 6) == 0) {
		lgm_pp_hal_dbg_enable = 1;
		printk(KERN_ERR"Debug Enabled!!!\n");
	} else if (strncmp(p, "disable", 7) == 0) {
		lgm_pp_hal_dbg_enable = 0;
		printk(KERN_ERR"Debug Disbled!!!\n");
	} else {
		printk(KERN_ERR "usage : echo <enable/disable> > /sys/kernel/debug/ppa/pp_hal/dbg\n");
	}

	return len;
}

#if IS_ENABLED(CONFIG_PPA_BBF247_MODE1)
static int ppa_run_cmd(const char *cmd)
{
	int ret;
	char **argv;
	static char *envp[] = {
		"HOME=/",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin",
		NULL
	};

	argv = argv_split(GFP_KERNEL, cmd, NULL);
	if (argv) {
		ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
		argv_free(argv);
	} else {
		ret = -ENOMEM;
	}

	if (ret)
		printk(KERN_ERR "%s: {%s} Failed %d\n", __func__, cmd, ret);

	return ret;
}

/* PON DS Session */
int32_t ppa_add_bbf247_mode1_ds_session(PPA_NETIF *rxif, PPA_NETIF *txif,
					u32 class, uint32_t *session_id)
{
	struct pp_sess_create_args args = {0};
	PPA_SUBIF *vuni_subif;
	PPA_SUBIF *lan_subif;
	int ret = PPA_FAILURE;
	struct netdev_attr qos_attr = {0};

	vuni_subif = kzalloc(sizeof(PPA_SUBIF), GFP_KERNEL);
	lan_subif = kzalloc(sizeof(PPA_SUBIF), GFP_KERNEL);

	if (!vuni_subif || !lan_subif) {
		printk(KERN_ERR "%s: subifid kmalloc failed\n", __func__);
		goto __out_free;
	}

	if (dp_get_netif_subifid(rxif, NULL, NULL, NULL, vuni_subif, 0)) {
		printk(KERN_ERR "%s: lan dp_get_netif_subif failed\n", __func__);
		goto __out_free;
	}

	if (dp_get_netif_subifid(txif, NULL, NULL, NULL, lan_subif, 0)) {
		printk(KERN_ERR "%s: vuni dp_get_netif_subif failed\n", __func__);
		goto __out_free;
	}

	args.in_port = vuni_subif->gpid;
	args.eg_port = lan_subif->gpid;
	qos_attr.portid = args.eg_port;
	qos_attr.tc = class;
	qos_attr.dst_q_high = -1;
	if (ppa_api_get_mapped_queue) {
		ppa_api_get_mapped_queue(txif, &qos_attr);
	} else {
		pr_err("eg_port(%d) get mapped queue err\n", args.eg_port);
		goto __out_free;
	}

	args.dst_q = qos_attr.dst_q_low;
	args.color = PP_COLOR_GREEN;
	set_bit(PP_SESS_FLAG_INTERNAL_HASH_CALC_BIT, &args.flags);
	args.ps = lan_subif->subif & 0xFFFF;
	set_bit(PP_SESS_FLAG_PS_VALID_BIT, &args.flags);
	args.ps |= 0x8000000;
	args.cls.n_flds = 2;
	args.cls.fld_data[0] = class;
	args.cls.fld_data[1] = 0;  /* Must check b16=0 for DS sessions */

	memset(&args.sgc, U8_MAX, sizeof(args.sgc));
	memset(&args.tbm, U8_MAX, sizeof(args.tbm));

	if (lan_subif->gpid == fbm.gpid && fbm.enable) {
		/* Add Fast Buffer Monitor sgc & tbm */
		args.tbm[0] = fbm.tbm_id;
		args.sgc[fbm.sgc_grp] = fbm.sgc_id;
	}

	printk("%s %d args: dst_q=%d in_port %u eg_port %u ps 0x%x f 0x%lx\n",
	       __FUNCTION__, __LINE__, args.dst_q, args.in_port, args.eg_port,
	       args.ps, args.flags);

	if ((ret = pp_session_create(&args, session_id, NULL))) {
		printk(KERN_ERR "%s: BBF.247 session_create failed!!! ret=%d\n",
		       __FUNCTION__, ret);
		goto __out_free;
	}
	PPA_HAL_RTSTATS_INC(curr_uc_ipv4_session);
	ret = PPA_SUCCESS;

__out_free:
	kfree(vuni_subif);
	kfree(lan_subif);
	return ret;
}

/* PON US Session */
int32_t ppa_add_bbf247_mode1_us_session(PPA_NETIF *rxif, PPA_NETIF *txif,
					uint32_t *session_id)
{
	struct pp_sess_create_args args = {0};
	PPA_SUBIF *vuni_subif;
	PPA_SUBIF *lan_subif;
	int ret = PPA_FAILURE;
	struct netdev_attr qos_attr = {0};

	vuni_subif = kzalloc(sizeof(PPA_SUBIF), GFP_KERNEL);
	lan_subif = kzalloc(sizeof(PPA_SUBIF), GFP_KERNEL);

	if (!vuni_subif || !lan_subif) {
		printk(KERN_ERR "%s: subifid kmalloc failed\n", __func__);
		goto __out_free;
	}

	if (dp_get_netif_subifid(rxif, NULL, NULL, NULL, lan_subif, 0)) {
		printk(KERN_ERR "%s: lan dp_get_netif_subifid failed\n", __func__);
		goto __out_free;
	}

	if (dp_get_netif_subifid(txif, NULL, NULL, NULL, vuni_subif, 0)) {
		printk(KERN_ERR "%s: vuni dp_get_netif_subifid failed\n", __func__);
		goto __out_free;
	}

	args.in_port = lan_subif->gpid;
	args.eg_port = vuni_subif->gpid;
	qos_attr.portid = args.eg_port;
	qos_attr.dst_q_high = -1;
	if (ppa_api_get_mapped_queue) {
		ret = ppa_api_get_mapped_queue(txif, &qos_attr);
		if (ret != 0)
			goto __out_free;
	} else {
		pr_err("eg_port(%d) get mapped queue err\n", args.eg_port);
		goto __out_free;
	}
	args.dst_q = qos_attr.dst_q_low;
	args.color = PP_COLOR_GREEN;
	set_bit(PP_SESS_FLAG_INTERNAL_HASH_CALC_BIT, &args.flags);
	args.ps = vuni_subif->subif & 0xFFFF;
	args.ps |= BIT(16); /* Set the US flag bit - for multicast control packets marking */
	set_bit(PP_SESS_FLAG_PS_VALID_BIT, &args.flags);

	memset(&args.sgc, U8_MAX, sizeof(args.sgc));
	memset(&args.tbm, U8_MAX, sizeof(args.tbm));

	printk("%s %d args: dst_q=%d in_port %u eg_port %u ps 0x%x f 0x%lx\n",
		__FUNCTION__, __LINE__, args.dst_q, args.in_port, args.eg_port,
		args.ps, args.flags);

	if ((ret = pp_session_create(&args, session_id, NULL))) {
		printk(KERN_ERR "%s: BBF.247 session_create failed!!! ret=%d\n",
		       __FUNCTION__, ret);
		goto __out_free;
	}
	PPA_HAL_RTSTATS_INC(curr_uc_ipv4_session);
	ret = PPA_SUCCESS;

__out_free:
	kfree(vuni_subif);
	kfree(lan_subif);
	return ret;
}

int32_t ppa_pp_update_ports(PPA_NETIF *lan_if, PPA_NETIF *vuni_if)
{
	struct pp_port_cfg vuni_cfg = {0};
	struct pp_port_cfg lan_cfg = {0};
	struct pp_port_cfg *lan_cfg_ptr = &lan_cfg;
	PPA_SUBIF *vuni_subif;
	PPA_SUBIF *lan_subif;
	int ret = PPA_FAILURE;

	vuni_subif = kzalloc(sizeof(PPA_SUBIF), GFP_KERNEL);
	lan_subif = kzalloc(sizeof(PPA_SUBIF), GFP_KERNEL);

	if (!vuni_subif || !lan_subif) {
		printk(KERN_ERR "%s: subifid kmalloc failed\n", __func__);
		goto __out_free;
	}

	if (dp_get_netif_subifid(lan_if, NULL, NULL, NULL, lan_subif, 0)) {
		printk(KERN_ERR "%s: lan dp_get_netif_subifid failed\n", __func__);
		goto __out_free;
	}

	if (dp_get_netif_subifid(vuni_if, NULL, NULL, NULL, vuni_subif, 0)) {
		printk(KERN_ERR "%s: vuni dp_get_netif_subifid failed\n", __func__);
		goto __out_free;
	}

	if (fbm.gpid == lan_subif->gpid && fbm.enable)
		lan_cfg_ptr = &fbm.pcfg;

	if (unlikely(pp_port_get(lan_subif->gpid, lan_cfg_ptr))) {
		printk(KERN_ERR "%s: pp_port_get failed gpid: %d\n", __func__, lan_subif->gpid);
		goto __out_free;
	}

	lan_cfg_ptr->rx.parse_type = NO_PARSE;
	if (unlikely(pp_port_update(lan_subif->gpid, lan_cfg_ptr))) {
		printk(KERN_ERR "%s: pp_port_update failed gpid: %d\n", __func__, lan_subif->gpid);
		goto __out_free;
	}

	if (unlikely(pp_port_get(vuni_subif->gpid, &vuni_cfg))) {
		printk(KERN_ERR "%s: pp_port_get failed gpid: %d\n", __func__, vuni_subif->gpid);
		goto __out_free;
	}

	/* Additionally set classfication based on class + b16 */
	vuni_cfg.rx.parse_type = NO_PARSE;
	vuni_cfg.rx.cls.n_flds = 2;
	vuni_cfg.rx.cls.cp[0].stw_off = 28;
	vuni_cfg.rx.cls.cp[0].copy_size = 4;
	vuni_cfg.rx.cls.cp[1].stw_off = 16;
	vuni_cfg.rx.cls.cp[1].copy_size = 1;

	if (unlikely(pp_port_update(vuni_subif->gpid, &vuni_cfg))) {
		printk(KERN_ERR "%s: pp_port_update failed gpid: %d\n", __func__, vuni_subif->gpid);
		goto __out_free;
	}
	ret = PPA_SUCCESS;

__out_free:
	kfree(vuni_subif);
	kfree(lan_subif);
	return ret;
}

void ppa_bbf247_mode1(PPA_IFNAME vani_netif_name[PPA_IF_NAME_SIZE],
		      PPA_IFNAME vuni_netif_name[PPA_IF_NAME_SIZE],
		      PPA_IFNAME lan_netif_name[PPA_IF_NAME_SIZE],
		      bool enable)
{
	struct pp_port_cfg vuni_cfg = {0};
	struct pp_port_cfg lan_cfg = {0};
	PPA_NETIF *vuni_if;
	PPA_NETIF *lan_if;
	PPA_SUBIF *vuni_subif;
	PPA_SUBIF *lan_subif;
	u32  session_id = 0, idx;
	char buffer[100];

	vuni_subif = kzalloc(sizeof(PPA_SUBIF), GFP_KERNEL);
	lan_subif = kzalloc(sizeof(PPA_SUBIF), GFP_KERNEL);

	if (!vuni_subif || !lan_subif) {
		printk(KERN_ERR "%s: subifid kmalloc failed\n", __func__);
		goto __out_free;
	}

	if (enable) {
		printk("Enable->vani: %s vuni: %s lan: %s\n", vani_netif_name, vuni_netif_name, lan_netif_name);
		if ((lan_if = ppa_get_netif(lan_netif_name)) == NULL) {
			printk(KERN_ERR "%s: get lan_if ppa_get_netif failed\n", __func__);
			goto __out_free;
		}

		if ((vuni_if = ppa_get_netif(vuni_netif_name)) == NULL) {
			printk(KERN_ERR "%s: get vuni_if ppa_get_netif failed\n", __func__);
			goto __out_free;
		}

		/* Re-create the br-lan bridge with user given interfaces */
		if (bbf247_sess->sess_cnt == 0) {
			/* Add the VANI0 interface always for mode1 */
			ppa_run_cmd("/usr/sbin/brctl addif br-lan VANI0");

			if (!(strcmp(vani_netif_name, "VANI0") == 0)) {
				snprintf(buffer, sizeof(buffer), "/usr/sbin/brctl addif br-lan %s", vani_netif_name);
				ppa_run_cmd(buffer);
			}

			snprintf(buffer, sizeof(buffer), "/usr/sbin/brctl addif br-lan %s", lan_netif_name);
			ppa_run_cmd(buffer);
		} else { /* ADD LAN interface with existing br-lan */
			snprintf(buffer, sizeof(buffer), "/usr/sbin/brctl addif br-lan %s", lan_netif_name);
			ppa_run_cmd(buffer);
		}

		/* Change Port configuration for VUNI and LAN */
		if (ppa_pp_update_ports(lan_if, vuni_if) != PPA_SUCCESS) {
			printk(KERN_ERR "%s: ppa_pp_update_ports failed\n", __func__);
			goto __br_lan_def_conf;
		}

		/* Create US session */
		if (ppa_add_bbf247_mode1_us_session(lan_if, vuni_if, &session_id) != PPA_SUCCESS) {
			printk(KERN_ERR "%s: ppa_add_bbf247_mode1_us_session failed\n", __func__);
			goto __br_lan_def_conf;
		}
		bbf247_sess->sess_id[bbf247_sess->sess_cnt++] = session_id;

		/* Create DS session */
		if (ppa_add_bbf247_mode1_ds_session(vuni_if, lan_if, (bbf247_sess->sess_cnt / 2), &session_id) != PPA_SUCCESS) {
			printk(KERN_ERR "%s: ppa_add_bbf247_mode1_ds_session failed\n", __func__);
			goto __br_lan_def_conf;
		}
		bbf247_sess->sess_id[bbf247_sess->sess_cnt++] = session_id;
	} else {
		printk("Disable->vuni_netif: %s\n", vuni_netif_name);

		if ((vuni_if = ppa_get_netif(vuni_netif_name)) == NULL) {
			printk(KERN_ERR "%s: get vuni_if ppa_get_netif failed\n", __func__);
			goto __out_free;
		}

		if (dp_get_netif_subifid(vuni_if, NULL, NULL, NULL, vuni_subif, 0)) {
			printk(KERN_ERR "%s: vuni dp_get_netif_subifid failed\n", __func__);
			goto __out_free;
		}

		if (unlikely(pp_port_get(vuni_subif->gpid, &vuni_cfg))) {
			printk(KERN_ERR "%s: vuni_if failed to get cfg of gpid: %d\n", __func__, vuni_subif->gpid);
			goto __out_free;
		}

		/* Revert the vUNI port config */
		vuni_cfg.rx.parse_type = L2_PARSE;
		vuni_cfg.rx.cls.n_flds = 0;

		if (unlikely(pp_port_update(vuni_subif->gpid, &vuni_cfg))) {
			printk(KERN_ERR "%s: pp_port_update failed  gpid: %d\n", __func__, vuni_subif->gpid);
			goto __out_free;
		}

		for (idx = 0; idx < (bbf247_sess->sess_cnt / 2); idx++) {
			if ((lan_if = ppa_get_netif(bbf247_sess->eth_arr[idx + 2])) == NULL) {
				printk(KERN_ERR "%s: get vuni_if ppa_get_netif failed\n", __func__);
				goto __br_lan_def_conf;
			}

			if (dp_get_netif_subifid(lan_if, NULL, NULL, NULL, lan_subif, 0)) {
				printk(KERN_ERR "%s: vuni dp_get_netif_subifid failed\n", __func__);
				goto __br_lan_def_conf;
			}

			if (unlikely(pp_port_get(lan_subif->gpid, &lan_cfg))) {
				printk(KERN_ERR "%s: lan_if failed to get cfg of gpid: %d\n", __func__, lan_subif->gpid);
				goto __br_lan_def_conf;
			}

			/* Revert the LAN port config */
			lan_cfg.rx.parse_type = L2_PARSE;
			lan_cfg.rx.cls.n_flds = 0;

			if (unlikely(pp_port_update(lan_subif->gpid, &lan_cfg))) {
				printk(KERN_ERR "%s: pp_port_update failed	gpid: %d\n", __func__, lan_subif->gpid);
				goto __br_lan_def_conf;
			}
		}
		goto __br_lan_def_conf;
	}

	goto __out_free;

__br_lan_def_conf:
	for (idx = 0; idx < bbf247_sess->sess_cnt; idx++) {
		if (bbf247_sess->sess_id[idx] != BBF247_INVALID_SESS_ID) {
			if (pp_session_delete(bbf247_sess->sess_id[idx], NULL)) {
				printk(KERN_ERR "%s: %d pp_session_delete failed\n",
				       __func__, bbf247_sess->sess_id[idx]);
			}
			PPA_HAL_RTSTATS_DEC(curr_uc_ipv4_session);
		}
		bbf247_sess->sess_id[idx] = BBF247_INVALID_SESS_ID;
	}

	/* Remove the VANI0 interface */
	ppa_run_cmd("/usr/sbin/brctl delif br-lan VANI0");
	if (!(strcmp(bbf247_sess->eth_arr[0], "VANI0") == 0)) {
		snprintf(buffer, sizeof(buffer), "/usr/sbin/brctl delif br-lan %s", bbf247_sess->eth_arr[0]);
		ppa_run_cmd(buffer);
	}

	bbf247_sess->sess_cnt = 0;
	memset(&bbf247_sess->eth_arr, 0, sizeof(char *) * ARRAY_SIZE(bbf247_sess->eth_arr));

__out_free:
	kfree(vuni_subif);
	kfree(lan_subif);
	return;
}

static int proc_read_ppv4_bbf247_hgu(struct seq_file *seq, void *v)
{
	int idx;

	if (!capable(CAP_SYSLOG)) {
		printk("Read Permission denied");
		return 0;
	}

	if (bbf247_sess->sess_cnt > 0) {
		seq_printf(seq,	"Interfaces\n");
		for (idx = 2; idx < BBF247_MAX_SESS_ID; idx++) {
			if (bbf247_sess->eth_arr[idx] != NULL)
				seq_printf(seq,	"\t %s->%s->%s\n",
						   bbf247_sess->eth_arr[idx],
						   bbf247_sess->eth_arr[0],
						   bbf247_sess->eth_arr[1]);
		}
	} else {
		seq_printf(seq,	"BBF247 Session Empty !!!\n");
	}

	return 0;
}

static int proc_read_ppv4_bbf247_hgu_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_ppv4_bbf247_hgu, NULL);
}

static ssize_t proc_set_ppv4_bbf247_hgu(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	int len, cnt = 0, idx, offset = 0;
	char *eth_arr[BBF247_MAX_SESS_ID];
	const char *s;
	char *p;
	char buffer[100], str[100];

	if (!capable(CAP_NET_ADMIN)) {
		printk("Write Permission denied");
		return 0;
	}

	len = min(count, (size_t)(sizeof(str) - 1));
	len -= ppa_copy_from_user(str, buf, len);
	while (len && str[len - 1] <= ' ')
		len--;
	str[len] = 0;

	for (p = str; *p && *p <= ' '; p++, len--);

	if (!*p)
		return count;

	if (strncmp(str, "help", sizeof(str)) == 0)
		goto __write_help;

	s = str;
	while (sscanf(s, "%99s%n", buffer, &offset) == 1) {
		s += offset;
		eth_arr[cnt] = kzalloc((strlen(buffer) + 1), GFP_KERNEL);
		if (!eth_arr[cnt]) {
			for (idx = 0; idx < cnt; idx++)
				kfree(eth_arr[idx]);
			printk(KERN_ERR "%s: kmalloc failed\n", __func__);
			return len;
		}
		strcpy(eth_arr[cnt++], buffer);
	}

	if (cnt == 0)
		goto __write_help;

	if ((strcmp(eth_arr[cnt - 1], "enable") == 0) && cnt > 3) {
		if ((strstr(eth_arr[0], "ANI") == NULL) ||
			(strstr(eth_arr[1], "VUNI0_") == NULL) ||
			(strstr(eth_arr[2], "eth0_") == NULL))
			goto __write_help;

		if (bbf247_sess->sess_cnt > 0) {
			printk("!!! BBF247 Session Already Created\n");
			goto __out_free;
		}

		memcpy(&bbf247_sess->eth_arr, &eth_arr, sizeof(char *) * (cnt - 1));
		for (idx = 2; idx < cnt - 1; idx++)
			ppa_bbf247_mode1(eth_arr[0], eth_arr[1], eth_arr[idx], true);
	} else if ((strcmp(eth_arr[cnt - 1], "disable") == 0) && (cnt == 1)) {
		if (bbf247_sess->sess_cnt <= 0) {
			printk("!!! BBF247 Session Not Created\n");
			goto __out_free;
		}
		ppa_bbf247_mode1(NULL, bbf247_sess->eth_arr[1], NULL, false);

		/* Free the interface name mem */
		for (idx = 0; idx < BBF247_MAX_SESS_ID; idx++)
			kfree(bbf247_sess->eth_arr[idx]);
	} else {
		goto __write_help;
	}

	return len;

__write_help:
	printk("Mode1: enable\n");
	printk("\t arg1 - VANI interface ( VANI0 or VANI0.xx or ANI0_wanxx_.. )\n");
	printk("\t arg2 - VUNI interface ( VUNI0_0 )\n");
	printk("\t arg3 - LAN  interfaces ( eth0_1 -> eth0_5)\n");
	printk("\t arg4 - enable\n");
	printk("\t Example# echo VANI0 VUNI0_0 eth0_1 enable> /sys/kernel/debug/ppa/hal/pp/bbf247_hgu_model\n\n");

	printk("Mode1: disable\n");
	printk("\t arg1 - disable\n");
	printk("\t Example# echo disable> /sys/kernel/debug/ppa/hal/pp/bbf247_hgu_model\n");
	goto __out_free;

__out_free:
	/* Free the interfaces memory */
	for (idx = 0; idx < cnt; idx++)
		kfree(eth_arr[idx]);

	return len;

}
#endif /*CONFIG_PPA_BBF247_MODE1*/

static struct ppa_debugfs_files lgm_hal_debugfs_files[] = {
	{ "accel",            0600, &dbgfs_file_ppv4_accel_seq_fops },
#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
	{ "vpn_tunnels",      0600, &dbgfs_file_ppv4_vpn_tunn_fops },
#endif /* CONFIG_INTEL_VPN || CONFIG_MXL_VPN */
	{ "dbg",              0600, &dbgfs_file_ppv4_debug_seq_fops },
	{ "tdox",             0600, &dbgfs_file_ppv4_tdox_enable_fops },
	{ "rtstats",          0600, &dbgfs_file_ppv4_rtstats_seq_fops },
	{ "ifstats",          0600, &dbgfs_file_ppv4_ifstats_seq_fops },
#if IS_ENABLED(CONFIG_PPA_BBF247_MODE1)
	{ "bbf247_hgu_model", 0600, &dbgfs_file_ppv4_bbf247_hgu_seq_fops },
#endif
	{ "supp-accel",       0600, &dbgfs_file_ppv4_support_accel_seq_fops },
};

static struct ppa_debugfs_files pphal_fbm_debugfs_files[] = {
	{ "status",           0400, &dbgfs_file_fbm_status_seq_fops },
};

void ppv4_proc_file_create(void)
{
#if IS_ENABLED(CONFIG_PPA_BBF247_MODE1)
	bbf247_sess = kzalloc(sizeof(*bbf247_sess), GFP_KERNEL);

	if (!bbf247_sess)
		return;

	memset(&bbf247_sess->sess_id, BBF247_INVALID_SESS_ID,
			sizeof(int) * ARRAY_SIZE(bbf247_sess->sess_id));

	memset(&bbf247_sess->eth_arr, 0,
			sizeof(char *) * ARRAY_SIZE(bbf247_sess->eth_arr));
#endif /*CONFIG_PPA_BBF247_MODE1*/

	ppa_debugfs_create(ppa_hal_debugfs_dir_get(), "pp",
		&ppa_ppv4hal_debugfs_dir, lgm_hal_debugfs_files,
		ARRAY_SIZE(lgm_hal_debugfs_files));
	if (ppa_ppv4hal_debugfs_dir)
		debugfs_create_u32("sess_timeout_thr", 0600,
			ppa_ppv4hal_debugfs_dir, &g_sess_timeout_thr);

	ppa_debugfs_create(ppa_hal_debugfs_dir_get(), "fbm",
		&ppa_fbm_debugfs_dir, pphal_fbm_debugfs_files,
		ARRAY_SIZE(pphal_fbm_debugfs_files));
	if (ppa_fbm_debugfs_dir) {
		debugfs_create_file_unsafe("gpid", 0600,
					   ppa_fbm_debugfs_dir, NULL,
					   &dbgfs_file_fbm_gpid_seq_fops);
		debugfs_create_file_unsafe("shaping_step", 0600,
					   ppa_fbm_debugfs_dir, NULL,
					   &dbgfs_file_fbm_step_seq_fops);
		debugfs_create_file_unsafe("shaping_small_step", 0600,
					   ppa_fbm_debugfs_dir, NULL,
					   &dbgfs_file_fbm_sstep_seq_fops);
		debugfs_create_file_unsafe("pool_thr", 0600,
					   ppa_fbm_debugfs_dir, NULL,
					   &dbgfs_file_fbm_pool_thr_seq_fops);
		debugfs_create_file_unsafe("min_cnt", 0600,
					   ppa_fbm_debugfs_dir, NULL,
					   &dbgfs_file_fbm_min_cnt_seq_fops);
		debugfs_create_file_unsafe("cir_high", 0600,
					   ppa_fbm_debugfs_dir, NULL,
					   &dbgfs_file_fbm_hcir_seq_fops);
		debugfs_create_file_unsafe("cir_low", 0600,
					   ppa_fbm_debugfs_dir, NULL,
					   &dbgfs_file_fbm_lcir_seq_fops);
		debugfs_create_file_unsafe("cir_max", 0600,
					   ppa_fbm_debugfs_dir, NULL,
					   &dbgfs_file_fbm_mcir_seq_fops);
		debugfs_create_file_unsafe("enable", 0600,
					   ppa_fbm_debugfs_dir, NULL,
					   &dbgfs_file_fbm_enable_seq_fops);
	}

#ifdef CONFIG_RFS_ACCEL
	ppa_rfs_proc_file_create();
#endif /* CONFIG_RFS_ACCEL */
	return;
}

void ppv4_proc_file_remove(void)
{
	ppa_debugfs_remove(ppa_ppv4hal_debugfs_dir,
		lgm_hal_debugfs_files,
		ARRAY_SIZE(lgm_hal_debugfs_files));

#if IS_ENABLED(CONFIG_PPA_BBF247_MODE1)
	kfree(bbf247_sess);
#endif /*CONFIG_PPA_BBF247_MODE1*/
#ifdef CONFIG_RFS_ACCEL
	ppa_rfs_proc_file_remove();
#endif /* CONFIG_RFS_ACCEL */
}
#endif /*defined(PPA_API_PROC)*/

static int pp_hal_sgc_alloc(PPA_NETIF *dev, struct sgc_info *sgc, int count)
{
	uint32_t owner;
	uint16_t cntr[2];
	uint32_t ret = PPA_SUCCESS;
	int i;

	/* distribute sgc group based on interface type */
	sgc[0].grp = sgc[1].grp = PP_SGC_LVL_MAX;
#ifdef DOCSIS_SUPPORT
	if (ppa_is_netif_bridged(dev)) {
		sgc[0].grp = PP_SGC_LVL_3;
		sgc[1].grp = PP_SGC_LVL_6;
	} else {
		sgc[0].grp = PP_SGC_LVL_6;
		sgc[1].grp = PP_SGC_LVL_3;
	}
#else
	if (ppa_check_is_ppp_netif(dev) ||
	    ppa_is_gre_netif(dev)) {
		sgc[0].grp = PP_SGC_LVL_4;
		sgc[1].grp = PP_SGC_LVL_5;
	} else if (netif_is_macvlan(dev) ||
		   ppa_dev_is_br(dev)) {
		sgc[0].grp = PP_SGC_LVL_5;
		sgc[1].grp = PP_SGC_LVL_6;
	} else if (is_vlan_dev(dev)) {
		sgc[0].grp = PP_SGC_LVL_6;
		sgc[1].grp = PP_SGC_LVL_5;
	} else if (ppa_is_netif_bridged(dev)) {
		sgc[0].grp = PP_SGC_LVL_3;
		sgc[1].grp = PP_SGC_LVL_2;
	} else {
		sgc[0].grp = PP_SGC_LVL_2;
		sgc[1].grp = PP_SGC_LVL_3;
	}
#endif /* DOCSIS_SUPPORT */

	owner = PP_SGC_SHARED_OWNER;
	for (i = 0; i < count; i++) {
		cntr[0] = cntr[1] = PP_SGC_INVALID;
		ret = pp_sgc_alloc(owner, sgc[i].grp, cntr, 2);
		if (unlikely(ret)) {
			dbg("<%s:%d> pp_sgc_alloc() failed for group:%u\n",
			    __func__, __LINE__, sgc[i].grp);
		}
		sgc[i].rx_id = cntr[0];
		sgc[i].tx_id = cntr[1];
	}

	return ret;
}

static int pp_hal_sgc_get(struct sgc_info *sgc, int count,
			  struct pp_stats *tx_stats, struct pp_stats *rx_stats)
{
	int ret = PPA_SUCCESS;
	int i;

	for (i = 0; i < count; i++) {
		if (tx_stats && (sgc[i].tx_id != PP_SGC_INVALID)) {
			ret = pp_sgc_get(sgc[i].grp, sgc[i].tx_id,
					 &tx_stats[i], NULL);
			if (unlikely(ret)) {
				dbg("<%s:%d> pp_sgc_get() failed for "
				    "cntr [%u:%u]\n", __func__, __LINE__,
				    sgc[i].grp, sgc[i].tx_id);
			}
		}
		if (rx_stats && (sgc[i].rx_id != PP_SGC_INVALID)) {
			ret = pp_sgc_get(sgc[i].grp, sgc[i].rx_id,
					 &rx_stats[i], NULL);
			if (unlikely(ret)) {
				dbg("<%s:%d> pp_sgc_get() failed for "
				    "cntr [%u:%u]\n", __func__, __LINE__,
				    sgc[i].grp, sgc[i].rx_id);
			}
		}
	}

	return ret;
}

static void pp_hal_sgc_free(struct sgc_info *sgc, int count)
{
	uint32_t owner;
	uint16_t cntr[2];
	uint32_t ret = 0;
	int i;

	owner = PP_SGC_SHARED_OWNER;
	for (i = 0; i < count; i++) {
		cntr[0] = sgc[i].rx_id;
		cntr[1] = sgc[i].tx_id;
		ret = pp_sgc_free(owner, sgc[i].grp, cntr, 2);
		if (unlikely(ret)) {
			dbg("<%s:%d> pp_sgc_free() failed for cntrs"
			    " [%u:%u], [%u:%u]\n", __func__, __LINE__,
			    sgc[i].grp, cntr[0],
			    sgc[i].grp, cntr[1]);
		}
	}
}

static inline int alloc_if_stats_idx(int indx, PPA_NETIF *dev)
{
	int ret;

	ret = pp_hal_sgc_alloc(dev, if_stats_db->if_info[indx].sgc, 2);
	if (likely(!ret)) {
		if_stats_db->if_info[indx].dev = dev;
		refcount_set(&if_stats_db->if_info[indx].ref_cnt, 1);
		set_bit(indx, if_stats_db->if_bitmap);
	}

	return ret;
}

static inline void free_if_stats_idx(int indx)
{
	pp_hal_sgc_free(if_stats_db->if_info[indx].sgc, 2);
	clear_bit(indx, if_stats_db->if_bitmap);
	memset(&if_stats_db->if_info[indx], 0, sizeof(struct if_info));
}

static inline int get_if_stats_idx(PPA_NETIF *dev)
{
	int indx;

	for_each_set_bit(indx, if_stats_db->if_bitmap, PP_HAL_MAX_IFS_NUM) {
		if (if_stats_db->if_info[indx].dev == dev) {
			refcount_inc(&if_stats_db->if_info[indx].ref_cnt);
			return indx;
		}
	}

	return -1;
}

static inline void put_if_stats_idx(PPA_NETIF *dev)
{
	int indx;

	for_each_set_bit(indx, if_stats_db->if_bitmap, PP_HAL_MAX_IFS_NUM) {
		if (if_stats_db->if_info[indx].dev == dev) {
			if (refcount_dec_and_test(
			    &if_stats_db->if_info[indx].ref_cnt))
				free_if_stats_idx(indx);
			break;
		}
	}
}

static int add_interface(struct netif_info *ifinfo)
{
	int ret;
	int indx;

	if (!ifinfo || !ifinfo->netif)
		return 0;

	if (!(ifinfo->flags & (NETIF_PHYS_PORT_GOT | NETIF_BRIDGE)))
		return 0;

	if (!strncmp(ifinfo->name, ifinfo->phys_netif_name, PPA_IF_NAME_SIZE)) {
		if (!(ifinfo->flags & NETIF_BRIDGE))
			return 0;
	}

	if (is_lgm_special_netif(ifinfo->netif))
		return 0;

	spin_lock_bh(&if_stats_db->lock);
	indx = get_if_stats_idx(ifinfo->netif);
	if (indx >= 0) {
		spin_unlock_bh(&if_stats_db->lock);
		return 0;
	}

	indx = find_first_zero_bit(if_stats_db->if_bitmap, PP_HAL_MAX_IFS_NUM);
	if (indx >= PP_HAL_MAX_IFS_NUM) {
		spin_unlock_bh(&if_stats_db->lock);
		return PPA_FAILURE;
	}
	ret = alloc_if_stats_idx(indx, ifinfo->netif);
	spin_unlock_bh(&if_stats_db->lock);
	return ret;
}

static int del_interface(struct netif_info *ifinfo)
{
	if (!ifinfo || !ifinfo->netif)
		return 0;

	spin_lock_bh(&if_stats_db->lock);
	put_if_stats_idx(ifinfo->netif);
	spin_unlock_bh(&if_stats_db->lock);
	return 0;
}

static int get_if_stats(PPA_NETIF *dev, struct intf_mib *ifmib)
{
	int ret = PPA_SUCCESS;
	int indx;
	struct sgc_info *sgc;
	struct pp_stats tx_stats[2];
	struct pp_stats rx_stats[2];
	int i;

	spin_lock_bh(&if_stats_db->lock);
	indx = get_if_stats_idx(dev);
	if (indx < 0) {
		spin_unlock_bh(&if_stats_db->lock);
		return PPA_FAILURE;
	}

	sgc = if_stats_db->if_info[indx].sgc;
	memset(&tx_stats, 0, (2 * sizeof(struct pp_stats)));
	memset(&rx_stats, 0, (2 * sizeof(struct pp_stats)));
	ret = pp_hal_sgc_get(sgc, 2, tx_stats, rx_stats);
	if (unlikely(ret)) {
		ret = PPA_FAILURE;
		goto exit;
	}

	for (i = 0; i < 2; i++) {
		/* Tx mib */
		ifmib->tx_packets += tx_stats[i].packets;
		ifmib->tx_bytes += tx_stats[i].bytes;

		/* Rx mib */
		ifmib->rx_packets += rx_stats[i].packets;
		ifmib->rx_bytes += rx_stats[i].bytes;
	}

exit:
	put_if_stats_idx(dev);
	spin_unlock_bh(&if_stats_db->lock);
	return ret;
}

static int test_and_attach_sgc(uint16_t sgc[PP_SI_SGC_MAX],
			       int indx, bool is_tx)
{
	int i;
	struct if_info *ifinfo = &if_stats_db->if_info[indx];

	for (i = 0; i < ARRAY_SIZE(ifinfo->sgc); i++) {
		if (sgc[ifinfo->sgc[i].grp] != PP_SGC_INVALID)
			continue;

		if (is_tx)
			sgc[ifinfo->sgc[i].grp] = ifinfo->sgc[i].tx_id;
		else
			sgc[ifinfo->sgc[i].grp] = ifinfo->sgc[i].rx_id;

		return PPA_SUCCESS;
	}

	return PPA_FAILURE;
}

static int attach_sgc(PPA_NETIF *rxif, PPA_NETIF *txif,
		      uint16_t sgc[PP_SI_SGC_MAX])
{
	int indx;
	PPA_NETIF *br_rxif = NULL, *br_txif = NULL;

	rcu_read_lock();
	spin_lock_bh(&if_stats_db->lock);
	if (rxif) {
		indx = get_if_stats_idx(rxif);
		if ((indx >= 0) && test_and_attach_sgc(sgc, indx, 0))
			put_if_stats_idx(rxif);
		if (ppa_is_netif_bridged(rxif))
			br_rxif = netdev_master_upper_dev_get_rcu(rxif);
	}

	if (txif) {
		indx = get_if_stats_idx(txif);
		if ((indx >= 0) && test_and_attach_sgc(sgc, indx, 1))
			put_if_stats_idx(txif);
		if (ppa_is_netif_bridged(txif))
			br_txif = netdev_master_upper_dev_get_rcu(txif);
	}

	/* Attach SGC for the bridge interface, if routed session */
	if (br_rxif != br_txif) {
		if (br_rxif) {
			indx = get_if_stats_idx(br_rxif);
			if ((indx >= 0) && test_and_attach_sgc(sgc, indx, 0))
				put_if_stats_idx(br_rxif);
		}
		if (br_txif) {
			indx = get_if_stats_idx(br_txif);
			if ((indx >= 0) && test_and_attach_sgc(sgc, indx, 1))
				put_if_stats_idx(br_txif);
		}
	}
	spin_unlock_bh(&if_stats_db->lock);
	rcu_read_unlock();

	return PPA_SUCCESS;
}

static void detach_sgc(PPA_NETIF *rxif, PPA_NETIF *txif)
{
	PPA_NETIF *br_rxif = NULL, *br_txif = NULL;

	rcu_read_lock();
	spin_lock_bh(&if_stats_db->lock);
	if (rxif) {
		put_if_stats_idx(rxif);
		if (ppa_is_netif_bridged(rxif))
			br_rxif = netdev_master_upper_dev_get_rcu(rxif);
	}
	if (txif) {
		put_if_stats_idx(txif);
		if (ppa_is_netif_bridged(txif))
			br_txif = netdev_master_upper_dev_get_rcu(txif);
	}

	/* Detach SGC for the bridge interface, if routed session */
	if (br_rxif != br_txif) {
		if (br_rxif)
			put_if_stats_idx(br_rxif);
		if (br_txif)
			put_if_stats_idx(br_txif);
	}
	spin_unlock_bh(&if_stats_db->lock);
	rcu_read_unlock();
}

/*
 * ####################################
 *		 Global Function
 * ####################################
 */

/*!
	\fn uint32_t get_hal_id(uint32_t *p_family,
			uint32_t *p_type,
			uint32_t *p_if,
			uint32_t *p_mode,
			uint32_t *p_major,
			uint32_t *p_mid,
			uint32_t *p_minor)
			char *name,
			char *version)
	\ingroup PPA_lgm_pp_hal_GLOBAL_FUNCTIONS
	\brief read HAL ID
	\param p_family	get family code
	\param p_type	get driver type
	\param p_if	get interface type
	\param p_mode	get driver mode
	\param p_major	get major number
	\param p_mid	get mid number
	\param p_minor	get minor number
	\return no return value
 */
void get_lgm_pp_hal_id(uint32_t *p_family,
			uint32_t *p_type,
			uint32_t *p_if,
			uint32_t *p_mode,
			uint32_t *p_major,
			uint32_t *p_mid,
			uint32_t *p_minor)
{
	if ( p_family )
		*p_family = VER_FAMILY;

	if ( p_type )
		*p_type = VER_DRTYPE;

	if ( p_if )
		*p_if = VER_INTERFACE;

	if ( p_mode )
		*p_mode = VER_ACCMODE;

	if ( p_major )
		*p_major = VER_MAJOR;

	if ( p_mid )
		*p_mid = VER_MID;

	if ( p_minor )
		*p_minor = VER_MINOR;
}

/*!
	\fn uint32_t get_firmware_id(uint32_t *id,
					 char *name,
					 char *version)
	\ingroup PPA_lgm_pp_hal_GLOBAL_FUNCTIONS
	\brief read firmware ID
	\param p_family	 get family code
	\param p_type	 get firmware type
	\return no return value
 */
int32_t get_firmware_id(uint32_t *id,
				char *p_name,
				char *p_version)
{
	/* TBD */
	/* Get the firmware version from PPv4 */

	/*
	*id=sw_version.nId;
	ppa_memcpy(p_name,sw_version.cName, PPA_VERSION_LEN);
	ppa_memcpy(p_version,sw_version.cVersion, PPA_VERSION_LEN);
	*/

	return PPA_SUCCESS;
}

/*!
	\fn uint32_t get_number_of_phys_port(void)
	\ingroup PPA_lgm_pp_hal_GLOBAL_FUNCTIONS
	\brief get max number of physical ports
	\return get max number of physical ports
 */
uint32_t get_number_of_phys_port(void)
{
	/* TBD?? needed ? get the port number dynamically from the system*/

	return MAX_LGM_PORTS;
}

/*!
	\fn void get_phys_port_info(uint32_t port, uint32_t *p_flags,
				PPA_IFNAME ifname[PPA_IF_NAME_SIZE])
	\ingroup PPA_lgm_pp_hal_GLOBAL_FUNCTIONS
	\brief get physical port information
	\param port	 in port id
	\param p_flags	 get flags
	\param ifname	 get inteface name [ depricated ]
	\return no return value
 */
void get_phys_port_info(uint32_t port, uint32_t *p_flags,
				PPA_IFNAME ifname[PPA_IF_NAME_SIZE])
{
	/* This function can only set the flags based on GSWIP-O configuration
	Interface name needs to be retrieved from the dp */

	if ( port >= MAX_LGM_PORTS) {
		if (p_flags)
			*p_flags = 0;
		if (ifname)
			*ifname = 0;
		return;
	}

	if (p_flags) {
		*p_flags = 0;
		switch (port) {
		case 0: /*CPU port */
			*p_flags = PPA_PHYS_PORT_FLAGS_MODE_CPU_VALID;
			*ifname = 0;
			break;
		case 1:
		case 2: /* ethernet wan port*/
			if (g_port_map & (1 << port)) {
				*p_flags = PPA_PHYS_PORT_FLAGS_MODE_ETH_WAN_VALID;
				*p_flags |= PPA_PHYS_PORT_FLAGS_OUTER_VLAN;
			}
			break;
		case 3: /*LAN side ports */
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
			if (g_port_map & (1 << port)) {
				*p_flags = PPA_PHYS_PORT_FLAGS_MODE_ETH_LAN_VALID;
				*p_flags |= PPA_PHYS_PORT_FLAGS_OUTER_VLAN;
			}
			break;
		case 9: /* dynamic ports */
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
		case 15:
			if (g_port_map & (1 << port)) {
				*p_flags = PPA_PHYS_PORT_FLAGS_MODE_ETH_MIX_VALID;
				*p_flags |= PPA_PHYS_PORT_FLAGS_OUTER_VLAN;
			}
			break;
		default:
			*p_flags = 0;
			break;
		}
	}
}

/*!
	\fn void get_max_route_entries(uint32_t *p_entry,
					uint32_t *p_mc_entry)
	\ingroup PPA_lgm_pp_hal_GLOBAL_FUNCTIONS
	\brief get maximum number of routing entries
	\param p_entry	get maximum number of uni-cast routing entries.
	\param p_mc_entry get maximum number of multicast routing entries.
	\return no return value
 */
void get_max_route_entries(uint32_t *p_entry,
				uint32_t *p_mc_entry)
{
	if ( p_entry )
		*p_entry = g_max_hw_sessions;

	if ( p_mc_entry )
		*p_mc_entry = MAX_MC_GROUP_ENTRIES;
}

/*!
	\fn void get_acc_mode(uint32_t f_is_lan, uint32_t *p_acc_mode)
	\ingroup PPA_lgm_pp_hal_GLOBAL_FUNCTIONS
	\brief get acceleration mode for interfaces (LAN/WAN)
	\param f_is_lan		 0: WAN interface, 1: LAN interface
	\param p_acc_mode	 a u32 data pointer to get acceleration mode (PPA_ACC_MODE_ROUTING / PPA_ACC_MODE_NONE)
	\return no return value
 */
void get_acc_mode(uint32_t f_is_lan, uint32_t *p_acc_mode)
{
	if (f_is_lan)
		*p_acc_mode = g_us_accel_enabled;
	else
		*p_acc_mode = g_ds_accel_enabled;
}

/*!
	\fn void set_acc_mode(uint32_t f_is_lan,
					uint32_t acc_mode)
	\ingroup PPA_lgm_pp_hal_GLOBAL_FUNCTIONS
	\brief set acceleration mode for interfaces (LAN/WAN)
	\param f_is_lan		 0: WAN interface, 1: LAN interface
	\param p_acc_mode	 acceleration mode (PPA_ACC_MODE_ROUTING / PPA_ACC_MODE_NONE/ PPA_ACC_MODE_BRIDGING/ PPA_ACC_MODE_HYBRID)
	\return no return value
*/
void set_acc_mode(uint32_t f_is_lan, uint32_t acc_mode)
{
	if (f_is_lan)
		g_us_accel_enabled = acc_mode;
	else
		g_ds_accel_enabled = acc_mode;

	g_supp_accel_enabled = acc_mode;
}

/**
 * @brief Update packet device qos priority, only for WLAN interface currently
 * @param PPA_NETIF
 * @param PPA_SUBIF
 * @param PPA_BUF
 * @param uint32_t
 * @return packet device qos priority
 */
static uint32_t ppa_update_pkt_devqos_priority(PPA_NETIF *dev, PPA_SUBIF *subif,
					       PPA_BUF *skb, uint32_t prio)
{
	uint32_t new_prio = prio;

	if (!dev || !subif || !skb)
		return prio;

	if (!(subif->alloc_flag & (DP_F_FAST_WLAN | DP_F_FAST_WLAN_EXT)))
		return prio;

	if (ppa_update_pkt_devqos_priority_hook &&
	    !ppa_update_pkt_devqos_priority_hook(dev, subif, skb))
		new_prio = ppa_get_pkt_priority(skb);

	dbg("dev:%s skbprio:%d changed to devqos:%d\n", dev->name, prio, new_prio);
	return new_prio;
}

static inline int32_t set_egress_port_n_queue(struct uc_session_node *p_item,
					struct pp_sess_create_args *rt_entry,
					struct pktprs_desc *desc,
					PPA_SUBIF *dp_port)
{
	PPA_NETIF *txif = p_item->tx_if;
	struct pp_port_cfg pcfg = {0};
	bool len_update = 0;
	struct netdev_attr qos_attr = {0};

	if (txif->ifindex != desc->tx->ifindex) {
		txif = ppa_dev_get_by_index(desc->tx->ifindex);
		ppa_put_netif(txif);
	}

	ppa_memset(dp_port, 0, sizeof(PPA_SUBIF));
	/* Get the egress gpid from the tx netdevice */
	if (dp_get_netif_subifid(txif, desc->skb, NULL, NULL, dp_port, 0)) {
		dbg("Unable to get tx netdevice:%s GPID!!!\n",
			ppa_get_netif_name(txif));
		return PPA_FAILURE;
	}

	p_item->pkt.priority = ppa_update_pkt_devqos_priority(txif, dp_port,
						       desc->skb,
						       p_item->pkt.priority);

	/* Set eg port */
	rt_entry->eg_port = dp_port->gpid;
	dbg("%s %d ig_gpid=%d eg_port=%d eg_gpid=%d\n", __FUNCTION__, __LINE__,
	rt_entry->in_port, dp_port->port_id, rt_entry->eg_port);

	/* set session destination queue */
	if (!ppa_api_get_mapped_queue) {
		pr_err("no queue mapping\n");
		return PPA_FAILURE;
	}
#ifdef HAVE_QOS_EXTMARK
	qos_attr.mark = p_item->pkt.extmark;
#else
	qos_attr.mark = p_item->pkt.mark;
#endif
	qos_attr.portid = rt_entry->eg_port;
	qos_attr.tc = p_item->pkt.priority;
	qos_attr.dst_q_high = -1;
	qos_attr.skb = desc->skb;

	if (ppa_api_get_mapped_queue(p_item->tx_if, &qos_attr)) {
		pr_err("eg_port(%d) get map queue err\n", rt_entry->eg_port);
		return PPA_FAILURE;
	}
	rt_entry->dst_q = qos_attr.dst_q_low;
	rt_entry->dst_q_high = qos_attr.dst_q_high;
	dbg("%s %d prio %d low %d high %d\n", __FUNCTION__, __LINE__,
	    p_item->pkt.priority, rt_entry->dst_q, rt_entry->dst_q_high);

	/* Set the egress port max_len */
	if (p_item->flags & (SESSION_VALID_VLAN_INS | SESSION_VALID_OUT_VLAN_INS)) {
		if (pp_port_get(dp_port->gpid, &pcfg)) {
			dbg("pp_port_get failed in %s %d\n", __FUNCTION__, __LINE__);
		}

		if ((p_item->flags & SESSION_VALID_VLAN_INS) &&
			pcfg.tx.max_pkt_size < (ETH_MTU + ETH_HLEN + VLAN_HLEN)) {
			pcfg.tx.max_pkt_size += VLAN_HLEN;
			len_update = 1;
		}
		if ((p_item->flags & SESSION_VALID_OUT_VLAN_INS) &&
			pcfg.tx.max_pkt_size < (ETH_MTU + ETH_HLEN + VLAN_HLEN*2)) {
			pcfg.tx.max_pkt_size += VLAN_HLEN;
			len_update = 1;
		}
		if (len_update) {
			/*Set the modified port configuration */
			if (pp_port_update(dp_port->gpid, &pcfg)) {
				dbg("pp_port_update failed in %s %d\n", __FUNCTION__, __LINE__);
			}
		}
	}

	return PPA_SUCCESS;
}

static void attach_sgam_info(PPA_BUF *skb,
			     struct pp_sess_create_args *pp_args_ptr)
{
#if IS_ENABLED(CONFIG_SGAM)
	struct sgam_skb_ext_info *ext_ptr = NULL;
	int i, j;
	uint8_t sgc_grp;
	uint32_t sgm_ext_id = mxl_skb_ext_get_ext_id(SGAM_EXT_NAME);

	if (sgm_ext_id == MXL_SKB_EXT_INVALID)
		return;

	ext_ptr = mxl_skb_ext_find(skb, sgm_ext_id);
	if (!ext_ptr)
		return;

	for (i = 0; i < SGAM_MAX_METER; i++) {
		if (ext_ptr->meter_id[i] == PP_TBM_INVALID)
			continue;

		/* Find the first free slot and copy the tbm id */
		for (j = 0; j < PP_SI_TBM_MAX; j++) {
			if (pp_args_ptr->tbm[j] != PP_TBM_INVALID)
				continue;
			pp_args_ptr->tbm[j] = ext_ptr->meter_id[i];
			/* Enable remark flag only for valid dscp values (0 to 63) */
			if (ext_ptr->remark_dscp < PPA_MAX_DSCP) {
				set_bit(PP_SESS_FLAG_REMARK_BIT, &pp_args_ptr->flags);
				pp_args_ptr->remark_dscp = ext_ptr->remark_dscp;
			}
			break;
		}
	}

	for (i = 0; i < SGAM_MAX_GROUP_ACCT; i++) {
		if (ext_ptr->acct_id[i] == PP_SGC_INVALID)
			continue;
		/* If there is already a sgc allocated for this session from the
		 * same sgc grp, then throw a warning before overwriting it.
		 */
		sgc_grp = ext_ptr->acct_pool[i];
		if (pp_args_ptr->sgc[sgc_grp] != PP_SGC_INVALID) {
			pr_warn("Overwriting sgc info!! grp: %u, prev id: %u, new id: %u\n",
				sgc_grp, pp_args_ptr->sgc[sgc_grp], ext_ptr->acct_id[i]);
		}
		pp_args_ptr->sgc[sgc_grp] = ext_ptr->acct_id[i];
	}
#endif /* IS_ENABLED(CONFIG_SGAM) */
}

static int lpdev_validate_socket(struct uc_session_node *p_item, struct pktprs_desc *desc)
{
	struct sock *sk = lpdev_sk_lookup(p_item, desc->skb->skb_iif);

	/* current lookup fails for the device bound socket */
	if (!sk) {
		dbg("sk lookup fails!\n");
		return PPA_FAILURE;
	}

	sock_gen_put(sk);
	return PPA_SUCCESS;
}

static int pktprs_push_dummy_eth_header(struct pktprs_hdr *h)
{
	uint8_t l, p, nxt, p_sz;
	uint16_t proto;

	if (!h || pktprs_ip_hdr_off(h, PKTPRS_HDR_LEVEL0)) {
		dbg("no ip header!\n");
		return -1;
	}

	p_sz = ETH_HLEN;
	if (h->buf_sz + p_sz > sizeof(h->buf)) {
		dbg("pktprs buffer overflow buf_sz:%d!\n", h->buf_sz);
		return -1;
	}

	if (((struct iphdr *)&h->buf[0])->version == 6) {
		proto = ETH_P_IPV6;
		nxt = PKTPRS_PROTO_IPV6;
	} else {
		proto = ETH_P_IP;
		nxt = PKTPRS_PROTO_IPV4;
	}

	/* go over all the next protocols and update the offset */
	for (l = 0; l < PKTPRS_HDR_LEVEL_NUM; l++) {
		for (p = 0; p <= PKTPRS_PROTO_LAST; p++) {
			if (test_bit(p, &h->proto_bmap[l]))
				h->proto_info[p][l].off += p_sz;
		}
	}

	/* add the header into buffer */
	memmove(&h->buf[p_sz], &h->buf[0], h->buf_sz);

	/* increase the buf_sz */
	h->buf_sz += p_sz;

	memcpy(&h->buf[0], get_lp_dummy_l2_header(), (ETH_ALEN * 2));
	((struct ethhdr *)&h->buf[0])->h_proto = htons(proto);

	p = PKTPRS_PROTO_MAC;
	h->proto_info[p][0].off = 0;
	h->proto_info[p][0].nxt = nxt;
	set_bit(p, &h->proto_bmap[0]);

	return 0;
}

/* FIXME: API for CPU queues */
static int cpu_qmap[4] = {2, 4, 6, 8};

int32_t add_supportive_hw_route_entry(PPA_ROUTING_INFO *route)
{
	int32_t ret = 0;
	uint32_t session_id = 0;
	struct dp_qos_q_logic q_logic = {0};
	struct pktprs_desc *desc = NULL;
	struct uc_session_node *p_item = NULL;
	struct pp_sess_create_args rt_entry;
	int i;

	if (!g_supp_accel_enabled) {
		dbg("g_supp_accel_enabled is not set!!\n");
		return PPA_FAILURE;
	}

	ppa_memset(&rt_entry, 0, sizeof(struct pp_sess_create_args));
	desc = (struct pktprs_desc *)route->session_meta;
	if (!desc) {
		dbg("pktprs descriptor is null!!!\n");
		return PPA_FAILURE;
	}

	p_item = (struct uc_session_node *)route->p_item;

	if (!p_item->ig_gpid) {
		dbg("Invalid igress gpid for %s\n", p_item->rx_if ?
				p_item->rx_if->name : "NULL");
		return PPA_FAILURE;
	}

	rt_entry.dst_q_high = -1;
	rt_entry.in_port = p_item->ig_gpid;
	/* Set eg port */
	rt_entry.eg_port = get_cpu_portinfo();
	rt_entry.tmp_ud_sz = COPY_32BYTES;
	rt_entry.color = lgm_get_session_color(p_item);

	for (i = 0; i < ARRAY_SIZE(rt_entry.sgc); i++)
		rt_entry.sgc[i] = PP_SGC_INVALID;

	/*TBD: Set the token bucket metering */
	for (i = 0; i < ARRAY_SIZE(rt_entry.tbm); i++)
		rt_entry.tbm[i] = PP_TBM_INVALID;

	q_logic.q_id = cpu_qmap[smp_processor_id()];

	if (dp_qos_get_q_logic(&q_logic, 0) == DP_FAILURE) {
		pr_err("%s:%d ERROR Failed to Logical Queue Id\n",
				__func__, __LINE__);
		return PPA_FAILURE;
	}

	rt_entry.dst_q = q_logic.q_logic_id;
	rt_entry.ps =  p_item->dest_subifid & 0xFFFF; /* sub_if_id */
	/*Set the session flags */
	set_bit(PP_SESS_FLAG_PS_VALID_BIT, &rt_entry.flags);
	ppa_memcpy(desc->tx, desc->rx, sizeof(struct pktprs_hdr));

	/* Fill in the fv information */
	rt_entry.rx = desc->rx;
	rt_entry.tx = desc->tx;
	/* Fill in the Hash information */
	rt_entry.hash.h1 = p_item->hwhash.h1;
	rt_entry.hash.h2 = p_item->hwhash.h2;
	rt_entry.hash.sig = p_item->hwhash.sig;

	dbg("ig gpid=%d eg gpid=%d, rt_entry.dst_q=%d q_logic.q_id %d\n",
			rt_entry.in_port, rt_entry.eg_port, rt_entry.dst_q,
			q_logic.q_id);

	rt_entry.dst_q_high = rt_entry.dst_q;

	/* Callin the API */
	ret = pp_session_create(&rt_entry, &session_id, NULL);
	if (ret) {
		PPA_HAL_RTSTATS_INC(uc_dropped_sess);
		switch (ret) {
		case GSW_ROUTE_ERROR_RT_SESS_FULL:
			nsess_add_fail_rt_tbl_full++;
			break;
		case GSW_ROUTE_ERROR_RT_COLL_FULL:
			nsess_add_fail_coll_full++;
			break;
		default:
			nsess_add_fail_oth++;
			break;
		}
		dbg("pp_session_create returned failure!! ret=%d\n", ret);
		return PPA_FAILURE;
	}

	/* dummy SGC attach just to increment reference count,
	 * which is decremented in deletion i.e., del_routing_entry()
	 */
	attach_sgc(p_item->rx_if, p_item->tx_if, rt_entry.sgc);

	dbg("pp_session_create succeeded id=%d\n",session_id);
	if (p_item->pkt.protocol == ETH_P_IP)
		PPA_HAL_RTSTATS_INC(curr_uc_ipv4_session);
	else
		PPA_HAL_RTSTATS_INC(curr_uc_ipv6_session);
	route->entry = p_item->routing_entry = session_id;
	p_item->flags |= SESSION_ADDED_IN_HW;
	p_item->dest_qid = rt_entry.dst_q;

	/*set used flag in hal db*/
	if ((session_id >= 0) && (session_id < g_max_hw_sessions)) {
		spin_lock(&g_hal_db_lock);
		pp_hal_db[session_id].used = 1;
		pp_hal_db[session_id].node = (void *)p_item;
		spin_unlock(&g_hal_db_lock);
	}
	return PPA_SUCCESS;
}

/*!
	\fn int32_t add_routing_entry(PPA_ROUTING_INFO *route_info)
	\ingroup PPA_lgm_pp_hal_GLOBAL_FUNCTIONS
	\brief add one routing entry
 */
int32_t add_routing_entry(PPA_ROUTING_INFO *route)
{
	int32_t ret = 0, i;
	uint32_t session_id = 0;
	struct pp_sess_create_args rt_entry;
	struct pktprs_desc *desc = NULL;
	PPA_SUBIF *dp_port;
	PPA_SUBIF *dp_port_vuni;
#if IS_ENABLED(CONFIG_LGM_TOE)
	bool sk_gro_support = 1;
	PPA_LRO_INFO lro_entry = {0};
	struct dp_qos_q_logic q_logic = {0};
#endif /*IS_ENABLED(CONFIG_LGM_TOE)*/
#if IS_ENABLED(CONFIG_INTEL_VPN)
	struct intel_vpn_tunnel_info tun_info = {0};
#elif IS_ENABLED(CONFIG_MXL_VPN)
	struct mxl_vpn_tunnel_info tun_info = {0};
#endif
	bool is_eg_vpna=0;

	struct uc_session_node *p_item = (struct uc_session_node *)route->p_item;
	if (!p_item) {
		dbg("uc_session_node is null!!!\n");
		return PPA_FAILURE;
	}

	desc = (struct pktprs_desc *)route->session_meta;
	if (!desc) {
		dbg("pktprs descriptor is null!!!\n");
		return PPA_FAILURE;
	}

	if (!PKTPRS_IS_MAC(desc->rx, PKTPRS_HDR_LEVEL0) &&
	    !(p_item->flag2 & SESSION_FLAG2_CPU_OUT)) {
		dbg("no mac header!\n");
		return PPA_FAILURE;
	}

	if ((!p_item->hwhash.h1) && (!p_item->hwhash.h2) && (!p_item->hwhash.sig)) {
		dbg("hardware hash is null!!!\n");
	}

	ppa_memset(&rt_entry, 0, sizeof(struct pp_sess_create_args));

	nsess_add++;

	rt_entry.in_port = p_item->ig_gpid;
	if (!rt_entry.in_port) {
		if (!(p_item->flag2 & SESSION_FLAG2_CPU_OUT)) {
			dbg("Ingress port in null!\n");
			return PPA_FAILURE;
		} else {
		/* Local out session */
		/*TBD: ingress port needs to be set as the litepath device gpid when the litepath HW acceleration is enabled*/
#if IS_ENABLED(LITEPATH_HW_OFFLOAD)
			if (lpdev_validate_socket(p_item, desc)) {
				p_item->flags |= SESSION_NOT_ACCELABLE;
				return PPA_FAILURE;
			}
			rt_entry.in_port = ppa_get_lp_gpid();
#else
			/*until the hw acceleration is enabled; we keep this session not accelable*/
			p_item->flags |= SESSION_NOT_ACCELABLE;
			return PPA_FAILURE;
#endif
		}
	}

	dp_port = ppa_malloc(sizeof(PPA_SUBIF));
	if (!dp_port) {
		dbg("[%s:%d] DP subif allocation failed!\n",
			__func__, __LINE__);
		return PPA_ENOMEM;
	}
	ppa_memset(dp_port, 0, sizeof(PPA_SUBIF));

	if (p_item->tx_if) {
	/* get the physical tx netdevice*/
		if (!(p_item->flags & SESSION_TUNNEL_ESP)
#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
			|| get_vpn_tun_params(p_item->spi, &tun_info)
#endif
		   ) {
			/* non-esp or real esp bypass sessions */
			if (set_egress_port_n_queue(p_item, &rt_entry,
				desc, dp_port) != PPA_SUCCESS) {
				ppa_free(dp_port);
				return PPA_FAILURE;
			}
		} else {
#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
			/*Get the vpn gpid and qid populated */
			spin_lock_bh(&g_tun_db_lock);
			/* add the tunnel to the db */
			if (!is_ipsec_tunnel_id_valid(p_item->tunnel_idx)) {
				p_item->tunnel_idx = tun_info.tunnel_id;
				ipsec_tunn_db_add(p_item);
			}
			/* add the session to the tunnel list for rekeying deletion */
			list_add(&p_item->tun_node,
				 &ipsec_tun_db[tun_info.tunnel_id].sessions);
			spin_unlock_bh(&g_tun_db_lock);

			if (tun_info.mode == VPN_MODE_TRANSPORT)
				set_bit(PP_SESS_FLAG_ESP_TRANSPORT_BIT, &rt_entry.flags);

			/* Downstream ESP packets; to be forwarded to the VPNA for decryption*/
			if (p_item->flag2 & SESSION_FLAG2_VALID_IPSEC_INBOUND) {
				/* IPSec Inbound session 1:Tunnel session*/
				is_eg_vpna = 1;
				if (set_vpn_inbound_session_params(&rt_entry, desc, p_item, &tun_info) != PPA_SUCCESS) {
					ppa_free(dp_port);
					return PPA_FAILURE;
				}
			} else {
				/*p_item->flag2 & SESSION_FLAG2_VALID_IPSEC_OUTBOUND*/
				if (tun_info.vpn_if->ifindex == desc->rx->ifindex) {
					/* we use the same tx pkt of the 1st
					 * session to open the 2nd one,
					 * so the ing port/gpid are not updated
					 */
					p_item->ig_gpid = g_vpna_conn.gpid;
					rt_entry.in_port = p_item->ig_gpid;
					/* IPSec Outboud session 2: Tunnel session "already encrypted"
					egress port and queue shall be like any other normal session*/
					set_bit(PP_SESS_FLAG_INTERNAL_HASH_CALC_BIT, &rt_entry.flags);
					set_bit(PP_SESS_FLAG_MTU_CHCK_BIT, &rt_entry.flags);
					if (set_egress_port_n_queue(p_item, &rt_entry,
						desc, dp_port) != PPA_SUCCESS) {
						ppa_free(dp_port);
						return PPA_FAILURE;
					}
				} else {
					/* In this case ingress packet is plain ethernet and egress
					is un encrypted ESP packet; we need to get the SPI from EGRESS packet*/
					/* IPSec Outbound session 1: Upstream TCP/UDP packets;
					to be forwarded to VPNA for ESP encapsulation and encryption */

					is_eg_vpna = 1;
					if (set_vpn_outbound_session_params(&rt_entry, desc, p_item, &tun_info) != PPA_SUCCESS) {
						ppa_free(dp_port);
						return PPA_FAILURE;
					}
				}
			}

			if (rt_entry.in_port == g_vpna_conn.gpid ||
				rt_entry.eg_port == g_vpna_conn.gpid) {
					set_bit(PP_SESS_FLAG_VPN_BIT, &rt_entry.flags);
			}
#endif /* CONFIG_INTEL_VPN || CONFIG_MXL_VPN */
		}
	} else {
		/* Locally terminated session we need to get the CPU GPID/queueid or LRO GPID/queueid*/
		if ((p_item->flag2 & SESSION_FLAG2_CPU_IN)) {
#if IS_ENABLED(CONFIG_LGM_TOE)
			if (!ppa_bypass_lro(desc->skb)) {
				/*add lro entry in PP and lro engine */
				ppa_memset(&lro_entry,0,sizeof(lro_entry));

				if (p_item->flags & SESSION_IS_TCP) {
					/*Set the session flags */
					if (is_hw_litepath_enabled()) {
						/* Soft LRO applicable only for C0 platforms */
						if (get_soc_rev() == CQM_LGM_C)
							set_bit(PP_SESS_FLAG_SLRO_INFO_BIT, &rt_entry.flags);
					}
					lro_entry.lro_type = LRO_TYPE_TCP;
					/*check mptcp options and if yes set
					lro_entry.lro_type = LRO_TYPE_MPTCP;
					*/
				} else if (p_item->flags & SESSION_TUNNEL_ESP) {
					dbg("ESP not supported in LRO\n");
				} else {
					struct sock *sk = NULL;
					struct udphdr *uh = udp_hdr(desc->skb);

					if (!uh) {
						ppa_free(dp_port);
						return PPA_FAILURE;
					}
					rcu_read_lock();
					switch (ntohs(desc->skb->protocol)) {
					case ETH_P_IP:
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 10, 110)
						sk = udp4_lib_lookup_skb(desc->skb, uh->source, uh->dest);
#else
						sk = __udp4_lib_lookup(dev_net(desc->skb->dev), ip_hdr(desc->skb)->saddr, uh->source,
								ip_hdr(desc->skb)->daddr, uh->dest, inet_iif(desc->skb),
								inet_sdif(desc->skb), &udp_table, NULL);
#endif
						break;
#if IS_ENABLED(CONFIG_IPV6)
					case ETH_P_IPV6:
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 10, 110)
						sk = udp6_lib_lookup_skb(desc->skb, uh->source, uh->dest);
#else
						sk = __udp6_lib_lookup(dev_net(desc->skb->dev), &ipv6_hdr(desc->skb)->saddr, uh->source,
								&ipv6_hdr(desc->skb)->daddr, uh->dest, inet6_iif(desc->skb),
								inet6_sdif(desc->skb), &udp_table, NULL);
#endif
						break;
#endif /* CONFIG_IPV6 */
					default:
						rcu_read_unlock();
						ppa_free(dp_port);
						dbg("%s Unsupported protocol:%x", __func__, ntohs(desc->skb->protocol));
						return PPA_FAILURE;
					}
					lro_entry.lro_type = LRO_TYPE_UDP;
					if (unlikely(!sk)) {
						dbg("%s invalid socket!", __func__);
						rcu_read_unlock();
						ppa_free(dp_port);
						return PPA_FAILURE;
					} else if (!udp_sk(sk)->gro_enabled) {
						dbg("%s udp socket can't accept GRO/LRO packets", __func__);
						sk_gro_support = 0;
					}
					rcu_read_unlock();
				}

				if (sk_gro_support &&
					!test_bit(PP_SESS_FLAG_SLRO_INFO_BIT, &rt_entry.flags) &&
					add_lro_entry(&lro_entry) == PPA_SUCCESS) {
					/* use lro hw only when soft lro flag is off */
					dbg("lro entry added\n");
					p_item->flag2 |= SESSION_FLAG2_LRO;
					p_item->lro_sessid = lro_entry.session_id;
					/*cpu gpid if litepath offload is not enabled*/
					rt_entry.eg_port = get_cpu_portinfo();
					/*LRO qid as returned from the lro conn*/
					rt_entry.dst_q = lro_entry.dst_q;
					rt_entry.dst_q_high = -1;
					/*set the lro flowid */
					rt_entry.lro_info = lro_entry.session_id;

					/*Set the number of Template UD bytes to copy*/
					rt_entry.tmp_ud_sz = COPY_16BYTES;

					/*Set the session flags */
					set_bit(PP_SESS_FLAG_LRO_INFO_BIT, &rt_entry.flags);
				} else {
					dbg("lro entry add failed\n");
					rt_entry.eg_port = get_cpu_portinfo();
					rt_entry.tmp_ud_sz = COPY_16BYTES;
					q_logic.q_id = get_cpu_qid();

					if (dp_qos_get_q_logic(&q_logic, 0) == DP_FAILURE) {
						pr_err("%s:%d ERROR Failed to Logical Queue Id\n", __func__, __LINE__);
						ppa_free(dp_port);
						return PPA_FAILURE;
					}
					rt_entry.dst_q = q_logic.q_logic_id;
#if !IS_ENABLED(LITEPATH_HW_OFFLOAD)
					/*HW offload is not enabled session cannot be accelerated*/
					p_item->flags |= SESSION_NOT_ACCELABLE;
					ppa_free(dp_port);
					return PPA_FAILURE;
#endif /*IS_ENABLED(LITEPATH_HW_OFFLOAD)*/
					goto non_lro_ppv4_session;
				}
			} else {
non_lro_ppv4_session:
				rt_entry.eg_port = get_cpu_portinfo();
				rt_entry.tmp_ud_sz = COPY_16BYTES;
				q_logic.q_id = get_cpu_qid();
				dbg("[%s] q_logic.q_id = %d q_logic.q_logic_id = %d\n",__func__, q_logic.q_id, q_logic.q_logic_id);
				if (dp_qos_get_q_logic(&q_logic, 0) == DP_FAILURE) {
					pr_err("%s:%d ERROR Failed to Logical Queue Id\n", __func__, __LINE__);
					ppa_free(dp_port);
					return PPA_FAILURE;
				}
				rt_entry.dst_q = q_logic.q_logic_id;
				rt_entry.dst_q_high = -1;
			}
#endif /*CONFIG_LGM_TOE*/

#if IS_ENABLED(LITEPATH_HW_OFFLOAD)
			/*Set the gpid and qid of lpdev device*/
			if (is_hw_litepath_enabled()) {
				rt_entry.eg_port = ppa_get_lp_gpid();
				if (!(p_item->flag2 & SESSION_FLAG2_LRO)) {
					rt_entry.dst_q = ppa_get_lp_qid();
					rt_entry.dst_q_high = -1;
				}
			}
#endif /*IS_ENABLED(LITEPATH_HW_OFFLOAD)*/
		} else {
			dbg("Unable to get tx netdevice GPID!!!\n");
			ppa_free(dp_port);
			return PPA_FAILURE;
		}
	}

#if 0 // FIXME: needs more clarity
	/* Set the fsqm priority */
	/* TBD: where to fetch this info */
	rt_entry.fsqm_prio = lgm_get_fsqm_prio(desc->skb, p_item->tx_if);
#endif

	/*Set Color for the session */
	/* TBD: Based on what we are supposed to set color*/
	rt_entry.color = lgm_get_session_color(p_item);

	for (i = 0; i < ARRAY_SIZE(rt_entry.sgc); i++)
		rt_entry.sgc[i] = PP_SGC_INVALID;

	/*TBD: Set the token bucket metering */
	for (i = 0; i < ARRAY_SIZE(rt_entry.tbm); i++)
		rt_entry.tbm[i] = PP_TBM_INVALID;

	/*Set the UD parameters */
	if (!p_item->is_loopback) {
		if (!is_eg_vpna) {
			rt_entry.ps = 0;

			if ((p_item->flag2 & SESSION_FLAG2_CPU_IN)) {
#if IS_ENABLED(LITEPATH_HW_OFFLOAD)
				if (is_hw_litepath_enabled()) {
					/* If litepath is enabled packet needs to be received
					   on litepath netdev */
					rt_entry.ps = ppa_get_lp_subif() & 0xFFFF; /* sub_if_id */
				}
#endif /*IS_ENABLED(LITEPATH_HW_OFFLOAD)*/
				if (p_item->flag2 & SESSION_FLAG2_LRO) {
#if IS_ENABLED(CONFIG_LGM_TOE)
					/*Set lro type in UD*/
					/*set the lro type in dw0[25:24]*/
					rt_entry.ps |= (lro_entry.lro_type & 0x03) << 24;
#endif /*IS_ENABLED(CONFIG_LGM_TOE)*/
				}
			} else {
				if ((dp_port->alloc_flag & DP_F_VUNI)
					&& (dp_port->data_flag & DP_SUBIF_VANI)) {

					dp_port_vuni = ppa_malloc(sizeof(PPA_SUBIF));
					if (!dp_port_vuni) {
						dbg("[%s:%d] DP subif allocation failed!\n",
							__func__, __LINE__);
						ppa_free(dp_port);
						return PPA_ENOMEM;
					}
					ppa_memset(dp_port_vuni, 0, sizeof(PPA_SUBIF));

					if (dp_get_netif_subifid(dp_port->associate_netif,
						NULL, NULL, NULL, dp_port_vuni, 0)) {
						dbg("Unable to get tx netdevice GPID!!!\n");
						ppa_free(dp_port_vuni);
						ppa_free(dp_port);
						return PPA_FAILURE;
					}
					/* Set eg port to vuni port*/
					rt_entry.eg_port = dp_port_vuni->gpid;
					rt_entry.ps =  dp_port_vuni->subif & 0xFFFF; /* sub_if_id */
					ppa_free(dp_port_vuni);
				} else if (dp_port->alloc_flag & DP_F_DOCSIS) {
					set_bit(PP_SESS_FLAG_DOCSIS_BIT, &rt_entry.flags);
					rt_entry.ps =  desc->skb->DW0;
					dbg("[Docsis] rt_entry.eg_port %d",
						rt_entry.eg_port);
				} else {
					rt_entry.ps =  p_item->dest_subifid & 0xFFFF; /* sub_if_id */
					if(!(dp_port->alloc_flag & DP_F_ACA)) {
						/*In case of DC interfaces we dont need Egress flag */
						/* This field is supposed to carry DevQos for wireless*/
						/*set the egress flag in the SI UD bit 27 of PS-B*/
						rt_entry.ps |= BIT(27);
					}
					if (dp_port->alloc_flag & (DP_F_FAST_WLAN |
								   DP_F_FAST_WLAN_EXT)) {
						/*In case of DC interfaces we dont need Egress flag */
						/* This field carries DevQos for wireless*/
						/*set the DevQoS bit 24:27 */
						rt_entry.ps |= (p_item->pkt.priority & 0xF) << 24;
						/*set the Calss bit 28:31 */
						rt_entry.ps |= (p_item->pkt.priority & 0xF) << 28;
						dbg("rt_entry.ps:0x%x qosprio:%d\n", rt_entry.ps, p_item->pkt.priority);
					}
				}
			}

			/*Set the session flags */
			set_bit(PP_SESS_FLAG_PS_VALID_BIT, &rt_entry.flags);
		}

	} else {
		/*TBD: Fill in the pp_port_cls_data in case we have a second cycle through PPv4 */
	}

	/* L3-type directpath egress: add dummy eth header, to be removed by dpdp driver */
	if (dp_port->alloc_flag & DP_F_DIRECT) {
		if (!PKTPRS_IS_MAC(desc->tx, PKTPRS_HDR_LEVEL0) &&
		    pktprs_push_dummy_eth_header(desc->tx)) {
			dbg("unsupported directpath egress as no MAC header!\n");
			ppa_free(dp_port);
			return PPA_FAILURE;
		}
	}

	if (is_hw_litepath_enabled() &&
		(p_item->flag2 & SESSION_FLAG2_CPU_OUT)) {
		ppa_memcpy(desc->rx, desc->tx, sizeof(struct pktprs_hdr));
		if (p_item->flags & SESSION_VALID_VLAN_INS)
			pktprs_proto_remove(desc->rx, PKTPRS_PROTO_VLAN0, PKTPRS_HDR_LEVEL0);
		if (p_item->flags & SESSION_VALID_OUT_VLAN_INS)
			pktprs_proto_remove(desc->rx, PKTPRS_PROTO_VLAN1, PKTPRS_HDR_LEVEL0);
		if (p_item->flags & SESSION_VALID_PPPOE)
			pktprs_proto_remove(desc->rx, PKTPRS_PROTO_PPPOE, PKTPRS_HDR_LEVEL0);
		/* update MAC with correct eth type */
		ppa_memcpy(desc->rx->buf, get_lp_dummy_l2_header(), ETH_HLEN);
		set_ethtype(desc->rx, p_item->pkt.protocol);
		p_item->rx_if = ppa_get_lp_dev();
		set_bit(PP_SESS_FLAG_INTERNAL_HASH_CALC_BIT, &rt_entry.flags);
		rt_entry.color = PP_COLOR_GREEN;
	}
	if ((p_item->flag2 & SESSION_FLAG2_CPU_IN))
		ppa_memcpy(desc->tx, desc->rx, sizeof(struct pktprs_hdr));

	/* Fill in the fv information */
	rt_entry.rx = desc->rx;
	rt_entry.tx = desc->tx;

	/* Fill in the Hash information */
	rt_entry.hash.h1 = p_item->hwhash.h1;
	rt_entry.hash.h2 = p_item->hwhash.h2;
	rt_entry.hash.sig = p_item->hwhash.sig;

#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
	/* in some esp transport inbound cases, the outer ip isn't removed
	 * and needs to be modified, after encryption, the next header protocol
	 * is changed by the PP uC w/o csum being updated, for performance
	 * reasons.
	 * here we reflect this change in the 2nd round session
	 */
	if (g_vpna_conn.gpid == rt_entry.in_port &&
	    !PKTPRS_IS_ESP(desc->rx, PKTPRS_HDR_LEVEL0) &&
	    !PKTPRS_IS_ESP(desc->tx, PKTPRS_HDR_LEVEL0) &&
	    PKTPRS_IS_IPV4(desc->rx, PKTPRS_HDR_LEVEL0) &&
	    !PKTPRS_IS_MULTI_IP(desc->rx) &&
	    PKTPRS_IS_IPV4(desc->tx, PKTPRS_HDR_LEVEL0) &&
	    !PKTPRS_IS_MULTI_IP(desc->tx)) {
		struct iphdr *txip;
		PP_IPSEC_TUN_NODE *tun_info;
		unsigned int tunn_id;
		ulong ps = desc->skb->DW0;

		/* get tunnel id */
		tunn_id = FIELD_GET(GENMASK(24, 20), ps);

		/* get tunnel id from original descriptor */
		tun_info = &ipsec_tun_db[tunn_id];
		if (!is_ipsec_tunnel_id_valid(tunn_id) || !tun_info->valid) {
			dbg("Invalid ipsec tunnel id %u, ps %#lx\n",
			    tunn_id, ps);
			ppa_free(dp_port);
			return PPA_FAILURE;
		}

		/* the only real usecase we need this is inbound transport mode
		 * w/o IP tunnels
		 */
		if (tun_info->trns_mode && tun_info->is_inbound) {
			/* the change we want to reflect is from esp to
			 * whatever we have in the tx
			 */
			txip = pktprs_ipv4_hdr(desc->tx, PKTPRS_HDR_LEVEL0);
			csum_replace2(&rt_entry.ip_csum_delta,
				      htons(tun_info->org_nexthdr),
				      htons(txip->protocol));
		}
	}
#endif /* CONFIG_INTEL_VPN || CONFIG_MXL_VPN */

	dbg("ig_gpid=%d eg_port=%d eg_gpid=%d, rt_entry.dst_q=%d\n",
		rt_entry.in_port, dp_port->port_id, rt_entry.eg_port, rt_entry.dst_q);
	ppa_free(dp_port);

	if (ppa_tdox_enable_get()                      && /* tdox enabled */
	    (p_item->flags & SESSION_IS_TCP)           && /* TCP only */
	    (rt_entry.eg_port != g_vpna_conn.gpid)) {    /* not VPN */
		/* ack prioritization allowed when high prio q is set */
		if (rt_entry.dst_q_high != -1)
			set_bit(PP_SESS_FLAG_TDOX_PRIO_BIT, &rt_entry.flags);
		/* ack suppression for allowed tx interfaces only */
		if (p_item->flag2 & SESSION_FLAG2_ACK_SUPP_ALLOWED)
			set_bit(PP_SESS_FLAG_TDOX_SUPP_BIT, &rt_entry.flags);
	}

	attach_sgc(p_item->rx_if, p_item->tx_if, rt_entry.sgc);

	if (rt_entry.eg_port == fbm.gpid && fbm.enable) {
		/* Add Fast Buffer Monitor sgc & tbm */
		rt_entry.tbm[0] = fbm.tbm_id;
		rt_entry.sgc[fbm.sgc_grp] = fbm.sgc_id;
	}

	attach_sgam_info(desc->skb, &rt_entry);

	if (rt_entry.dst_q_high == -1)
		rt_entry.dst_q_high = rt_entry.dst_q;

	/* Callin the API */
	if ((ret = pp_session_create(&rt_entry, &session_id, NULL))) {
		PPA_HAL_RTSTATS_INC(uc_dropped_sess);
		switch(ret) {
		/* TBD: handle the correct errorcode */
		case GSW_ROUTE_ERROR_RT_SESS_FULL:
			nsess_add_fail_rt_tbl_full++;
			break;
		case GSW_ROUTE_ERROR_RT_COLL_FULL:
			nsess_add_fail_coll_full++;
			break;
		default:
			nsess_add_fail_oth++;
			break;
		}
		dbg("pp_session_create returned failure!! %s %d ret=%d\n", __FUNCTION__, __LINE__,ret);
#if IS_ENABLED(CONFIG_LGM_TOE)
		if (p_item->flag2 & SESSION_FLAG2_LRO) {
			del_lro_entry(rt_entry.lro_info);
		}
#endif /* CONFIG_LGM_TOE */
		detach_sgc(p_item->rx_if, p_item->tx_if);
		return PPA_FAILURE;
	}

	dbg("%s %d pp_session_create succeeded id=%d\n", __FUNCTION__, __LINE__,session_id);
	if (p_item->pkt.protocol == ETH_P_IP)
		PPA_HAL_RTSTATS_INC(curr_uc_ipv4_session);
	else
		PPA_HAL_RTSTATS_INC(curr_uc_ipv6_session);
	route->entry = p_item->routing_entry = session_id;
	p_item->flags |= SESSION_ADDED_IN_HW;
	p_item->dest_qid = rt_entry.dst_q;

	/*set used flag in hal db*/
	if ((session_id >= 0) && (session_id < g_max_hw_sessions)) {
		spin_lock_bh(&g_hal_db_lock);
		pp_hal_db[session_id].used = 1;
		if (test_bit(PP_SESS_FLAG_LRO_INFO_BIT, &rt_entry.flags))
			pp_hal_db[session_id].lro = 1;
		pp_hal_db[session_id].node = (void*)p_item;
#if IS_ENABLED(LITEPATH_HW_OFFLOAD)
		if (is_hw_litepath_enabled()) {
			pp_hal_db[session_id].lp_rxinfo =
				(struct lp_info *)
				ppa_malloc(sizeof(struct lp_info));
			if (pp_hal_db[session_id].lp_rxinfo) {
				ppa_memset(pp_hal_db[session_id].lp_rxinfo,
					   0, sizeof(struct lp_info));
				if (p_item->flag2 & SESSION_FLAG2_CPU_IN) {
					struct sock *sk = desc->skb->sk;
					enum pktprs_proto proto_type = PKTPRS_PROTO_IPV4;
#if IS_ENABLED(CONFIG_IPV6)
					if (PKTPRS_IS_IPV6(desc->tx, PKTPRS_HDR_LEVEL0))
						proto_type = PKTPRS_PROTO_IPV6;
#endif

					pp_hal_db[session_id].lp_rxinfo->is_soft_lro =
						test_bit(PP_SESS_FLAG_SLRO_INFO_BIT, &rt_entry.flags);
					pp_hal_db[session_id].lp_rxinfo->dst =
						dst_clone(skb_dst(desc->skb));
					if (sk && sk->sk_bound_dev_if) {
						pp_hal_db[session_id].lp_rxinfo->netif =
							dev_get_by_index_rcu(sock_net(sk),
									     sk->sk_bound_dev_if);
					} else {
						pp_hal_db[session_id].lp_rxinfo->netif =
							ppa_get_lp_dev();
					}
					pp_hal_db[session_id].lp_rxinfo->l3_offset =
						pktprs_hdr_off(desc->tx, proto_type,
							       PKTPRS_HDR_LEVEL0);
					pp_hal_db[session_id].lp_rxinfo->l4_offset =
						pktprs_hdr_sz(desc->tx, proto_type,
							      PKTPRS_HDR_LEVEL0);
					pp_hal_db[session_id].lp_rxinfo->is_pppoe =
						PKTPRS_IS_PPPOE(desc->tx,
								PKTPRS_HDR_LEVEL0);
					pp_hal_db[session_id].lp_rxinfo->proto =
						p_item->pkt.protocol;
					pp_hal_db[session_id].lp_rxinfo->lro_sessid =
						p_item->lro_sessid;
				} else if (p_item->flag2 & SESSION_FLAG2_CPU_OUT) {
					struct sock *sk = lpdev_sk_lookup(p_item, desc->skb->skb_iif);

					if (sk) {
						dbg("%s sk:%px sk_hw_learnt:1\n", __func__, sk);
						set_sk_hw_learnt(sk, 1);
						pp_hal_db[session_id].lp_rxinfo->sock = sk;
					} else {
						pr_err("%s sk:null sk_hw_learnt:1\n", __func__);
					}
				}
				refcount_set(&pp_hal_db[session_id].lp_rxinfo->refcnt, 1);
			} else {
				pr_err("[%s:%d] lp_rxinfo alloc failure!\n", __func__, __LINE__);
			}
		}
#endif /*IS_ENABLED(LITEPATH_HW_OFFLOAD)*/
		spin_unlock_bh(&g_hal_db_lock);
		dbg("%s %d session id=%d p_item=%px\n", __FUNCTION__, __LINE__, p_item->routing_entry, p_item);
	} else {
		dbg("invalid session_id %d!!\n", session_id);
	}

	return PPA_SUCCESS;
}

/*!
	\fn int32_t del_routing_entry(PPA_ROUTING_INFO *route_info)
	\ingroup PPA_lgm_pp_hal_GLOBAL_FUNCTIONS
	\brief add one routing entry
*/
int32_t del_routing_entry(PPA_ROUTING_INFO *route)
{
	int32_t ret = 0;
#if IS_ENABLED(LITEPATH_HW_OFFLOAD)
	struct lp_info *lp_rxinfo = NULL;
#endif
	struct uc_session_node *p_item = (struct uc_session_node *)route->p_item;
	if (!p_item)
		return PPA_FAILURE;

	if (p_item->flags & SESSION_ADDED_IN_HW) {
		dbg("%s %d deleting p_item=%px sessionid=%d\n", __FUNCTION__,
		    __LINE__, p_item, p_item->routing_entry);
#if IS_ENABLED(LITEPATH_HW_OFFLOAD)
		if (is_hw_litepath_enabled() &&
		    (p_item->flag2 & SESSION_FLAG2_CPU_OUT)) {
			struct sock *sk;

			spin_lock_bh(&g_hal_db_lock);
			lp_rxinfo = pp_hal_db[p_item->routing_entry].lp_rxinfo;
			sk = (lp_rxinfo ? lp_rxinfo->sock : NULL);
			if (sk) {
				dbg("%s sk:%px sk_hw_learnt:0\n", __func__, sk);
				lp_rxinfo->sock = NULL;
				set_sk_hw_learnt(sk, 0);
				sock_gen_put(sk);
			} else {
				pr_err("%s sk:null sk_hw_learnt:0\n", __func__);
			}
			spin_unlock_bh(&g_hal_db_lock);
		}
#endif /* LITEPATH_HW_OFFLOAD */

		if ((ret = pp_session_delete(p_item->routing_entry, NULL))) {
			dbg("pp_session delete returned Error:%d\n",ret);
		} else {
			if (p_item->pkt.protocol == ETH_P_IP)
				PPA_HAL_RTSTATS_DEC(curr_uc_ipv4_session);
			else
				PPA_HAL_RTSTATS_DEC(curr_uc_ipv6_session);
#if IS_ENABLED(CONFIG_LGM_TOE)
			if (p_item->flag2 & SESSION_FLAG2_LRO)
				del_lro_entry(p_item->lro_sessid);
#endif /* CONFIG_LGM_TOE */
			/*Reset set used flag in hal db*/
			spin_lock_bh(&g_hal_db_lock);
#if IS_ENABLED(LITEPATH_HW_OFFLOAD)
			lp_rxinfo = pp_hal_db[p_item->routing_entry].lp_rxinfo;
			if (lp_rxinfo)
				lp_rxinfo_put(lp_rxinfo);
#endif /*IS_ENABLED(LITEPATH_HW_OFFLOAD)*/
			ppa_memset(&pp_hal_db[p_item->routing_entry],0,sizeof(PP_HAL_DB_NODE));
			spin_unlock_bh(&g_hal_db_lock);
			detach_sgc(p_item->rx_if, p_item->tx_if);
		}

	}
	p_item->flags &= ~SESSION_ADDED_IN_HW;

#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
	if (!list_empty(&p_item->tun_node)) {
		spin_lock_bh(&g_tun_db_lock);
		if (!list_empty(&p_item->tun_node))
			list_del_init(&p_item->tun_node);
		spin_unlock_bh(&g_tun_db_lock);
	}
#endif

	return ret;
}

/*!
	\fn void del_wan_mc_entry(uint32_t entry)
	\ingroup PPA_lgm_pp_hal_GLOBAL_FUNCTIONS
	\brief delete one multicast routing entry
	\param entry	entry number got from function call "add_wan_mc_entry"
	\return no return value
 */
int32_t del_wan_mc_entry(PPA_MC_INFO *mc_route)
{
	int32_t ret = 0, i;

	if (mc_route->p_item) {
		struct mc_session_node *p_item = (struct mc_session_node *)mc_route->p_item;

		spin_lock_bh(&g_hal_mc_db_lock);
		if (mc_db[p_item->grp.group_id].used) {
			/*1. Delete the multicast Mc session */
			for (i = 0; i < MAX_MC_CLIENT_PER_GRP; i++) {
				if (is_valid_session(mc_db[p_item->grp.group_id].dst[i].sess_id)) {
					/*1. Delete all the group member PPv4sessions*/
					/* session_id always stored +1 to handle valid sessionid 0*/
					if ((ret = pp_session_delete(mc_db[p_item->grp.group_id].dst[i].sess_id - 1, NULL))) {
						dbg("pp_session delete multicast client session returned Error:%d\n", ret);
					}
				}
				/*If the interface bitmask is set have to remove the uC entry */
				if (p_item->grp.if_mask & (1 << i)) {
					/* 2.Reset the bit in uC multicast group*/
					if ((ret = pp_mcast_dst_set(p_item->grp.group_id, i, PPA_IF_DEL))) {
						dbg("pp_mcast_dst_set returned Error:%d\n", ret);
					}
				}
			}

			/* 3.Clear the hal db entry */
			ppa_memset(&mc_db[p_item->grp.group_id], 0, sizeof(MC_DB_NODE));
			/* Clear the HW flag */
			p_item->flags &= ~SESSION_ADDED_IN_HW;

			/*If the session is not a DROP session */
			if (!(p_item->flags & SESSION_DROP)) {
				/*4. Delete the multicast group PPv4 session*/
				if (is_valid_session(mc_route->p_entry)) {
					if ((ret = pp_session_delete(mc_route->p_entry - 1, NULL))) {
						dbg("pp_session delete multicast group session returned Error:%d\n", ret);
					}
					if (!p_item->grp.sess_info->ip_mc_group.f_ipv6)
						PPA_HAL_RTSTATS_DEC(curr_mc_ipv4_session);
					else
						PPA_HAL_RTSTATS_DEC(curr_mc_ipv6_session);
					p_item->mc_entry = mc_route->p_entry = 0;
				}
			}
		}
		spin_unlock_bh(&g_hal_mc_db_lock);
	}

	return ret;
}

/*!
	\fn int32_t update_wan_mc_entry(PPA_MC_INFO mc_route)
	\ingroup PPA_lgm_pp_hal_GLOBAL_FUNCTIONS
*/
int32_t update_wan_mc_entry(PPA_MC_INFO *mc_route)
{
	struct pp_sess_create_args pp_args = {0};
	struct lgm_mc_args *mc_args = NULL;
	uint32_t session_id = 0, dev_idx = 0;
	PPA_SUBIF *dp_port;
	int32_t ret = PPA_FAILURE, i = 0;
	struct netdev_attr qos_attr = {0};
	uint32_t skb_prio;

	struct mc_session_node *p_item = (struct mc_session_node *)mc_route->p_item;
	if (!p_item) {
		dbg("mc_session_node is null!!!\n");
		return PPA_FAILURE;
	}

	/*If the call is invoked from the parsing driver p_item->session action will not be NULL*/
	if (!p_item->session_action) {

		/*Call is invoked from multicast daemon
		Following actions needs to be invoked
		1. update the HAL MC DB
		2. based on the current operation mc_route->cop we need to update the pp uC */
		if (mc_route->cop) {
			dev_idx = mc_route->cop->index; /* [valid index 0 -7] */
			if ((dev_idx >= 0) && (dev_idx < MAX_MC_GROUP_ENTRIES)) {
				/*Update the bit in uC multicast group*/
				if ((ret = pp_mcast_dst_set(p_item->grp.group_id, dev_idx, mc_route->cop->flag))) {
					dbg("pp_mcast_dst_set returned Error:%d group = %d index = %d op = %d\n",
						ret, p_item->grp.group_id, dev_idx, mc_route->cop->flag);
				} else {
					dbg("uC mc %s for group=%d index=%d dev=%s\n, "
						, (mc_route->cop->flag ? "set" : "reset"), p_item->grp.group_id, dev_idx,
						p_item->grp.txif[dev_idx].netif->name);
				/*If the operation is delete we need to delete the correspoinding session from the pp*/
					if (mc_route->cop->flag == PPA_IF_DEL) {
						spin_lock_bh(&g_hal_mc_db_lock);
						if (is_valid_session(mc_db[p_item->grp.group_id].dst[dev_idx].sess_id)) {
							/*Delete the group member PPv4sessions*/
							/* session_id always stored +1 to handle valid sessionid 0*/
							if ((ret = pp_session_delete(
								mc_db[p_item->grp.group_id].dst[dev_idx].sess_id - 1, NULL))) {
								dbg("pp_session delete multicast client session %d returned Error:%d\n",
									mc_db[p_item->grp.group_id].dst[dev_idx].sess_id - 1, ret);
							}
							dbg("pp_session delete multicast client session %d succeeded\n",
								mc_db[p_item->grp.group_id].dst[dev_idx].sess_id - 1);
							/*Clear the index in the db*/
							ppa_memset(&mc_db[p_item->grp.group_id].dst[dev_idx],
								0, sizeof(struct client_info));
						}
						spin_unlock_bh(&g_hal_mc_db_lock);
					} else {
						/* Set egress netdevice for the client in the DB */
						spin_lock_bh(&g_hal_mc_db_lock);
						mc_db[p_item->grp.group_id].dst[dev_idx].netdev
							= p_item->grp.txif[dev_idx].netif;
						spin_unlock_bh(&g_hal_mc_db_lock);
						p_item->flags |= SESSION_ADDED_IN_HW;
					}
				}
			}
		} else {
			/*operation not specified nothing needs to be done */
			dbg("Multicast operation not specified !!!\n");
		}
		return ret;
	}

	/*IF the control reaches here the call is invoked from the parsing driver */
	mc_args = (struct lgm_mc_args *) p_item->session_action;
	if (mc_args && !mc_args->desc) {
		dbg("pktprs descriptor is null!!!\n");
		return PPA_FAILURE;
	}

	if (!mc_args->ig_gpid) {
		dbg("Session ingress gpid is not valid\n");
		return PPA_FAILURE;
	}

	memset(&pp_args, 0, sizeof(pp_args));

	pp_args.color = PP_COLOR_GREEN;
	/* Fill in the Hash information */
	pp_args.hash.h1 = mc_args->hwhash.h1;
	pp_args.hash.h2 = mc_args->hwhash.h2;
	pp_args.hash.sig = mc_args->hwhash.sig;

	/*TBD:Set the session group counters */
	for (i = 0; i < ARRAY_SIZE(pp_args.sgc); i++)
		pp_args.sgc[i] = PP_SGC_INVALID;
	/*TBD: Set the token bucket metering */
	for (i = 0; i < ARRAY_SIZE(pp_args.tbm); i++)
		pp_args.tbm[i] = PP_TBM_INVALID;
	/*End TBD Set*/

	/*************Getting ingress and egress ports***************/
	pp_args.in_port = mc_args->ig_gpid;

	/*Compare the ingress gpid with the multicast GPID; which is stored*/
	/*if the gpids match this is session for a specific destination.*/
	if (pp_args.in_port == g_mcast_nf.gpid) {
		/* Find the tx netdevice */
		if (p_item->grp.group_id == mc_args->groupid &&
			((p_item->grp.if_mask >> (mc_args->dst_idx)) & 1)) {

			dev_idx = mc_args->dst_idx; /* [valid value returned is [0-15] */
			if ((dev_idx >= 0) && dev_idx < MAX_MC_CLIENT_PER_GRP) {
				/* if session already exists return */
				spin_lock_bh(&g_hal_mc_db_lock);
				if (is_valid_session(mc_db[p_item->grp.group_id].dst[dev_idx].sess_id)) {
					/*Session exists but Add request is coming again
					we need to compare the HASH and if it is not matching delete the session*/
					if ((mc_db[p_item->grp.group_id].dst[dev_idx].sess_hash.h1
						!= mc_args->hwhash.h1) ||
						(mc_db[p_item->grp.group_id].dst[dev_idx].sess_hash.h2
						!= mc_args->hwhash.h2)) {
						/*Delete the group member PPv4sessions*/
						/* session_id always stored +1 to handle valid sessionid 0*/
						if ((ret = pp_session_delete(
							mc_db[p_item->grp.group_id].dst[dev_idx].sess_id - 1, NULL))) {
							dbg("pp_session delete multicast dst sess%d ret Error:%d\n",
								mc_db[p_item->grp.group_id].dst[dev_idx].sess_id - 1, ret);
						}

						/*Clear the index in the db*/
						mc_db[p_item->grp.group_id].dst[dev_idx].sess_id = 0;
						mc_db[p_item->grp.group_id].dst[dev_idx].sess_hash.h1 = 0;
						mc_db[p_item->grp.group_id].dst[dev_idx].sess_hash.h2 = 0;
						dbg("deleted client session at index =%d\n", dev_idx);
					} else {
						dbg("A client session exists for group=%d at index=%d\n",
							p_item->grp.group_id, dev_idx);
					}
					spin_unlock_bh(&g_hal_mc_db_lock);
					return PPA_SUCCESS;
				}
				spin_unlock_bh(&g_hal_mc_db_lock);

				dp_port = ppa_malloc(sizeof(PPA_SUBIF));
				if (!dp_port) {
					dbg("[%s:%d] DP subif allocation failed!!!\n",
						__func__, __LINE__);
					return PPA_ENOMEM;
				}
				ppa_memset(dp_port, 0, sizeof(PPA_SUBIF));

				skb_prio = p_item->grp.priority;
				if (p_item->grp.txif[dev_idx].netif) {
					PPA_NETIF *txif = p_item->grp.txif[dev_idx].netif;

					/* get physical device for any logical destination member */
					if (txif->ifindex != mc_args->desc->tx->ifindex) {
						txif = ppa_dev_get_by_index(mc_args->desc->tx->ifindex);
						ppa_put_netif(txif);
					}

					/*************Get the egress gpid from the tx netdevice******/
					if (dp_get_netif_subifid(txif,
						NULL, NULL, NULL, dp_port, 0)){

						dbg("Unable to get tx netdevice GPID!!!\n");
						ppa_free(dp_port);
						return PPA_FAILURE;
					}

					skb_prio = ppa_update_pkt_devqos_priority(
							txif,
							dp_port,
							mc_args->desc->skb,
							p_item->grp.priority);

					/* egress gpid */
					pp_args.eg_port = dp_port->gpid;
					qos_attr.portid = pp_args.eg_port;
					qos_attr.tc = skb_prio;
					qos_attr.dst_q_high = -1;
#ifdef HAVE_QOS_EXTMARK
					qos_attr.mark = p_item->grp.qos_mark.extmark;
#else
					qos_attr.mark = p_item->grp.qos_mark.mark;
#endif
					/* egress qid */
					if (ppa_api_get_mapped_queue) {
						if (ppa_api_get_mapped_queue(
						    p_item->grp.txif[dev_idx].netif,
						    &qos_attr))
							return PPA_FAILURE;
					} else {
						pr_err("eg_port(%d) get mapped queue err\n", pp_args.eg_port);
						return PPA_FAILURE;
					}
					pp_args.dst_q = qos_attr.dst_q_low;
					dbg("dst_dev=%s\n", p_item->grp.txif[dev_idx].netif->name);
					/************************************************************/
				}

				/*Setup the classification parameters*/
				/*classification not based on FV: Duplicate packets pass through PPv4*/
				pp_args.rx = mc_args->desc->rx;
				pp_args.tx = mc_args->desc->tx;
				/*End of FV information*/

				/*Classification is based on the Groupid and the dst_index present in the UD0*/
				pp_args.cls.n_flds = 2;
				pp_args.cls.fld_data[0] = mc_args->groupid;
				pp_args.cls.fld_data[1] = mc_args->dst_idx;

				/*Set the egress UD parameters */
				pp_args.ps = dp_port->subif & 0xFFFF; /* VAP bits */
				/*For wlan stations we need to pass the multicast gpid to the fw for reliable multicast*/
				if ((p_item->grp.txif[dev_idx].if_flags & NETIF_DIRECTCONNECT_WIFI)) {
					/* multicast group id bit[0-7] */
					pp_args.ps |= p_item->grp.group_id & 0xFF;
					pp_args.ps |= BIT(15); /* MCF bit */

					/* set the DevQoS bit 24:27 */
					pp_args.ps |= (skb_prio & 0xF) << 24;
					/* set the Calss bit 28:31 */
					pp_args.ps |= (skb_prio & 0xF) << 28;
					dbg("dev:%s qosprio:%d ps:0x%x\n",
					    ppa_get_netif_name(p_item->grp.txif[dev_idx].netif),
					    skb_prio, pp_args.ps);
				}

				if (!(dp_port->alloc_flag & DP_F_ACA)) {
					/*In case of DC interfaces we dont need Egress flag */
					/* This field is supposed to carry DevQos for wireless*/
					/* set the egress flag in the SI UD bit 27 of PS-B */
					pp_args.ps |= BIT(27);
				}
				ppa_free(dp_port);

				set_bit(PP_SESS_FLAG_PS_VALID_BIT, &pp_args.flags);

				pp_args.mcast.grp_idx = p_item->grp.group_id;
				pp_args.mcast.dst_idx = mc_args->dst_idx;
				/*Set the session flags */
				set_bit(PP_SESS_FLAG_MCAST_DST_BIT, &pp_args.flags);

				/*add hardware session */
				if ((ret = pp_session_create(&pp_args, &session_id, NULL))) {
					dbg("pp_session_create returned failure!! %s %d ret=%d\n", __FUNCTION__, __LINE__, ret);
				} else {
					/* store session_id against the corresponding dev_idx in the hal mc db */
					if (is_valid_session(session_id + 1)) {
						spin_lock_bh(&g_hal_mc_db_lock);
						/*always stored +1 to handle index 0*/
						mc_db[p_item->grp.group_id].dst[dev_idx].sess_id = session_id + 1;
						mc_db[p_item->grp.group_id].dst[dev_idx].sess_hash.h1 = mc_args->hwhash.h1;
						mc_db[p_item->grp.group_id].dst[dev_idx].sess_hash.h2 = mc_args->hwhash.h2;
						spin_unlock_bh(&g_hal_mc_db_lock);
						dbg("Added client session for index=%d session_id=%d\n",dev_idx, session_id + 1);
					}
				}
			}
		} else {
			dbg("Device index %d not valid for multicast group %d\n", dev_idx, mc_args->groupid);
		}
	} else if (!p_item->mc_entry) {
		/*It is multicast group session*/
		/* In case of multicast group session the egress gpid must be set as ingress gpid for the uC to identify correct IGP*/
		/*pp_args.eg_port = mc_args->ig_gpid;*/
		pp_args.eg_port = g_mcast_nf.gpid;

		/*egress qid static qid allocated during mc NF creation*/
		pp_args.dst_q = g_mcast_nf.qid;

		/* group session should not insert any destination member protocol */
		if (p_item->flags & SESSION_VALID_VLAN_INS)
			pktprs_proto_remove(mc_args->desc->tx, PKTPRS_PROTO_VLAN0, PKTPRS_HDR_LEVEL0);

		/*Filling in the FV information*/
		pp_args.rx = mc_args->desc->rx;
		pp_args.tx = mc_args->desc->tx;
		/*End of FV information*/

		/* multicast group id bit[0-8] */
		pp_args.ps = p_item->grp.group_id & 0x1FF;

		/* multicast NF subif id [15:9]*/
		pp_args.ps |= (g_mcast_nf.subif & 0x7F) << 9;

		set_bit(PP_SESS_FLAG_PS_VALID_BIT, &pp_args.flags);

		pp_args.mcast.grp_idx = p_item->grp.group_id;
		/*Set the session flags */
		set_bit(PP_SESS_FLAG_MCAST_GRP_BIT, &pp_args.flags);

		/*add hardware session */
		if ((ret = pp_session_create(&pp_args, &session_id, NULL))) {
			dbg("pp_session_create returned failure!! %s %d ret=%d\n", __FUNCTION__, __LINE__, ret);
			PPA_HAL_RTSTATS_INC(mc_dropped_sess);
		} else {
			/* Multicast group session */
			if (is_valid_session(session_id + 1)) {
				/*always stored +1 to handle index 0*/
				mc_route->p_entry = p_item->mc_entry = session_id + 1;
				spin_lock_bh(&g_hal_mc_db_lock);
				mc_db[p_item->grp.group_id].used = 1;
				mc_db[p_item->grp.group_id].grp_sess_hash.h1 = mc_args->hwhash.h1;
				mc_db[p_item->grp.group_id].grp_sess_hash.h2 = mc_args->hwhash.h2;
				spin_unlock_bh(&g_hal_mc_db_lock);
				dbg("Added group session session_id=%d\n", session_id + 1);
				if (!p_item->grp.sess_info->ip_mc_group.f_ipv6)
					PPA_HAL_RTSTATS_INC(curr_mc_ipv4_session);
				else
					PPA_HAL_RTSTATS_INC(curr_mc_ipv6_session);
			}
		}
	} else {
	/*If the session exists and hw ahsh is not matching.. delete the session*/
		spin_lock_bh(&g_hal_mc_db_lock);
		if (mc_db[p_item->grp.group_id].used
			&& ((mc_db[p_item->grp.group_id].grp_sess_hash.h1
			!= mc_args->hwhash.h1) ||
			(mc_db[p_item->grp.group_id].grp_sess_hash.h2
			!= mc_args->hwhash.h2))) {
			/* delete all the dst sessions */
			for (i = 0; i < MAX_MC_CLIENT_PER_GRP; i++) {
				if (is_valid_session(mc_db[p_item->grp.group_id].dst[i].sess_id)) {
					/*1. Delete all the group member PPv4sessions*/
					/* session_id always stored +1 to handle valid sessionid 0*/
					if ((ret = pp_session_delete(mc_db[p_item->grp.group_id].dst[i].sess_id - 1, NULL))) {
						dbg("pp_session delete multicast client session returned Error:%d\n", ret);
					}
				}
				mc_db[p_item->grp.group_id].dst[i].sess_id = 0;
				mc_db[p_item->grp.group_id].dst[i].sess_hash.h1 = 0;
				mc_db[p_item->grp.group_id].dst[i].sess_hash.h2 = 0;
			}
			/* delete the grp sessions */
			if ((ret = pp_session_delete(mc_route->p_entry - 1, NULL))) {
				dbg("pp_session delete mcast grp sess ret Error:%d\n", ret);
			}
			p_item->mc_entry = mc_route->p_entry = 0;
			/* reset the db entry */
			mc_db[p_item->grp.group_id].used = 0;
			mc_db[p_item->grp.group_id].grp_sess_hash.h1 = 0;
			mc_db[p_item->grp.group_id].grp_sess_hash.h2 = 0;
			ppa_memset(&mc_db[p_item->grp.group_id].stats, 0, sizeof(struct pp_stats));
		} else {
			dbg("MC group session exists\n");
		}
		spin_unlock_bh(&g_hal_mc_db_lock);
	}

	return ret;
}

void get_itf_mib(uint32_t itf, struct ppe_itf_mib *p)
{
}

/*!
	\fn int32_t get_routing_entry_stats_diff(uint32_t session_id, uint8_t *f_hit, uint64_t *bytes, uint64_t *packets)
	\brief get one routing entry's stats counter
	\param session_id session id
	\param f_hit hit status False/True
	\param bytes number of diff bytes from last reading
	\param packets number of diff packets from last reading.
	\return error code from switch API
 */
int32_t get_routing_entry_stats_diff(uint32_t session_id, uint8_t *f_hit, uint64_t *bytes, uint64_t *packets)
{
	int ret = PPA_SUCCESS;
	struct pp_stats tmp_stats;

	spin_lock_bh(&g_hal_db_lock);
	if ((session_id >= 0) && (session_id < g_max_hw_sessions) && (pp_hal_db[session_id].used)) {
		ret = pp_session_stats_get(session_id, &tmp_stats);
		if (ret == PPA_SUCCESS) {
			if (tmp_stats.packets != pp_hal_db[session_id].stats.packets) {
				*packets = tmp_stats.packets - pp_hal_db[session_id].stats.packets;
				*bytes = tmp_stats.bytes - pp_hal_db[session_id].stats.bytes;
				*f_hit = 1;
				pp_hal_db[session_id].stats.packets = tmp_stats.packets;
				pp_hal_db[session_id].stats.bytes = tmp_stats.bytes;
			}
		}
	} else {
		ret = PPA_FAILURE;
	}
	spin_unlock_bh(&g_hal_db_lock);
	return ret;
}

int32_t get_mc_routing_entry_stats_diff(uint32_t session_id, uint16_t group_id,
					uint8_t *f_hit, uint64_t *bytes, uint64_t *packets)
{
	int ret = PPA_SUCCESS;
	struct pp_stats tmp_stats;

	spin_lock_bh(&g_hal_mc_db_lock);
	if (is_valid_session(session_id) && (mc_db[group_id].used)) {
		ret = pp_session_stats_get((session_id - 1), &tmp_stats);
		if (ret == PPA_SUCCESS) {
			if (tmp_stats.packets != mc_db[group_id].stats.packets) {
				*packets = tmp_stats.packets - mc_db[group_id].stats.packets;
				*bytes = tmp_stats.bytes - mc_db[group_id].stats.bytes;
				*f_hit = 1;
				mc_db[group_id].stats.packets = tmp_stats.packets;
				mc_db[group_id].stats.bytes = tmp_stats.bytes;
			}
		}
	} else {
		ret = PPA_FAILURE;
	}
	spin_unlock_bh(&g_hal_mc_db_lock);
	return ret;
}

static inline uint32_t ppa_drv_get_phys_port_num(void)
{
	return MAX_LGM_PORTS;
}

/* All the capabilities currently supported	are hardcoded
// register all the capabilities supported by PPV4 HAL*/
static int32_t lgm_pp_hal_register_caps(void)
{
	int32_t res = PPA_SUCCESS;

	if ((res = ppa_drv_register_cap(SESS_IPV4, 1, PPV4_HAL)) != PPA_SUCCESS) {
		dbg("ppa_drv_register_cap returned failure for capability SESS_IPV4!!!\n");
		goto PP_HAL_FAIL;
	}

	if ((res = ppa_drv_register_cap(SESS_IPV6, 1, PPV4_HAL)) != PPA_SUCCESS) {
		dbg("ppa_drv_register_cap returned failure for capability SESS_IPV6!!!\n");
		goto PP_HAL_FAIL;
	}

	if ((res = ppa_drv_register_cap(SESS_MC_DS, 1, PPV4_HAL)) != PPA_SUCCESS) {
		dbg("ppa_drv_register_cap returned failure for capability SESS_MC_DS!!!\n");
		goto PP_HAL_FAIL;
	}

	if ((res = ppa_drv_register_cap(TUNNEL_6RD, 1, PPV4_HAL)) != PPA_SUCCESS) {
		dbg("ppa_drv_register_cap returned failure for capability TUNNEL_6RD!!!\n");
		goto PP_HAL_FAIL;
	}

	if ((res = ppa_drv_register_cap(TUNNEL_DSLITE, 1, PPV4_HAL)) != PPA_SUCCESS) {
		dbg("ppa_drv_register_cap returned failure for capability TUNNEL_DSLITE!!!\n");
		goto PP_HAL_FAIL;
	}

	if ((res = ppa_drv_register_cap(TUNNEL_L2TP_US, 1, PPV4_HAL)) != PPA_SUCCESS) {
		dbg("ppa_drv_register_cap returned failure for capability TUNNEL_L2TP_US!!!\n");
		goto PP_HAL_FAIL;
	}

	if ((res = ppa_drv_register_cap(TUNNEL_L2TP_DS, 1, PPV4_HAL)) != PPA_SUCCESS) {
		dbg("ppa_drv_register_cap returned failure for capability TUNNEL_L2TP_DS!!!\n");
		goto PP_HAL_FAIL;
	}

	if ((res = ppa_drv_register_cap(TUNNEL_GRE_US, 1, PPV4_HAL)) != PPA_SUCCESS) {
		dbg("ppa_drv_register_cap returned failure for capability TUNNEL_GRE_US!!\n");
		goto PP_HAL_FAIL;
	}

	if ((res = ppa_drv_register_cap(TUNNEL_GRE_DS, 1, PPV4_HAL)) != PPA_SUCCESS) {
		dbg("ppa_drv_register_cap returned failure for capability TUNNEL_GRE_DS!!\n");
		goto PP_HAL_FAIL;
	}

	if ((res = ppa_drv_register_cap(TUNNEL_VXLAN, 1, PPV4_HAL)) != PPA_SUCCESS) {
		dbg("ppa_drv_register_cap returned failure for capability TUNNEL_VXLAN!!\n");
		goto PP_HAL_FAIL;
	}

	if ((res = ppa_drv_register_cap(SESS_LOCAL_IN, 1, PPV4_HAL)) != PPA_SUCCESS) {
		pr_err("ppa_drv_register_cap returned failure for capability SESS_LOCAL_IN!!!\n");
		return res;
	}

	if ((res = ppa_drv_register_cap(SESS_LOCAL_OUT, 1, PPV4_HAL)) != PPA_SUCCESS) {
		pr_err("ppa_drv_register_cap returned failure for capability SESS_LOCAL_OUT!!!\n");
		return res;
	}

	return res;

PP_HAL_FAIL:
	ppa_drv_deregister_cap(SESS_IPV4,PPV4_HAL);
	ppa_drv_deregister_cap(SESS_IPV6,PPV4_HAL);
	ppa_drv_deregister_cap(SESS_MC_DS,PPV4_HAL);
	ppa_drv_deregister_cap(TUNNEL_6RD,PPV4_HAL);
	ppa_drv_deregister_cap(TUNNEL_DSLITE,PPV4_HAL);
	ppa_drv_deregister_cap(TUNNEL_L2TP_DS,PPV4_HAL);
	ppa_drv_deregister_cap(TUNNEL_GRE_DS,PPV4_HAL);
	ppa_drv_deregister_cap(TUNNEL_VXLAN,PPV4_HAL);
	return res;
}

static int32_t lgm_pp_hal_deregister_caps(void)
{
	ppa_drv_deregister_cap(SESS_BRIDG,PPV4_HAL);
	ppa_drv_deregister_cap(SESS_IPV4,PPV4_HAL);
	ppa_drv_deregister_cap(SESS_IPV6,PPV4_HAL);
	ppa_drv_deregister_cap(SESS_MC_DS,PPV4_HAL);
	ppa_drv_deregister_cap(TUNNEL_6RD,PPV4_HAL);
	ppa_drv_deregister_cap(TUNNEL_DSLITE,PPV4_HAL);
	ppa_drv_deregister_cap(TUNNEL_L2TP_DS,PPV4_HAL);
	ppa_drv_deregister_cap(QOS_CLASSIFY,PPV4_HAL);
	ppa_drv_deregister_cap(TUNNEL_GRE_DS,PPV4_HAL);
	ppa_drv_deregister_cap(TUNNEL_VXLAN,PPV4_HAL);

	return PPA_SUCCESS;
}

static void get_hal_stats(PPA_HAL_STATS *stat)
{
	unsigned int cpu;
	const PPA_HAL_STATS *rt;

	memset(stat, 0, sizeof(PPA_HAL_STATS));
	stat->max_uc_session = g_max_hw_sessions;
	stat->max_mc_session = MAX_MC_GROUP_ENTRIES;
	stat->max_uc_ipv4_session = -1;
	stat->max_uc_ipv6_session = -1;
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

static int32_t lgm_pp_hal_generic_hook(PPA_GENERIC_HOOK_CMD cmd, void *buffer, uint32_t flag)
{
	/*dbg("lgm_pp_hal_generic_hook cmd 0x%x_%s\n", cmd, ENUM_STRING(cmd) );*/
	switch (cmd) {
	case PPA_GENERIC_HAL_GET_PORT_MIB: {
			int i=0;
			int num;
			PPA_PORT_MIB *mib = (PPA_PORT_MIB*) buffer;
			num = NUM_ENTITY(mib->mib_info) > ppa_drv_get_phys_port_num() ? ppa_drv_get_phys_port_num() : NUM_ENTITY(mib->mib_info) ;
			for (i = 0; i < num; i++) {
			/* port mib needs to be read from dp library ?? or PP ?? */
			/*
				mib->mib_info[i].ig_fast_rt_ipv4_udp_pkts = pae_port_mib.nRxUCv4UDPPktsCount;
				mib->mib_info[i].ig_fast_rt_ipv4_tcp_pkts = pae_port_mib.nRxUCv4TCPPktsCount;
				mib->mib_info[i].ig_fast_rt_ipv4_mc_pkts = pae_port_mib.nRxMCv4PktsCount;
				mib->mib_info[i].ig_fast_rt_ipv4_bytes = pae_port_mib.nRxIPv4BytesCount;
				mib->mib_info[i].ig_fast_rt_ipv6_udp_pkts = pae_port_mib.nRxUCv6UDPPktsCount;
				mib->mib_info[i].ig_fast_rt_ipv6_tcp_pkts = pae_port_mib.nRxUCv6TCPPktsCount;
				mib->mib_info[i].ig_fast_rt_ipv6_mc_pkts = pae_port_mib.nRxMCv6PktsCount;
				mib->mib_info[i].ig_fast_rt_ipv6_bytes = pae_port_mib.nRxIPv6BytesCount;
				mib->mib_info[i].ig_cpu_pkts = pae_port_mib.nRxCpuPktsCount;
				mib->mib_info[i].ig_cpu_bytes = pae_port_mib.nRxCpuBytesCount;
				mib->mib_info[i].ig_drop_pkts = pae_port_mib.nRxPktsDropCount;
				mib->mib_info[i].ig_drop_bytes = pae_port_mib.nRxBytesDropCount;
				mib->mib_info[i].eg_fast_pkts = pae_port_mib.nTxPktsCount;
				mib->mib_info[i].eg_fast_bytes = pae_port_mib.nTxBytesCount;
			*/
				if ((i >= 1) && (i <= 6))
					mib->mib_info[i].port_flag = PPA_PORT_MODE_ETH;
				else if (i == 13)
					mib->mib_info[i].port_flag = PPA_PORT_MODE_DSL;
				else if (i == 0)	/* 0 is CPU port*/
					mib->mib_info[i].port_flag = PPA_PORT_MODE_CPU;
				else
					mib->mib_info[i].port_flag = PPA_PORT_MODE_EXT;
			}
			mib->port_num = num;
			/*dbg("port_num=%d\n", mib->port_num);*/
			return PPA_SUCCESS;
		}
	 case PPA_GENERIC_HAL_GET_MAX_ENTRIES: {

			PPA_MAX_ENTRY_INFO *entry = (PPA_MAX_ENTRY_INFO *)buffer;
			entry->max_lan_entries = g_max_hw_sessions;
			entry->max_wan_entries = g_max_hw_sessions;
			entry->max_mc_entries = MAX_MC_GROUP_ENTRIES;

			return PPA_SUCCESS;
		}
	case PPA_GENERIC_HAL_GET_HAL_VERSION: {

			PPA_VERSION *v = (PPA_VERSION *)buffer;
			get_lgm_pp_hal_id(&v->family, &v->type, &v->itf, &v->mode, &v->major, &v->mid, &v->minor);

			return PPA_SUCCESS;
		}
	case PPA_GENERIC_HAL_GET_PPE_FW_VERSION: {

			PPA_VERSION *v = (PPA_VERSION *)buffer;
			get_lgm_pp_hal_id(&v->family, &v->type, &v->itf, &v->mode, &v->major, &v->mid, &v->minor);

			return get_firmware_id(&v->id, v->name, v->version);
		}
	case PPA_GENERIC_HAL_GET_PHYS_PORT_NUM: {

			PPA_COUNT_CFG *count = (PPA_COUNT_CFG *)buffer;
			count->num = get_number_of_phys_port();

			return PPA_SUCCESS;
		 }
	case PPA_GENERIC_HAL_GET_PHYS_PORT_INFO: {

			PPE_IFINFO *info = (PPE_IFINFO *) buffer;
			get_phys_port_info(info->port, &info->if_flags, info->ifname);

			return PPA_SUCCESS;
		}
	case PPA_GENERIC_HAL_SET_ROUT_CFG:
	case PPA_GENERIC_HAL_SET_BRDG_CFG: {

			/* not supported */
			return PPA_SUCCESS;
		}
	case PPA_GENERIC_HAL_SET_ACC_ENABLE: {

			/*Enable/disable upstream/downstream acceleration */
			PPA_ACC_ENABLE *cfg = (PPA_ACC_ENABLE *)buffer;
			set_acc_mode(cfg->f_is_lan, cfg->f_enable);

			return PPA_SUCCESS;
		}
	 case PPA_GENERIC_HAL_GET_ACC_ENABLE: {

			PPA_ACC_ENABLE *cfg = (PPA_ACC_ENABLE *)buffer;
			get_acc_mode(cfg->f_is_lan, &cfg->f_enable);

			return PPA_SUCCESS;
		}
	case PPA_GENERIC_HAL_GET_IPV6_FLAG: {

			/*Always returns enabled*/
			return PPA_ENABLED;
		}
	case PPA_GENERIC_HAL_ADD_COMPLEMENT_ENTRY:
	case PPA_GENERIC_HAL_DEL_COMPLEMENT_ENTRY:
	case PPA_GENERIC_HAL_UPDATE_SESS_META:
	case PPA_GENERIC_HAL_CLEAR_SESS_META: {

			/* No special metadate needed for PPv4 HAL*/
			if (g_us_accel_enabled || g_ds_accel_enabled)
				return PPA_SUCCESS;
			else
				return PPA_FAILURE;
		}
	case PPA_GENERIC_HAL_ADD_ROUTE_ENTRY: {

			PPA_ROUTING_INFO *route = (PPA_ROUTING_INFO *)buffer;
			struct uc_session_node *p_item = (struct uc_session_node *)route->p_item;
			if (!p_item)
				return PPA_FAILURE;
			/* Add supportive CPU bound session in HW */
			if (p_item->flags & SESSION_ADDED_IN_SW)
				return add_supportive_hw_route_entry(route);

			if (is_lansession(p_item->flags)) {
				if (!g_us_accel_enabled) {
					dbg("\n PPv4 HAL US Acceleration is disabled!!! \n");
					return PPA_FAILURE;
				}
			} else {
				if (!g_ds_accel_enabled) {
					dbg("\n PPv4 HAL DS Acceleration is disabled!!! \n");
					return PPA_FAILURE;
				}
			}
			return add_routing_entry(route);
		}
	case PPA_GENERIC_HAL_DEL_ROUTE_ENTRY: {

			PPA_ROUTING_INFO *route = (PPA_ROUTING_INFO *)buffer;
			while ((del_routing_entry(route)) < 0) {
				return PPA_FAILURE;
			}
			return PPA_SUCCESS;
		}
	case PPA_GENERIC_HAL_ADD_MC_ENTRY:
	case PPA_GENERIC_HAL_UPDATE_MC_ENTRY: {

			PPA_MC_INFO *mc = (PPA_MC_INFO *)buffer;
			return update_wan_mc_entry(mc);
		}
	case PPA_GENERIC_HAL_DEL_MC_ENTRY: {

			PPA_MC_INFO *mc = (PPA_MC_INFO *)buffer;
			del_wan_mc_entry(mc);
			return PPA_SUCCESS;
		}
	 case PPA_GENERIC_HAL_GET_ROUTE_ACC_BYTES: {

			PPA_ROUTING_INFO *route = (PPA_ROUTING_INFO *)buffer;

			get_routing_entry_stats_diff(route->entry, &route->f_hit, &route->bytes, &route->packets);
			return PPA_SUCCESS;
		}
	case PPA_GENERIC_HAL_GET_MC_ACC_BYTES: {

			PPA_MC_INFO *mc = (PPA_MC_INFO *)buffer;
			struct mc_session_node *p_item = mc->p_item;
			uint16_t group_id = (p_item ? p_item->grp.group_id : 0);

			return get_mc_routing_entry_stats_diff(mc->p_entry, group_id, &mc->f_hit, &mc->bytes, &mc->packets);
		}
	case PPA_GENERIC_HAL_ADD_IF: {
			return add_interface((struct netif_info *)buffer);
		}
	case PPA_GENERIC_HAL_DEL_IF: {
			return del_interface((struct netif_info *)buffer);
		}
	case PPA_GENERIC_HAL_GET_ITF_MIB: {

			PPE_ITF_MIB_INFO *mib = (PPE_ITF_MIB_INFO *)buffer;
			get_itf_mib( mib->itf, &mib->mib);
			return PPA_SUCCESS;
		}
	case PPA_GENERIC_HAL_GET_NEW_ITF_MIB: {

			PPA_ITF_MIB_INFO *mibinfo = (PPA_ITF_MIB_INFO *)buffer;

			if (!mibinfo || !mibinfo->ifinfo ||
			    !mibinfo->ifinfo->netif)
				return PPA_FAILURE;

			return get_if_stats(mibinfo->ifinfo->netif,
					    &mibinfo->mib);
		}
	case PPA_GENERIC_HAL_INIT: {

			PPA_HAL_INIT_CFG *cfg = (PPA_HAL_INIT_CFG*)buffer;
			del_routing_session_cb = cfg->del_cb;

			return lgm_pp_hal_register_caps();
		}
	case PPA_GENERIC_HAL_EXIT: {

			del_routing_session_cb = NULL;
			return lgm_pp_hal_deregister_caps();
		}
	case PPA_GENERIC_HAL_GET_STATS:
	{
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

/**************************************************************************************************
* Each entry in the inactivity list is being inactive in HW for more than 420 seconds.
* For each entry in the inactivity list
* Call the ppa callback for hw session delete.
* it will internally call the hal session delete entry
***************************************************************************************************/
void pphal_session_inact_cb(struct pp_cb_args *args)
{
	struct pp_inactive_list_cb_args *inact_args;
	uint32_t i, session_id = 0;
	uint32_t num_open_sess = 0;

	dbg("%s invoked\n",__FUNCTION__);

	if (args->ev != PP_INACTIVE_LIST) {
		dbg("%s %d empty list\n", __FUNCTION__, __LINE__);
		return;
	}

	inact_args = container_of(args, struct pp_inactive_list_cb_args, base);
	pp_open_sessions_get(&num_open_sess);

	if (inact_args->base.ret) {
		dbg("failed to get inactive sessions list %d\n", inact_args->base.ret);
		goto done;
	}

	dbg("%s %d inact_args->n_sessions=%d\n", __FUNCTION__, __LINE__, inact_args->n_sessions);

	/*for each entry in the pp hal_db update the inactiviry status*/
	for (i = 0; i < inact_args->n_sessions; i++) {
		session_id = inact_args->inact_sess[i];
		dbg("%s %d inact_args->inact_sess[i]=%d pp_hal_db[%d].used=%d\n", __FUNCTION__, __LINE__,
				session_id, session_id, pp_hal_db[session_id].used);
		if (((session_id >= 0) && (session_id < g_max_hw_sessions)) && pp_hal_db[session_id].used) {
			/* lro sessions are limited to 256 and inactive-scan timeout_thr is 32k,
			   hence lro sessions need early delete to avoid lro table getting exhausted */
			if (!pp_hal_db[session_id].lro && (num_open_sess < g_sess_timeout_thr))
				continue;
			dbg("%s %d deleting %d p_item=%px p_item->sessiond=%d\n",
					__FUNCTION__, __LINE__, session_id, pp_hal_db[session_id].node,
					((struct uc_session_node *)pp_hal_db[session_id].node)->routing_entry);
			del_routing_session_cb(pp_hal_db[session_id].node);
		}
	}

done:
	/*free the inact_list after processing*/
	if (inact_args->inact_sess)
		ppa_free(inact_args->inact_sess);
}

/**
 * @brief Enable/Disable the FBM by changing the port tailroom size
 * @param en true for enable, false for disable
 */
static void pphal_fbm_enable(bool en)
{
	int32_t ret;
	uint16_t new_tr;

	if (fbm.tbm.enable == en)
		return; /* No changes, done. */

	/* The Fast buffer pool is for 256B buffers.
	 * For disabling the use of the ssb pool we modify the port
	 * tailroom to a larger number of bytes which will cuase the DMA to
	 * select the next policy (512B)
	 */
	if (en)
		new_tr = fbm.orig_tr;
	else
		new_tr = FBM_DIS_TR_SZ(fbm.pcfg.tx.headroom_size);

	fbm.tbm.enable = en;
	if (fbm.pcfg.tx.tailroom_size == new_tr)
		return;

	fbm.pcfg.tx.tailroom_size = new_tr;
	/* Set the modified port configuration (new tailroom value) */
	ret = pp_port_update(fbm.gpid, &fbm.pcfg);
	if (ret)
		pr_err("Failed to set FBM GPID conf\n");
}

/**
 * @brief Get the CIR value by the L1 rate and the L2 bytes per packet
 * @param l1_rate L1 rate in bytes
 * @param l2_bytes number of L2 bytes of packet
 * @return uint64_t CIR value (L2) in bytes
 */
static inline uint64_t pphal_fbm_cir_get(uint64_t l1_rate, uint64_t l2_bytes)
{
	return l2_bytes ? (l1_rate / (l2_bytes + FBM_L1_BYTES) * l2_bytes) : 0;
}

/**
 * @brief Process the FBM iteration when the PPS is consider to "low"
 * @param pps current pps
 * @param pps_thr the pps threshold
 * @param update_tbm if required to update the pp TBM
 */
static void pphal_fbm_low_pps_process(uint64_t pps, uint64_t pps_thr,
				      bool *update_tbm)
{
	if (fbm.tbm.enable) {
		/* Disable the fast buffer pool and PP TBM */
		pphal_fbm_enable(false);
		if (update_tbm)
			*update_tbm = true;
		return;
	}
	/* TBM is disabled - check if possible to increase the interval
	 * If PPS < half of PPS threshold --> increase timer interval
	 * Otherwise, Keep timer 1sec for fast response
	 */
	if (pps < pps_thr / 2)
		fbm.interval = FBM_SLOW_TIMER;
	else
		fbm.interval = FBM_FAST_TIMER;

	/* No need to update TBM (already disabled) */
	if (update_tbm)
		*update_tbm = false;
}

/**
 * @brief Process the FBM iteration when the PPS is consider to "high"
 * @param pkts number of packet in current iteration
 * @param bytes number of bytes in current iteration
 */
static void pphal_fbm_high_pps_process(uint64_t pkts, uint64_t bytes)
{
	uint64_t avg_pkt_sz, lcir, hcir, mcir;
	struct pp_bmgr_pool_stats pstats;

	if (!pkts)
		return;

	fbm.interval = FBM_FAST_TIMER;
	avg_pkt_sz = bytes / pkts;
	if (avg_pkt_sz > FBM_MAX_PKT_SZ) {
		/* Larger packets, no need for FBM, disable */
		pphal_fbm_enable(false);
		return;
	}

	/* Short packets, using FBM, adapt TBM to pkts size */
	pphal_fbm_enable(true);
	/* Read fast pool stats */
	pp_bmgr_pool_stats_get(&pstats, fbm.pool_id);

	lcir = pphal_fbm_cir_get(fbm.shaping_low, avg_pkt_sz);
	if (pstats.pool_allocated_ctr > fbm.pool_fill_thr) {
		if (fbm.tbm.cir > lcir) {
			/* Fast buffers almost gone - reduce cir */
			fbm.tbm.cir =
				max(fbm.tbm.cir - fbm.shaping_step, lcir);
			pr_debug("[FBM]: Allocated buffers %u, Reduce CIR %llu\n",
				 pstats.pool_allocated_ctr, fbm.tbm.cir * 8);
		} else {
			/* If the min rate shaping was applied and the fast
			 * pool fill level cannot recover, Disbale the fast
			 * pool, this is probably not a DDR load related.
			 * Might be QoS congestion which not required to use
			 * the fast buffers
			 */
			if (++fbm.min_cir_cnt >= fbm.min_cir_cnt_thr)
				pphal_fbm_enable(false);
			pr_debug("[FBM]: Allocated buffers %u, MIN CIR %llu\n",
				 pstats.pool_allocated_ctr, fbm.tbm.cir * 8);
		}
		return;
	}
	fbm.min_cir_cnt = 0;

	hcir = pphal_fbm_cir_get(fbm.shaping_high, avg_pkt_sz);
	if (fbm.tbm.cir < hcir) {
		/* Increase cir up to the 10G (L1) rate */
		fbm.tbm.cir =
			min(fbm.tbm.cir + (2 * fbm.shaping_step), hcir);
		pr_debug("[FBM]: Allocated buffers %u, Increase CIR %llu\n",
			 pstats.pool_allocated_ctr, fbm.tbm.cir * 8);
		return;
	}

	mcir = pphal_fbm_cir_get(fbm.shaping_max, avg_pkt_sz);
	/* Traffic is stable with low ssb utilization but we might possibly
	 * Increase the shaping value even more to achive line rate
	 * 1. fast pool is almost empty --> lower than 1/4 of the fill thr
	 * 2. cir above the high threshold
	 * 3. cir below the max threshold
	 * Increase cir in smaller steps
	 */
	if (pstats.pool_allocated_ctr < (fbm.pool_fill_thr >> 2) &&
	    fbm.tbm.cir >= hcir && fbm.tbm.cir < mcir) {
		fbm.tbm.cir += fbm.shaping_small_step;
		pr_debug("[FBM]: Allocated buffers %u, Increase CIR (small step) %llu\n",
			 pstats.pool_allocated_ctr, fbm.tbm.cir * 8);
	}
}

/**
 * @brief Process the FBM iteration
 */
static void pphal_fbm_process(void)
{
	struct pp_stats sgc;
	uint64_t pps_thr = FBM_PPS_THR * (fbm.interval / FBM_FAST_TIMER);
	bool update_tbm = true;

	/* Read the PP SGC counter */
	pp_sgc_get(fbm.sgc_grp, fbm.sgc_id, &sgc, NULL);

	/* Take actions according to the PPS */
	if (sgc.packets < pps_thr)
		pphal_fbm_low_pps_process(sgc.packets, pps_thr, &update_tbm);
	else
		pphal_fbm_high_pps_process(sgc.packets, sgc.bytes);

	/* Update TBM config in PP */
	if (update_tbm)
		pp_dual_tbm_set(fbm.tbm_id, &fbm.tbm);

	/* Reset PP SGC for next iteration */
	pp_sgc_mod(PP_SI_SGC_MAX, fbm.sgc_grp, fbm.sgc_id,
		   PP_STATS_RESET, 0, 0);

	pr_debug("[FBM]: dev=%s, tbm=%s, rate=%11llu, pkts=%08llu, bytes=%10llu, timer_interval[mSec]=%u\n",
		 FBM_IF, fbm.tbm.enable ? "Enable " : "Disable",
		 fbm.tbm.enable ? fbm.tbm.cir * 8 : 0, sgc.packets, sgc.bytes,
		 fbm.interval);
}

/**
 * @brief Main FBM timer handler
 * @param timer FBM timer
 */
static void pphal_fbm_tbm_timer_update(struct timer_list *timer)
{
	pphal_fbm_process();
	mod_timer(&fbm.timer, jiffies + msecs_to_jiffies(fbm.interval));
}

/**
 * @brief Update the FBM GPID
 * @param gpid new FBM GPID
 * @return int32_t 0 for success
 */
static int32_t pphal_fbm_gpid_update(uint32_t gpid)
{
	int32_t ret;
	struct pp_bmgr_policy_params policy = { 0 };

	if (gpid >= PP_MAX_PORT) {
		pr_err("Invalid GPID %u\n", gpid);
		return -EINVAL;
	}

	if (fbm.gpid == gpid)
		return 0;

	if (fbm.gpid < PP_MAX_PORT) {
		/* Clean previous gpid */
		fbm.pcfg.tx.tailroom_size = fbm.orig_tr;
		ret = pp_port_update(fbm.gpid, &fbm.pcfg);
		if (ret) {
			pr_err("Failed to set FBM GPID conf\n");
			return ret;
		}
	}

	fbm.gpid = gpid;
	/* Get the new GPID configuration */
	ret = pp_port_get(gpid, &fbm.pcfg);
	if (ret) {
		pr_err("Failed to get the FBM GPID conf\n");
		return ret;
	}
	fbm.gpid = gpid;
	ret = pp_bmgr_policy_conf_get(fbm.pcfg.tx.base_policy, &policy);
	if (ret) {
		pr_err("Failed to get the FBM policy info\n");
		return ret;
	}
	fbm.pool_id = policy.pools_in_policy[0].pool_id;
	/* Pool fill level threshold is 63% by default */
	fbm.pool_fill_thr = policy.pools_in_policy[0].max_allowed * 63 / 100;
	fbm.orig_tr = fbm.pcfg.tx.tailroom_size;
	fbm.pcfg.tx.tailroom_size =
		FBM_DIS_TR_SZ(fbm.pcfg.tx.headroom_size);
	ret = pp_port_update(fbm.gpid, &fbm.pcfg);
	if (ret)
		pr_err("Failed to set FBM GPID conf\n");

	return ret;
}

/**
 * @brief Exit FBM
 */
static void pphal_fbm_exit(void)
{
	del_timer(&fbm.timer);
}

/**
 * @brief Init the FBM
 * @return int32_t 0 for success
 */
static int32_t pphal_fbm_init(void)
{
	int32_t ret = PPA_SUCCESS;
	dp_subif_t *dp_subif = NULL;

	memset(&fbm, 0, sizeof(fbm));
	fbm.enable = true;
	fbm.gpid = PP_PORT_INVALID;
	fbm.interval = FBM_SLOW_TIMER;
	fbm.tbm.enable = false;
	fbm.tbm.cir = pphal_fbm_cir_get(FBM_HIGH_RATE_BPS, FBM_MIN_PKT_SZ);
	fbm.tbm.cbs = FBM_TBM_CBS_DFLT;
	fbm.shaping_step = FBM_CIR_STEP;
	fbm.shaping_small_step = FBM_CIR_SSTEP;
	fbm.shaping_low = FBM_LOW_RATE_BPS;
	fbm.shaping_high = FBM_HIGH_RATE_BPS;
	fbm.shaping_max = FBM_MAX_RATE_BPS;
	fbm.min_cir_cnt_thr = FBM_MIN_RATE_IT_CNT;

	dp_subif = ppa_malloc(sizeof(dp_subif_t));
	if (!dp_subif) {
		pr_err("Failed to allocate memory for dp_subif\n");
		return -ENOMEM;
	}

	memset(dp_subif, 0, sizeof(dp_subif_t));
	/* Get the FBM port info */
	ret = dp_get_port_subitf_via_ifname(FBM_IF, dp_subif);
	if (ret) {
		pr_err("Failed to get dp subif for FBM port %s\n", FBM_IF);
		ppa_free(dp_subif);
		return ret;
	}

	ret = pphal_fbm_gpid_update(dp_subif->gpid);
	if (ret) {
		pr_err("Failed to update FBM GPID\n");
		ppa_free(dp_subif);
		return ret;
	}

	ret = pp_dual_tbm_alloc(&fbm.tbm_id, &fbm.tbm);
	if (ret) {
		pr_err("Failed to create FBM dynamic TBM\n");
		ppa_free(dp_subif);
		return ret;
	}

	fbm.sgc_grp = PP_SGC_LVL_0;
	ret = pp_sgc_alloc(PP_SI_SGC_MAX, fbm.sgc_grp, &fbm.sgc_id, 1);
	if (ret) {
		pr_err("Failed to create FBM SGC\n");
		ppa_free(dp_subif);
		return ret;
	}

	/* Init FBM tbm timer */
	if (fbm.enable) {
		timer_setup(&fbm.timer, pphal_fbm_tbm_timer_update, 0);
		mod_timer(&fbm.timer, jiffies + msecs_to_jiffies(fbm.interval));
	}
	ppa_free(dp_subif);
	return ret;
}

struct lp_info *pp_hal_db_get_lp_rxinfo(int32_t sess_id)
{
#if IS_ENABLED(LITEPATH_HW_OFFLOAD)
	spin_lock_bh(&g_hal_db_lock);
	if (pp_hal_db[sess_id].used && pp_hal_db[sess_id].lp_rxinfo) {
		refcount_inc(&pp_hal_db[sess_id].lp_rxinfo->refcnt);
		spin_unlock_bh(&g_hal_db_lock);
		return pp_hal_db[sess_id].lp_rxinfo;
	}
	spin_unlock_bh(&g_hal_db_lock);
#endif /* LITEPATH_HW_OFFLOAD */
	return NULL;
}

bool is_pp_sess_valid(int32_t sess_id)
{
	bool valid = false;

	spin_lock_bh(&g_hal_db_lock);
	if ((sess_id >= 0) && (sess_id < g_max_hw_sessions)) {
		valid = pp_hal_db[sess_id].used;
	}
	spin_unlock_bh(&g_hal_db_lock);

	return valid;
}
EXPORT_SYMBOL(is_pp_sess_valid);

/*
 * ####################################
 *		 Init/Cleanup API
 * ####################################
 */
static inline void hal_init(void)
{
	int32_t ret=0;

	/* register callback with the hal selector*/
	ppa_drv_generic_hal_register(PPV4_HAL, lgm_pp_hal_generic_hook);

	init_lro_hal();

	init_if_stats();

	ret = pp_max_sessions_get(&g_max_hw_sessions);
	if (unlikely(ret))
		return;

	/* delete timed out sessions only in case we have at least 50% used */
	g_sess_timeout_thr = g_max_hw_sessions / 2;

	/* initialize the HAL DB */
	pp_hal_db = (PP_HAL_DB_NODE *) ppa_malloc(sizeof(PP_HAL_DB_NODE) * g_max_hw_sessions);
	if (!pp_hal_db) {
		pr_err("Failed to allocate hal db\n");
		return;
	}
	ppa_memset(pp_hal_db, 0, sizeof(PP_HAL_DB_NODE) * g_max_hw_sessions);

	/*initalize the HAL MC DB*/
	ppa_memset(mc_db, 0, sizeof(MC_DB_NODE) * MAX_MC_GROUP_ENTRIES);

#if IS_ENABLED(LITEPATH_HW_OFFLOAD)
	/*Initialize Application litepath offload*/
	init_app_lp();
#endif /*IS_ENABLED(LITEPATH_HW_OFFLOAD)*/

	/*Initialize the MC NF and Register the MC callback*/
	init_mc_nf();

	/*Initialize the Fragmenter NF*/
	init_frag_nf();

	/*Initialize the TDOX NF*/
	init_tdox_nf();

	/*Initialize the Remarking NF*/
	init_remarking_nf();

#if IS_ENABLED(CONFIG_INTEL_VPN) || IS_ENABLED(CONFIG_MXL_VPN)
	/*Initialize VPN flow*/
	init_vpn_offload();
#else
	/*Initialize the IPSEC_LLD NF*/
	init_ipsec_lld_nf();
#endif /* CONFIG_INTEL_VPN || CONFIG_MXL_VPN */

	/*Init the lock*/
	spin_lock_init(&g_hal_db_lock);
	/*Init the mc db lock*/
	spin_lock_init(&g_hal_mc_db_lock);
	ret = pphal_fbm_init();
	if (ret)
		pr_err("Failed to init hal FBM\n");

#ifdef CONFIG_RFS_ACCEL
	ppa_rfs_alloc_steer_db();
#endif /* CONFIG_RFS_ACCEL */
}

static inline void hal_exit(void)
{
	pphal_fbm_exit();
	uninit_frag_nf();
	uninit_mc_nf();
	uninit_if_stats();
	uninit_tdox_nf();
	uninit_remarking_nf();
#if !IS_ENABLED(CONFIG_INTEL_VPN) && !IS_ENABLED(CONFIG_MXL_VPN)
	uninit_ipsec_lld_nf();
#endif
	uninit_lro_hal();

#if IS_ENABLED(LITEPATH_HW_OFFLOAD)
	uninit_app_lp();
#endif /*IS_ENABLED(LITEPATH_HW_OFFLOAD)*/

#ifdef CONFIG_RFS_ACCEL
	ppa_rfs_free_steer_db();
#endif /* CONFIG_RFS_ACCEL */

	ppa_drv_generic_hal_deregister(PPV4_HAL);
}

static int __init lgm_pp_hal_init(void)
{
	hal_init();
#if defined(PPA_API_PROC)
	ppv4_proc_file_create();
#endif
	printk(KERN_INFO"lgm_pp_hal loaded successfully MAX_HW_SESSIONS=%d\n", g_max_hw_sessions);
	return 0;
}

static void __exit lgm_pp_hal_exit(void)
{
#if defined(PPA_API_PROC)
	ppv4_proc_file_remove();
#endif
	hal_exit();
}

module_init(lgm_pp_hal_init);
module_exit(lgm_pp_hal_exit);
MODULE_LICENSE("GPL");
