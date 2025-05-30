/******************************************************************************
 **
 ** FILE NAME	: ppa_stack_al.c
 ** PROJECT	  : PPA
 ** MODULES	  : PPA Protocol Stack Adaption Layer (Linux)
 **
 ** DATE		 : 4 NOV 2008
 ** AUTHOR	   : Xu Liang
 ** DESCRIPTION  : PPA Protocol Stack Adaption Layer (Linux)
 ** COPYRIGHT	: Copyright © 2020-2024 MaxLinear, Inc.
 **               Copyright (c) 2009
 **		  Lantiq Deutschland GmbH
 **		  Am Campeon 3; 85579 Neubiberg, Germany
 **
 **   For licensing information, see the file 'LICENSE' in the root folder of
 **   this software module.
 **
 ** HISTORY
 ** $Date		$Author		 $Comment
 ** 04 NOV 2008  Xu Liang		Initiate Version
 ** 10 Jul 2017  Kamal Eradath   Standalone stack adaptation layer
 *******************************************************************************/
/*
 * ####################################
 *			  Version No.
 * ####################################
 */
#define VER_FAMILY	0x60	/*  bit 0: res	*/
/*		1: Danube	*/
/*		2: Twinpass	*/
/*		3: Amazon-SE	*/
/*		4: res		*/
/*		5: AR9		*/
/*		6: GR9		*/
#define VER_DRTYPE	0x10	/*  bit 0: Normal Data Path driver*/
/*		1: Indirect-Fast Path driver	*/
/*		2: HAL driver			*/
/*		3: Hook driver			*/
/*		4: Stack/System Adaption Layer driver */
/*		5: PPA API driver		*/
#define VER_INTERFACE	0x00	/*  bit 0: MII 0*/
/*		1: MII 1	*/
/*		2: ATM WAN	*/
/*		3: PTM WAN	*/
#define VER_ACCMODE	0x00	/*  bit 0: Routing*/
/*		1: Bridging	*/
#define VER_MAJOR	0
#define VER_MID		0
#define VER_MINOR	3
/*
 * ####################################
 *			  Head File
 * ####################################
 */
/*
 *  Common Head File
 */
#include <linux/version.h>
#include <generated/autoconf.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/atmdev.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <asm/time.h>
#include <net/netfilter/nf_conntrack.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
#include <../net/8021q/vlan.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#else
#include <linux/if_bridge.h>
#endif
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>
#include <net/ip_tunnels.h>
#include <linux/if_tunnel.h>
#include <net/ip6_tunnel.h>
#include <linux/kallsyms.h>
#include <linux/if_macvlan.h>
/*Note, don't call any other PPA functions/varaible outside of stack adaption layer,
	like g_ppa_dbg_enable. The reason is the ppa
  	stack layer is the first module loaded into kernel. All other PPA modules depend on it. */
/*
 *  Chip Specific Head File
 */
#include <net/ppa/ppa_api.h>
#include <net/ppa/ppa_stack_al.h>
#include "ppa_api_misc.h"
#include "ppa_stack_tnl_al.h"

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#define ppa_conntrack_get			 nf_ct_get
#else
#define ppa_conntrack_get			 ip_conntrack_get
#endif

/*
 * ####################################
 *			  Definition
 * ####################################
 */
#if defined(DISABLE_INLINE) && DISABLE_INLINE
#define INLINE
#else
#define INLINE		inline
#endif

#define ENABLE_MY_MEMCPY	0

#define MULTICAST_IP_START	0xE0000000  /*224.0.0.0 */
#define MULTICAST_IP_END	0xEFFFFFFF  /*239.255.255.255*/

#if IS_ENABLED(CONFIG_VLAN_8021Q)
#define VLAN_DEV_INFO vlan_dev_priv
#endif

/* MAC_FMT starts to defined in 2.6.24*/
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

#define MAC_ARG(x) ((u8 *)(x))[0], ((u8 *)(x))[1], ((u8 *)(x))[2], \
	((u8 *)(x))[3], ((u8 *)(x))[4], ((u8 *)(x))[5]
/*
 * ####################################
 *			  Data Type
 * ####################################
 */

/*
 * ####################################
 *			 Declaration
 * ####################################
 */

static bool lgm_pp_hal_tdox_enable = true;
uint32_t g_ppa_dbg_enable = DBG_ENABLE_MASK_ERR;
uint32_t max_print_num=~0;

extern u32 ppa_hash_conntrack_raw(const struct nf_conntrack_tuple *tuple, const struct net *net);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
extern struct nf_conntrack_l4proto* __nf_ct_l4proto_find(u_int16_t l3proto, u_int8_t l4proto);
extern bool nf_ct_get_tuple(const struct sk_buff *skb, unsigned int nhoff,
			unsigned int dataoff, u_int16_t l3num, u_int8_t protonum,
			struct net *net,
			struct nf_conntrack_tuple *tuple,
			const struct nf_conntrack_l3proto *l3proto,
			const struct nf_conntrack_l4proto *l4proto);
#else
extern const struct nf_conntrack_l4proto *__nf_ct_l4proto_find(u_int16_t l3proto, u_int8_t l4proto);
#endif

/*
 * ####################################
 *		   Global Variable
 * ####################################
 */
static DEFINE_SPINLOCK(g_local_irq_save_flag_lock);
/*
 * ####################################
 *		   Global Variable
 * ####################################
 */

/*
 * ####################################
 *		   Extern Variable
 * ####################################
 */

/*
 * ####################################
 *			Local Function
 * ####################################
 */
static uint8_t *ppa_get_transport_header(const PPA_BUF *ppa_buf);

/*
 * ####################################
 *		   Global Function
 * ####################################
 */
void ppa_get_stack_al_id(uint32_t *p_family,
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

PPA_SESSION *ppa_get_session(PPA_BUF *ppa_buf)
{
	enum ip_conntrack_info ctinfo;

	return ppa_conntrack_get(ppa_buf, &ctinfo);
}

/*
   port functions from 2.6.32, make it easier to port to 2.6.32
   skb coresponding functions supported by linux kernel from version 2.6.22
   ipv4_is_multicast supported by linux kernel from version 2.6.25
 */
static uint8_t *ppa_get_transport_header(const PPA_BUF *ppa_buf)
{
	struct iphdr *iph = NULL;
#if IS_ENABLED(CONFIG_IPV6)
	if(ppa_is_pkt_ipv6(ppa_buf)){/*ipv6 frame with extention header is already filtered*/
		return (skb_network_header(ppa_buf) + sizeof(struct ipv6hdr));
	}
#endif

	iph = ip_hdr(ppa_buf);
	return (skb_network_header(ppa_buf) + iph->ihl*4);
}


/* Support IPV6 fuctions */
#if IS_ENABLED(CONFIG_IPV6)
uint8_t ppa_get_ipv6_l4_proto(PPA_BUF *ppa_buf)
{
	uint8_t nexthdr;
	struct ipv6hdr *ip6hdr;

	ip6hdr = ipv6_hdr(ppa_buf);
	nexthdr = ip6hdr->nexthdr;

	return nexthdr;
}

uint8_t ppa_get_ipv6_tos(PPA_BUF *ppa_buf)
{
	return ((ipv6_hdr(ppa_buf)->priority << 4) + (ipv6_hdr(ppa_buf)->flow_lbl[0] >> 4));
}

PPA_IPADDR ppa_get_ipv6_saddr(PPA_BUF *ppa_buf)
{
	struct ipv6hdr *ip6hdr = ipv6_hdr(ppa_buf);
	return *(PPA_IPADDR *) &ip6hdr->saddr;
}

PPA_IPADDR ppa_get_ipv6_daddr(PPA_BUF *ppa_buf)
{
	struct ipv6hdr *ip6hdr = ipv6_hdr(ppa_buf);
	return *(PPA_IPADDR *) &ip6hdr->daddr;
}

uint8_t ppa_get_ipv6_hoplimit(PPA_BUF *ppa_buf)
{
	struct ipv6hdr *ip6hdr = ipv6_hdr(ppa_buf);
	return ip6hdr->hop_limit;
}

int32_t ppa_is_ipv6_multicast(PPA_BUF *ppa_buf)
{
	struct ipv6hdr *ip6hdr = ipv6_hdr(ppa_buf);
	return ipv6_addr_is_multicast(&ip6hdr->daddr);
}

uint32_t ppa_is_ipv6_fragment(PPA_BUF *ppa_buf)
{
	uint32_t nhoff, nexthdr;

	nhoff = IP6CB(ppa_buf)->nhoff;
	nexthdr = skb_network_header(ppa_buf)[nhoff];

	return (nexthdr == IPPROTO_FRAGMENT);
}
#endif

/*functions special for ipv4 */
uint8_t ppa_get_ip_l4_proto(PPA_BUF *ppa_buf)
{
	struct iphdr *hdr = ip_hdr(ppa_buf);
	return hdr->protocol;
}

uint8_t ppa_get_ip_tos(PPA_BUF *ppa_buf)
{
	struct iphdr *hdr = ip_hdr(ppa_buf);
	return hdr->tos;
}

PPA_IPADDR ppa_get_ip_saddr(PPA_BUF *ppa_buf)
{
	struct iphdr *hdr = ip_hdr(ppa_buf);
	return *(PPA_IPADDR *) &hdr->saddr;
}

PPA_IPADDR ppa_get_ip_daddr(PPA_BUF *ppa_buf)
{
	struct iphdr *hdr = ip_hdr(ppa_buf);
	return *(PPA_IPADDR *) &hdr->daddr;
}

uint8_t ppa_get_ip_ttl(PPA_BUF *ppa_buf)
{
	struct iphdr *hdr = ip_hdr(ppa_buf);
	return hdr->ttl;
}

int32_t ppa_is_ip_multicast(PPA_BUF *ppa_buf)
{
	struct iphdr *hdr = ip_hdr(ppa_buf);
	return ipv4_is_multicast(hdr->daddr);
}

uint32_t ppa_is_ip_fragment(PPA_BUF *ppa_buf)
{
	struct iphdr *hdr = ip_hdr(ppa_buf);
	return (hdr->frag_off & htons(IP_MF|IP_OFFSET)) == 0 ? 0 : 1;
}
/*=====function above are special for ipv4 =====*/
#ifdef CONFIG_PPA_PP_LEARNING
uint16_t ppa_get_pkt_protocol(PPA_BUF *ppa_buf)
{
	if(ppa_buf)
		return ppa_buf->protocol;
	return 0;
}
EXPORT_SYMBOL(ppa_get_pkt_protocol);
#endif

uint8_t ppa_get_pkt_ip_proto(PPA_BUF *ppa_buf)
{
#if IS_ENABLED(CONFIG_IPV6)
	if(ppa_is_pkt_ipv6(ppa_buf)){
		return ppa_get_ipv6_l4_proto(ppa_buf);
	}
#endif
	return ppa_get_ip_l4_proto(ppa_buf);
}

uint8_t ppa_get_pkt_ip_tos(PPA_BUF *ppa_buf)
{
#if IS_ENABLED(CONFIG_IPV6)
	if(ppa_is_pkt_ipv6(ppa_buf)){
		return ppa_get_ipv6_tos(ppa_buf);
	}
#endif
	return ppa_get_ip_tos(ppa_buf);
}

void ppa_get_pkt_src_ip(PPA_IPADDR *ip, PPA_BUF *ppa_buf)
{
#if IS_ENABLED(CONFIG_IPV6)
	if(ppa_is_pkt_ipv6(ppa_buf)){
		*ip = ppa_get_ipv6_saddr(ppa_buf);
	} else
#endif
	*ip = ppa_get_ip_saddr(ppa_buf);
}

uint32_t ppa_get_pkt_ip_len(PPA_BUF *ppa_buf)
{
#if IS_ENABLED(CONFIG_IPV6)
	if(ppa_is_pkt_ipv6(ppa_buf)){
		return sizeof(struct in6_addr);
	}
#endif
	return sizeof(uint32_t);
}

void ppa_get_pkt_dst_ip(PPA_IPADDR *ip, PPA_BUF *ppa_buf)
{
#if IS_ENABLED(CONFIG_IPV6)
	if(ppa_is_pkt_ipv6(ppa_buf)){
		*ip = ppa_get_ipv6_daddr(ppa_buf);
	} else
#endif
	*ip = ppa_get_ip_daddr(ppa_buf);
}

uint8_t ppa_get_pkt_ip_ttl(PPA_BUF *ppa_buf)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (ppa_is_pkt_ipv6(ppa_buf))
		return ppa_get_ipv6_hoplimit(ppa_buf);
#endif

	return ppa_get_ip_ttl(ppa_buf);
}

int8_t *ppa_get_pkt_ip_string(PPA_IPADDR ppa_ip, uint32_t flag, int8_t *strbuf)
{
	if(!strbuf)
		return strbuf;

	strbuf[0] = 0;
	if(flag){
#if IS_ENABLED(CONFIG_IPV6)
		ppa_sprintf(strbuf, "%pI6", ppa_ip.ip6);
#endif
	} else {
		ppa_sprintf(strbuf, "%pI4", &ppa_ip.ip);
	}
	return strbuf;
}

int8_t *ppa_get_pkt_mac_string(uint8_t *mac, int8_t *strbuf)
{
	if(!strbuf)
		return strbuf;

	ppa_sprintf(strbuf, MAC_FMT, MAC_ARG(mac));
	return strbuf;
}

int32_t ppa_is_pkt_multicast(PPA_BUF *ppa_buf)
{
	if ( ppa_buf->pkt_type == PACKET_MULTICAST )
		return 1;

#if IS_ENABLED(CONFIG_IPV6)
	if(ppa_is_pkt_ipv6(ppa_buf)){
		return ppa_is_ipv6_multicast(ppa_buf);
	}
#endif
	return ppa_is_ip_multicast(ppa_buf);
}

uint32_t ppa_is_pkt_fragment(PPA_BUF *ppa_buf)
{
#if IS_ENABLED(CONFIG_IPV6)
	if(ppa_is_pkt_ipv6(ppa_buf)){
		return ppa_is_ipv6_fragment(ppa_buf);
	}
#endif
	return ppa_is_ip_fragment(ppa_buf);

}

uint16_t ppa_get_pkt_src_port(PPA_BUF *ppa_buf)
{
	return (uint16_t)(((struct udphdr *)ppa_get_transport_header(ppa_buf))->source);
}

uint16_t ppa_get_pkt_dst_port(PPA_BUF *ppa_buf)
{
	return (uint16_t)(((struct udphdr *)ppa_get_transport_header(ppa_buf))->dest);
}

uint8_t *ppa_get_pkt_src_mac_ptr(PPA_BUF *ppa_buf)
{
#ifdef CONFIG_MIPS
	if ( (uint32_t)skb_mac_header(ppa_buf) < KSEG0 )
		return NULL;
#endif
	return skb_mac_header(ppa_buf) + PPA_ETH_ALEN;
}

void ppa_get_pkt_rx_src_mac_addr(PPA_BUF *ppa_buf, uint8_t mac[PPA_ETH_ALEN])
{
#ifdef CONFIG_MIPS
	if ( (uint32_t)skb_mac_header(ppa_buf) >= KSEG0 )
#endif
	ppa_memcpy(mac, skb_mac_header(ppa_buf) + PPA_ETH_ALEN, PPA_ETH_ALEN);
}

void ppa_get_pkt_rx_dst_mac_addr(PPA_BUF *ppa_buf, uint8_t mac[PPA_ETH_ALEN])
{
#ifdef CONFIG_MIPS
	if ( (uint32_t)skb_mac_header(ppa_buf) >= KSEG0 )
#endif
	ppa_memcpy(mac, skb_mac_header(ppa_buf), PPA_ETH_ALEN);
}

void ppa_get_src_mac_addr(PPA_BUF *ppa_buf, uint8_t mac[PPA_ETH_ALEN],const int offset)
{
	ppa_memcpy(mac, ((uint8_t*) (ppa_buf->data)) + offset + PPA_ETH_ALEN, PPA_ETH_ALEN);
}

/*
 *  If it is multicast packet, then return multicast dst & src ip address and success, otherwise return failure(-1).
 *  Note, this function will be called at bridge level and ip stack level.
 *  i.e. skb->data point to mac header or ip header
 */
int ppa_get_multicast_pkt_ip(PPA_BUF *ppa_buf, void *dst_ip, void *src_ip)
{
	/*  note, here ppa_buf may be L2 level, or L3 level. So we have to move pointer to get its real ip  */
	uint16_t protocol = ppa_buf->protocol;
	uint8_t *p;
	IP_ADDR_C *dstip,*srcip;

	p = (uint8_t *) ppa_buf->data;

	if(!dst_ip || !src_ip){
		return PPA_FAILURE;
	}

	dstip = (IP_ADDR_C *)dst_ip;
	srcip = (IP_ADDR_C *)src_ip;

	if( p[0] == 0x01 ) {
	/* we regard it a l2 level packet if first byte is 0x01
	( multicast mac address, otherwise we think it is a ip packet.*/
#if defined(PPA_STACK_ENABLE_DEBUG_PRINT) && PPA_STACK_ENABLE_DEBUG_PRINT
		{
			int i;
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"ppa_get_pkt_src_ip2(protocol=%x)-1:", ppa_buf->protocol);
			for ( i = 0; i < 30; i++ )
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%02x ", ppa_buf->data[i]);
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
		}
#endif
		p += ETH_HLEN -2;  /*p point to protocol*/
		protocol = ( p[0] << 8 ) + p[1];
#if defined(PPA_STACK_ENABLE_DEBUG_PRINT) && PPA_STACK_ENABLE_DEBUG_PRINT
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"protocol=%04x\n", protocol );
#endif
		while ( protocol == ETH_P_8021Q ) {
			/*  move p to next protocol */
			p += 4 ;  /*8021q have*/

			protocol = ( p[0] << 8 ) + p[1];
#if defined(PPA_STACK_ENABLE_DEBUG_PRINT) && PPA_STACK_ENABLE_DEBUG_PRINT
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"protocol=%04x\n", protocol);
#endif
		}

#if defined(PPA_STACK_ENABLE_DEBUG_PRINT) && PPA_STACK_ENABLE_DEBUG_PRINT
		{
			int i;

			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"p index=%d\n", (char *)p - (char *)ppa_buf->data);

			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"ppa_get_pkt_src_ip2(protocol=%x )-2:", ppa_buf->protocol);
			for ( i = 0; i < 30; i++ )
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%02x ", ppa_buf->data[i]);
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"\n");
		}
#endif
	}

	if( protocol == ETH_P_IP ) {
		struct iphdr *iph = (struct iphdr *)p;

		if ( iph->daddr >= MULTICAST_IP_START && iph->daddr<= MULTICAST_IP_END ){

			dstip->f_ipv6 = srcip->f_ipv6 = 0;
			dstip->ip.ip = iph->daddr;
			srcip->ip.ip = iph->saddr;

			return PPA_SUCCESS;
		}
		return PPA_FAILURE;
	}
	else if( protocol == ETH_P_IPV6 ){
		struct ipv6hdr *ip6hdr = (struct ipv6hdr *)p;

		if(ipv6_addr_is_multicast(&ip6hdr->daddr)){

			dstip->f_ipv6 = srcip->f_ipv6 = 1;
			ppa_memcpy(dstip->ip.ip6, &ip6hdr->daddr, sizeof(dstip->ip.ip6));
			ppa_memcpy(srcip->ip.ip6, &ip6hdr->saddr, sizeof(srcip->ip.ip6));

			return PPA_SUCCESS;
		}
		return PPA_FAILURE;
	}
	return PPA_FAILURE;
}

PPA_NETIF *ppa_get_pkt_src_if(PPA_BUF *ppa_buf)
{
	return ppa_buf->dev;
}

PPA_NETIF *ppa_get_pkt_dst_if(PPA_BUF *ppa_buf)
{
	struct dst_entry *dst = ppa_dst(ppa_buf);

	if (dst) {
#if IS_ENABLED(CONFIG_SOC_GRX500) && !IS_ENABLED(CONFIG_SOC_PRX)
		if (netif_is_bond_master(dst->dev))
			return ppa_get_bond_xmit_xor_intrf_hook(ppa_buf, dst->dev);
#endif
		return dst->dev;
	} else {
		return ppa_buf->dev; /*For bridged session*/
	}
}

#if defined(CONFIG_PPA_HANDLE_CONNTRACK_SESSIONS)
uint32_t ppa_get_session_priority(PPA_BUF *ppa_buf)
{
	if( ppa_buf ) return skb_get_session_priority(ppa_buf);

	return 0;
}

uint32_t ppa_get_low_prio_thresh(uint32_t flags)
{
	return nf_conntrack_low_prio_thresh;
}

struct timespec ppa_timespec_sub(struct timespec lhs, struct timespec rhs)
{
	return timespec_sub(lhs,rhs);
}

s64 ppa_timespec_to_ns(struct timespec *lhs)
{
	return timespec_to_ns(lhs);
}
void ppa_get_monotonic( struct timespec *lhs)
{
	getrawmonotonic(lhs);
}

uint32_t ppa_get_def_prio_thresh(uint32_t flags)
{
	return nf_conntrack_default_prio_thresh;
}

uint32_t ppa_get_low_prio_data_rate(uint32_t flags)
{
	return nf_conntrack_low_prio_data_rate;
}

uint32_t ppa_get_def_prio_data_rate(uint32_t flags)
{
	return nf_conntrack_default_prio_data_rate;
}

uint32_t ppa_get_session_limit_enable(uint32_t flags)
{
	return nf_conntrack_session_limit_enable;
}
uint32_t ppa_get_tcp_initial_offset(uint32_t flags)
{
	return nf_conntrack_tcp_initial_offset;
}
uint32_t ppa_get_tcp_steady_offset(uint32_t flags)
{
	return nf_conntrack_tcp_steady_offset;
}
#endif

#if !IS_ENABLED(CONFIG_PPPOE)
int32_t ppa_pppoe_get_pppoe_addr(PPA_NETIF *netif, struct pppoe_addr *pa)
{
	return PPA_EPERM;
}

__u16 ppa_pppoe_get_pppoe_session_id(PPA_NETIF *netif)
{
	return 0;
}

__u16 ppa_get_pkt_pppoe_session_id(PPA_BUF *ppa_buf)
{
	return 0;
}

int32_t ppa_pppoe_get_eth_netif(PPA_NETIF *netif, PPA_IFNAME pppoe_eth_ifname[PPA_IF_NAME_SIZE])
{
	return PPA_EPERM;
}
#endif

#if !IS_ENABLED(CONFIG_PPPOL2TP)
__u16 ppa_pppol2tp_get_l2tp_session_id(struct net_device *dev)
{
	return 0;
}
__u16 ppa_pppol2tp_get_l2tp_tunnel_id(struct net_device *dev)
{
	return 0;
}
int32_t ppa_pppol2tp_get_base_netif(PPA_NETIF *netif, PPA_IFNAME pppol2tp_eth_ifname[PPA_IF_NAME_SIZE])
{
	return PPA_EPERM;
}
int32_t ppa_pppol2tp_get_src_addr(struct net_device *dev, uint32_t *outer_srcip)
{
	return PPA_EPERM;
}
int32_t ppa_pppol2tp_get_dst_addr(struct net_device *dev, uint32_t *outer_dstip)
{
	return PPA_EPERM;
}
#endif

#if IS_ENABLED(CONFIG_PPPOE)
uint32_t ppa_check_is_ppp_netif(PPA_NETIF *netif)
{
	if (!netif)
		return PPA_NETIF_FAIL;

	return (netif->type == ARPHRD_PPP && (netif->flags & IFF_POINTOPOINT) );
}

uint32_t ppa_check_is_pppoe_netif(PPA_NETIF *netif)
{
	struct pppoe_addr pa;

	if(!(netif->type == ARPHRD_PPP && (netif->flags & IFF_POINTOPOINT) ))
		return 0;
	return ppa_pppoe_get_pppoe_addr(netif, &pa) == PPA_SUCCESS ? 1 : 0;
}

int32_t ppa_pppoe_get_dst_mac(PPA_NETIF *netif, uint8_t mac[PPA_ETH_ALEN])
{
	int32_t ret;
	struct pppoe_addr pa;

	if ( (ret = ppa_pppoe_get_pppoe_addr(netif, &pa)) != PPA_SUCCESS ) {
		pr_err("fail in getting pppoe addr\n");
		return ret;
	}

	ppa_memcpy(mac, pa.remote, sizeof(pa.remote));
	return PPA_SUCCESS;
}

int32_t ppa_pppoe_get_physical_if(PPA_NETIF *netif, PPA_IFNAME *ifname, PPA_IFNAME phy_ifname[PPA_IF_NAME_SIZE])
{
	if ( !netif )
		netif = ppa_get_netif(ifname);

	if ( !netif )
		return PPA_EINVAL;

	if ( !ppa_check_is_pppoe_netif(netif) )
		return PPA_EINVAL;

	return ppa_pppoe_get_eth_netif(netif, phy_ifname);
}
#else
uint32_t ppa_check_is_pppoe_netif(PPA_NETIF *netif)
{
	return 0;
}
int32_t ppa_pppoe_get_dst_mac(PPA_NETIF *netif, uint8_t mac[PPA_ETH_ALEN])
{
	return PPA_EPERM;
}
int32_t ppa_pppoe_get_physical_if(PPA_NETIF *netif, PPA_IFNAME *ifname, PPA_IFNAME phy_ifname[PPA_IF_NAME_SIZE])
{
	return PPA_EPERM;
}

uint32_t ppa_check_is_ppp_netif(PPA_NETIF *netif)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
int ppa_dev_is_br(PPA_NETIF *netif)
{
	return (netif_is_bridge_master(netif) || netif_is_ovs_master(netif));
}
#endif

#if IS_ENABLED(CONFIG_PPPOL2TP)
int32_t ppa_pppol2tp_get_physical_if(PPA_NETIF *netif, PPA_IFNAME *ifname, PPA_IFNAME phy_ifname[PPA_IF_NAME_SIZE])
{
	return ppa_pppol2tp_get_base_netif(netif, phy_ifname) == PPA_SUCCESS ? 0 : 1;
}

uint32_t ppa_check_is_pppol2tp_netif(PPA_NETIF *netif)
{
	struct pppol2tp_addr pa;

	if(netif->type == ARPHRD_PPP && (netif->flags & IFF_POINTOPOINT) ) {

		return ppa_pppol2tp_get_l2tp_addr(netif, &pa) == PPA_SUCCESS ? 1 : 0;
	}
	return 0;
}

int32_t ppa_pppol2tp_get_dst_mac(PPA_NETIF *netif, uint8_t *mac)
{
	int32_t ret;
	struct pppol2tp_addr pa;

	if ( (ret = ppa_pppol2tp_get_l2tp_addr(netif, &pa)) != PPA_SUCCESS ) {
		pr_err("fail in getting pppol2tp addr\n");
		return ret;
	}
	if( (ret = ppa_pppol2tp_get_l2tp_dmac(netif,mac)) != PPA_SUCCESS ) {
		pr_err("fail in getting pppol2tp dmac\n");
		return ret;
	}
	return PPA_SUCCESS;
}
#else
int32_t ppa_pppol2tp_get_physical_if(PPA_NETIF *netif, PPA_IFNAME *ifname, PPA_IFNAME phy_ifname[PPA_IF_NAME_SIZE])
{
	return PPA_EPERM;
}

uint32_t ppa_check_is_pppol2tp_netif(PPA_NETIF *netif)
{
	return 0;
}

int32_t ppa_pppol2tp_get_dst_mac(PPA_NETIF *netif, uint8_t *mac)
{
	return PPA_EPERM;
}
#endif
int32_t ppa_get_dst_mac(PPA_BUF *ppa_buf,
		PPA_SESSION *p_session,
		uint8_t mac[PPA_ETH_ALEN],
		uint32_t daddr)
{
	int32_t ret = PPA_ENOTAVAIL;
	struct dst_entry *dst = NULL;
	struct net_device *netif = NULL;

	/*
	 *  Assumption, function only gets called from POSTROUTING so skb->dev = o/p i/f
	 *	netif = ppa_buf->dev;
	 */
	netif = ppa_get_pkt_dst_if(ppa_buf);
	if(!netif)
		return ret;

#if IS_ENABLED(CONFIG_IPV6_SIT)
	if(netif->type == ARPHRD_SIT){
		return ppa_get_6rd_dst_mac(netif,ppa_buf, mac,daddr);
	}
#endif

#if IS_ENABLED(CONFIG_IPV6_TUNNEL)
	if(netif->type == ARPHRD_TUNNEL6) {
		return ppa_get_dslite_dst_mac(netif,ppa_buf, mac);
	}
#endif

	if(ppa_is_gre_netif(netif)) {
		return ppa_get_gre_dmac(mac,netif,ppa_buf);
	}

#if IS_ENABLED(CONFIG_SOC_GRX500) && IS_ENABLED(CONFIG_VXLAN)
	if (ppa_is_vxlan_netif(netif)) {
		return ppa_get_vxlan_dmac(mac, netif, ppa_buf);
	}
#endif
	/* First need to check if PPP output interface */
	if ( ppa_check_is_ppp_netif(netif) ) {
		/*
		 * If interface is neither PPPoE or L2TP, return failure(not possible).
		 */
back_to_pppoe:
		/* Check if PPPoE interface */
		if ( ppa_check_is_pppoe_netif(netif) ) {
			/* Determine PPPoE MAC address */
			return ppa_pppoe_get_dst_mac(netif, mac);
		}

		/* Check if PPPoL2TP interface */
		if ( ppa_check_is_pppol2tp_netif(netif) ) {
			char name[PPA_IF_NAME_SIZE];
			if ( ppa_pppol2tp_get_base_netif(netif, name) || !(netif = ppa_get_netif(name)) ) {
				ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"%s: Cannot get PPPOL2TP ppa netif %s address!",
						__FUNCTION__,
						((netif) ? netif->name : "NULL"));
				return PPA_ENOTAVAIL;
			}

			if(ppa_check_is_ppp_netif(netif))
				goto back_to_pppoe;

			/* If not PPPoE then Determine MAC address for DHCP/Static WAN */
			if(ppa_buf->dev) {
				return ppa_pppol2tp_get_dst_mac(ppa_buf->dev, mac);
			}
			else
				return PPA_ENOTAVAIL;
		}
		return PPA_ENOTPOSSIBLE;
	}

	dst = ppa_dst(ppa_buf);
	if ( !dst ) {
		return PPA_ENOTAVAIL; /*  Dst MAC address not known*/
	}

	ret = ppa_get_dmac_from_dst_entry(mac,ppa_buf,dst);
	return ret;
}

PPA_NETIF *ppa_get_netif_by_net(const struct net *net, const PPA_IFNAME *ifname)
{
	PPA_NETIF *netif;
	if (ifname && net) {
		netif = dev_get_by_name((struct net *)net, ifname);
		if (netif) {
			dev_put(netif);
			return netif;
		} else
			return NULL;
	}
	return NULL;
}

PPA_NETIF *ppa_get_netif(const PPA_IFNAME *ifname)
{
	/*This implementation has risk that the device is destroyed after we get and free it*/

	PPA_NETIF *netif;

	if ( ifname && (netif = ppa_dev_get_by_name(ifname)) )
	{
		dev_put(netif);
		return netif;
	}
	else
		return NULL;
}

int32_t ppa_get_netif_ifindex(const PPA_IFNAME *ifname)
{
	PPA_NETIF *netif;

	netif = ppa_get_netif(ifname);
	if(netif)
		return netif->ifindex;

	return PPA_FAILURE;
}

void ppa_put_netif(PPA_NETIF *netif)
{
	if(netif)
		dev_put(netif);
}

PPA_NETIF *ppa_get_br_dev(PPA_NETIF *netif)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 1, 21)
	if(netif && netif_is_bridge_port(netif))
#else
	if(netif && br_port_exists(netif))
#endif
		return(br_port_get_rcu(netif)->br->dev);

	return NULL;
}

int32_t ppa_get_netif_hwaddr(PPA_NETIF *netif, uint8_t mac[PPA_ETH_ALEN], uint32_t flag_down_only)
{

	PPA_NETIF* orgif;

	if (netif == NULL)
		return PPA_FAILURE;

	orgif = netif; /*Needed to print debug info*/
	ppa_memset(mac, 0, PPA_ETH_ALEN);

hwaddr_top:

	if( ppa_check_is_ppp_netif(netif) ) {

		char name[PPA_IF_NAME_SIZE];
                if(ppa_if_is_pppoa(netif, NULL)) {
                        ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,
                                "Cannot get hw-mac for PPPOA dev");
                        goto hwaddr_error;
                }

		if ( ppa_check_is_pppol2tp_netif(netif) ) {

			if ( ppa_pppol2tp_get_base_netif(netif, name) ||
					!(netif = ppa_get_netif(name)) ) {
				goto hwaddr_error;
			}
		}
                if ( ppa_check_is_pppoe_netif(netif) ) {

			if ( ppa_pppoe_get_eth_netif(netif, name) || !(netif = ppa_get_netif(name)) ) {
				goto hwaddr_error;
			}
		}
#if IS_ENABLED(CONFIG_IPV6_SIT)
	} else if ( netif->type == ARPHRD_SIT ) {
		if ((netif = ppa_get_6rd_phyif(netif)) == NULL )
			goto hwaddr_error;
		goto hwaddr_top; /*Alternative: call ppa_get_netif_hwaddr*/
#endif
#if IS_ENABLED(CONFIG_IPV6_TUNNEL)
	} else if ( netif->type == ARPHRD_TUNNEL6) {
		if ((netif = ppa_get_ip4ip6_phyif(netif)) == NULL )
			goto hwaddr_error;

		goto hwaddr_top; /*Alternative: ppa_get_netif_hwaddr*/
#endif
	} else if( ppa_is_gre_netif(netif) ) {
		if( (netif = ppa_get_gre_phyif(netif)) == NULL)
			goto hwaddr_error;
		goto hwaddr_top; /*Alternative: call ppa_get_netif_hwaddr*/

	}
#if IS_ENABLED(CONFIG_SOC_GRX500) && IS_ENABLED(CONFIG_VXLAN)
	else if (ppa_is_vxlan_netif(netif)) {
		if ((netif = ppa_get_vxlan_phyif(netif)) == NULL)
			goto hwaddr_error;

		goto hwaddr_top;
	}
#endif
	if ( netif->type == ARPHRD_ETHER || netif->type == ARPHRD_EETHER )
	{
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 1, 21)
		if(  !(netif_is_bridge_port(netif))  || flag_down_only )
#else
		if(  !(br_port_exists(netif))  || flag_down_only )
#endif
			ppa_memcpy(mac, netif->dev_addr, PPA_ETH_ALEN);
		else
			ppa_memcpy(mac, br_port_get_rcu(netif)->br->dev->dev_addr, PPA_ETH_ALEN);
		return PPA_SUCCESS;
	}

hwaddr_error:
	ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,
			"Cannot get hw-mac for %s dev!", orgif->name);
	return PPA_ENOTAVAIL;
}


int32_t ppa_get_physical_if(PPA_NETIF *netif, PPA_IFNAME *ifname, PPA_IFNAME phy_ifname[PPA_IF_NAME_SIZE])
{
	uint32_t ret = 0;
	if (!netif)
		netif = ppa_get_netif(ifname);

	if (!netif || strnlen(netif->name, PPA_IF_NAME_SIZE) == 0)
		return PPA_EINVAL;

	if( ppa_check_is_ppp_netif(netif) )  {

		if (ppa_if_is_pppoa(netif, NULL) || ppa_if_is_ipoa(netif, NULL)) {
			ppa_strncpy(phy_ifname, netif->name, PPA_IF_NAME_SIZE);
			ret = PPA_SUCCESS;
			goto ppp_ret;
		}
		else if (ppa_check_is_pppol2tp_netif(netif)) {

			ret = ppa_pppol2tp_get_base_netif(netif, phy_ifname);
			if ( ret == PPA_SUCCESS ) {
				ret = ppa_get_physical_if(NULL,phy_ifname, phy_ifname);
			}
		} else if (ppa_check_is_pppoe_netif(netif)) {

			ret = ppa_pppoe_get_eth_netif(netif, phy_ifname);
			if (ret == PPA_SUCCESS) {
				ret = ppa_get_physical_if(NULL, phy_ifname, phy_ifname);
			}
		}
ppp_ret:
		return ret;
	}

#if IS_ENABLED(CONFIG_MACVLAN)
	if (netif_is_macvlan(netif)) {
		netif = macvlan_dev_real_dev(netif);
		if (netif != NULL)
			return ppa_get_physical_if(netif, NULL, phy_ifname);
		return PPA_FAILURE;
	}
#endif

	if(ppa_is_gre_netif(netif)) {
		if((netif = (PPA_NETIF *) ppa_get_gre_phyif(netif)))
			return ppa_get_physical_if(netif, NULL, phy_ifname);
		return PPA_FAILURE;
	}

#if IS_ENABLED(CONFIG_VXLAN)
	if (ppa_is_vxlan_netif(netif)) {
		if ((netif = (PPA_NETIF *)ppa_get_vxlan_phyif(netif)))
			return ppa_get_physical_if(netif, NULL, phy_ifname);

		return PPA_FAILURE;
	}
#endif

#if IS_ENABLED(CONFIG_VLAN_8021Q)
	if ((netif->priv_flags & IFF_802_1Q_VLAN)) {
		return ppa_get_physical_if(NULL,
			VLAN_DEV_INFO(netif)->real_dev->name,
			phy_ifname);
	}
#endif

#if IS_ENABLED(CONFIG_IPV6_SIT)
	if( netif->type == ARPHRD_SIT){
		if((netif = (PPA_NETIF *)ppa_get_6rd_phyif(netif)) == NULL){
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"6RD, cannot get physical device\n");
			return PPA_FAILURE;
		}

		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"6RD physical device name: %s \n", netif->name);
		return ppa_get_physical_if(netif, NULL, phy_ifname);
	}
#endif

#if IS_ENABLED(CONFIG_IPV6_TUNNEL)
	if( netif->type == ARPHRD_TUNNEL6) {
		if((netif = (PPA_NETIF *)ppa_get_ip4ip6_phyif(netif)) == NULL){
			ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"dslite, cannot get physical device\n");
			return PPA_FAILURE;
		}
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT,"dslite physical device name: %s \n", netif->name);
		return ppa_get_physical_if(netif, NULL, phy_ifname);
	}
#endif
	if (ppa_if_is_veth_if(netif, NULL)) { /* veth device */
		ppa_debug(DBG_ENABLE_MASK_DEBUG_PRINT, "This is a veth device. Device name: %s \n", netif->name);
		return PPA_FAILURE;
	}

	ppa_strncpy(phy_ifname, netif->name, PPA_IF_NAME_SIZE);
	return PPA_SUCCESS;
}

int32_t ppa_get_lower_if(PPA_NETIF *netif, PPA_IFNAME *ifname,
		PPA_IFNAME lower_ifname[PPA_IF_NAME_SIZE])
{
	if (!netif)
		netif = ppa_get_netif(ifname);

	if (!netif)
		return PPA_EINVAL;

	lower_ifname[0] = '\0';

	if (netif_is_macvlan(netif)) {
		struct net_device *lowerdev = macvlan_dev_real_dev(netif);
		if (lowerdev != NULL)
			ppa_strncpy(lower_ifname, lowerdev->name,
					PPA_IF_NAME_SIZE);
	}
	return PPA_SUCCESS;
}
EXPORT_SYMBOL(ppa_get_lower_if);

int32_t ppa_if_is_vlan_if(PPA_NETIF *netif, PPA_IFNAME *ifname)
{
#if IS_ENABLED(CONFIG_VLAN_8021Q) || defined (CONFIG_WAN_VLAN_SUPPORT)
	if ( !netif )
		netif = ppa_get_netif(ifname);

	if ( !netif )
		return 0;

	if ( (netif->priv_flags & IFF_802_1Q_VLAN) ) {
		return 1;
	}

#if defined(CONFIG_WAN_VLAN_SUPPORT)
	if ( (netif->priv_flags & IFF_BR2684_VLAN) )
		return 1;
#endif

#endif

	return 0;
}

int32_t ppa_is_macvlan_if(PPA_NETIF *netif, PPA_IFNAME *ifname)
{
	if ( !netif )
		netif = ppa_get_netif(ifname);

	if ( !netif )
		return 0;

	if (netif_is_macvlan(netif))
		return 1;

	return 0;
}

int32_t ppa_vlan_get_underlying_if(PPA_NETIF *netif, PPA_IFNAME *ifname, PPA_IFNAME underlying_ifname[PPA_IF_NAME_SIZE])
{
	int ret=PPA_EINVAL;
#if !IS_ENABLED(CONFIG_VLAN_8021Q) && !defined(CONFIG_WAN_VLAN_SUPPORT)
	goto lbl_ret;
#endif
	if ( !netif )
		netif = ppa_get_netif(ifname);

	if ( !netif )
		goto lbl_ret;

#if IS_ENABLED(CONFIG_VLAN_8021Q)
	/*
	 * This order of eval below is important, so that nas0.10 iface
	 * is correctly eval as VLAN_8021Q, and then nas0 can be eval
	 * as BR2684_VLAN :-)
	 */
	if ( (netif->priv_flags & IFF_802_1Q_VLAN) ) {
		ppa_strncpy(underlying_ifname, VLAN_DEV_INFO(netif)->real_dev->name, PPA_IF_NAME_SIZE);
		ret=PPA_SUCCESS;
	}
#endif

#if defined(CONFIG_WAN_VLAN_SUPPORT)
	if ( (netif->priv_flags & IFF_BR2684_VLAN) ) {
		/* br2684 does not create a new netdevice, so name is same */
		ppa_strncpy(underlying_ifname, netif->name, PPA_IF_NAME_SIZE);
		ret=PPA_SUCCESS;
	}
#endif
lbl_ret:
	return ret;
}

int32_t ppa_vlan_get_physical_if(PPA_NETIF *netif, PPA_IFNAME *ifname, PPA_IFNAME phy_ifname[PPA_IF_NAME_SIZE])
{
#if IS_ENABLED(CONFIG_VLAN_8021Q)
	PPA_IFNAME ifname_tmp[2][PPA_IF_NAME_SIZE] = {{0}};
	int pos = 0;

	snprintf(phy_ifname, PPA_IF_NAME_SIZE, "%s", ifname_tmp[pos]);

	while ( ppa_vlan_get_underlying_if(NULL, ifname_tmp[pos], ifname_tmp[pos ^ 0x01]) == PPA_SUCCESS )
		pos ^= 0x01;

	ppa_strncpy(phy_ifname, ifname_tmp[pos], PPA_IF_NAME_SIZE);

	return PPA_SUCCESS;
#else
	return PPA_EPERM;
#endif
}

#ifdef CONFIG_WAN_VLAN_SUPPORT
extern int br2684_vlan_dev_get_vid(struct net_device *dev, uint16_t *vid);
#endif

uint32_t ppa_get_vlan_id(PPA_NETIF *netif)
{
#if IS_ENABLED(CONFIG_VLAN_8021Q)
	uint32_t vid=0;
#endif
	if ( !netif )
		return ~0;
#if IS_ENABLED(CONFIG_VLAN_8021Q)
	vid = vlan_dev_vlan_id(netif);
		return (uint32_t)vid;
#endif
#if defined(CONFIG_WAN_VLAN_SUPPORT)
	if (br2684_vlan_dev_get_vid(netif, &vid) == 0 )
		return (uint32_t) vid;
#endif

	return ~0;
}

uint16_t ppa_get_vlan_type(PPA_NETIF *netif)
{
#if IS_ENABLED(CONFIG_VLAN_8021Q)
	return (vlan_dev_priv(netif)->vlan_proto);
# else
	return 0;
#endif
}


uint32_t ppa_get_vlan_tag(PPA_BUF *ppa_buf)
{
#if IS_ENABLED(CONFIG_VLAN_8021Q)
	unsigned short tag;

	if ( ppa_buf && vlan_get_tag(ppa_buf, &tag) == 0 )
		return (uint32_t)tag;
#endif

	return ~0;
}

uint32_t ppa_is_bond_slave(PPA_IFNAME *ifname, PPA_NETIF *netif)
{
	if ( !netif )
		netif = ppa_get_netif(ifname);

	if ( !netif )
		return 0;
	return netif_is_bond_slave(netif);
}

int32_t ppa_get_bridge_member_ifs(PPA_IFNAME *ifname, int *num_ifs, PPA_IFNAME **pp_member_ifs)
{
	/*TODO: wait for implementation*/
	return PPA_ENOTIMPL;
}

int32_t ppa_if_is_br_if(PPA_NETIF *netif, PPA_IFNAME *ifname)
{
	if ( !netif )
		netif = ppa_get_netif(ifname);
	else
		netif = ppa_get_netif(netif->name); /* to make sure that the netif is not freed by anyone */

	if(netif && ppa_dev_is_br(netif))
		return 1;

	return 0;
}

int32_t ppa_if_is_veth_if(PPA_NETIF *netif, PPA_IFNAME *ifname)
{
	if (!netif) {
		netif = ppa_get_netif(ifname);
	} else {
		netif = ppa_get_netif(netif->name); /* to make sure that the netif is not freed by anyone */
	}

	if (netif && netif->netdev_ops)
		return ppa_if_is_veth(netif);

	return 0;
}

struct net *ppa_get_current_net_ns()
{
	return current->nsproxy->net_ns;
}

int ppa_dev_is_loopback(PPA_NETIF *netif)
{
	return (netif->type == ARPHRD_LOOPBACK) ? 1 : 0;
}

int32_t ppa_get_netif_ip(uint32_t *ip, PPA_NETIF *netif)
{
	struct in_ifaddr* if_info = NULL;
	struct in_device* in_dev = NULL;

	if ( !netif ) {
		return PPA_FAILURE;
	}

	in_dev = netif->ip_ptr;
	if ( !in_dev ) {
		return PPA_FAILURE;
	}

	if_info = in_dev->ifa_list;
	for (;if_info;if_info=if_info->ifa_next)
	{
		if (!(strcmp(if_info->ifa_label,netif->name))) {
			*ip = if_info->ifa_address;
			return PPA_SUCCESS;
		}
	}
	return PPA_FAILURE;
}

#if IS_ENABLED(CONFIG_PPA_RT_SESS_LEARNING)
int32_t ppa_get_br_dst_port(PPA_NETIF *netif, PPA_BUF *ppa_buf, PPA_NETIF **p_netif)
{
	int32_t ret = PPA_FAILURE;
	unsigned char dest[PPA_ETH_ALEN];

	if ( !netif || !ppa_dev_is_br(netif) )
		return PPA_EINVAL;

	if ( (ret = ppa_get_dst_mac(ppa_buf, NULL, dest,0)) != PPA_SUCCESS )
		return ret == PPA_ENOTAVAIL ? PPA_EAGAIN : PPA_FAILURE;

	return ppa_get_br_dst_port_with_mac(netif, dest, p_netif);
}

int32_t ppa_get_br_dst_port_with_mac(PPA_NETIF *netif, uint8_t mac[PPA_ETH_ALEN], PPA_NETIF **p_netif)
{
	int32_t ret = PPA_FAILURE;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
	struct net_bridge *br;
	struct net_bridge_fdb_entry *dst;
#endif

	if ( !netif || !ppa_dev_is_br(netif))
		return PPA_EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
	br = netdev_priv(netif);
#endif
	if ( mac[0] & 1 )
		return PPA_ENOTAVAIL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
	ppa_rcu_read_lock();
	if((dst = ppa_br_fdb_get(br,mac,0)) != NULL) {
		*p_netif = dst->dst->dev;
		ret = PPA_SUCCESS;
	}
	ppa_rcu_read_unlock();
#else
	if ((*p_netif = br_fdb_find_port_rcu(netif, mac, 0)) != NULL) {
		ret = PPA_SUCCESS;
	}
#endif
	return ret;
}
#endif

int32_t ppa_br2684_get_vcc(PPA_NETIF *netif, PPA_VCC **pvcc)
{
	if( ppa_br2684_get_vcc_fn != NULL)
		return ppa_br2684_get_vcc_fn( netif, pvcc);

	return PPA_EPERM;
}

int32_t ppa_if_is_br2684(PPA_NETIF *netif, PPA_IFNAME *ifname)
{
	if( ppa_if_is_br2684_fn != NULL)
		return ppa_if_is_br2684_fn( netif, ifname);
	return 0;
}

int32_t ppa_if_is_veth(PPA_NETIF *netif)
{
	if (ppa_if_ops_veth_xmit_fn != NULL)
		return ppa_if_ops_veth_xmit_fn(netif);
	return 0;
}

int32_t ppa_if_is_ipoa(PPA_NETIF *netif, PPA_IFNAME *ifname)
{
	if( ppa_if_is_ipoa_fn != NULL)
		return ppa_if_is_ipoa_fn(netif, ifname);
	return 0;
}

#if !IS_ENABLED(CONFIG_PPPOATM)
int32_t ppa_pppoa_get_vcc(PPA_NETIF *netif, PPA_VCC **patmvcc)
{
	return PPA_EPERM;
}

int32_t ppa_if_is_pppoa(PPA_NETIF *netif, PPA_IFNAME *ifname)
{
	return 0;
}
#endif

uint32_t ppa_is_session_equal(PPA_SESSION *session1, PPA_SESSION *session2)
{
	return session1 == session2 ? 1 : 0;
}

uint32_t ppa_get_session_helper(PPA_SESSION *p_session)
{
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	struct nf_conn_help *help = nfct_help(p_session);
	return help ? 1 : 0;
#else
	return (p_session->helper) ? 1 : 0;
#endif
}

void ppa_tdox_enable_set(bool value)
{
	lgm_pp_hal_tdox_enable = value;
}
EXPORT_SYMBOL(ppa_tdox_enable_set);

bool ppa_tdox_enable_get(void)
{
	return lgm_pp_hal_tdox_enable;
}
EXPORT_SYMBOL(ppa_tdox_enable_get);

int32_t ppa_bypass_lro(PPA_BUF *ppa_buf)
{
#if IS_ENABLED(CONFIG_LGM_TOE)
	int len_diff = -1;

	/* tcp acks shall be non LRO ppv4 session */
	if (ppa_buf) {
		if (ntohs(ppa_buf->protocol) == ETH_P_IP) {
			if (ip_hdr(ppa_buf)->protocol == IPPROTO_TCP) {
				len_diff = ntohs(ip_hdr(ppa_buf)->tot_len)
					   - (ip_hdrlen(ppa_buf)
					      + tcp_hdrlen(ppa_buf));
			}
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (ntohs(ppa_buf->protocol) == ETH_P_IPV6) {
			if (ipv6_hdr(ppa_buf)->nexthdr == IPPROTO_TCP) {
				len_diff = ntohs(ipv6_hdr(ppa_buf)->payload_len)
					   - tcp_hdrlen(ppa_buf);
			}
		}
#endif
		if ((ppa_buf->len < 100) && !len_diff)
			return 1;
	}
#else /* !CONFIG_LGM_TOE */
	PPA_SESSION *p_session = NULL;
	enum ip_conntrack_info  ct_info;

	p_session = ppa_conntrack_get(ppa_buf, &ct_info);
	if(p_session) {
#if IS_ENABLED(CONFIG_NF_CONNTRACK_MARK)
		return ((p_session->mark & 0x100) == 0x100 ? 1 : 0);
#else
		return 0;
#endif /* CONFIG_NF_CONNTRACK_MARK */
	}
#endif /* CONFIG_LGM_TOE */
	return 0;
}

uint32_t ppa_check_is_special_session(PPA_BUF *ppa_buf, PPA_SESSION *p_session)
{
	enum ip_conntrack_info  ct_info;

	if ( !p_session )
		p_session = ppa_conntrack_get(ppa_buf, &ct_info);

	if(p_session) {
		if ( ppa_get_session_helper(p_session) )
			return 1;

		if ( ppa_get_nat_helper(p_session) )
			return 1;
	}
	return 0;
}

int32_t ppa_lock_init(PPA_LOCK *p_lock)
{
	if ( !p_lock )
		return PPA_EINVAL;

	ppe_lock_init(&p_lock->lock);
	return PPA_SUCCESS;
}

void ppa_trace_lock_get(PPA_LOCK *p_lock)
{
	ASSERT(p_lock->cnt == 0,"Lock already taken!!!, lock cnt: %d\n", p_lock->cnt);
	if(p_lock->cnt != 0){
		dump_stack();
	}
	p_lock->cnt += 1;
}

void ppa_trace_lock_release(PPA_LOCK *p_lock)
{
	ASSERT(p_lock->cnt == 1, "Lock already released!!!, lock cnt: %d\n", p_lock->cnt);
	if(p_lock->cnt != 1){
		dump_stack();
	}
	p_lock->cnt -= 1;
}

void ppa_lock_get(PPA_LOCK *p_lock)
{
	ppa_spin_lock_bh(&p_lock->lock);
	ppa_trace_lock_get(p_lock);

}

void ppa_lock_release(PPA_LOCK *p_lock)
{
	ppa_trace_lock_release(p_lock);
	ppa_spin_unlock_bh(&p_lock->lock);
}

uint32_t ppa_lock_get2(PPA_LOCK *p_lock)
{
	unsigned long sys_flag = 0;

	spin_lock_irqsave(&p_lock->lock, sys_flag);
	return sys_flag;
}

void ppa_lock_release2(PPA_LOCK *p_lock, uint32_t sys_flag)
{
	spin_unlock_irqrestore(&p_lock->lock, (unsigned long)sys_flag);
}

void ppa_lock_destroy(PPA_LOCK *p_lock)
{
}

uint32_t ppa_disable_int(void)
{
	unsigned long sys_flag = 0;

	spin_lock_irqsave(&g_local_irq_save_flag_lock, sys_flag);
	return sys_flag;
}

void ppa_enable_int(uint32_t flag)
{
	spin_unlock_irqrestore(&g_local_irq_save_flag_lock, (unsigned long)flag);
}

void *ppa_malloc(uint32_t size)
{
	gfp_t flags = 0;

	if (in_atomic() || in_interrupt())
		flags |= GFP_ATOMIC;
	else
		flags |= GFP_KERNEL;
	return kmalloc(size, flags);
}

void *ppa_alloc_dma(uint32_t size)
{
	gfp_t flags = 0;

	flags |= GFP_DMA;
	if (in_atomic() || in_interrupt())
		flags |= GFP_ATOMIC;
	else
		flags |= GFP_KERNEL;
	return kmalloc(size, flags);
}
EXPORT_SYMBOL(ppa_alloc_dma);


int32_t ppa_free(void *buf)
{
	kfree(buf);
	return PPA_SUCCESS;
}

#if defined(PPA_KMALLOC_METHOD)
#define MAX_MEM_SIZE_NUM  40
typedef struct cache_info
{
	uint32_t size;
	uint32_t count;
}cache_info;
cache_info cache_size_array[MAX_MEM_SIZE_NUM];
uint32_t cache_size_num = 0;

int32_t ppa_mem_cache_create(const char *name, uint32_t size, PPA_MEM_CACHE **pp_cache)
{ /*return pp_cache from 1, not from 0*/
	uint32_t i, index;

	if ( !pp_cache )
		return PPA_EINVAL;

	if( cache_size_num == 0 ) {
		ppa_memset(cache_size_array, 0, sizeof(cache_size_array) );
	} else {
		/*check whether such cache size alerady exists*/
		for(i=0; i<cache_size_num; i++) {
			if( cache_size_array[i].size == size ) {
				*pp_cache =(PPA_MEM_CACHE *) (i+1);
				cache_size_array[i].count ++;
				err(" *pp_cache=%u\n", (uint32_t )*pp_cache );
				return PPA_SUCCESS;
			}
		}
	}
	if( cache_size_num >= MAX_MEM_SIZE_NUM ) {
		err("Too many cache size: %d. Need increase the cache_size_array.\n", cache_size_num );
		return PPA_EINVAL;
	}
	index = cache_size_num;

	cache_size_array[index].size = size;
	cache_size_array[index].count ++;
	cache_size_num++;
	*pp_cache = (PPA_MEM_CACHE *)(index + 1 );
	err(" *pp_cache=%u for size=%d\n", (uint32_t )*pp_cache,  cache_size_array[index].size);

	return PPA_SUCCESS;
}

int32_t ppa_mem_cache_destroy(PPA_MEM_CACHE *p_cache)
{
	return PPA_SUCCESS;
}

void *ppa_mem_cache_alloc(PPA_MEM_CACHE *p_cache)
{
	uint32_t index = (uint32_t)p_cache -1;

	if( index >= cache_size_num ) {
		err("Why p_cache index (%u) > cache_size_num(%u)\n", (unsigned int)index, (unsigned int)cache_size_num );
		return NULL;
	}
	if( cache_size_array[index].size == 0 ) {
		err("why cache_size_array[%d] is zero\n", (uint32_t)index );
		return NULL;
	}

	return ppa_malloc(cache_size_array[index].size);
}

int32_t ppa_mem_cache_free(void *buf, PPA_MEM_CACHE *p_cache)
{
	ppa_free(buf);
	return PPA_SUCCESS;
}

int32_t ppa_kmem_cache_shrink(PPA_MEM_CACHE *cachep)
{
	return PPA_SUCCESS;
}

#else
static void ctor_ppa(void *region)
{ }

int32_t ppa_mem_cache_create(const char *name, uint32_t size, PPA_MEM_CACHE **pp_cache)
{
	PPA_MEM_CACHE* p_cache;

	if ( !pp_cache )
		return PPA_EINVAL;
	p_cache = kmem_cache_create(name, size, 0, SLAB_HWCACHE_ALIGN, ctor_ppa);
	if ( !p_cache )
		return PPA_ENOMEM;

	*pp_cache = p_cache;
	return PPA_SUCCESS;
}

int32_t ppa_mem_cache_destroy(PPA_MEM_CACHE *p_cache)
{
	if ( !p_cache )
		return PPA_EINVAL;

	kmem_cache_destroy(p_cache);

	return PPA_SUCCESS;
}

void *ppa_mem_cache_alloc(PPA_MEM_CACHE *p_cache)
{
	return kmem_cache_alloc(p_cache, GFP_ATOMIC);
}

int32_t ppa_mem_cache_free(void *buf, PPA_MEM_CACHE *p_cache)
{
	if ( !p_cache )
		return PPA_FAILURE;
	kmem_cache_free(p_cache, buf);
	return PPA_SUCCESS;
}

int32_t ppa_kmem_cache_shrink(PPA_MEM_CACHE *cachep)
{
	return kmem_cache_shrink(cachep);
}
#endif

void ppa_memcpy(void *dst, const void *src, uint32_t count)
{
#if defined(ENABLE_MY_MEMCPY) && ENABLE_MY_MEMCPY
	char *d = (char *)dst, *s = (char *)src;

	if (count >= 32) {
		int i = 8 - (((unsigned long) d) & 0x7);

		if (i != 8)
			while (i-- && count--) {
				*d++ = *s++;
			}

		if (((((unsigned long) d) & 0x7) == 0) &&
				((((unsigned long) s) & 0x7) == 0)) {
			while (count >= 32) {
				unsigned long long t1, t2, t3, t4;
				t1 = *(unsigned long long *) (s);
				t2 = *(unsigned long long *) (s + 8);
				t3 = *(unsigned long long *) (s + 16);
				t4 = *(unsigned long long *) (s + 24);
				*(unsigned long long *) (d) = t1;
				*(unsigned long long *) (d + 8) = t2;
				*(unsigned long long *) (d + 16) = t3;
				*(unsigned long long *) (d + 24) = t4;
				d += 32;
				s += 32;
				count -= 32;
			}
			while (count >= 8) {
				*(unsigned long long *) d =
					*(unsigned long long *) s;
				d += 8;
				s += 8;
				count -= 8;
			}
		}

		if (((((unsigned long) d) & 0x3) == 0) &&
				((((unsigned long) s) & 0x3) == 0)) {
			while (count >= 4) {
				*(unsigned long *) d = *(unsigned long *) s;
				d += 4;
				s += 4;
				count -= 4;
			}
		}

		if (((((unsigned long) d) & 0x1) == 0) &&
				((((unsigned long) s) & 0x1) == 0)) {
			while (count >= 2) {
				*(unsigned short *) d = *(unsigned short *) s;
				d += 2;
				s += 2;
				count -= 2;
			}
		}
	}

	while (count--) {
		*d++ = *s++;
	}
#else
	memcpy(dst, src, count);
#endif
}

void ppa_memset(void *dst, uint32_t pad, uint32_t n)
{
	memset(dst, pad, n);
}

int ppa_memcmp(const void *src, const void *dest, size_t count)
{
	return memcmp(src, dest, count);
}

#if KERNEL_VERSION(4, 15, 0) > LINUX_VERSION_CODE
int32_t ppa_timer_setup(PPA_TIMER *p_timer, void (*callback)(unsigned long), unsigned long data)
{
	setup_timer(p_timer,callback,data);
	return 0;
}
EXPORT_SYMBOL(ppa_timer_setup);

int32_t ppa_timer_pending(PPA_TIMER *p_timer)
{
	return timer_pending(p_timer);
}
EXPORT_SYMBOL(ppa_timer_pending);

int32_t ppa_timer_init(PPA_TIMER *p_timer, void (*callback)(unsigned long))
{
	init_timer(p_timer);
	p_timer->function = callback;

	return 0;
}
EXPORT_SYMBOL(ppa_timer_init);
void ppa_timer_del(PPA_TIMER *p_timer)
{
	del_timer_sync(p_timer);
}
EXPORT_SYMBOL(ppa_timer_del);

int32_t ppa_timer_add(PPA_TIMER *p_timer, uint32_t timeout_in_sec)
{
	p_timer->expires = jiffies + timeout_in_sec * HZ - 1;
	add_timer(p_timer);

	return 0;
}
EXPORT_SYMBOL(ppa_timer_add);
#else
int32_t ppa_hrt_init(PPA_HRT *p_timer, PPA_HRT_RESTART (*fnp_callback)(PPA_HRT *))
{
	hrtimer_init(p_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	p_timer->function = fnp_callback;
	return 0;

}
EXPORT_SYMBOL(ppa_hrt_init);

void ppa_hrt_start(PPA_HRT *p_timer, int32_t polling_time)
{
#if IS_ENABLED(LGM_HAPS)
	//scaling time for HAPS
	hrtimer_start(p_timer, ktime_set(0,polling_time*20000000L), HRTIMER_MODE_REL_PINNED);
#else
	hrtimer_start(p_timer, ktime_set(polling_time,0), HRTIMER_MODE_REL_PINNED);
#endif
}
EXPORT_SYMBOL(ppa_hrt_start);

uint64_t ppa_hrt_forward(PPA_HRT *p_timer, int32_t polling_time)
{
#if IS_ENABLED(LGM_HAPS)
	//scaling time for HAPS
	return hrtimer_forward_now(p_timer,ktime_set(0,polling_time*20000000L));
#else
	return hrtimer_forward_now(p_timer,ktime_set(polling_time,0));
#endif
}
EXPORT_SYMBOL(ppa_hrt_forward);

void ppa_hrt_stop(PPA_HRT *p_timer)
{
	hrtimer_cancel(p_timer);
}
EXPORT_SYMBOL(ppa_hrt_stop);

void ppa_hrt_restart(PPA_HRT *p_timer)
{
	hrtimer_restart(p_timer);
}
EXPORT_SYMBOL(ppa_hrt_restart);
#endif

uint32_t ppa_get_time_in_sec(void)
{
	return (jiffies + HZ / 2) / HZ;
}

PPA_TASK* ppa_kthread_create( int (*threadfn)(void *data), void *data, const char fn_name[])
{
	return kthread_create(threadfn,data,fn_name);
}

int ppa_kthread_should_stop(void)
{
	return kthread_should_stop();
}

int ppa_kthread_stop(PPA_TASK* k)
{
	return kthread_stop(k);
}

void ppa_wake_up_process(PPA_TASK* k)
{
	wake_up_process(k);
}

void ppa_schedule(void)
{
	schedule();
}

void ppa_set_current_state(int state)
{
	__set_current_state(state);
}

PPA_NETIF* ppa_netdev_master_upper_dev_get(PPA_NETIF *netif)
{
	return netdev_master_upper_dev_get_rcu(netif);
}

void ppa_rtnl_lock(void)
{
	rtnl_lock();
}

void ppa_rtnl_unlock(void)
{
	rtnl_unlock();
}

int32_t ppa_atomic_read(PPA_ATOMIC *v)
{
	return atomic_read(v);
}

void ppa_atomic_set(PPA_ATOMIC *v, int32_t i)
{
	atomic_set(v, i);
}

int32_t ppa_atomic_inc(PPA_ATOMIC *v)
{
	return atomic_inc_return(v);
}

int32_t ppa_atomic_dec(PPA_ATOMIC *v)
{
	return atomic_dec_if_positive(v);
}

int32_t ppa_atomic_inc_not_zero(PPA_ATOMIC *v)
{
	return atomic_inc_not_zero(v);
}

int32_t ppa_atomic_dec_and_test(PPA_ATOMIC *v)
{
	return atomic_dec_and_test(v);
}
EXPORT_SYMBOL(ppa_atomic_dec_and_test);

void ppa_hlist_replace(PPA_HLIST_NODE *old, PPA_HLIST_NODE *new)
{
	new->next = old->next;
	new->pprev = old->pprev;
	*(new->pprev) = new;
	if(old->next)
		new->next->pprev = &new->next;
	old->next = LIST_POISON1;
	old->pprev = LIST_POISON2;
}

PPA_BUF *ppa_buf_clone(PPA_BUF *buf, uint32_t flags)
{
	return skb_clone(buf, 0);
}

int32_t ppa_buf_cloned(PPA_BUF *buf)
{
	return skb_cloned(buf) ? 1 : 0;
}

PPA_BUF *ppa_buf_get_prev(PPA_BUF *buf)
{
	return buf != NULL ? buf->prev : NULL;
}

PPA_BUF *ppa_buf_get_next(PPA_BUF *buf)
{
	return buf != NULL ? buf->next : NULL;
}

void ppa_buf_free(PPA_BUF *buf)
{
	if ( buf != NULL ) {
		buf->prev = buf->next = NULL;
		dev_kfree_skb_any(buf);
	}
}

uint32_t ppa_copy_from_user(void *to, const void PPA_USER  *from, uint32_t  n)
{
	return copy_from_user(to, from, n);
}
uint32_t ppa_copy_to_user(void PPA_USER *to, const void *from, uint32_t  n)
{
	return copy_to_user(to, from, n);
}

uint8_t *ppa_strncpy(uint8_t *dest, const uint8_t *src, PPA_SIZE_T n)
{
	dest[n - 1] = '\0';
	return strncpy(dest, src, (n - 1));
}

int32_t ppa_str_cmp(char *str1,char *str2)
{
	return ( (strcmp(str1,str2) == 0) ? 1 : 0);
}

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
session_type ppa_is_ipv4_ipv6(PPA_XFRM_STATE *x)
{
	switch (x->props.family) {
		default:
		case AF_INET:
			return SESSION_IPV4;
		case AF_INET6:
			return SESSION_IPV6;
	}
}
bool ppa_ipsec_addr_equal(PPA_XFRM_ADDR *a, PPA_XFRM_ADDR *b, PPA_SA_FAMILY family)
{
	switch (family) {
		default:
		case AF_INET:
			return ((__force u32)a->a4 ^ (__force u32)b->a4) == 0;
		case AF_INET6:
			return xfrm6_addr_equal(a, b);
	}
}
#endif

int32_t ppa_register_netdev(PPA_NETIF *dev)
{
	return register_netdev(dev);
}

void ppa_unregister_netdev(PPA_NETIF *dev)
{
	unregister_netdev(dev);
}

int32_t ppa_register_chrdev(int32_t  major, const uint8_t *name, PPA_FILE_OPERATIONS  *fops)
{
	return register_chrdev(major, name, fops);
}

void ppa_unregister_chrdev(int32_t  major, const uint8_t *name)
{
	unregister_chrdev(major, name);
	return;
}

int ppa_snprintf(uint8_t * buf, size_t size, const uint8_t *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i=vsnprintf(buf,size,fmt,args);
	va_end(args);
	return i;
}

int ppa_sprintf(uint8_t * buf, const uint8_t *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i=vsprintf(buf,fmt,args);
	va_end(args);
	return i;
}

/*Note, in linux, IOC is defined as below
  define _IOC(dir,type,nr,size) \
  (((dir)  << _IOC_DIRSHIFT) | \
  ((type) << _IOC_TYPESHIFT) | \
  ((nr)   << _IOC_NRSHIFT) | \
  ((size) << _IOC_SIZESHIFT))
  or other os, should refer to it to define below adaption layer accordingly
 */

uint32_t ppa_ioc_type(uint32_t nr)
{
	return  _IOC_TYPE(nr);
}

uint32_t ppa_ioc_nr(uint32_t nr)
{
	return  _IOC_NR(nr);
}

uint32_t ppa_ioc_dir(uint32_t nr)
{
	return  _IOC_DIR(nr);
}

uint32_t ppa_ioc_read(void)
{
	return  _IOC_READ;
}

uint32_t ppa_ioc_write(void)
{
	return  _IOC_WRITE;
}

uint32_t ppa_ioc_size(uint32_t nr)
{
	return  _IOC_SIZE(nr);
}

uint32_t ppa_ioc_access_ok(uint32_t type, uint32_t addr, uint32_t size)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#ifdef CONFIG_MIPS
	return  access_ok((void *)addr, size);
#else
	return  access_ok(addr, size);
#endif
#else
	return  access_ok(type, addr, size);
#endif
}

uint32_t ppa_ioc_verify_write(void)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 20, 17)
	return 1;
#else
	return VERIFY_WRITE;
#endif
}

uint32_t ppa_ioc_verify_read(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 17)
	return 0;
#else
	return VERIFY_READ;
#endif
}

uint16_t ppa_vlan_dev_get_egress_qos_mask(PPA_NETIF *dev, PPA_BUF *buf)
{
#if IS_ENABLED(CONFIG_VLAN_8021Q)
	if ( (dev->priv_flags & IFF_802_1Q_VLAN) )
		return vlan_dev_get_egress_qos_mask((struct net_device *)dev, buf->priority);
#endif
#if defined(CONFIG_WAN_VLAN_SUPPORT)
	if ( (dev->priv_flags & IFF_BR2684_VLAN) )
		return ((struct sk_buff *)buf)->priority & 0x7;
#endif
	return 0;
}

static uint32_t get_hash_from_ct(const struct nf_conn *ct, uint8_t dir,
				 struct nf_conntrack_tuple* tuple)
{
  /*struct net *net = nf_ct_net(ct);*/
  *tuple = ct->tuplehash[dir].tuple;

/* HASH is calcuated using tuple and hash value.
Always, passing init_net as namespace to ensure session is not dependent on namespaces.
Applciable for Veth LOCAL_IN and LOCAL_OUT sessions
Previously 2 sessions were created. Now one session is created for containers */
  return ppa_hash_conntrack_raw(tuple, &init_net);

}

static int get_hash_from_skb(struct sk_buff *skb,
			     unsigned char pf,
			     uint32_t * u32_hash,
			     struct nf_conntrack_tuple *tuple)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
	u_int8_t protonum;
	unsigned int dataoff;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *tmpl = NULL;
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conntrack_l4proto *l4proto;
	int ret;
#endif
	struct net* net= NULL;

	if(skb->dev) {
		net = dev_net(skb->dev);
	} else if(skb->sk){
		net = sock_net(skb->sk);
	} else {
		net = &init_net;
	}


	if( pf == 0 ) {
		if (skb->protocol == htons(ETH_P_IP)) {
				  pf = PF_INET;
		} else if (skb->protocol == htons(ETH_P_IPV6)) {
				  pf = PF_INET6;
	}/*else - other protocols*/

	if( pf == 0 ) return -1;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
	l3proto = __nf_ct_l3proto_find(pf);
	ret = l3proto->get_l4proto(skb, skb_network_offset(skb), &dataoff, &protonum);
	if (ret <= 0) {
		return -1;
	}

	l4proto = __nf_ct_l4proto_find(pf, protonum);
	if (l4proto->error != NULL) {
	/*TODO: Pass pre routing/post routing hooknum*/
	ret = l4proto->error(net, tmpl, skb, dataoff, &ctinfo, pf, NF_INET_POST_ROUTING);
		if (ret <= 0) {
			return -1;
		}
	}

	if (!nf_ct_get_tuple(skb, skb_network_offset(skb),
							 dataoff, pf, protonum, net, tuple, l3proto,
							 l4proto)) {
#else
	if (!nf_ct_get_tuplepr(skb, skb_network_offset(skb), pf, net, tuple)) {
#endif
		pr_debug("Can't get tuple\n");
		return -1;
	}

/* HASH is calcuated using tuple and hash value.
Always, passing init_net as namespace to ensure session is not dependent on namespaces.
Applciable for Veth LOCAL_IN and LOCAL_OUT sessions
Previously 2 sessions were created. Now one session is created for containers */
	*u32_hash = ppa_hash_conntrack_raw(tuple, &init_net);

	return 0;
}

uint32_t ppa_get_hash_from_ct( const PPA_SESSION *ct,
		uint8_t dir,
		PPA_TUPLE* tuple)
{
	return get_hash_from_ct(ct,dir,tuple);
}
EXPORT_SYMBOL(ppa_get_hash_from_ct);

int ppa_get_hash_from_packet( PPA_BUF *ppa_buf,
		unsigned char pf,
		uint32_t *u32_hash,
		PPA_TUPLE* tuple )
{
	return get_hash_from_skb(ppa_buf,pf,u32_hash,tuple);
}
EXPORT_SYMBOL(ppa_get_hash_from_packet);

int  ppa_get_base_mtu(PPA_NETIF *netif)
{
	PPA_NETIF *netif_tmp=NULL;
	PPA_IFNAME underlying_ifname[PPA_IF_NAME_SIZE]={0};
	if( ppa_get_physical_if( netif, NULL, underlying_ifname) == PPA_SUCCESS)  {
		netif_tmp = ppa_get_netif(underlying_ifname);
		if(netif_tmp)
			return (netif_tmp->mtu);
	}

	return netif->mtu;
}

int  ppa_get_mtu(PPA_NETIF *netif)
{
	return netif->mtu;
}

#if defined(CONFIG_PPA_TCP_LITEPATH)
int ppa_do_ip_route(PPA_BUF *skb, PPA_NETIF *netif)
{
	return ip_route_input_noref(skb, ip_hdr(skb)->daddr, ip_hdr(skb)->saddr, ip_hdr(skb)->tos, netif);
}
EXPORT_SYMBOL(ppa_do_ip_route);
#endif

uint32_t cal_64_div(uint64_t t1, uint64_t t2)
{ /* cal the value of t1 divided by t2 */
	if( t1 == 0 ) return 0;
	if( t2 == 0 ) return (uint32_t)-1;

	while( (t1 > WRAPROUND_32BITS) || (t2 > WRAPROUND_32BITS) )
	{
		t2 = t2 >> 1;
		t1 = t1 >> 1;
	}

	if( t1 == 0 ) return 0;
	if( t2 == 0 ) return (uint32_t)-1;

	return (uint32_t)t1/(uint32_t)t2;
}

extern int sysctl_ip_default_ttl;
int32_t ppa_get_ip_ttl_default()
{
	return sysctl_ip_default_ttl;
}


void ppa_si_meminfo(PPA_SYSINFO *sysinfo)
{
	return si_meminfo(sysinfo);
}
#ifndef CONFIG_SWAP
void ppa_si_swapinfo(PPA_SYSINFO *sysinfo)
{
	return si_swapinfo(sysinfo);
}

uint64_t ppa_si_freeram(PPA_SYSINFO *sysinfo)
{
	return sysinfo->freeram;
}
#endif
uint64_t ppa_nfct_counter(PPA_SESSION *ct)
{
	struct nf_conn_counter *counter;
	struct nf_conn_acct *acct = nf_conn_acct_find(ct);
	uint64_t count=0;

	if (acct) {
		counter = acct->counter;
		count = atomic64_read(&counter[IP_CT_DIR_ORIGINAL].bytes);
		count += atomic64_read(&counter[IP_CT_DIR_REPLY].bytes);
	}
	return count;
}

int __init ppa_api_stack_init(void)
{
	pr_debug("PPA Stack Adaptation layer Loaded...\n");
	return 0;
}

void __exit ppa_api_stack_exit(void)
{
	pr_debug("PPA Stack Adaptation layer unloaded...\n");
}

module_init(ppa_api_stack_init);
module_exit(ppa_api_stack_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PPA Stack Adaptation Layer");


EXPORT_SYMBOL(ppa_get_stack_al_id);
EXPORT_SYMBOL(ppa_get_session);
EXPORT_SYMBOL(ppa_get_pkt_ip_proto);
EXPORT_SYMBOL(ppa_get_pkt_ip_tos);
EXPORT_SYMBOL(ppa_get_pkt_src_ip);
EXPORT_SYMBOL(ppa_get_multicast_pkt_ip);
EXPORT_SYMBOL(ppa_get_pkt_ip_len);
EXPORT_SYMBOL(ppa_get_pkt_dst_ip);
EXPORT_SYMBOL(ppa_get_pkt_ip_ttl);
EXPORT_SYMBOL(ppa_get_pkt_ip_string);
EXPORT_SYMBOL(ppa_get_pkt_src_port);
EXPORT_SYMBOL(ppa_get_pkt_dst_port);
EXPORT_SYMBOL(ppa_get_pkt_src_mac_ptr);
EXPORT_SYMBOL(ppa_get_pkt_rx_src_mac_addr);
EXPORT_SYMBOL(ppa_get_src_mac_addr);
EXPORT_SYMBOL(ppa_get_pkt_rx_dst_mac_addr);
EXPORT_SYMBOL(ppa_get_pkt_src_if);
EXPORT_SYMBOL(ppa_get_pkt_dst_if);
#if defined(CONFIG_PPA_HANDLE_CONNTRACK_SESSIONS)
EXPORT_SYMBOL(ppa_get_low_prio_thresh);
EXPORT_SYMBOL(ppa_get_def_prio_thresh);
EXPORT_SYMBOL(ppa_get_low_prio_data_rate);
EXPORT_SYMBOL(ppa_get_def_prio_data_rate);
EXPORT_SYMBOL(ppa_timespec_to_ns);
EXPORT_SYMBOL(ppa_get_monotonic);
EXPORT_SYMBOL(ppa_timespec_sub);
EXPORT_SYMBOL(ppa_get_session_priority);
EXPORT_SYMBOL(ppa_get_session_limit_enable);
EXPORT_SYMBOL(ppa_get_tcp_steady_offset);
EXPORT_SYMBOL(ppa_get_tcp_initial_offset);
#endif

EXPORT_SYMBOL(ppa_pppoe_get_physical_if);
EXPORT_SYMBOL(ppa_pppol2tp_get_physical_if);
EXPORT_SYMBOL(ppa_check_is_ppp_netif);
EXPORT_SYMBOL(ppa_check_is_pppoe_netif);
EXPORT_SYMBOL(ppa_pppoe_get_dst_mac);
EXPORT_SYMBOL(ppa_check_is_pppol2tp_netif);
EXPORT_SYMBOL(ppa_pppol2tp_get_dst_mac);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
EXPORT_SYMBOL(ppa_dev_is_br);
#endif

EXPORT_SYMBOL(ppa_get_dst_mac);
EXPORT_SYMBOL(ppa_get_netif);
EXPORT_SYMBOL(ppa_get_netif_ifindex);
EXPORT_SYMBOL(ppa_get_netif_by_net);
EXPORT_SYMBOL(ppa_get_base_mtu);
EXPORT_SYMBOL(ppa_get_mtu);
EXPORT_SYMBOL(ppa_put_netif);
EXPORT_SYMBOL(ppa_get_netif_hwaddr);
EXPORT_SYMBOL(ppa_get_br_dev);
EXPORT_SYMBOL(ppa_get_physical_if);
EXPORT_SYMBOL(ppa_if_is_vlan_if);
EXPORT_SYMBOL(ppa_is_macvlan_if);
EXPORT_SYMBOL(ppa_vlan_get_underlying_if);
EXPORT_SYMBOL(ppa_vlan_get_physical_if);
EXPORT_SYMBOL(ppa_get_vlan_id);
EXPORT_SYMBOL(ppa_get_vlan_type);
EXPORT_SYMBOL(ppa_get_vlan_tag);
EXPORT_SYMBOL(ppa_is_bond_slave);
EXPORT_SYMBOL(ppa_get_bridge_member_ifs);
EXPORT_SYMBOL(ppa_if_is_br_if);
EXPORT_SYMBOL(ppa_if_is_veth_if);
EXPORT_SYMBOL(ppa_dev_is_loopback);
EXPORT_SYMBOL(ppa_get_current_net_ns);
EXPORT_SYMBOL(ppa_get_netif_ip);
#if IS_ENABLED(CONFIG_PPA_RT_SESS_LEARNING)
EXPORT_SYMBOL(ppa_get_br_dst_port);
EXPORT_SYMBOL(ppa_get_br_dst_port_with_mac);
#endif
EXPORT_SYMBOL(ppa_br2684_get_vcc);
EXPORT_SYMBOL(ppa_if_is_br2684);
EXPORT_SYMBOL(ppa_if_is_veth);
EXPORT_SYMBOL(ppa_if_is_ipoa);
EXPORT_SYMBOL(ppa_is_session_equal);
EXPORT_SYMBOL(ppa_get_session_helper);
EXPORT_SYMBOL(ppa_check_is_special_session);
EXPORT_SYMBOL(ppa_is_pkt_fragment);
EXPORT_SYMBOL(ppa_get_pkt_mac_string);
EXPORT_SYMBOL(ppa_is_pkt_multicast);

EXPORT_SYMBOL(ppa_nfct_counter);
EXPORT_SYMBOL(ppa_lock_init);
EXPORT_SYMBOL(ppa_lock_get);
EXPORT_SYMBOL(ppa_lock_release);
EXPORT_SYMBOL(ppa_lock_get2);
EXPORT_SYMBOL(ppa_lock_release2);
EXPORT_SYMBOL(ppa_lock_destroy);
EXPORT_SYMBOL(ppa_disable_int);
EXPORT_SYMBOL(ppa_enable_int);
EXPORT_SYMBOL(ppa_malloc);
EXPORT_SYMBOL(ppa_free);
EXPORT_SYMBOL(ppa_mem_cache_create);
EXPORT_SYMBOL(ppa_mem_cache_destroy);
EXPORT_SYMBOL(ppa_mem_cache_alloc);
EXPORT_SYMBOL(ppa_mem_cache_free);
EXPORT_SYMBOL(ppa_kmem_cache_shrink);
EXPORT_SYMBOL(ppa_memcpy);
EXPORT_SYMBOL(ppa_memset);
EXPORT_SYMBOL(ppa_memcmp);
EXPORT_SYMBOL(ppa_get_time_in_sec);
EXPORT_SYMBOL(ppa_kthread_create);
EXPORT_SYMBOL(ppa_kthread_should_stop);
EXPORT_SYMBOL(ppa_kthread_stop);
EXPORT_SYMBOL(ppa_wake_up_process);
EXPORT_SYMBOL(ppa_schedule);
EXPORT_SYMBOL(ppa_set_current_state);
EXPORT_SYMBOL(ppa_netdev_master_upper_dev_get);
EXPORT_SYMBOL(ppa_rtnl_lock);
EXPORT_SYMBOL(ppa_rtnl_unlock);
EXPORT_SYMBOL(ppa_atomic_read);
EXPORT_SYMBOL(ppa_atomic_set);
EXPORT_SYMBOL(ppa_atomic_inc);
EXPORT_SYMBOL(ppa_atomic_dec);
EXPORT_SYMBOL(ppa_atomic_inc_not_zero);
EXPORT_SYMBOL(ppa_hlist_replace);
EXPORT_SYMBOL(ppa_buf_clone);
EXPORT_SYMBOL(ppa_buf_cloned);
EXPORT_SYMBOL(ppa_buf_get_prev);
EXPORT_SYMBOL(ppa_buf_get_next);
EXPORT_SYMBOL(ppa_buf_free);
EXPORT_SYMBOL(ppa_copy_from_user);
EXPORT_SYMBOL(ppa_copy_to_user);
EXPORT_SYMBOL(ppa_strncpy);
EXPORT_SYMBOL(ppa_str_cmp);
#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
EXPORT_SYMBOL(ppa_is_ipv4_ipv6);
EXPORT_SYMBOL(ppa_ipsec_addr_equal);
#endif
EXPORT_SYMBOL(ppa_register_netdev);
EXPORT_SYMBOL(ppa_unregister_netdev);
EXPORT_SYMBOL(ppa_register_chrdev);
EXPORT_SYMBOL(ppa_unregister_chrdev);
EXPORT_SYMBOL(ppa_sprintf);
EXPORT_SYMBOL(ppa_snprintf);
EXPORT_SYMBOL(ppa_ioc_type);
EXPORT_SYMBOL(ppa_ioc_nr);
EXPORT_SYMBOL(ppa_ioc_read);
EXPORT_SYMBOL(ppa_ioc_write);
EXPORT_SYMBOL(ppa_ioc_size);
EXPORT_SYMBOL(ppa_ioc_access_ok);
EXPORT_SYMBOL(ppa_ioc_dir);
EXPORT_SYMBOL(ppa_ioc_verify_read);
EXPORT_SYMBOL(ppa_ioc_verify_write);
EXPORT_SYMBOL(ppa_vlan_dev_get_egress_qos_mask);
EXPORT_SYMBOL(g_ppa_dbg_enable);
EXPORT_SYMBOL(max_print_num);
EXPORT_SYMBOL(cal_64_div);
EXPORT_SYMBOL(ppa_get_ip_ttl_default);

EXPORT_SYMBOL(ppa_si_meminfo);
#ifndef CONFIG_SWAP
EXPORT_SYMBOL(ppa_si_swapinfo);
EXPORT_SYMBOL(ppa_si_freeram);
#endif
EXPORT_SYMBOL(ppa_bypass_lro);
