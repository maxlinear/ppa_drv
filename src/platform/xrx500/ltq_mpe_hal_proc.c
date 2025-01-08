/*******************************************************************************
 **
 ** FILE NAME	: ltq_mpe_hal_proc.c
 ** PROJECT	: MPE HAL
 ** MODULES	: MPE (Routing/Bridging Acceleration )
 **
 ** DATE 	: 20 Mar 2014
 ** AUTHOR	: Purnendu Ghosh
 ** DESCRIPTION	: MPE HAL Layer
 ** COPYRIGHT	: Copyright © 2020-2021 MaxLinear, Inc.		
 **               Copyright (c) 2009
 **	          Lantiq Deutschland GmbH
 **		  Am Campeon 3; 85579 Neubiberg, Germany
 **
 **	 For licensing information, see the file 'LICENSE' in the root folder of
 **	 this software module.
 **
 ** HISTORY
 ** $Date		$Author				$Comment
 ** 20 Mar 2014		Purnendu Ghosh		 Initiate Version
 *******************************************************************************/

/*			
 *	Common Header File
 */
//#include <linux/autoconf.h>
#include <linux/version.h>
#include <generated/autoconf.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <linux/firmware.h>
#include <linux/platform_device.h>
#include <lantiq.h>
#include <lantiq_soc.h>
#include <linux/clk.h>
#include <net/ip_tunnels.h>
#include <linux/if_arp.h>
#include <linux/in.h>
#include <asm/uaccess.h>
#include <net/ip6_tunnel.h>
#include <net/ipv6.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

/*
 *	Chip Specific Head File
 */
#include <net/ppa/ppa_api.h>
#include <net/ppa/ppa_hal_api.h>
#include <net/ppa/ppa_drv_wrapper.h>
#include "ltq_mpe_api.h"
#include "ltq_mpe_hal.h"
#include "mpe_fw_be.h"
#include <asm/ltq_vmb.h>

#define PARAM_NUM 5
#define MPE_ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define set_ltq_mpe_dbg_flag(v, e, f) do {;\
		if (e > 0)\
				v |= (uint32_t)(f);\
		else\
				v &= (uint32_t) (~f); } \
		while (0)

uint32_t mpe_dbg_flag = 0;
uint32_t g_mpeh_dbg_enable = 0;

static struct proc_dir_entry *ppa_mpe_proc_dir;
static struct dentry *dbgfs_ppa_mpe;
#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
static struct dentry *dbgfs_ppa_mpe_ipsec;
#endif

char *mpe_dbg_flag_str[] = {
	"enable_debug",		/* to align with MPE FW misc.h enum */
	"enable_error",
	"enable_assert",
	"dbg_tm",
	"wk_rx_data", /* DUMP_RX_DATA */
	"wk_accel", /* DBG_WK_ACCEL */
	"wk_mcast", /* DBG_WK_MCAST */
	"wk_parser", /* DBG_WK_PARSER */	
	"wk_tx_data", /* DUMP_TX_DATA */
	"wk_tx_desc", /* DUMP_TX_DESCRIPTOR */
	"wk_tx_pmac", /* DUMP_TX_PMAC */
	"dummy_4",
};

/*
* ####################################
*             Declaration
* ####################################
*/

static int proc_read_genconf_seq_open(struct inode *, struct file *);
static int proc_read_tc_full_dbg_seq_open(struct inode *, struct file *);

static int proc_read_fwHdr_seq_open(struct inode *inode, struct file *file);

static int proc_read_tc_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_tc(struct file *file, const char __user *buf, size_t count, loff_t *data);

static int proc_read_hw_res_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_hw_res(struct file *file, const char __user *buf, size_t count, loff_t *data);


static int proc_read_session_mib_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_session_mib(struct file *file, const char __user *buf, size_t count, loff_t *data);


static int proc_read_tc_mib_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_tc_mib(struct file *file, const char __user *buf, size_t count, loff_t *data);


static int proc_read_itf_mib_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_itf_mib(struct file *file, const char __user *buf, size_t count, loff_t *data);


static int proc_read_hit_mib_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_hit_mib(struct file *file, const char __user *buf, size_t count, loff_t *data);

static int proc_read_fw_dbg_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_fw_dbg(struct file *file, const char __user *buf, size_t count, loff_t *data);


static int proc_read_ipv4_sessions_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_ipv4_sessions(struct file *file, const char __user *buf, size_t count, loff_t *data);


static int proc_read_ipv6_sessions_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_ipv6_sessions(struct file *file, const char __user *buf, size_t count, loff_t *data);


static int proc_read_test_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_test(struct file *file, const char __user *buf, size_t count, loff_t *data);


static int proc_read_session_action_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_session_action(struct file *file, const char __user *buf, size_t count, loff_t *data);

static int proc_read_accel_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_accel(struct file *file, const char __user *buf, size_t count, loff_t *data);

static int proc_read_fw_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_fw(struct file *file, const char __user *buf, size_t count, loff_t *data);

static int proc_read_multicast_vap_list_seq_open(struct inode *inode, struct file *file);

static int proc_read_dbg(struct seq_file *, void *);
static ssize_t proc_write_dbg(struct file *, const char __user *, size_t, loff_t *);
static int proc_read_dbg_seq_open(struct inode *, struct file *);


#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
static int proc_read_tunnel_info_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_tunnel_info(struct file *file, const char __user *buf, size_t count, loff_t *data);

static int proc_read_xfrm_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_xfrm(struct file *file, const char __user *buf, size_t count, loff_t *data);

static int proc_read_eip97_seq_open(struct inode *inode, struct file *file);
static ssize_t proc_write_eip97(struct file *file, const char __user *buf, size_t count, loff_t *data);
#endif
static int proc_read_version_seq_open(struct inode *inode, struct file *file);

static int proc_read_session_count_seq_open(struct inode *inode, struct file *file);

extern void mpe_hal_dump_fw_header(struct seq_file *seq);
extern void mpe_hal_dump_genconf_offset(struct seq_file *seq);
extern void mpe_hal_dump_tc_hw_res_all(void); 
extern int32_t mpe_hal_pause_tc(uint8_t ucCpu, uint8_t ucTc);
extern int32_t	mpe_hal_resume_tc(uint8_t ucCpu, uint8_t ucTc);
extern int32_t	mpe_hal_add_tc(uint8_t ucCpu, uint32_t tc_type);
extern int32_t	mpe_hal_delete_tc(uint8_t ucCpu, uint8_t ucTc);
extern void mpe_hal_dump_session_mib_cntr(struct seq_file *seq);
extern void mpe_hal_dump_tc_mib(struct seq_file *seq);
extern void mpe_hal_clear_tc_mib(void);
extern void mpe_hal_debug_cfg(uint32_t ucDbg);
extern void mpe_hal_dump_itf_mib_cntr(struct seq_file *seq);
extern void mpe_hal_dump_hit_mib(struct seq_file *seq);
extern void mpe_hal_clear_hit_mib(void);
extern void mpe_hal_clear_tc_mib(void);
extern void mpe_hal_clear_session_mib(void);
extern void mpe_hal_clear_itf_mib(void);
extern void mpe_hal_dump_ipv4_cmp_table_entry(struct seq_file *seq);
extern void mpe_hal_dump_ipv6_cmp_table_entry(struct seq_file *seq);
extern void mpe_hal_dump_mpe_detailed_dbg(struct seq_file *seq);
extern void mpe_hal_test(uint32_t testcase);
extern void mpe_hal_display_session_action(uint32_t tbl, uint32_t current_ptr);
extern void mpe_hal_config_accl_mode(uint32_t mode);
extern void mpe_hal_config_vap_qos(uint32_t enable);
extern int32_t mpe_hal_fw_load(void);
extern int32_t mpe_hal_fw_unload(void);
extern void dump_mpe_version(struct seq_file *seq);
extern void mpe_session_count(struct seq_file *seq);
extern void mpe_hal_dump_vap_list(struct seq_file *seq);

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
extern int32_t mpe_hal_dump_ipsec_tunnel_info(int32_t tun_id);
extern int32_t mpe_hal_dump_ipsec_xfrm_sa(uint32_t tunnel_index);
extern int32_t mpe_hal_dump_ipsec_eip97_params(int32_t tunnel_index);
#endif
extern uint32_t g_MPE_accl_mode;
extern uint32_t g_vap_qos_support;
extern bool g_MPE_mc_accl_mode;

void remove_leading_whitespace(char **p, int *len)
{
	while (*len && ((**p == ' ') || (**p == '\r') || (**p == '\r'))) {
		(*p)++;
		(*len)--;
	}
}


int ltq_split_buffer(char *buffer, char *array[], int max_param_num)
{
	int i, set_copy = 0;
	int res = 0;
	int len;

	for (i = 0; i < max_param_num; i++)
		array[i] = NULL;
	if (!buffer)
		return 0;
	len = strlen(buffer);
	for (i = 0; i < max_param_num;) {
		remove_leading_whitespace(&buffer, &len);
		for (;
			 *buffer != ' ' && *buffer != '\0' && *buffer != '\r'
			 && *buffer != '\n' && *buffer != '\t'; buffer++, len--) {
			/*Find first valid charactor */
			set_copy = 1;
			if (!array[i])
				array[i] = buffer;
		}

		if (set_copy == 1) {
			i++;
			if (*buffer == '\0' || *buffer == '\r'
				|| *buffer == '\n') {
				*buffer = 0;
				break;
			}
			*buffer = 0;
			buffer++;
			len--;
			set_copy = 0;

		} else {
			if (*buffer == '\0' || *buffer == '\r'
				|| *buffer == '\n')
				break;
			buffer++;
			len--;
		}
	}
	res = i;

	return res;
}


static int strincmp(const char *p1, const char *p2, int n)
{
	int c1 = 0, c2;

	while ( n && *p1 && *p2 )
	{
		c1 = *p1 >= 'A' && *p1 <= 'Z' ? *p1 + 'a' - 'A' : *p1;
		c2 = *p2 >= 'A' && *p2 <= 'Z' ? *p2 + 'a' - 'A' : *p2;
		if ( (c1 -= c2) )
			return c1;
		p1++;
		p2++;
		n--;
	}

	return n ? *p1 - *p2 : c1;
}


int Atoi(char *str)
{
	int res = 0;	/* Initialize result*/
	int sign = 1;	/* Initialize sign as positive */
	int i = 0;	/* Initialize index of first digit */

	/* If number is negative, then update sign */
	if (str[0] == '-') {
		sign = -1;
		i++;	/* Also update index of first digit*/
	}

	/* Iterate through all digits and update the result */
	for (; str[i] != '\0'; ++i)
		res = res*10 + str[i] - '0';

	/* Return result with sign */
	return sign*res;
}

int return_val( char *p, char *str)
{
	char *temp;
	char buf[30];
	snprintf(buf, sizeof(buf), "%s", p);

	if ((temp =strstr(buf, str)) != NULL ){
		while(*temp != ' ' && *temp ) {
			temp++;
		}
		str = ++temp;
		while(*temp != ' ' && *temp ) {
			temp++;
		}

		*temp = '\0';
	}
	return Atoi(str);
}

char * return_string( char *buf, char *str)
{
	char *temp;

	if ((temp =strstr(buf, str)) != NULL ){
		while(*temp != ' ' && *temp ) {
			temp++;
		}
		str = ++temp;
		while(*temp != ' ' && *temp ) {
			temp++;
		}

		*temp = '\0';
	}
	return str ;
}


/* Proc function for /proc/ppa/mpe/genconf */
static const struct file_operations dbgfs_file_genconf_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_genconf_seq_open,
	.read		= seq_read,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_genconf(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	mpe_hal_dump_genconf_offset( seq );
	return 0;
}

static int proc_read_genconf_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_genconf, NULL);
}

/* Proc function for /proc/ppa/mpe/fwHdr */
static const struct file_operations dbgfs_file_fwHdr_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_fwHdr_seq_open,
	.read		= seq_read,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_fwHdr(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	mpe_hal_dump_fw_header( seq );
	return 0;
}

static int proc_read_fwHdr_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_fwHdr, NULL);
}


/* Proc function for /proc/ppa/mpe/tc */
static const struct file_operations dbgfs_file_tc_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_tc_seq_open,
	.read		= seq_read,
	.write		= proc_write_tc,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_tc(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	seq_printf(seq, "echo start <vpe-no> <tc-type> > /proc/ppa/mpe/tc\n");
	seq_printf(seq, "echo stop/pause/resume <vpe-no> <tc-no> > /proc/ppa/mpe/tc\n");
	return 0;
}

static ssize_t proc_write_tc(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len, num=0, vpe_num=0, tcNum=0;
	char str[50];
	char *p;
	char *param_list[PARAM_NUM] = { 0 };

	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if ( strstr(p, "help")) {
		printk( "echo start <vpe-no> <tc-type> > /proc/ppa/mpe/tc\n");
		printk( "echo stop/pause/resume <vpe-no> <tc-no> > /proc/ppa/mpe/tc\n");
		return count;
	} else {
		num = ltq_split_buffer(p, param_list, PARAM_NUM);

		if (strincmp(param_list[0], "start", 5) == 0) {
			vpe_num = Atoi(param_list[1]);
			if(param_list[2] && !strincmp(param_list[2], "DL", 2))
				mpe_hal_add_tc(vpe_num,TYPE_DIRECTLINK);
			else
				mpe_hal_add_tc(vpe_num,TYPE_WORKER);
		} else if ((strincmp(param_list[0], "stop", 4) == 0) && param_list[1] && param_list[2]) {
			vpe_num = Atoi(param_list[1]);
			tcNum = Atoi(param_list[2]);
			mpe_hal_delete_tc(vpe_num,tcNum);
		} else if ((strincmp(param_list[0], "pause", 5) == 0) && param_list[1] && param_list[2]) {
			vpe_num = Atoi(param_list[1]);
			tcNum = Atoi(param_list[2]);
			mpe_hal_pause_tc(vpe_num, tcNum);
		} else if ((strincmp(param_list[0], "resume", 6) == 0) && param_list[1] && param_list[2]) {
			vpe_num = Atoi(param_list[1]);
			tcNum = Atoi(param_list[2]);
			mpe_hal_resume_tc(vpe_num,tcNum);
		} else {
			printk("Wrong Parameter : try \n");
			printk("echo help > /proc/ppa/mpe/tc\n");
			printk("echo start/stop/pause/resume cpu_num <opt: DL> <opt: TC number> > /proc/ppa/mpe/tc\n");
		}

	}

	return count;

}

static int proc_read_tc_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_tc, NULL);
}

/* Proc function for /proc/ppa/mpe/hw_res */
static const struct file_operations dbgfs_file_hw_res_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_hw_res_seq_open,
	.read		= seq_read,
	.write		= proc_write_hw_res,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_hw_res(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	seq_printf(seq, "Specific TC:\n\techo <tc-no> > /proc/ppa/mpe/hw_res\n");
	seq_printf(seq, "All TC:\n\techo -1 > /proc/ppa/mpe/hw_res\n");
	return 0;
}

static ssize_t proc_write_hw_res(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if ( strstr(p, "help")) {
		printk("echo <tc-num>/-1(for all TC) > /proc/ppa/mpe/tc\n");
		return count;

	} else {
		int32_t tc = Atoi(p);
		printk("tc= %d\n", tc);
		if (tc == -1 ) {
			mpe_hal_dump_tc_hw_res_all();			
		}
	}
	return count ;
}

static int proc_read_hw_res_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_hw_res, NULL);
}

/* Proc function for /proc/ppa/mpe/session_mib */
static const struct file_operations dbgfs_file_session_mib_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_session_mib_seq_open,
	.read		= seq_read,
	.write		= proc_write_session_mib,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_session_mib(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	/*	int test = 20;
	seq_printf(seq, "Specific TC:\n\techo <tc-no> > /proc/ppa/mpe/hw_res\n");
	seq_printf(seq, "All TC:\n\techo -1 > /proc/ppa/mpe/hw_res\n");*/
	mpe_hal_dump_session_mib_cntr(seq); 
	return 0;
}


static ssize_t proc_write_session_mib(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if ( strstr(p, "help")) {
		printk("echo <tc-num> > /proc/ppa/mpe/session_mib\n");
		return count;

	} else {
		printk("cmd=%s\n", p);
		mpe_hal_clear_session_mib();
	}
	return count ;
}


static int proc_read_session_mib_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_session_mib, NULL);
}

/* Proc function for /proc/ppa/mpe/tc_mib */
static const struct file_operations dbgfs_file_tc_mib_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_tc_mib_seq_open,
	.read		= seq_read,
	.write		= proc_write_tc_mib,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};


static int proc_read_tc_mib(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	/*	int test = 20;
	seq_printf(seq, "Specific TC:\n\techo <tc-no> > /proc/ppa/mpe/hw_res\n");
	seq_printf(seq, "All TC:\n\techo -1 > /proc/ppa/mpe/hw_res\n");*/
	mpe_hal_dump_tc_mib(seq);
	return 0;
}


static ssize_t proc_write_tc_mib(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}

	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if ( strstr(p, "help")) {
		printk("echo clear > /proc/ppa/mpe/tc_mib\n");
		return count;

	} else {
		printk("p=%s\n", p);
		mpe_hal_clear_tc_mib();	
	}
	return count ;
}


static int proc_read_tc_mib_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_tc_mib, NULL);
}

/* Proc function for /proc/ppa/mpe/itf_mib */
static const struct file_operations dbgfs_file_itf_mib_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_itf_mib_seq_open,
	.read		= seq_read,
	.write		= proc_write_itf_mib,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};


static int proc_read_itf_mib(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	mpe_hal_dump_itf_mib_cntr(seq);
	return 0;
}

static ssize_t proc_write_itf_mib(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if ( strstr(p, "help")) {
		printk("echo clear > /proc/ppa/mpe/itf_mib\n");
		return count;

	} else {
		printk("cmd=%s\n", p);
		mpe_hal_clear_itf_mib();
	}
	return count ;
}

static int proc_read_itf_mib_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_itf_mib, NULL);
}


/* Proc function for /proc/ppa/mpe/hit_mib */
static const struct file_operations dbgfs_file_hit_mib_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_hit_mib_seq_open,
	.read		= seq_read,
	.write		= proc_write_hit_mib,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_hit_mib(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	mpe_hal_dump_hit_mib(seq);
	return 0;
}


static ssize_t proc_write_hit_mib(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if ( strstr(p, "help")) {
		printk("echo clear > /proc/ppa/mpe/hit_mib\n");
		return count;

	} else {
		printk("cmd=%s\n", p);
		mpe_hal_clear_hit_mib();
	}
	return count ;
}


static int proc_read_hit_mib_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_hit_mib, NULL);
}


/* Proc function for /proc/ppa/mpe/IPv4_sessions */
static const struct file_operations dbgfs_file_ipv4_sessions_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_ipv4_sessions_seq_open,
	.read		= seq_read,
	.write		= proc_write_ipv4_sessions,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_ipv4_sessions(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	mpe_hal_dump_ipv4_cmp_table_entry(seq);
	return 0;
}

static ssize_t proc_write_ipv4_sessions(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if ( strstr(p, "help")) {
		printk("echo clear > /proc/ppa/mpe/IPv4_sessions\n");
		return count;

	} else {
		printk("p=%s\n", p);
	}
	return count ;
}

static int proc_read_ipv4_sessions_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_ipv4_sessions, NULL);
}


/* Proc function for /proc/ppa/mpe/IPv6_sessions */
static const struct file_operations dbgfs_file_ipv6_sessions_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_ipv6_sessions_seq_open,
	.read		= seq_read,
	.write		= proc_write_ipv6_sessions,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_ipv6_sessions(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	mpe_hal_dump_ipv6_cmp_table_entry( seq );
	return 0;
}

static ssize_t proc_write_ipv6_sessions(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if ( strstr(p, "help")) {
		printk("echo clear > /proc/ppa/mpe/IPv6_sessions\n");
		return count;

	} else {
		printk("p=%s\n", p);
	}
	return count ;
}

static int proc_read_ipv6_sessions_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_ipv6_sessions, NULL);
}

/* Proc function for /proc/ppa/mpe/fw_dbg */
static const struct file_operations dbgfs_file_fw_dbg_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_fw_dbg_seq_open,
	.read		= seq_read,
	.write		= proc_write_fw_dbg,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int proc_read_fw_dbg(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	seq_printf(seq, "echo enable/disable > /proc/ppa/mpe/fw_dbg\n");
	return 0;
}

static ssize_t proc_write_fw_dbg(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;
	char *param_list[20];
	int f_enable, i, j, num;

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;


	if ( strstr(p, "help")) {
		printk("echo enable/disable > /proc/ppa/mpe/fw_dbg\n");
		return count;

	} else {
		printk("p=%s\n", p);

		num = ltq_split_buffer(p, param_list, MPE_ARRAY_SIZE(param_list));

		if (strincmp(param_list[0], "enable", 6) == 0)
			f_enable = 1;
		else if (strincmp(param_list[0], "disable", 7) == 0)
			f_enable = -1;
		else {
			printk("echo <enable/disable> ");
			for (i = 0; i < MPE_ARRAY_SIZE(mpe_dbg_flag_str); i++)
				printk("%s ", mpe_dbg_flag_str[i]);
			printk(" > /proc/mpe/cfg_mpe_dbg\n");
			return count;	
		}

		if (!param_list[1]) {	 /*no parameter after enable or disable: set/clear all debug flags */
			set_ltq_mpe_dbg_flag(mpe_dbg_flag, f_enable, -1);
		} else {
			for (i = 1; i < num; i++) {
				for (j = 0; j < MPE_ARRAY_SIZE(mpe_dbg_flag_str); j++)
					if (strincmp(param_list[i], mpe_dbg_flag_str[j], strlen(param_list[i])) == 0) {
						set_ltq_mpe_dbg_flag(mpe_dbg_flag,	f_enable, (1 << j));
						break;
					}
			}
		}

	}
	printk("<-------- mpe_dbg_flag = %d\n",mpe_dbg_flag);
	mpe_hal_debug_cfg(mpe_dbg_flag );
	return count ;
}


static int proc_read_fw_dbg_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_fw_dbg, NULL);
}


/* Proc function for /proc/ppa/mpe/tc_full_dbg */
static const struct file_operations dbgfs_file_tc_full_dbg_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_tc_full_dbg_seq_open,
	.read		= seq_read,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_tc_full_dbg(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	mpe_hal_dump_mpe_detailed_dbg(seq);
	return 0;
}

static int proc_read_tc_full_dbg_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_tc_full_dbg, NULL);
}

/* Proc function for /proc/ppa/mpe/test */
static const struct file_operations dbgfs_file_test_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_test_seq_open,
	.read		= seq_read,
	.write		= proc_write_test,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_test(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	seq_printf(seq, "echo <val> > /proc/ppa/mpe/test");
	return 0;
}


static ssize_t proc_write_test(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if ( strstr(p, "help")) {
		printk("echo clear > /proc/ppa/mpe/IPv6_sessions\n");
		return count;

	} else {
		int32_t val=0 ;
		val = Atoi(p);
		printk("p=%s, val=%d\n", p, val);
		mpe_hal_test(val);
	}
	return count ;
}


static int proc_read_test_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_test, NULL);
}

/* Proc function for /proc/ppa/mpe/session_action */
static const struct file_operations dbgfs_file_session_action_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_session_action_seq_open,
	.read		= seq_read,
	.write		= proc_write_session_action,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_session_action(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	seq_printf(seq, "echo <Tbl typ> <idx> > /proc/ppa/mpe/session_action\n");
	seq_printf(seq, "Tbl typ:\n\t1 - IPv4 Table\n\t2 - IPv6 Table\n\t3 - Hardware Action Table\n");
	return 0;
}


static ssize_t proc_write_session_action(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;
	char *param_list[PARAM_NUM] = { 0 };

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if ( strstr(p, "help")) {
		printk("echo <table type> <idx> > /proc/ppa/mpe/session_action\n");
		return count;

	} else {
		int32_t idx=0 , tbl=0, num=0;
		num = ltq_split_buffer(p, param_list, MPE_ARRAY_SIZE(param_list));
		if (num != 2) {
			printk("echo <table type> <idx> > /proc/ppa/mpe/session_action\n");
			return count;
		}
		idx = Atoi(param_list[1]);
		tbl = Atoi(param_list[0]);
		printk("p=%s, idx=%d tbl=%d\n", p, idx, tbl);
		mpe_hal_display_session_action(tbl, idx);
	}
	return count ;
}

static int proc_read_session_action_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_session_action, NULL);
}

static int proc_read_vap_qos(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	if (g_vap_qos_support) {
		seq_printf(seq, "MPE VAP QoS Support : enable\n");
	} else {
		seq_printf(seq, "MPE VAP QoS Support : disable\n");
	}
	return 0;
}

static int proc_read_vap_qos_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_vap_qos, NULL);
}

static ssize_t proc_write_vap_qos(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;
	char *param_list[PARAM_NUM] = { 0 };

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;


	if ( strstr(p, "help")) {
		printk("echo <enable/disable> > /proc/ppa/mpe/vap_qos\n");
		return count;
	} else {
		int32_t num=0, f_enable=0;
		num = ltq_split_buffer(p, param_list, MPE_ARRAY_SIZE(param_list));
		if (num == 1) {
			if (strincmp(param_list[0], "enable", 6) == 0)
				f_enable = 1;
			else if (strincmp(param_list[0], "disable", 7) == 0)
				f_enable = 0;
			else {
				printk("echo <enable/disable> /proc/ppa/mpe/vap_qos\n");
				return count;
			}
			mpe_hal_config_vap_qos(f_enable);

		} else {
			printk("echo help > /proc/ppa/mpe/vap_qos\n");
		}
	}
	return count ;
}

/* Proc function for /proc/ppa/mpe/vap_qos */
static const struct file_operations dbgfs_file_vap_qos_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_vap_qos_seq_open,
	.read		= seq_read,
	.write		= proc_write_vap_qos,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

/* Proc function for /proc/ppa/mpe/accel */
static const struct file_operations dbgfs_file_accel_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_accel_seq_open,
	.read		= seq_read,
	.write		= proc_write_accel,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_accel(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	if (g_MPE_accl_mode) {
		seq_printf(seq, "MPE accel : enable\n");
		if (g_MPE_mc_accl_mode)
			seq_printf(seq, "MPE mc accel : enable\n");
		else
			seq_printf(seq, "MPE mc accel : disable\n");
	} else {
		seq_printf(seq, "MPE accel : disable\n");
	}
	return 0;
}


static ssize_t proc_write_accel(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;
	char *param_list[PARAM_NUM] = { 0 };

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;


	if ( strstr(p, "help")) {
		printk("echo <enable/disable> [mc] > /proc/ppa/mpe/accel\n");
		printk("echo <start/stop> > /proc/ppa/mpe/accel\n");
		return count;

	} else {
		int32_t num=0, f_enable=0;
		num = ltq_split_buffer(p, param_list, MPE_ARRAY_SIZE(param_list));
		if (num == 2) {
			if (strincmp(param_list[1], "mc", 2) == 0) {
				if (strincmp(param_list[0], "enable", 6) == 0)
					g_MPE_mc_accl_mode = true;
				else if (strincmp(param_list[0], "disable", 7) == 0)
					g_MPE_mc_accl_mode = false;
			}

		} else if (num == 1) {
			if (strincmp(param_list[0], "enable", 6) == 0)
				f_enable = 1;
			else if (strincmp(param_list[0], "disable", 7) == 0)
				f_enable = 0;
			else if (strincmp(param_list[0], "start", 5) == 0)
				f_enable = 2;
			else if (strincmp(param_list[0], "stop", 4) == 0)
				f_enable = 3;
			else {
				printk("echo <enable/disable/start/stop> /proc/ppa/mpe/accel\n");
				return count;
			}
			mpe_hal_config_accl_mode(f_enable);

		} else {
			printk("echo help > /proc/ppa/mpe/accel\n");
		}
	}
	return count ;
}

static int proc_read_accel_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_accel, NULL);
}

/* Proc function for /proc/ppa/mpe/fw */
static const struct file_operations dbgfs_file_fw_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_fw_seq_open,
	.read		= seq_read,
	.write		= proc_write_fw,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_fw(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	seq_printf(seq, "echo <load/unload> > /proc/ppa/mpe/fw\n");
	return 0;
}

static ssize_t proc_write_fw(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;
	char *param_list[PARAM_NUM] = { 0 };

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;


	if ( strstr(p, "help")) {
		printk("echo <load/unload> > /proc/ppa/mpe/fw\n");
		return count;

	} else {
		int32_t num=0 ;
		num = ltq_split_buffer(p, param_list, MPE_ARRAY_SIZE(param_list));
		if (num == 1) {
			if (strincmp(param_list[0], "load", 4) == 0)
				mpe_hal_fw_load();
			else if (strincmp(param_list[0], "unload", 6) == 0)
				mpe_hal_fw_unload();
			else {
				printk("echo <load/unload> > /proc/ppa/mpe/fw\n");
				return count;
			}
		} else {
			printk("echo help > /proc/ppa/mpe/fw\n");
		}
	}
	return count ;
}


static int proc_read_fw_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_fw, NULL);
}

/* Proc function for /proc/ppa/mpe/multicast_vap_list */
static const struct file_operations dbgfs_file_multicast_vap_list_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_multicast_vap_list_seq_open,
	.read		= seq_read,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};


static int proc_read_multicast_vap_list(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	mpe_hal_dump_vap_list(seq);
	return 0;
}

static int proc_read_multicast_vap_list_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_multicast_vap_list, NULL);
}

/* Proc function for /proc/ppa/mpe/dbg */
static const struct file_operations dbgfs_file_dbg_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_dbg_seq_open,
	.read		= seq_read,
	.write		= proc_write_dbg,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int proc_read_dbg_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_dbg, NULL);
}

struct ppa_dbg_info
{
	char *cmd;
	char *description;
	uint32_t flag;
};

static struct ppa_dbg_info dbg_enable_mask_str[] = {
	{"err",		"error print",		DBG_ENABLE_MASK_ERR },
	{"dbg",		"debug print",		DBG_ENABLE_MASK_DEBUG_PRINT},
	/*the last one */
	{"all",		"enable all debug",		-1}
};

static int proc_read_dbg(struct seq_file *seq, void *v)
{
	int i;

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}

	for (i = 0; i < NUM_ENTITY(dbg_enable_mask_str) - 1; ++i) {
		seq_printf(seq, "%-10s(%s) :	%-5s\n",
			dbg_enable_mask_str[i].cmd,
				dbg_enable_mask_str[i].description,
				(g_mpeh_dbg_enable & dbg_enable_mask_str[i].flag)
						? "enabled" : "disabled");
	}

	return 0;
}

static ssize_t proc_write_dbg(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	int len, i;
	char str[64];
	char *p;

	int f_enable = 0;

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
	if (!*p)
		return count;

	if (strincmp(p, "enable", 6) == 0) {
		p += 6 + 1;  /*skip enable and one blank*/
		len -= 6 + 1;  /*len maybe negative now if there is no other parameters*/
		f_enable = 1;
	} else if (strincmp(p, "disable", 7) == 0) {
		p += 7 + 1;  /*skip disable and one blank*/
		len -= 7 + 1; /*len maybe negative now if there is no other parameters*/
		f_enable = -1;
	} else if (strincmp(p, "help", 4) == 0 || *p == '?') {
		 printk("echo <enable/disable> [");
		 for (i = 0; i < NUM_ENTITY(dbg_enable_mask_str); ++i) printk("%s/", dbg_enable_mask_str[i].cmd );
	}

	if (f_enable) {
		if ((len <= 0) || ( p[0] >= '0' && p[1] <= '9') ) {
			if (f_enable > 0)
				g_mpeh_dbg_enable |= DBG_ENABLE_MASK_ALL;
			else
				g_mpeh_dbg_enable &= ~DBG_ENABLE_MASK_ALL;
		} else {
			do {
				for (i = 0; i < NUM_ENTITY(dbg_enable_mask_str); ++i)
					if (strincmp(p, dbg_enable_mask_str[i].cmd, strlen(dbg_enable_mask_str[i].cmd)) == 0) {
						if (f_enable > 0)
							g_mpeh_dbg_enable |= dbg_enable_mask_str[i].flag;
						else
							g_mpeh_dbg_enable &= ~dbg_enable_mask_str[i].flag;

						p += strlen(dbg_enable_mask_str[i].cmd) + 1; /*skip one blank*/
						len -= strlen(dbg_enable_mask_str[i].cmd) + 1;
						break;
					}
			} while (i < NUM_ENTITY(dbg_enable_mask_str));
		}
	}

	return count;
}

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
/* Proc function for /proc/ppa/mpe/ipsec/tunnel_info */
static const struct file_operations dbgfs_file_tunnel_info_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_tunnel_info_seq_open,
	.read		= seq_read,
	.write		= proc_write_tunnel_info,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};


static int proc_read_tunnel_info(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	return 0;
}


static ssize_t proc_write_tunnel_info(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;
	char *param_list[PARAM_NUM] = { 0 };

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if ( strstr(p, "help")) {
		printk("for specific tunnel 'echo <tunnel Id> > /proc/ppa/mpe/ipsec/tunnel_info\n'");
		printk("cat /proc/ppa/mpe/ipsec/tunnel_info\n");
		return count;

	} else {
		int32_t num=0 ;
		num = ltq_split_buffer(p, param_list, MPE_ARRAY_SIZE(param_list));
		if (num == 1) {
			printk("tunnel Id=%d\n", Atoi(param_list[0]));
			mpe_hal_dump_ipsec_tunnel_info(Atoi(param_list[0]));
		} else {
			printk("echo help > /proc/ppa/mpe/multicast_vap_list\n");
		}
	}
	return count ;
}


static int proc_read_tunnel_info_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_tunnel_info, NULL);
}

/* Proc function for /proc/ppa/mpe/ipsec/xfrm */
static const struct file_operations dbgfs_file_xfrm_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_xfrm_seq_open,
	.read		= seq_read,
	.write		= proc_write_xfrm,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_xfrm(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	return 0;
}


static ssize_t proc_write_xfrm(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;
	char *param_list[PARAM_NUM] = { 0 };

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;


	if ( strstr(p, "help")) {
		printk("for specific tunnel 'echo <tunnel Id> > /proc/ppa/mpe/ipsec/xfrm\n'");
		printk("cat /proc/ppa/mpe/ipsec/xfrm\n");
		return count;

	} else {
		int32_t num=0 ;
		num = ltq_split_buffer(p, param_list, MPE_ARRAY_SIZE(param_list));
		if (num == 1) {
			printk("tunnel Id=%d\n", Atoi(param_list[0]));
			mpe_hal_dump_ipsec_xfrm_sa(Atoi(param_list[0]));
		} else {
			printk("echo help > /proc/ppa/mpe/ipsec/xfrm\n");
		}
	}
	return count ;
}

static int proc_read_xfrm_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_xfrm, NULL);
}


/* Proc function for /proc/ppa/mpe/ipsec/eip97 */
static const struct file_operations dbgfs_file_eip97_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_eip97_seq_open,
	.read		= seq_read,
	.write		= proc_write_eip97,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_eip97(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	return 0;
}

static ssize_t proc_write_eip97(struct file *file, const char __user *buf, size_t count, loff_t *data)
{
	uint32_t len;
	char str[50];
	char *p;
	char *param_list[PARAM_NUM] = { 0 };

	if (!capable(CAP_NET_ADMIN)) {
		printk ("Write Permission denied");
		return 0;
	}
	len = min(count, sizeof(str) - 1);
	len -= ppa_copy_from_user(str, buf, len);
	while ( len && str[len - 1] <= ' ' )
		len--;
	str[len] = 0;
	for ( p = str; *p && *p <= ' '; p++, len-- );
	if ( !*p )
		return count;

	if ( strstr(p, "help")) {
		printk("for specific tunnel 'echo <tunnel Id> > /proc/ppa/mpe/ipsec/eip97\n'");
		return count;

	} else {
		int32_t num=0 ;
		num = ltq_split_buffer(p, param_list, MPE_ARRAY_SIZE(param_list));
		if (num == 1) {
			printk("tunnel Id=%d\n", Atoi(param_list[0]));
			mpe_hal_dump_ipsec_eip97_params(Atoi(param_list[0]));
		} else {
			printk("echo help > /proc/ppa/mpe/ipsec/eip97\n");
		}
	}
	return count ;
}


static int proc_read_eip97_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_eip97, NULL);
}
#endif

/* Proc function for /proc/ppa/mpe/version */
static const struct file_operations dbgfs_file_version_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_version_seq_open,
	.read		= seq_read,
	.llseek	 	= seq_lseek,
	.release	= single_release,
};

static int proc_read_version(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	dump_mpe_version(seq);
	return 0;
}

static int proc_read_version_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_version, NULL);
}

/* Proc function for /proc/ppa/mpe/session_count */
static const struct file_operations dbgfs_file_session_count_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_read_session_count_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};


static int proc_read_session_count(struct seq_file *seq, void *v)
{
	if (!capable(CAP_NET_ADMIN)) {
		printk ("Read Permission denied");
		return 0;
	}
	mpe_session_count(seq);
	return 0;
}

static int proc_read_session_count_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_read_session_count, NULL);
}

int mpe_hal_procfs_create(void)
{
	if (!g_ppa_proc_dir)
		g_ppa_proc_dir = proc_mkdir("ppa", NULL);

	ppa_mpe_proc_dir = proc_mkdir("mpe", g_ppa_proc_dir);
	proc_create("vap_qos", 0600,
		ppa_mpe_proc_dir,
		&dbgfs_file_vap_qos_seq_fops);

	return 0;
}

void mpe_hal_procfs_destroy(void)
{
	remove_proc_entry("vap_qos", ppa_mpe_proc_dir);
	remove_proc_entry("mpe", g_ppa_proc_dir);
	ppa_mpe_proc_dir = NULL;
}

static struct ppa_debugfs_files mpe_hal_debugfs_files[] = {
	{ "genconf",            0600, &dbgfs_file_genconf_seq_fops },
	{ "fwHdr",              0600, &dbgfs_file_fwHdr_seq_fops },
	{ "tc",                 0600, &dbgfs_file_tc_seq_fops },
	{ "hw_res",             0600, &dbgfs_file_hw_res_seq_fops },
	{ "session_mib",        0600, &dbgfs_file_session_mib_seq_fops },
	{ "tc_mib",             0600, &dbgfs_file_tc_mib_seq_fops },
	{ "itf_mib",            0600, &dbgfs_file_itf_mib_seq_fops },
	{ "hit_mib",            0600, &dbgfs_file_hit_mib_seq_fops },
	{ "IPv4_sessions",      0600, &dbgfs_file_ipv4_sessions_seq_fops },
	{ "IPv6_sessions",      0600, &dbgfs_file_ipv6_sessions_seq_fops },
	{ "fw_dbg",             0600, &dbgfs_file_fw_dbg_seq_fops },
	{ "tc_full_dbg",        0600, &dbgfs_file_tc_full_dbg_seq_fops },
	{ "test",               0600, &dbgfs_file_test_seq_fops },
	{ "session_action",     0600, &dbgfs_file_session_action_seq_fops },
	{ "accel",              0600, &dbgfs_file_accel_seq_fops },
	{ "fw",                 0600, &dbgfs_file_fw_seq_fops },
	{ "multicast_vap_list", 0600, &dbgfs_file_multicast_vap_list_seq_fops },
	{ "session_count",      0600, &dbgfs_file_session_count_seq_fops },
	{ "version",            0600, &dbgfs_file_version_seq_fops },
	{ "dbg",                0600, &dbgfs_file_dbg_seq_fops },
};

#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
static struct ppa_debugfs_files mpe_hal_ipsec_debugfs_files[] = {
	{ "tunnel_info", 0600, &dbgfs_file_tunnel_info_seq_fops },
	{ "xfrm",        0600, &dbgfs_file_xfrm_seq_fops },
	{ "eip97",       0600, &dbgfs_file_eip97_seq_fops },
};
#endif

int mpe_hal_debugfs_create(void)
{
	ppa_debugfs_create(ppa_hal_debugfs_dir_get(), "mpe",
		&dbgfs_ppa_mpe, mpe_hal_debugfs_files,
		ARRAY_SIZE(mpe_hal_debugfs_files));
#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	ppa_debugfs_create(dbgfs_ppa_mpe, "ipsec",
		&dbgfs_ppa_mpe_ipsec, mpe_hal_ipsec_debugfs_files,
		ARRAY_SIZE(mpe_hal_ipsec_debugfs_files));
#endif
	return 0;
}

void mpe_hal_debugfs_destroy(void)
{
#if IS_ENABLED(CONFIG_PPA_MPE_IP97)
	ppa_debugfs_remove(dbgfs_ppa_mpe_ipsec,
		mpe_hal_ipsec_debugfs_files,
		ARRAY_SIZE(mpe_hal_ipsec_debugfs_files));
#endif
	ppa_debugfs_remove(dbgfs_ppa_mpe,
		mpe_hal_debugfs_files,
		ARRAY_SIZE(mpe_hal_debugfs_files));
}
