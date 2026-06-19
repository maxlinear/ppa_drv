#ifndef __PPA_API_QOS_HELPER_H__
#define __PPA_API_QOS_HELPER_H__
/******************************************************************************
 *
 * FILE NAME	: ppa_api_qos_helper.h
 * PROJECT	: LGM
 * MODULES	: PPA framework support for QoS notification support and helper
 *
 * DESCRIPTION	: PPA API support for QoS events and helper functions.
 * COPYRIGHT	: Copyright (C) 2022-2023 MaxLinear, Inc.
 *
 * For licensing information, see the file 'LICENSE' in the root folder
 * of this software module.
 *
 * HISTORY
 * $Date                 $Author                 $Comment
 * 06 SEPT 2022          Gaurav Sharma           Initial PPA APIs support for
 *                                               TC-QoS
 *
 *****************************************************************************/

/**
 * @brief Support for QoS helper module initialization.
 * @param void
 * @return void
 */
void ppa_netdev_qos_helper_init(void);

/**
 * @brief Support for QoS helper module de-register.
 * @param void
 * @return void
 */
void ppa_netdev_qos_helper_deinit(void);

/**
 * @brief Add device to QoS helper db.
 * @param net device.
 * @return PPA_SUCCESS/PPA_FAILURE
 */
int32_t ppa_qos_helper_dev_add(PPA_NETIF *dev);

/**
 * @brief Modify device in QoS helper db.
 * @param net device.
 * @return PPA_SUCCESS/PPA_FAILURE
 */
int32_t ppa_qos_helper_dev_modify(PPA_NETIF *oldif, PPA_NETIF *newif);

/**
 * @brief Refresh cached DPM subif state (dfl_eg_sess[]/alloc_flag/def_q/dpid)
 *        for an interface already tracked by the QoS helper. Must be invoked
 *        when DPM may have re-allocated the subif at runtime (e.g. WiFi
 *        disable/enable). Does not touch the qid_map[] populated by tc events.
 * @param net device.
 * @return PPA_SUCCESS/PPA_FAILURE
 */
int32_t ppa_qos_helper_dev_refresh(PPA_NETIF *dev);

/**
 * @brief Remove device from helper db.
 * @param netdevice.
 * @return PPA_SUCCESS/PPA_FAILURE
 */
int32_t ppa_qos_helper_dev_del(struct netif_info *p_ifinfo);
#endif /* __PPA_API_QOS_HELPER_H__ */

