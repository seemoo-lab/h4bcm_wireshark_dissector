/* packet-h4bcm.c
 * Routines for Bluetooth H4 Broadcom vendor specific additions
 * Copyright 2019, Jiska Classen / Secure Mobile Networking Lab
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#include <wireshark/config.h>
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <string.h>

/* type definitions for Broadcom diagnostics */
#define DIA_LM_SENT			0x00
#define DIA_LM_RECV			0x01
#define DIA_MEM_PEEK_RESP		0x03
#define DIA_MEM_DUMP_RESP		0x04
#define DIA_TEST_COMPL			0x0a
#define DIA_MEM_POKE_RESP		0x11
#define DIA_CPU_LOAD_RESP		0x15
#define DIA_ACL_BR_RESP			0x16
#define DIA_ACL_EDR_RESP		0x17
#define DIA_AUX_RESP			0x18
#define DIA_ACL_UNKN1_RESP		0x1a
#define DIA_ACL_UNKN2_RESP		0x1b
#define DIA_CON_RESP			0x1f
#define DIA_LE_SENT			0x80
#define DIA_LE_RECV			0x81
#define DIA_ACL_BR_RESET		0xb9
#define DIA_ACL_BR_GET			0xc1
#define DIA_ACL_EDR_GET			0xc2
#define DIA_AUX_GET			0xc3
#define DIA_ACL_UNKN1_GET		0xc5
#define DIA_ACL_UNKN2_GET		0xc6
#define DIA_CON_GET			0xcf
#define DIA_LM_ENABLE			0xf0
#define DIA_MEM_PEEK_GET		0xf1
#define DIA_MEM_POKE_GET		0xf2
#define DIA_MEM_DUMP_GET		0xf3
#define DIA_PKT_TEST			0xf6

/* function prototypes */
void proto_reg_handoff_h4bcm(void);

/* initialize the protocol and registered fields */
static int proto_h4bcm = -1;
static int hf_h4bcm_type = -1;
static int hf_h4bcm_clock = -1;
static int hf_h4bcm_maclow = -1;
static int hf_h4bcm_pldhdr = -1;
static int hf_h4bcm_llid = -1;
static int hf_h4bcm_pldflow = -1;
static int hf_h4bcm_length = -1;
static int hf_h4bcm_payload = -1;
static int hf_h4bcm_lm_toggle = -1;
static int hf_h4bcm_stats_null_rcvd = -1;
static int hf_h4bcm_stats_poll_rcvd = -1;
static int hf_h4bcm_stats_dm1_rcvd = -1;
static int hf_h4bcm_stats_dh1_rcvd = -1;
static int hf_h4bcm_stats_dv_rcvd = -1;
static int hf_h4bcm_stats_aux1_rcvd = -1;
static int hf_h4bcm_stats_dm3_rcvd = -1;
static int hf_h4bcm_stats_dh3_rcvd = -1;
static int hf_h4bcm_stats_dm5_rcvd = -1;
static int hf_h4bcm_stats_dh5_rcvd = -1;
static int hf_h4bcm_stats_null_tx = -1;
static int hf_h4bcm_stats_poll_tx = -1;
static int hf_h4bcm_stats_dm1_tx = -1;
static int hf_h4bcm_stats_dh1_tx = -1;
static int hf_h4bcm_stats_dv_tx = -1;
static int hf_h4bcm_stats_aux1_tx = -1;
static int hf_h4bcm_stats_dm3_tx = -1;
static int hf_h4bcm_stats_dh3_tx = -1;
static int hf_h4bcm_stats_dm5_tx = -1;
static int hf_h4bcm_stats_dh5_tx = -1;
static int hf_h4bcm_stats_acl_rx = -1;
static int hf_h4bcm_stats_acl_tx = -1;
static int hf_h4bcm_stats_hec_err = -1;
static int hf_h4bcm_stats_crc_err = -1;
static int hf_h4bcm_stats_seqn_rep = -1;
static int hf_h4bcm_stats_soft_rst = -1;
static int hf_h4bcm_stats_test_tx = -1;;
static int hf_h4bcm_stats_test_rx = -1;
static int hf_h4bcm_stats_test_err = -1;
static int hf_h4bcm_stats_2dh1_rcvd = -1;
static int hf_h4bcm_stats_3dh1_rcvd = -1;
static int hf_h4bcm_stats_2dh3_rcvd = -1;
static int hf_h4bcm_stats_3dh3_rcvd = -1;
static int hf_h4bcm_stats_2dh5_rcvd = -1;
static int hf_h4bcm_stats_3dh5_rcvd = -1;
static int hf_h4bcm_stats_2dh1_tx = -1;
static int hf_h4bcm_stats_3dh1_tx = -1;
static int hf_h4bcm_stats_2dh3_tx = -1;
static int hf_h4bcm_stats_3dh3_tx = -1;
static int hf_h4bcm_stats_2dh5_tx = -1;
static int hf_h4bcm_stats_3dh5_tx = -1;
static int hf_h4bcm_le_ether = -1;
static int hf_h4bcm_le_handle = -1;
static int hf_h4bcm_le_opcode = -1;
static int hf_h4bcm_le_opcode_ext = -1;
static int hf_h4bcm_ll_version_ind_versnr = -1;
static int hf_h4bcm_ll_version_ind_compid = -1;
static int hf_h4bcm_ll_version_ind_subversnr = -1;

/* initialize the subtree pointers */
static gint ett_h4bcm = -1;
static gint ett_h4bcm_pldhdr = -1;
static gint ett_h4bcm_acl_br_stats = -1;
static gint ett_h4bcm_acl_edr_stats = -1;

/* subdissectors */
static dissector_handle_t btlmp_handle = NULL;

/* reversed Broadcom diagnostic types */
static const value_string h4bcm_types[] = {
	{ DIA_LM_SENT, "LM Sent" },
	{ DIA_LM_RECV, "LM Received" },
	{ DIA_MEM_PEEK_RESP, "Memory Access Response to Peek" },
	{ DIA_MEM_DUMP_RESP, "Memory Hex Dump Response" },
	{ DIA_TEST_COMPL, "Reported Completed Test" },
	{ DIA_MEM_POKE_RESP, "Memory Access Response to Poke" },
	{ DIA_CPU_LOAD_RESP, "CPU Load" },
	{ DIA_ACL_BR_RESP, "Basic Rate ACL Stats Data" },
	{ DIA_ACL_EDR_RESP, "EDR ACL Stats Data" },
	{ DIA_AUX_RESP, "Received Aux Response" },
	{ DIA_ACL_UNKN1_RESP, "ACL Stats Data (Type 0x1A)" },
	{ DIA_ACL_UNKN2_RESP, "ACL Stats Data (Type 0x1B)" },
	{ DIA_CON_RESP, "Get Connection Response" },
	{ DIA_LE_SENT, "LE LM Sent" },				// Low Energy LL Control PDU LMP Message
	{ DIA_LE_RECV, "LE LM Received" },
	{ DIA_ACL_BR_RESET, "Reset Basic Rate ACL Stats" },	// memclr(DHM_ACLPktStats)
	{ DIA_ACL_BR_GET, "Get Basic Rate ACL Stats" },
	{ DIA_ACL_EDR_GET, "Get EDR ACL Stats" },
	{ DIA_ACL_UNKN1_GET, "Get ACL Stats (Type 0x1A)" },	// BTMUtil_Send_2045_ACL_Stats(0x1a, cmd)
	{ DIA_ACL_UNKN2_GET, "Get ACL Stats (Type 0x1B)" },
	{ DIA_AUX_GET, "Get Aux Stats"},			// BTMUtil_SendAuxStats
	{ DIA_CON_GET, "Get Connection Stats"},			// ulp_send_connection_stats(0x1F)
	{ DIA_LM_ENABLE, "Toggle LMP Logging" },
	{ DIA_MEM_PEEK_GET, "Memory Peek" },
	{ DIA_MEM_POKE_GET, "Memory Poke" },
	{ DIA_MEM_DUMP_GET, "Memory Hex Dump" },
	{ DIA_PKT_TEST, "BTMMstr_BBPktTest" },
};

static const value_string llid_codes[] = {
	{ 0x0, "undefined" },
	{ 0x1, "Continuation fragment of an L2CAP message (ACL-U)" },
	{ 0x2, "Start of an L2CAP message or no fragmentation (ACL-U)" },
	{ 0x3, "LMP message (ACL-C)" },
	{ 0, NULL }
};

/* This table is needed due to Brodcoms wrong LMP length passing... */
static const int lmp_lengths[] = {
	 0, /* LMP_VSC */
	 2, /* LMP_NAME_REQ */
	17, /* LMP_NAME_RES */
	 2, /* LMP_ACCEPTED */
	 3, /* LMP_NOT_ACCEPTED */
	 1, /* LMP_CLKOFFSET_REQ */
	 3, /* LMP_CLKOFFSET_RES */
	 2, /* LMP_DETACH */
	17, /* LMP_IN_RAND */
	17, /* LMP_COMB_KEY */
	17, /* LMP_UNIT_KEY */
	17, /* LMP_AU_RAND */
	 5, /* LMP_SRES */
	17, /* LMP_TEMP_RAND */
	17, /* LMP_TEMP_KEY */
	 2, /* LMP_ENCRYPTION_MODE_REQ */
	 2, /* LMP_ENCRYPTION_KEY_SIZE_REQ */
	17, /* LMP_START_ENCRYPTION_REQ */
	 1, /* LMP_STOP_ENCRYPTION_REQ */
	 5, /* LMP_SWITCH_REQ */
	 7, /* LMP_HOLD */
	 7, /* LMP_HOLD_REQ */
	10, /* LMP_SNIFF_REQ */
	 0,
	 1, /* LMP_UNSNIFF_REQ */
	17, /* LMP_PARK_REQ */
	 0,
	 4, /* LMP_SET_BROADCAST_SCAN_WINDOW */
	11, /* LMP_MODIFY_BEACON */
	15, /* LMP_UNPARK_BD_ADDR_REQ */
	13, /* LMP_UNPARK_PM_ADDR_REQ */
	 2, /* LMP_INCR_POWER_REQ */
	 2, /* LMP_DECR_POWER_REQ */
	 1, /* LMP_MAX_POWER */
	 1, /* LMP_MIN_POWER */
	 1, /* LMP_AUTO_RATE */
	 2, /* LMP_PREFERRED_RATE */
	 6, /* LMP_VERSION_REQ */
	 6, /* LMP_VERSION_RES */
	 9, /* LMP_FEATURES_REQ */
	 9, /* LMP_FEATURES_RES */
	 4, /* LMP_QUALITY_OF_SERVICE */
	 4, /* LMP_QUALITY_OF_SERVICE_REQ */
	 7, /* LMP_SCO_LINK_REQ */
	 3, /* LMP_REMOVE_SCO_LINK_REQ */
	 2, /* LMP_MAX_SLOT */
	 2, /* LMP_MAX_SLOT_REQ */
	 1, /* LMP_TIMING_ACCURACY_REQ */
	 3, /* LMP_TIMING_ACCURACY_RES */
	 1, /* LMP_SETUP_COMPLETE */
	 1, /* LMP_USE_SEMI_PERMANENT_KEY */
	 1, /* LMP_HOST_CONNECTION_REQ */
	 9, /* LMP_SLOT_OFFSET */
	 3, /* LMP_PAGE_MODE_REQ */
	 3, /* LMP_PAGE_SCAN_MODE_REQ */
	 3, /* LMP_SUPERVISION_TIMEOUT */
	 1, /* LMP_TEST_ACTIVATE */
	10, /* LMP_TEST_CONTROL */
	 1, /* LMP_ENCRYPTION_KEY_SIZE_MASK_REQ */
	 3, /* LMP_ENCRYPTION_KEY_SIZE_MASK_RES */
	16, /* LMP_SET_AFH */
	 4, /* LMP_ENCAPSULATED_HEADER */
	17, /* LMP_ENCAPSULATED_PAYLOAD */
	17, /* LMP_SIMPLE_PAIRING_CONFIRM */
	17, /* LMP_SIMPLE_PAIRING_NUMBER */
	17, /* LMP_DHKEY_CHECK */
};

static const int lmp_lengths_ext[] = {
	 0,
	 4, /* LMP_ACCEPTED_EXT */
	 5, /* LMP_NOT_ACCEPTED_EXT */
	12, /* LMP_FEATURES_REQ_EXT */
	12, /* LMP_FEATURES_RES_EXT */
	 0,
	 0,
	 0,
	 0,
	 0,
	 0,
	 3, /* LMP_PACKET_TYPE_TABLE_REQ */
	16, /* LMP_ESCO_LINK_REQ */
	 4, /* LMP_REMOVE_ESCO_LINK_REQ */
	 0,
	 0,
	 7, /* LMP_CHANNEL_CLASSIFICATION_REQ */
	12, /* LMP_CHANNEL_CLASSIFICATION */
	 0,
	 0,
	 0,
	 9, /* LMP_SNIFF_SUBRATING_REQ */
	 9, /* LMP_SNIFF_SUBRATING_RES */
	 2, /* LMP_PAUSE_ENCRYPTION_REQ */
	 2, /* LMP_RESUME_ENCRYPTION_REQ */
	 5, /* LMP_IO_CAPABILITY_REQ */
	 5, /* LMP_IO_CAPABILITY_RES */
	 2, /* LMP_NUMERIC_COMPARISON_FAILED */
	 2, /* LMP_PASSKEY_FAILED */
	 2, /* LMP_OOB_FAILED */
	 3, /* LMP_KEYPRESS_NOTIFICATION */
	 3, /* LMP_POWER_CONTROL_REQ */
	 3, /* LMP_POWER_CONTROL_RES */
};

/* Bluetooth 5.0 specification p. 2589 */
static const value_string lm_le_opcodes[] = {
	{ 0x0, "LE LL Connection Update Request" },
	{ 0x1, "LE LL Channel Map Request" },
	{ 0x2, "LE LL Terminate Indication" },
	{ 0x3, "LE LL Encryption Request" },
	{ 0x4, "LE LL Encryption Response" },
	{ 0x5, "LE LL Start Encryption Request" },
	{ 0x6, "LE LL Start Encryption Response" },
	{ 0x7, "LE LL Unknown Response" },
	{ 0x8, "LE LL Feature Request" },
	{ 0x9, "LE LL Feature Response" },
	{ 0xa, "LE LL Pause Encryption Request" },
	{ 0xb, "LE LL Pause Encryption Response" },
	{ 0xc, "LE LL Version Indication" },
	{ 0xd, "LE LL Reject Indication" },
	{ 0xe, "LE LL Slave Feture Request" },
	{ 0xf, "LE LL Connection Parameter Request" },
	{ 0x10, "LE LL Connection Parameter Response" },
	{ 0x11, "LE LL Extended Reject Indication" },
	{ 0x12, "LE LL Ping Request" },
	{ 0x13, "LE LL Ping Response" },
	{ 0x14, "LE LL Length Request" },
	{ 0x15, "LE LL Length Response" },
	{ 0x16, "LE LL Update Indication" },
	{ 0x17, "LE LL Physical Layers Request" },
	{ 0x18, "LE LL Physical Layers Response" },
	{ 0x19, "LE LL Minimum Number of Used Channels Indication" },
	{ 0xff, "LE LL Broadcom Vendor Specific" },
	{ 0, NULL }
};

static const value_string lm_le_opcodes_ext[] = {
	{ 0x1, "LE LL Vendor Specific Feature Request" },
	{ 0x2, "LE LL Vendor Specific Feature Response" },
	{ 0x3, "LE LL Vendor Specific Enable Bcs Timeline" },
	{ 0x4, "LE LL Random Address Change" },
	{ 0, NULL }
};

static const true_false_string lm_toggle = {
	"enabled",
	"disabled"
};

/* one byte payload header */
int
dissect_payload_header1(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_item *hdr_item;
	proto_tree *hdr_tree;
	
	/* DM1 is only transmitted within full diagnostic reports */
	DISSECTOR_ASSERT(tvb_reported_length(tvb) == 63);

	hdr_item = proto_tree_add_item(tree, hf_h4bcm_pldhdr, tvb, offset, 1, ENC_NA);
	hdr_tree = proto_item_add_subtree(hdr_item, ett_h4bcm_pldhdr);

	proto_tree_add_item(hdr_tree, hf_h4bcm_llid, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(hdr_tree, hf_h4bcm_pldflow, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(hdr_tree, hf_h4bcm_length, tvb, offset, 1, ENC_NA);

	/* payload length */
	return tvb_get_guint8(tvb, offset) >> 3;
}

/* Dissect common LM and LE LM header */
void
dissect_lm_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int is_sent)
{
	guint32 mac;
	gchar *mac_string = (gchar *)g_malloc(12);
	
	/* LMP and LCP are only transmitted within full diagnostic reports */
	DISSECTOR_ASSERT(tvb_reported_length(tvb) == 63);
	
	/* clock of the BT master */
	proto_tree_add_item(tree, hf_h4bcm_clock, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	
	/* decode and display MAC address in src/dst fields */
	mac = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
	g_snprintf(mac_string, 12,
		"%02x:%02x:%02x:%02x",
		(mac & 0xff000000) >>24,
		(mac & 0x00ff0000) >>16,
		(mac & 0x0000ff00) >> 8,
		(mac & 0x000000ff));
	
	proto_tree_add_item(tree, hf_h4bcm_maclow, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	
	if (is_sent == 1) {
		col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "controller");
		col_set_str(pinfo->cinfo, COL_RES_DL_DST, mac_string);
	} else {
		col_set_str(pinfo->cinfo, COL_RES_DL_SRC, mac_string);
		col_set_str(pinfo->cinfo, COL_RES_DL_DST, "controller");
	}
}

/* Pass LMP handling to existing dissector if available */
void
dissect_lmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	int len;
	int opcode;
	int dm1_hdr;
	tvbuff_t *pld_tvb;

	/* LMP is only transmitted within full diagnostic reports */
	DISSECTOR_ASSERT(tvb_reported_length(tvb) == 63);
	
	/* DM1 header is common in both directions */
	dm1_hdr = tvb_get_guint8(tvb, offset);
	len = dissect_payload_header1(tree, tvb, offset);
	
	/* Longest LMP packet is 17 bytes */
	DISSECTOR_ASSERT(len <= 17);
	
	offset += 1;
	
	/* In receive direction, diagnostic LMP always sends a packet length 17,
	 * which makes failed assertions inside the LMP decoder...
	 * The fixed length corresponds to a DM1 header of 0x8f in flow direction
	 * receive, so we can check this directly instead of maybe re-checking
	 * valid length 17 in sent direction.
	 * This fix is really ugly, but it makes the LMP decoders assertions pass.
	 */
	if (dm1_hdr == 0x8f) {
		/* Get normal / extended opcode length. Will be 0 if undefined. */
		len = 0;
		opcode = tvb_get_guint8(tvb, offset) >> 1;
		if (opcode <= 65) {
			len = lmp_lengths[opcode];
		} else if (opcode == 127) {
			opcode = tvb_get_guint8(tvb, offset + 1);
			if (opcode <= 32) {
				len = lmp_lengths_ext[opcode];
			}
		}
	}

	/* Check that we have a LMP dissector or else just display raw payload */
	if (btlmp_handle && len != 0) {
		pld_tvb = tvb_new_subset_length_caplen(tvb, offset, len, len);
		call_dissector(btlmp_handle, pld_tvb, pinfo, tree);
	} else {
		/* Maximum (constant) LMP length is 17 */
		proto_tree_add_item(tree, hf_h4bcm_payload, tvb, offset, 17, ENC_LITTLE_ENDIAN);
	}
}

/* TODO placeholder for responses we don't know yet */
void
dissect_unkn_resp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	DISSECTOR_ASSERT(tvb_reported_length(tvb) == 63);

	proto_tree_add_item(tree, hf_h4bcm_type, tvb, offset-1, 1, ENC_NA);

	/* Sent from chip to host */
	col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "controller");
	col_set_str(pinfo->cinfo, COL_RES_DL_DST, "host");
}

/* TODO placeholder for commands with arguments that are none or unknown */
void
dissect_unkn_get(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	DISSECTOR_ASSERT(tvb_reported_length(tvb) >= 1);

	proto_tree_add_item(tree, hf_h4bcm_type, tvb, offset-1, 1, ENC_NA);

	/* Sent from host to chip */
	col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "host");
	col_set_str(pinfo->cinfo, COL_RES_DL_DST, "controller");
}

/* ACL BR stats */
void
dissect_acl_br_stats(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)

{
	proto_item *stats_item;
	proto_tree *stats_tree;

	DISSECTOR_ASSERT(tvb_reported_length(tvb) == 63);

	/* Sent from chip to host */
	col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "controller");
	col_set_str(pinfo->cinfo, COL_RES_DL_DST, "host");

	/* Display previous item as tree header */
	stats_item = proto_tree_add_item(tree, hf_h4bcm_type, tvb, offset-1, 1, ENC_NA);

	/* Make stats subtree */
	stats_tree = proto_item_add_subtree(stats_item, ett_h4bcm_acl_br_stats);

	proto_tree_add_item(stats_tree, hf_h4bcm_stats_null_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_poll_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dm1_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dh1_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dv_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_aux1_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dm3_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dh3_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dm5_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dh5_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_null_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_poll_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dm1_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dh1_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dv_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_aux1_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dm3_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dh3_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dm5_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dh5_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	/* FIXME within the next 16 bytes, some are 4 bytes long ... not 100% sure which */
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_acl_rx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_acl_tx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_hec_err, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_crc_err, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_seqn_rep, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_soft_rst, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_test_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_test_rx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_test_err, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
}

/* ACL EDR stats */
void
dissect_acl_edr_stats(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_item *stats_item;
	proto_tree *stats_tree;

	DISSECTOR_ASSERT(tvb_reported_length(tvb) == 63);

	/* Sent from chip to host */
	col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "controller");
	col_set_str(pinfo->cinfo, COL_RES_DL_DST, "host");

	/* Display previous item as tree header */
	stats_item = proto_tree_add_item(tree, hf_h4bcm_type, tvb, offset-1, 1, ENC_NA);

	/* Make stats subtree */
	stats_tree = proto_item_add_subtree(stats_item, ett_h4bcm_acl_edr_stats);

	proto_tree_add_item(stats_tree, hf_h4bcm_stats_null_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_poll_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dm1_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_2dh1_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_3dh1_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_2dh3_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_3dh3_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_2dh5_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_3dh5_rcvd, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	offset += 2; /* with this offset, null packets match */
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_null_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_poll_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_dm1_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_2dh1_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_3dh1_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_2dh3_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_3dh3_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_2dh5_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_3dh5_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	offset += 2; /* with this offset, acl bytes are correct */
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_acl_rx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_acl_tx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_hec_err, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_crc_err, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_seqn_rep, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_soft_rst, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_test_tx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_test_rx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
	proto_tree_add_item(stats_tree, hf_h4bcm_stats_test_err, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
}

/* LL_VERSION_IND p. 2594 
 */
void
dissect_ll_version_ind(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_tree_add_item(tree, hf_h4bcm_ll_version_ind_versnr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_h4bcm_ll_version_ind_compid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_h4bcm_ll_version_ind_subversnr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

/* LM LE
 * Most of this is already implemented in "btle" in Wireshark...
 * But somewhat different format :( So we do it here.
 */
void
dissect_lm_le(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int is_sent)
{
	int opcode;
	int opcode_ext;
	guint64 mac;
	gchar *mac_string = (gchar *)g_malloc(18);
	
	/* LMP and LCP are only transmitted within full diagnostic reports */
	DISSECTOR_ASSERT(tvb_reported_length(tvb) == 63);
	
	/* clock of the BT master */
	proto_tree_add_item(tree, hf_h4bcm_clock, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* standard MAC address this time */
	mac = tvb_get_guint64(tvb, offset-2, ENC_BIG_ENDIAN);
	g_snprintf(mac_string, 18,
		"%02x:%02x:%02x:%02x:%02x:%02x",
		(mac & 0xff0000000000) >>40,
		(mac & 0x00ff00000000) >>32,
		(mac & 0x0000ff000000) >>24,
		(mac & 0x000000ff0000) >>16,
		(mac & 0x00000000ff00) >> 8,
		(mac & 0x0000000000ff));
	proto_tree_add_item(tree, hf_h4bcm_le_ether, tvb, offset, 6, ENC_LITTLE_ENDIAN);
	offset += 6;

	if (is_sent == 1) {
		col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "controller");
		col_set_str(pinfo->cinfo, COL_RES_DL_DST, mac_string);
	} else {
		col_set_str(pinfo->cinfo, COL_RES_DL_SRC, mac_string);
		col_set_str(pinfo->cinfo, COL_RES_DL_DST, "controller");
	}

	/* Handle (only 1 byte, even though it can be 2 bytes long?!) */
	proto_tree_add_item(tree, hf_h4bcm_le_handle, tvb, offset, 1, ENC_NA);
	offset += 1;
	
	opcode = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_h4bcm_le_opcode, tvb, offset, 1, ENC_NA);
	col_add_str(pinfo->cinfo, COL_INFO, val_to_str(opcode,
			lm_le_opcodes, "LE LL Unknown Opcode (%d)"));
	offset += 1;

	switch (opcode) {
	case 0x0c:
		dissect_ll_version_ind(tree, tvb, offset);
		break;
	/* Broadcom vendor specific stuff... */
	case 0xff:
		opcode_ext = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_h4bcm_le_opcode_ext, tvb, offset, 1, ENC_NA);
		col_add_str(pinfo->cinfo, COL_INFO, val_to_str(opcode_ext,
		lm_le_opcodes_ext, "LE LL Unknown VSC Opcode (%d)"));
		offset += 1;
		break;
	default:
		break;
	}
}

/* Show if LM + LM LE logging was enabled or disabled */
void
dissect_lm_toggle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	DISSECTOR_ASSERT(tvb_reported_length(tvb) >= 1);

	/* Sent from host UART to chip */
	col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "host");
	col_set_str(pinfo->cinfo, COL_RES_DL_DST, "controller");

	/* OFF and ON */
	proto_tree_add_item(tree, hf_h4bcm_lm_toggle, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
}

/* dissect a packet */
static int
dissect_h4bcm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *h4bcm_item, *type_item;
	proto_tree *h4bcm_tree, *type_tree;
	int offset;
	int h4bcm_type;

	/* sanity check: length */
	if (tvb_reported_length(tvb) < 1)
		/* bad length: look for a different dissector */
		return 0;
	
	
	/* fprintf(stderr, "total len %d\n", tvb_reported_length(tvb)); */

	/* make entries in protocol column and info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI H4 Broadcom");

	/* create display subtree for the protocol */
	offset = 0;
	h4bcm_item = proto_tree_add_item(tree, proto_h4bcm, tvb, offset, -1, ENC_NA);
	h4bcm_tree = proto_item_add_subtree(h4bcm_item, ett_h4bcm);
		
	h4bcm_type = tvb_get_guint8(tvb, offset);
	col_add_str(pinfo->cinfo, COL_INFO, val_to_str(h4bcm_type, h4bcm_types, "Unknown Type (%d)"));
	offset += 1;
		
	switch (h4bcm_type) {
	case DIA_LM_SENT:
		dissect_lm_header(tvb, pinfo, h4bcm_tree, offset, 1);
		offset += 8;
		dissect_lmp(tvb, pinfo, h4bcm_tree, offset);
		break;
	case DIA_LM_RECV:
		dissect_lm_header(tvb, pinfo, h4bcm_tree, offset, 0);
		offset += 11;
		dissect_lmp(tvb, pinfo, h4bcm_tree, offset);
		break;
	case DIA_ACL_BR_RESP:
		dissect_acl_br_stats(tvb, pinfo, h4bcm_tree, offset);
		break;
	case DIA_ACL_EDR_RESP:
		dissect_acl_edr_stats(tvb, pinfo, h4bcm_tree, offset);
		break;
	case DIA_LE_SENT:
		dissect_lm_le(tvb, pinfo, h4bcm_tree, offset, 1);
		break;
	case DIA_LE_RECV:
		dissect_lm_le(tvb, pinfo, h4bcm_tree, offset, 0);
		break;
	case DIA_LM_ENABLE:
		dissect_lm_toggle(tvb, pinfo, h4bcm_tree, offset);
		break;
	case DIA_MEM_PEEK_RESP:
	case DIA_MEM_DUMP_RESP:
	case DIA_TEST_COMPL:
	case DIA_MEM_POKE_RESP:
	case DIA_CPU_LOAD_RESP:
	case DIA_AUX_RESP:
	case DIA_ACL_UNKN1_RESP:
	case DIA_ACL_UNKN2_RESP:
		dissect_unkn_resp(tvb, pinfo, h4bcm_tree, offset);
		break;
	case DIA_ACL_BR_RESET:
	case DIA_ACL_BR_GET:
	case DIA_ACL_EDR_GET:
	case DIA_AUX_GET:
	case DIA_ACL_UNKN1_GET:
	case DIA_ACL_UNKN2_GET:
	case DIA_CON_GET:
	case DIA_MEM_PEEK_GET:
	case DIA_MEM_POKE_GET:
	case DIA_MEM_DUMP_GET:
	case DIA_PKT_TEST:
		dissect_unkn_get(tvb, pinfo, h4bcm_tree, offset);
		break;
	default:
		break;
	}

	/* Return the amount of data this dissector was able to dissect */
	return tvb_reported_length(tvb);
}

/* register the protocol with Wireshark */
void
proto_register_h4bcm(void)
{
	/* list of fields */
	static hf_register_info hf[] = {
		{ &hf_h4bcm_type,
			{ "Type", "h4bcm.type",
			FT_UINT8, BASE_HEX, VALS(h4bcm_types), 0x0,
			"Diagnostic Information Type", HFILL }
		},
		{ &hf_h4bcm_clock,
			{ "Clock", "h4bcm.clock",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Bluetooth Master Clock", HFILL }
		},
		{ &hf_h4bcm_maclow,
			{ "Remote MAC Address", "h4bcm.maclow",
			FT_BYTES, SEP_COLON, NULL, 0x0,
			"Lower MAC address part, sufficient for l2ping ff:ff:maclow", HFILL }
		},
		{ &hf_h4bcm_pldhdr,
			{ "Payload Header", "h4bcm.pldhdr",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_llid,
			{ "LLID", "h4bcm.llid",
			FT_UINT8, BASE_HEX, VALS(llid_codes), 0x03,
			"Logical Link ID", HFILL }
		},
		{ &hf_h4bcm_pldflow,
			{ "Flow", "h4bcm.flow",
			FT_BOOLEAN, 8, NULL, 0x04,
			"Payload Flow indication", HFILL }
		},
		{ &hf_h4bcm_length,
			{ "Length", "h4bcm.length",
			FT_UINT8, BASE_DEC, NULL, 0xf8,
			"Payload Length", HFILL }
		},
		{ &hf_h4bcm_payload,
			{ "Payload", "h4bcm.payload",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_lm_toggle,
			{ "LM and LM LE Logging", "h4bcm.logging",
			FT_BOOLEAN, 8, TFS(&lm_toggle), 0x01,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_null_rcvd,
			{ "Null Packets Received", "h4bcm.stats.null_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_poll_rcvd,
			{ "Poll Packets Received", "h4bcm.stats.poll_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_dm1_rcvd,
			{ "DM1 Packets Received", "h4bcm.stats.dm1_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_dh1_rcvd,
			{ "DH1 Packets Received", "h4bcm.stats.dh1_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_dv_rcvd,
			{ "DV Packets Received", "h4bcm.stats.dv_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_aux1_rcvd,
			{ "AUX1 Packets Received", "h4bcm.stats.aux1_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_dm3_rcvd,
			{ "DM3 Packets Received", "h4bcm.stats.dm3_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_dh3_rcvd,
			{ "DH3 Packets Received", "h4bcm.stats.dh3_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_dm5_rcvd,
			{ "DM5 Packets Received", "h4bcm.stats.dm5_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_dh5_rcvd,
			{ "DH5 Packets Received", "h4bcm.stats.dh5_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_null_tx,
			{ "Null Packets Transmitted", "h4bcm.stats.null_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_poll_tx,
			{ "Poll Packets Transmitted", "h4bcm.stats.poll_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_dm1_tx,
			{ "DM1 Packets Transmitted", "h4bcm.stats.dm1_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_dh1_tx,
			{ "DH1 Packets Transmitted", "h4bcm.stats.dh1_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_dv_tx,
			{ "DV Packets Transmitted", "h4bcm.stats.dv_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_aux1_tx,
			{ "AUX1 Packets Transmitted", "h4bcm.stats.aux1_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_dm3_tx,
			{ "DM3 Packets Transmitted", "h4bcm.stats.dm3_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_dh3_tx,
			{ "DH3 Packets Transmitted", "h4bcm.stats.dh3_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_dm5_tx,
			{ "DM5 Packets Transmitted", "h4bcm.stats.dm5_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_dh5_tx,
			{ "DH5 Packets Transmitted", "h4bcm.stats.dh5_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_acl_rx,
			{ "Total Received ACL Bytes", "h4bcm.stats.acl_rx",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_acl_tx,
			{ "Total Transmitted ACL Bytes", "h4bcm.stats.acl_tx",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_hec_err,
			{ "HEC Errors", "h4bcm.stats.hec_err",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_crc_err,
			{ "CRC Errors", "h4bcm.stats.crc_err",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_seqn_rep,
			{ "Seqn Repeat", "h4bcm.stats.seqn_rep",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_soft_rst,
			{ "Soft Reset", "h4bcm.stats.soft_rst",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_test_tx,
			{ "TestMode Transmitted Packets", "h4bcm.stats.test_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_test_rx,
			{ "TestMode Received Packets", "h4bcm.stats.test_rx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_test_err,
			{ "TestMode Packet Errors", "h4bcm.stats.test_err",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_2dh1_rcvd,
			{ "2DH1 Packets Received", "h4bcm.stats.2dh1_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_3dh1_rcvd,
			{ "3DH1 Packets Received", "h4bcm.stats.3dh1_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_2dh3_rcvd,
			{ "2DH3 Packets Received", "h4bcm.stats.2dh3_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_3dh3_rcvd,
			{ "3DH3 Packets Received", "h4bcm.stats.3dh3_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_2dh5_rcvd,
			{ "2DH5 Packets Received", "h4bcm.stats.2dh5_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_3dh5_rcvd,
			{ "3DH5 Packets Received", "h4bcm.stats.3dh5_rcvd",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_2dh1_tx,
			{ "2DH1 Packets Transmitted", "h4bcm.stats.2dh1_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_3dh1_tx,
			{ "3DH1 Packets Transmitted", "h4bcm.stats.3dh1_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_2dh3_tx,
			{ "2DH3 Packets Transmitted", "h4bcm.stats.2dh3_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_3dh3_tx,
			{ "3DH3 Packets Transmitted", "h4bcm.stats.3dh3_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_2dh5_tx,
			{ "2DH5 Packets Transmitted", "h4bcm.stats.2dh5_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_stats_3dh5_tx,
			{ "3DH5 Packets Transmitted", "h4bcm.stats.3dh5_tx",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_le_ether,
			{ "Remote MAC Address", "h4bcm.le.address",
			FT_BYTES, SEP_COLON, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_le_handle,
			{ "Handle", "h4bcm.le.handle",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_le_opcode,
			{ "Opcode", "h4bcm.le.opcode",
			FT_UINT8, BASE_HEX, VALS(lm_le_opcodes), 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_le_opcode_ext,
			{ "Broadcom Specific Opcode", "h4bcm.le.opcodeext",
			FT_UINT8, BASE_HEX, VALS(lm_le_opcodes_ext), 0x0,
			NULL, HFILL }
		},
		{ &hf_h4bcm_ll_version_ind_versnr,
			{ "VersNr", "h4bcm.le.versnr",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Version", HFILL }
		},
		{ &hf_h4bcm_ll_version_ind_subversnr,
			{ "SubVersNr", "h4bcm.le.subversnr",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Subversion", HFILL }
		},
		{ &hf_h4bcm_ll_version_ind_compid,
			{ "CompID", "h4bcm.le.compid",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Company", HFILL }
		},
	};

	/* protocol subtree arrays */
	static gint *ett[] = {
		&ett_h4bcm,
		&ett_h4bcm_pldhdr,
		&ett_h4bcm_acl_br_stats,
		&ett_h4bcm_acl_edr_stats,
	};

	/* register the protocol name and description */
	proto_h4bcm = proto_register_protocol(
		"Bluetooth H4 Serial Broadcom Vendor Specific",	/* full name */
		"H4 Broadcom",			/* short name */
		"h4bcm"			/* abbreviation (e.g. for filters) */
		);

	/* register the header fields and subtrees used */
	proto_register_field_array(proto_h4bcm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_h4bcm(void)
{
	dissector_handle_t h4bcm_handle;
	h4bcm_handle = create_dissector_handle(dissect_h4bcm, proto_h4bcm);
	
	/* hci_h4.type == 0x07 */
	dissector_add_uint("hci_h4.type", 0x07, h4bcm_handle);
	
	/* LMP dissector from https://github.com/greatscottgadgets/libbtbb */
	btlmp_handle = find_dissector("btlmp");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
