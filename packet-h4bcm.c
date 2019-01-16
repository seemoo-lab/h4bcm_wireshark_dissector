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

/* initialize the subtree pointers */
static gint ett_h4bcm = -1;
static gint ett_h4bcm_type = -1;
static gint ett_h4bcm_pldhdr = -1;

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

/* one byte payload header */
int
dissect_payload_header1(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_item *hdr_item;
	proto_tree *hdr_tree;

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
		col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "local");
		col_set_str(pinfo->cinfo, COL_RES_DL_DST, mac_string);
	} else {
		col_set_str(pinfo->cinfo, COL_RES_DL_SRC, mac_string);
		col_set_str(pinfo->cinfo, COL_RES_DL_DST, "local");
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
	
	
	/* DM1 header is common in both directions */
	dm1_hdr = tvb_get_guint8(tvb, offset);
	len = dissect_payload_header1(tree, tvb, offset);
	
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


/* dissect a packet */
static int
dissect_h4bcm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *h4bcm_item, *type_item;
	proto_tree *h4bcm_tree, *type_tree;
	int offset;
	int h4bcm_type;
    
	/* Avoid error: 'type' may be used uninitialized in this function */
	guint8 type = 0xff;

	/* sanity check: length */
	if (tvb_reported_length(tvb) < 63)
		/* bad length: look for a different dissector */
		return 0;

	/* maybe should verify HEC */

	/* make entries in protocol column and info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI H4 Broadcom");

	/* create display subtree for the protocol */
	offset = 0;
	h4bcm_item = proto_tree_add_item(tree, proto_h4bcm, tvb, offset, -1, ENC_NA);
	h4bcm_tree = proto_item_add_subtree(h4bcm_item, ett_h4bcm);
	
	/* type / opcode */
	type_item = proto_tree_add_item(h4bcm_tree, hf_h4bcm_type, tvb, offset, 1, ENC_NA);
	type_tree = proto_item_add_subtree(type_item, ett_h4bcm_type);
		
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
	/* TODO
	 * 12: Opcode
	 * 	0: Connection Update Request [and decoding of subvariables]
	 * 	1: Channel Map Request [and decoding of subvariables]
	 * 	...
	 * 	12: Version ID
	 * 	13: Reject Ind 
	 */
	case DIA_LE_SENT:
		dissect_lm_header(tvb, pinfo, h4bcm_tree, offset, 1);
		break;
	case DIA_LE_RECV:
		dissect_lm_header(tvb, pinfo, h4bcm_tree, offset, 0);
		break;
	default:
		break;
	}
	
	
	/* TODO
	 * Packet Logger still has some decoder details for:
	 * 0x16 contents
	 * 0x17 contents
	 * 
	 */
	
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
	};

	/* protocol subtree arrays */
	static gint *ett[] = {
		&ett_h4bcm,
		&ett_h4bcm_type,
		&ett_h4bcm_pldhdr,
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
