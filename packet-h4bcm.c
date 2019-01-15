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
static dissector_handle_t btbrlmp_handle = NULL; //TODO lmp handover

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

void
dissect_lmp_sent(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	int len;
	int llid;
	tvbuff_t *pld_tvb;
	
	proto_tree_add_item(tree, hf_h4bcm_clock, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_h4bcm_maclow, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	len = dissect_payload_header1(tree, tvb, offset);
	llid = tvb_get_guint8(tvb, offset) & 0x3;
	offset += 1;
	
	if (llid == 3 && btbrlmp_handle) {
		/* LMP */
		pld_tvb = tvb_new_subset_length_caplen(tvb, offset, len, len);
		call_dissector(btbrlmp_handle, pld_tvb, pinfo, tree);
	} else {
		proto_tree_add_item(tree, hf_h4bcm_payload, tvb, offset, 17, ENC_LITTLE_ENDIAN);
	}
	
	//TODO except from offset, lmp sent / received are pretty similar ...
}

void
dissect_lmp_received(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_tree_add_item(tree, hf_h4bcm_clock, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_h4bcm_maclow, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 8;
	proto_tree_add_item(tree, hf_h4bcm_payload, tvb, offset, 17, ENC_LITTLE_ENDIAN);
	//TODO handover to lmp dissector
}

/* dissect a packet */
static int
dissect_h4bcm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *h4bcm_item, *type_item;
	proto_tree *h4bcm_tree, *type_tree;
	int offset;
	int h4bcm_type;
    
    
    /*
     * Known structure so far:
     * 1 byte flow, 1 = receive, 0 = send
     * 4 bytes clock 
     * 4 bytes lower mac address
     * lmp send:
     *      1202, 17 bytes zero
     *      at offset 0x1d: 02 0107 74c5 0800 1706 
     *      6 bytes mac address reverse byte order
     *      0400 0000 8f5d 0562 5800 0000 0000 0000 0000 00
     * lmp rec:
     *      000000 (3 bytes zero)
     *      lmp packet header from there
     *      at offset 0x1d: 00 0007 6084 08 (zeros) 
     * Offset & 1: 1 = Master, 0 = Slave
     * Offset >>1: Opcode
     */
        
    /*
     * Packet Decoder:
     * 0:   00 (Send)
     * 1-4: Clock
     * 5-8: 4 Byte MAC Address
     * if Byte 0 (whatever condition):
     *      Variant 1:
     *      12: Header, Offset = 13
     *      Variant 2:
     *      9: Header, Offset = 10
     *      [tons of decoding standard LMP]
     * 		Header decoding: -> Standard Header before LMP as in existing wireshark code
     * 			a1 & 3:	1: ACL-U / Continuation fragment of an L2CAP message
     * 				2: ACL-U / Start of an L2CAP message or no fragmentation
     * 				3: ACL-C / LMP message
     * 				4: Undefined
     * 			(a1>>2) & 1: Flow
     * 			a1>>3:	Length
     * 5-10:    Full MAC Address
     * 11:      Handle
     * if h4_ref == 0x81 (-> LE!!!): Direction is Receive, else Sent
     * 12: Opcode
     *  -> Low Energy LL Control PDU LMP Message
     *      0: Connection Update Request [and decoding of subvariables]
     *      1: Channel Map Request [and decoding of subvariables]
     *      ...
     *     12: Version ID
     *     13: Reject Ind
     * 
     * 
     * General commands:
     * F0:
     *      1: Turn on LMP Logging
     *      0: Turn off LMP Logging
     * B9: Reset Basic Rate ACL Stats
     * C2: Get EDR ACL Stats
     * C1: Get Basic Rate ACL Stats
     * 17: EDR ACL Stats Data
     *      1: Null Packets Received
     *      1 >> 16: Poll Packets Received
     *      1 >> 32: DM1 Packets Received
     *      high(1) >> 16: 2DH1 Packets Received
     *      ... [lots of decoding]
     *      57: TestMode Packet Errors
     * 16: Basic Rate ACL Stats Data
     *      [also lots of decoding]
     * 
     * Generic Class is PLDecoder
     * ... it even has PLDecoder setSamplesArray ?!
     */
    
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
		dissect_lmp_sent(tvb, pinfo, tree, offset);
		break;
	case DIA_LM_RECV:
		dissect_lmp_received(type_tree, tvb, offset);
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
	btbrlmp_handle = find_dissector("btbrlmp");
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
