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
#define DIA_ACL_BR			0x16
#define DIA_ACL_EDR			0x17
#define DIA_LE_SENT			0x80
#define DIA_LE_RECV			0x81
#define DIA_ACL_BR_RESET		0xb9
#define DIA_ACL_BR_GET			0xc1
#define DIA_ACL_EDR_GET			0xc2
#define DIA_LM_ENABLE			0xf0


/* function prototypes */
void proto_reg_handoff_h4bcm(void);

/* initialize the protocol and registered fields */
static int proto_h4bcm = -1;
static int hf_h4bcm_type = -1;
static int hf_h4bcm_lmp = -1;
static int hf_h4bcm_clock = -1;
static int hf_h4bcm_maclow = -1;
static int hf_h4bcm_payload = -1;

/* initialize the subtree pointers */
static gint ett_h4bcm = -1;
static gint ett_h4bcm_type = -1;
static gint ett_h4bcm_lmp = -1;

/* subdissectors */
static dissector_handle_t btbrlmp_handle = NULL; //TODO lmp handover

/* reversed Broadcom diagnostic types */
static const value_string h4bcm_types[] = {
	{ DIA_LM_SENT, "LM Sent" },
	{ DIA_LM_RECV, "LM Received" },
	{ DIA_ACL_BR, "Basic Rate ACL Stats Data" },
	{ DIA_ACL_EDR, "EDR ACL Stats Data" },
	{ DIA_LE_SENT, "LE LM Sent" }, //Low Energy LL Control PDU LMP Message
	{ DIA_LE_RECV, "LE LM Received" },
	{ DIA_ACL_BR_RESET, "Reset Basic Rate ACL Stats" },
	{ DIA_ACL_BR_GET, "Get Basic Rate ACL Stats" },
	{ DIA_ACL_EDR_GET, "Get EDR ACL Stats" },
	{ DIA_LM_ENABLE, "Toggle LMP Logging" },
};

void
dissect_lmp_sent(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_tree_add_item(tree, hf_h4bcm_clock, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_h4bcm_maclow, tvb, offset, 4, ENC_LITTLE_ENDIAN); //MAC addr of slave (or the station we connected to?)
	offset += 4;
	proto_tree_add_item(tree, hf_h4bcm_payload, tvb, offset, 17, ENC_LITTLE_ENDIAN); //still slave despite the direction
	//TODO handover to lmp dissector
}

void
dissect_lmp_received(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_tree_add_item(tree, hf_h4bcm_clock, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	proto_tree_add_item(tree, hf_h4bcm_maclow, tvb, offset, 4, ENC_LITTLE_ENDIAN); //still slave despite the direction
	offset += 8;
	proto_tree_add_item(tree, hf_h4bcm_payload, tvb, offset, 17, ENC_LITTLE_ENDIAN); //still slave despite the direction
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
		dissect_lmp_sent(type_tree, tvb, offset);
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
		//TODO lmp subtree ?
		{ &hf_h4bcm_clock,
			{ "Clock", "h4bcm.clock",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Bluetooth Master Clock", HFILL }
		},
		{ &hf_h4bcm_maclow,
			{ "MAC Address", "h4bcm.maclow",
			FT_BYTES, SEP_COLON, NULL, 0x0,
			"Lower MAC address part, sufficient for l2ping ff:ff:maclow", HFILL }
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
	
	// hci_h4.type == 0x07
	dissector_add_uint("hci_h4.type", 0x07, h4bcm_handle);
	//btbrlmp_handle = find_dissector("btbrlmp");
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
