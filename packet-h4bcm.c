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
#include <stdio.h> //TODO remove after debugging

/* function prototypes */
void proto_reg_handoff_h4bcm(void);

/* initialize the protocol and registered fields */
static int proto_h4bcm = -1;
static int hf_h4bcm_type = -1;

/* field values */
// static const true_false_string direction = {
// 	"Slave to Master",
// 	"Master to Slave"
// };


/* initialize the subtree pointers */
static gint ett_h4bcm = -1;
static gint ett_h4bcm_type = -1;

/* subdissectors */
static dissector_handle_t btbrlmp_handle = NULL; //TODO we might also be able to use this one ourselves :)




/* dissect a packet */
static int
dissect_h4bcm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *h4bcm_item, *type_item;
	proto_tree *h4bcm_tree, *type_tree;
	int offset;
    
    
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
     * if h4_ref == 0x81 (??): Direction is Receive, else Sent
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
     * 80/81 seems to be BLE link layer
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

	if (tree) {
	/* create display subtree for the protocol */
		offset = 0;
		h4bcm_item = proto_tree_add_item(tree, proto_h4bcm, tvb, offset, -1, ENC_NA);
		h4bcm_tree = proto_item_add_subtree(h4bcm_item, ett_h4bcm);
		
		/* type / opcode */
		type_item = proto_tree_add_item(h4bcm_tree, hf_h4bcm_type, tvb, offset, 1, ENC_NA);
		type_tree = proto_item_add_subtree(type_item, ett_h4bcm_type);
        
	}
// 	/* see if we are being asked for details */
// 	if (tree) {
// 
// 
// 		/* ID packets have no header, no payload */
// 		if (tvb_reported_length(tvb) == 0)
// 			return 1;
// 
// 		/* meta data */
// 		meta_item = proto_tree_add_item(h4bcm_tree, hf_h4bcm_meta, tvb, offset, 3, ENC_NA);
// 		meta_tree = proto_item_add_subtree(meta_item, ett_h4bcm_meta);
// 
// 		proto_tree_add_item(meta_tree, hf_h4bcm_dir, tvb, offset, 1, ENC_NA);
// 		proto_tree_add_item(meta_tree, hf_h4bcm_clk, tvb, offset, 4, ENC_LITTLE_ENDIAN);
// 		offset += 4;
// 
// 		proto_tree_add_item(meta_tree, hf_h4bcm_channel, tvb, offset, 1, ENC_NA);
// 		offset += 1;
// 
// 		proto_tree_add_item(meta_tree, hf_h4bcm_clkbits, tvb, offset, 1, ENC_NA);
// 		proto_tree_add_item(meta_tree, hf_h4bcm_addrbits, tvb, offset, 1, ENC_NA);
// 		offset += 1;
// 
// 		/* packet header */
// 		pkthdr_item = proto_tree_add_item(h4bcm_tree, hf_h4bcm_pkthdr, tvb, offset, 3, ENC_NA);
// 		pkthdr_tree = proto_item_add_subtree(pkthdr_item, ett_h4bcm_pkthdr);
// 
// 		proto_tree_add_item(pkthdr_tree, hf_h4bcm_ltaddr, tvb, offset, 1, ENC_NA);
// 		proto_tree_add_item(pkthdr_tree, hf_h4bcm_type, tvb, offset, 1, ENC_NA);
// 		offset += 1;
// 		proto_tree_add_bitmask(pkthdr_tree, tvb, offset, hf_h4bcm_flags,
// 			ett_h4bcm_flags, flag_fields, ENC_NA);
// 		offset += 1;
// 		proto_tree_add_item(pkthdr_tree, hf_h4bcm_hec, tvb, offset, 1, ENC_NA);
// 		offset += 1;
// 
// 		/* payload */
// 		switch (type) {
// 		case 0x0: /* NULL */
// 		case 0x1: /* POLL */
// 			break;
// 		case 0x2: /* FHS */
// 			dissect_fhs(h4bcm_tree, tvb, offset);
// 			break;
// 		case 0x3: /* DM1 */
// 			dissect_dm1(h4bcm_tree, tvb, pinfo, offset);
// 			break;
// 		case 0x4: /* DH1/2-DH1 */
// 			dissect_dm1(h4bcm_tree, tvb, pinfo, offset);
// 			break;
// 		case 0x5: /* HV1 */
// 		case 0x6: /* HV2/2-EV3 */
// 		case 0x7: /* HV3/EV3/3-EV3 */
// 		case 0x8: /* DV/3-DH1 */
// 		case 0x9: /* AUX1 */
// 		case 0xa: /* DM3/2-DH3 */
// 		case 0xb: /* DH3/3-DH3 */
// 		case 0xc: /* EV4/2-EV5 */
// 		case 0xd: /* EV5/3-EV5 */
// 		case 0xe: /* DM5/2-DH5 */
// 		case 0xf: /* DH5/3-DH5 */
// 			proto_tree_add_item(h4bcm_tree, hf_h4bcm_payload, tvb, offset, -1, ENC_NA);
// 			break;
// 		default:
// 			break;
// 		}
// 	}

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
			FT_NONE, BASE_NONE, NULL, 0x0,
			"Diagnostic information type", HFILL }
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
