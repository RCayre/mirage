from scapy.all import *

'''
This module contains some scapy definitions for communicating with an HCI device.
'''

class HCI_Cmd_LE_Rand(Packet):
	name = "HCI Command LE Rand"
	fields_desc = []	

class HCI_LE_Meta_Enhanced_Connection_Complete(Packet):
    name = "Enhanced Connection Complete"
    fields_desc = [ByteEnumField("status", 0, {0: "success"}),
                   LEShortField("handle", 0),
                   ByteEnumField("role", 0, {0: "master"}),
                   ByteEnumField("patype", 0, {0: "public", 1: "random"}),
                   LEMACField("paddr", None),
                   LEMACField("localresolvprivaddr", None),
                   LEMACField("peerresolvprivaddr", None),
                   LEShortField("interval", 54),
                   LEShortField("latency", 0),
                   LEShortField("supervision", 42),
                   XByteField("clock_latency", 5), ]

    def answers(self, other):
        if HCI_Cmd_LE_Create_Connection not in other:
            return False

        return (other[HCI_Cmd_LE_Create_Connection].patype == self.patype and
                other[HCI_Cmd_LE_Create_Connection].paddr == self.paddr)



class SM_Security_Request(Packet):
    name = "Security Request"
    fields_desc = [BitField("authentication", 0, 8)]

bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Rand, opcode=0x2018)
bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Enhanced_Connection_Complete, event = 0xa)
bind_layers(SM_Hdr, SM_Security_Request, sm_command=0xb)
