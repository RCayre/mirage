from mirage.libs.zigbee_utils.rzusbstick import *
from mirage.libs.zigbee_utils.packets import *
from mirage.libs.zigbee_utils.helpers import *
from mirage.libs.zigbee_utils.pcap import *
from mirage.libs.zigbee_utils.scapy_xbee_layers import *
from mirage.libs import wireless
from mirage.core.module import *
import struct

class ZigbeeEmitter(wireless.Emitter):
	def __init__(self,interface):
		deviceClass = None
		if "rzusbstick" in interface:
			deviceClass = RZUSBStickDevice
		elif interface[-5:] == ".pcap":
			deviceClass = ZigbeePCAPDevice
		super().__init__(interface=interface,deviceType=deviceClass)

	def convert(self,packet):
		frame = Dot15d4(seqnum=packet.sequenceNumber)
		if isinstance(packet,ZigbeeBeaconRequest):
			frame /= Dot15d4Cmd(
						cmd_id="BeaconReq",
						dest_addr=packet.destAddr,
						dest_panid=packet.destPanID
					)
		elif isinstance(packet,ZigbeeAssociationRequest):
			frame /= Dot15d4Cmd(	cmd_id="AssocReq",
						dest_addr=packet.destAddr,
						dest_panid=packet.destPanID,
						src_addr=packet.srcAddr,
						src_panid=packet.srcPanID
				)/Dot15d4CmdAssocReq(
						allocate_address=(1 if packet.allocateAddress else 0),
						security_capability = (1 if packet.securityCapability else 0),
						power_source=(1 if packet.powerSource else 0),
						device_type=(1 if packet.deviceType else 0),
						receiver_on_when_idle=(1 if packet.receiverOnWhenIdle else 0),
						alternate_pan_coordinator=(1 if packet.alternatePanCoordinator else 0)
				)
		elif isinstance(packet,ZigbeeAssociationResponse):
			frame /= Dot15d4Cmd(
						cmd_id="AssocResp",
						dest_addr=packet.destAddr,
						dest_panid=packet.destPanID,
						src_addr=packet.srcAddr
				)/Dot15d4CmdAssocResp(
						short_address=frame.assignedAddr,
						association_status=status
				)
		
		elif isinstance(packet,ZigbeeDataRequest):
			frame /= Dot15d4Cmd(
						cmd_id="DataReq",
						dest_addr=packet.destAddr,
						dest_panid=packet.destPanID,
						src_addr=packet.srcAddr,
						src_panid=packet.srcPanID
				)

		elif isinstance(packet,ZigbeeDisassociationNotification):
			frame /= Dot15d4Cmd(
						cmd_id="DisassocNotify",
							dest_addr=packet.destAddr,
							dest_panid=packet.destPanID,
							src_addr=packet.srcAddr,
						src_panid=packet.srcPanID
				)/Dot15d4CmdDisassociation(disassociation_reason=packet.reason)

		elif isinstance(packet,ZigbeeAcknowledgment):
			frame /= Dot15d4Ack()
		elif isinstance(packet,ZigbeeXBeeData):
			frame /= Dot15d4Data(
						dest_addr=packet.destAddr,
						dest_panid=packet.destPanID,
						src_addr=packet.srcAddr
					)/Xbee_Hdr(
						counter=packet.counter,
						unknown=packet.unknown
					)/packet.data
				
		elif isinstance(packet,ZigbeeApplicationData):
			frame /= Dot15d4Data(
						dest_addr=packet.destAddr,
						dest_panid=packet.destPanID,
						src_addr=packet.srcAddr
					)/ZigbeeAppDataPayload(packet.data)
		elif isinstance(packet,ZigbeeApplicationEncryptedData):
			frame /= Dot15d4Data(
						dest_addr=packet.destAddr,
						dest_panid=packet.destPanID,
						src_addr=packet.srcAddr
					)/ZigbeeSecurityHeader(
						nwk_seclevel=packet.securityLevel,
						key_type=packet.keyType,
						fc=packet.frameCounter,
						data=packet.data,
						mic=frame.mic
				)

			if packet.source is not None:
				frame.source = packet.source
				frame.extended_nonce=1
						
			if packet.keySequenceNumber is not None:
				frame.key_seqnum = packet.keySequenceNumber

		if isinstance(packet,ZigbeeAssociationRequest) or isinstance(packet,ZigbeeBeaconRequest) or isinstance(packet,ZigbeeDataRequest) or isinstance(packet,ZigbeeXBeeData) or isinstance(packet,ZigbeeApplicationData) or isinstance(packet,ZigbeeApplicationEncryptedData):
			frame.fcf_ackreq = 1
		
		if hasattr(packet,"srcAddr"):
			if packet.srcAddr <= 0xFFFF:
				frame.fcf_srcaddrmode = "Short"
			else:
				frame.fcf_srcaddrmode = "Long"
		else:
			frame.fcf_srcaddrmode = "None"

		if hasattr(packet,"destAddr"):
			if packet.destAddr <= 0xFFFF:
				frame.fcf_destaddrmode = "Short"
			else:
				frame.fcf_destaddrmode = "Long"
		else:
			frame.fcf_destaddrmode = "None"
		#frame.show()
		return frame

class ZigbeeReceiver(wireless.Receiver):
	def __init__(self,interface):
		deviceClass = None
		if "rzusbstick" in interface:
			deviceClass = RZUSBStickDevice
		elif interface[-5:] == ".pcap":
			deviceClass = ZigbeePCAPDevice
		super().__init__(interface=interface,deviceType=deviceClass)

	def convert(self,packet):
		if "rzusbstick" in self.interface:
			(channel,rssi,validCrc,linkQualityIndicator,frame) = packet
		else:
			frame = packet
		new = ZigbeePacket(sequenceNumber=frame.seqnum,data=raw(frame))
		new.packet = frame

		if frame[Dot15d4].fcf_frametype == 0 or Dot15d4Beacon in frame: 
			new = ZigbeeBeacon(
						sequenceNumber=frame.seqnum,
						srcAddr=frame.src_addr,
						srcPanID=frame.src_panid,
						assocPermit=frame.sf_assocpermit,
						coordinator=frame.sf_pancoord,
						payload=False
					)
			if ZigBeeBeacon in frame:
		                new.payload = True
		                new.endDeviceCapacity=frame.end_device_capacity
		                new.routerCapacity=frame.router_capacity
		                new.extendedPanID=':'.join('{:02x}'.format(i).upper() for i in struct.pack('>Q',frame.extended_pan_id))
		elif frame[Dot15d4].fcf_frametype == 1 or Dot15d4Data in frame:
			if b"\r\n" == raw(frame[Dot15d4Data:])[-4:-2]:
				xbeeData = Xbee_Hdr(raw(frame[Dot15d4Data:][1:]))
				new = ZigbeeXBeeData(srcAddr=frame.src_addr,destAddr=frame.dest_addr,destPanID=frame.dest_panid,data=raw(xbeeData)[2:-2],counter=xbeeData.counter,unknown=xbeeData.unknown)

			elif (ZigbeeAppDataPayload in frame and frame.frame_control & 0x02) or ZigbeeSecurityHeader in frame:
				new = ZigbeeApplicationEncryptedData(
									sequenceNumber=frame.seqnum,
									srcAddr=frame.src_addr,
									destAddr=frame.dest_addr,
									destPanID=frame.dest_panid,
									keyType=frame.key_type,
									securityLevel=frame.nwk_seclevel,
									frameCounter=frame.fc,
									data=frame.data,
									mic=frame.mic
								)
				if frame.extended_nonce == 1:
					new.source = frame[ZigbeeSecurityHeader].source
				if frame.key_type == 1:
					new.keySequenceNumber = frame.key_seqnum
			elif (ZigbeeAppDataPayload in frame and frame.aps_frametype == 0):
				new = ZigbeeApplicationData(
								sequenceNumber=frame.seqnum,
								srcAddr=frame.src_addr,
								destAddr=frame.dest_addr,
								destPanID=frame.dest_panid,
								data=raw(frame[ZigbeeAppDataPayload:]))
			
		elif frame[Dot15d4].fcf_frametype == 2 or Dot15d4Ack in frame:
			new = ZigbeeAcknowledgment(sequenceNumber=frame.seqnum)
		elif frame[Dot15d4].fcf_frametype == 3 or Dot15d4Cmd in frame:
			if frame.cmd_id == 1:
				new = ZigbeeAssociationRequest(
								sequenceNumber=frame.seqnum,
								srcAddr=frame.src_addr,
								destAddr=frame.dest_addr,
								srcPanID=frame.src_panid,
								destPanID=frame.dest_panid,
								allocateAddress=(frame.allocate_address == 1),
								securityCapability=(frame.security_capability==1),
								receiverOnWhenIdle=(frame.receiver_on_when_idle==1),
								powerSource=(frame.power_source==1),
								deviceType=(frame.device_type==1),
								alternatePanCoordinator=(frame.alternate_pan_coordinator==1)
							)
				
			elif frame.cmd_id == 2:
				new = ZigbeeAssociationResponse(
								sequenceNumber=frame.seqnum,
								srcAddr=frame.src_addr,
								destAddr=frame.dest_addr,
								destPanID=frame.dest_panid,
								assignedAddr=frame.short_address,
								status=frame.association_status
							)
			elif frame.cmd_id == 3:
				new = ZigbeeDisassociationNotification(
								sequenceNumber=frame.seqnum,
								srcAddr=frame.src_addr,
								srcPanID=frame.src_panid,
								destAddr=frame.dest_addr,
								destPanID=frame.dest_panid,
								reason=frame.disassociation_reason
								)
			elif frame.cmd_id == 4:
				new = ZigbeeDataRequest(
								sequenceNumber=frame.seqnum,
								srcAddr=frame.src_addr,
								destPanID=frame.dest_panid,
								destAddr=frame.dest_addr
							)

			elif frame.cmd_id == 7:
				new = ZigbeeBeaconRequest(
								sequenceNumber=frame.seqnum,
								destAddr=frame.dest_addr,
								destPanID=frame.dest_panid
							)

			
		if "rzusbstick" in self.interface:
			new.additionalInformations = ZigbeeSniffingParameters(
										rssi = rssi,
										linkQualityIndicator = linkQualityIndicator,
										validCrc = validCrc,
										channel = channel
									)

		return new

WirelessModule.registerEmitter("zigbee",ZigbeeEmitter)
WirelessModule.registerReceiver("zigbee",ZigbeeReceiver)
