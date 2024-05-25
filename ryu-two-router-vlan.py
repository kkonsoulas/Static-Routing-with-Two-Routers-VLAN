# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches interconnected forming two vlans.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import vlan
from ryu.lib.packet import ether_types
from ryu.lib.packet import icmp
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.ofproto.ofproto_v1_0_parser import OFPPacketIn
import array




class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # self.vlan_to_mac_to_port.setdefault(0x2,{})
        # self.vlan_to_mac_to_port.setdefault(0x3,{})
        
        #init static info
        self.DPIDtoDATA = {}
        self.DPIDtoDATA.setdefault(0x1A,{})
        self.DPIDtoDATA[0x1A]["LANMAC"] = "00:00:00:00:01:01"
        self.DPIDtoDATA[0x1A]["NETMAC"] = '00:00:00:00:03:01'
        self.DPIDtoDATA[0x1A]["NETMACDST"] = '00:00:00:00:03:02'
        self.DPIDtoDATA[0x1A]["PRIORITYMAC"] = '00:00:00:00:05:01'
        self.DPIDtoDATA[0x1A]["IP"] = "192.168.1.1"
        self.DPIDtoDATA[0x1A]["NETMASK"] = "192.168.1."
        self.DPIDtoDATA[0x1A]["LANPORT"] = 2
        self.DPIDtoDATA[0x1A]["NETPORT"] = 1
        self.DPIDtoDATA[0x1A]["PRIORITYPORT"] = 4

        self.DPIDtoDATA.setdefault(0x1B,{})
        self.DPIDtoDATA[0x1B]["LANMAC"] = "00:00:00:00:02:01"
        self.DPIDtoDATA[0x1B]["NETMAC"] = '00:00:00:00:03:02'
        self.DPIDtoDATA[0x1B]["NETMACDST"] = '00:00:00:00:03:01'
        self.DPIDtoDATA[0x1B]["PRIORITYMAC"] = '00:00:00:00:05:02'
        self.DPIDtoDATA[0x1B]["IP"] = "192.168.2.1"
        self.DPIDtoDATA[0x1B]["NETMASK"] = "192.168.2."
        self.DPIDtoDATA[0x1B]["LANPORT"] = 2
        self.DPIDtoDATA[0x1B]["NETPORT"] = 1
        self.DPIDtoDATA[0x1B]["PRIORITYPORT"] = 4

        self.IPtoMAC = {}
        self.IPtoMAC["192.168.1.2"] = "00:00:00:00:01:02"
        self.IPtoMAC["192.168.1.3"] = "00:00:00:00:01:03"
        self.IPtoMAC["192.168.2.2"] = "00:00:00:00:02:02"
        self.IPtoMAC["192.168.2.3"] = "00:00:00:00:02:03"

        self.DPIDtoVLAN={}
        self.DPIDtoVLAN.setdefault(0x2,{})
        self.DPIDtoVLAN[0x2]["TRUNKPORT"] = {1}
        self.DPIDtoVLAN[0x2][100] = {2,3}
        self.DPIDtoVLAN[0x2][200] = {4}
        self.DPIDtoVLAN.setdefault(0x3,{})
        self.DPIDtoVLAN[0x3]["TRUNKPORT"] = {1}
        self.DPIDtoVLAN[0x3][100] = {4}
        self.DPIDtoVLAN[0x3][200] = {2,3}
        
        self.VLANIDS = {100,200}



    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        # print(type(datapath))
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)

        #if dpid == router then handle it here
        if self.routerPktHandler(dpid,msg):
            return

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port
        
        # print("We are at dpid: "+str(dpid))

        #get vlan id of switch's port
        for vlanId in self.DPIDtoVLAN[dpid]:
            if msg.in_port in self.DPIDtoVLAN[dpid][vlanId]:    
                break
        
        actions=[]
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

            #check if packet came from trunkport and extract vid
            if ethertype == ether_types.ETH_TYPE_8021Q:
                vlanPacket = pkt.get_protocol(vlan.vlan)
                vlanId = vlanPacket.vid
                actions.append(datapath.ofproto_parser.OFPActionStripVlan())
                # print("Came from trunk port and the dst mac is known")
            
            #if to be sent to trunkport tag it
            if out_port in self.DPIDtoVLAN[dpid]["TRUNKPORT"]:
                actions.append(datapath.ofproto_parser.OFPActionVlanVid(vlanId))
                msg.buffer_id = ofproto.OFP_NO_BUFFER

            #return if it is destined for the wrong vlan
            if out_port not in self.DPIDtoVLAN[dpid]["TRUNKPORT"] and out_port not in self.DPIDtoVLAN[dpid][vlanId]:
                print("outport not in vlan id")
                return
            
            # print("Known Mac")
            #send the packet and add flow
            actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
        else:#broadcast

            #packet from access port
            if ethertype !=  ether_types.ETH_TYPE_8021Q: 
                #send packet to VLAN access ports
                ports = self.DPIDtoVLAN[dpid][vlanId]
                ports.remove(msg.in_port)
                for p in ports:
                    actions.append(datapath.ofproto_parser.OFPActionOutput(p))
                ports.add(msg.in_port)
                msg.buffer_id = ofproto.OFP_NO_BUFFER
                self.sendPkt(datapath,msg,actions)
                
                #create vlan packet to send to trunk port
                vlanPacket = vlan.vlan(vid=vlanId,ethertype=ethertype)
                eth = ethernet.ethernet(dst=eth.dst,src=eth.src,ethertype=ether_types.ETH_TYPE_8021Q)
                newPacket = packet.Packet()
                newPacket.add_protocol(eth)
                newPacket.add_protocol(vlanPacket)

                #remove old ethernet packet (with wrong ethertype)
                protocols = pkt.protocols
                protocols.pop(0)

                #add remaining protocols of packet
                for p in protocols:
                    newPacket.add_protocol(p)
                 
                newPacket.serialize()


                #update the msg
                msg.data = newPacket.data
                msg.buffer_id = ofproto.OFP_NO_BUFFER

                #send to trunkport
                self.sendPkt(datapath,msg,[datapath.ofproto_parser.OFPActionOutput(1)])
                return

            # print("Unknown mac, came from trunk port (flood)")
            vlanPacket = pkt.get_protocol(vlan.vlan)
            vlanId = vlanPacket.vid
            actions.append(datapath.ofproto_parser.OFPActionStripVlan())
            ports = self.DPIDtoVLAN[dpid][vlanId]
            out_port = ofproto.OFPP_FLOOD #for not getting added as a flow
            # print("I have an encapsulated packet")
            for p in ports:
                actions.append(datapath.ofproto_parser.OFPActionOutput(p))
            msg.buffer_id = ofproto.OFP_NO_BUFFER
            
            

        match = datapath.ofproto_parser.OFPMatch(
            in_port=msg.in_port, dl_dst=haddr_to_bin(dst))

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

        return

    def routerPktHandler(self,dpid:int,msg: OFPPacketIn):
        if dpid not in self.DPIDtoDATA:
            #not a router
            return False
        
        datapath = msg.datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
            
            arpPacket =  pkt.get_protocol(arp.arp)

            if arpPacket.dst_ip != self.DPIDtoDATA[dpid]["IP"]:
                return True

            #prepare arp fields
            arpPacket.opcode = 2
            arpPacket.dst_mac = arpPacket.src_mac
            arpPacket.src_mac = self.DPIDtoDATA[dpid]["LANMAC"]
            arpPacket.src_ip , arpPacket.dst_ip = arpPacket.dst_ip, arpPacket.src_ip
               
            #prepare ethernet fields
            eth.dst = arpPacket.dst_mac
            eth.src = arpPacket.src_mac
               
            #create packet
            pkt = packet.Packet()
            pkt.add_protocol(eth)
            pkt.add_protocol(arpPacket)
            pkt.serialize()

            #configure data and send parameters
            out_port = msg.in_port
            msg.data = pkt.data
            msg.buffer_id = ofproto.OFP_NO_BUFFER
            msg.in_port = ofproto.OFPP_CONTROLLER
            #configure action
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            
            #send packet
            self.sendPkt(datapath,msg,actions)
        elif eth.ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
            ipPacket = pkt.get_protocol(ipv4.ipv4)

            if ipPacket.dst.startswith(self.DPIDtoDATA[dpid]["NETMASK"]):
                src = self.DPIDtoDATA[dpid]["LANMAC"]
                out_port = self.DPIDtoDATA[dpid]["LANPORT"]
                dst = self.IPtoMAC[ipPacket.dst]
            elif ipPacket.dst.startswith('192.168.2.') or ipPacket.dst.startswith('192.168.1.') :
                src = self.DPIDtoDATA[dpid]["NETMAC"]
                out_port=self.DPIDtoDATA[dpid]["NETPORT"]
                dst = self.DPIDtoDATA[dpid]["NETMACDST"]
            else:
                oldIcmpPacket = pkt.get_protocol(icmp.icmp)
                icmpData = icmp.dest_unreach(data=msg.data[14:])
                icmpPacket = icmp.icmp(csum=0,code= 1,type_=icmp.ICMP_DEST_UNREACH ,data=icmpData)

                pkt = packet.Packet()
                #ethernet config
                eth.src , eth.dst = eth.dst, eth.src
                pkt.add_protocol(eth)
                #ip config
                ipDst = ipPacket.src
                ipSrc = self.DPIDtoDATA[dpid]["IP"]
                ipPacket = ipv4.ipv4(src = ipSrc,dst=ipDst,proto=ipPacket.proto)
                pkt.add_protocol(ipPacket)
                #add icmp
                pkt.add_protocol(icmpPacket)
                pkt.serialize()
                
                #configure data to be sent
                out_port = msg.in_port
                msg.data = pkt.data
                msg.buffer_id = ofproto.OFP_NO_BUFFER
                msg.in_port = ofproto.OFPP_CONTROLLER
                actions= [datapath.ofproto_parser.OFPActionOutput(out_port)]

                self.sendPkt(datapath,msg,actions)
                return True
                
                
            #add flow
            actions = [datapath.ofproto_parser.OFPActionSetDlDst(dst),
                       datapath.ofproto_parser.OFPActionSetDlSrc(src),
                       datapath.ofproto_parser.OFPActionOutput(out_port)]
            
            if ipPacket.dst.startswith(self.DPIDtoDATA[dpid]["NETMASK"]):
                match = datapath.ofproto_parser.OFPMatch(nw_dst=ipPacket.dst ,dl_type=0x0800)
            else:
                match = datapath.ofproto_parser.OFPMatch(nw_dst_mask=24,nw_dst=ipPacket.dst ,dl_type=0x0800)             
            self.add_flow(datapath=datapath,match=match,actions=actions)
            
            #send packet
            self.sendPkt(datapath,msg,actions)

        return True

    def sendPkt(self,datapath,msg:OFPPacketIn,actions:list):
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=msg.data)
        datapath.send_msg(out)
        return

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = msg.datapath_id

        self.logger.info("Datapath ID is %s", hex(dpid))
        # print(type(dpid))
        if dpid == 0x1a:
            match = datapath.ofproto_parser.OFPMatch(nw_dst_mask=24,nw_dst="192.168.2.1",nw_tos=8 ,dl_type=0x0800)
            actions = [
                datapath.ofproto_parser.OFPActionOutput(4),
                datapath.ofproto_parser.OFPActionSetDlSrc('00:00:00:00:05:01'),
                datapath.ofproto_parser.OFPActionSetDlDst('00:00:00:00:05:02')
                ]
            self.add_flow( datapath, match, actions )
            
        elif dpid == 0x1b:
            match = datapath.ofproto_parser.OFPMatch(nw_dst_mask=24,nw_dst="192.168.1.1",nw_tos=8 ,dl_type=0x0800)
            actions = [
                datapath.ofproto_parser.OFPActionOutput(4),
                datapath.ofproto_parser.OFPActionSetDlSrc('00:00:00:00:05:02'),
                datapath.ofproto_parser.OFPActionSetDlDst('00:00:00:00:05:01')
                ]
            self.add_flow( datapath, match, actions )

        return


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
