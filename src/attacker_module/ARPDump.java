package attacker_module;

import java.io.IOException;
import java.net.InetAddress;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;

public class ARPDump {
	public static void main(String[] args)
			throws IOException, PcapNativeException, InterruptedException, NotOpenException {
		PcapWrapper pcap = new PcapWrapper();
		System.out.println("SrcIP: " + pcap.getSrcIp());
		System.out.println("SrcMAC: " + pcap.getSrcMac());

		PacketListener listener = new PacketListener() {
			@Override
			public void gotPacket(Packet packet) {
				if (packet.contains(ArpPacket.class)) {
					ArpPacket arp = packet.get(ArpPacket.class);
					InetAddress srcIp = arp.getHeader().getSrcProtocolAddr();
					InetAddress dstIp = arp.getHeader().getDstProtocolAddr();
					MacAddress srcMac = arp.getHeader().getSrcHardwareAddr();
					MacAddress dstMac = arp.getHeader().getDstHardwareAddr();
					EthernetPacket eth = packet.get(EthernetPacket.class);
					MacAddress ethSrcMac = eth.getHeader().getSrcAddr();
					if(arp.getHeader().getOperation().equals(ArpOperation.REQUEST)) {
						System.out.println("Who has " + dstIp + "? Tell " + srcIp);
					} else if(arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
						System.out.println(srcIp + " is at " + srcMac);
					}
				}
			}
		};

		pcap.loop(-1, listener);
	}
}
