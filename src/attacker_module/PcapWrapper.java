package attacker_module;

import java.io.IOException;
import java.net.InetAddress;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

public class PcapWrapper {
	private static final int SNAPLEN = 65535;
	private static final int TIMEOUT = 10;

	private PcapNetworkInterface nif;
	private final InetAddress srcIp;
	private final MacAddress srcMac;
	private final PcapHandle handle;
	private final PcapHandle sendHandle;

	public PcapWrapper() throws IOException, PcapNativeException {
		nif = new NifSelector().selectNetworkInterface();
		srcIp = nif.getAddresses().get(1).getAddress();
		srcMac = MacAddress.getByAddress(nif.getLinkLayerAddresses().get(0).getAddress());
		handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, TIMEOUT);
		sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, TIMEOUT);
	}
	
	public InetAddress getSrcIp() {
		return srcIp;
	}
	
	public MacAddress getSrcMac() {
		return srcMac;
	}

	public void loop(int count, PacketListener listener)
			throws PcapNativeException, InterruptedException, NotOpenException {
		handle.loop(count, listener);
	}

	public void send(Packet packet) throws PcapNativeException, NotOpenException {
		sendHandle.sendPacket(packet);
	}
}
