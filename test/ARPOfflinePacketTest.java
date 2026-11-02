
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.protocol.JProtocol;

public class ARPOfflinePacketTest {

    static JMemoryPacket buildGatewayReply(String senderMAC) {

		String ethernetDestination = "020000000001";

		String senderIP = "C0000201";  // 192.0.2.1

		String targetMAC = "020000000001";
		String targetIP = "C0000202";  // 192.0.2.2

		String arpHex =
				ethernetDestination
			  + senderMAC
			  + "0806"
			  + "0001"
			  + "0800"
			  + "06"
			  + "04"
			  + "0002"
			  + senderMAC
			  + senderIP
			  + targetMAC
			  + targetIP;

		return new JMemoryPacket(
				JProtocol.ETHERNET_ID,
				arpHex
		);
	}

    static void sendOfflinePacket(String label, String mac) {

        System.out.println("\n========== " + label + " ==========");

        JMemoryPacket packet = buildGatewayReply(mac);

        Dump_ARP_Spoofing_Detection.processArpPacket(packet);
    }

    public static void main(String[] args) {
		
		// Load network configuration
		Dump_ARP_Spoofing_Detection.configureForTest();

        Dump_ARP_Spoofing_Detection.setTestMode(true);

        Dump_ARP_Spoofing_Detection.resetDetectionStateForTest();

        System.out.println("==========================================");
        System.out.println("       GATEWAY RECOVERY TEST");
        System.out.println("==========================================");

        // TEST 1: Trusted Gateway MAC
		sendOfflinePacket(
			"TEST 1: TRUSTED GATEWAY MAC",
			"0200000000A1"
		);

		// TEST 2: Suspicious Gateway MAC
		sendOfflinePacket(
			"TEST 2: CHANGE TO FAKE MAC",
			"020000000099"
		);

		// TEST 3: Return to Trusted Gateway MAC
		sendOfflinePacket(
			"TEST 3: RECOVERY TO TRUSTED MAC",
			"0200000000A1"
		);

		// TEST 4: Same fake MAC appears again
		sendOfflinePacket(
			"TEST 4: FAKE MAC APPEARS AGAIN",
			"020000000099"
		);

        System.out.println("\n==========================================");
        System.out.println("       GATEWAY RECOVERY TEST COMPLETED");
        System.out.println("==========================================");
    }
}
