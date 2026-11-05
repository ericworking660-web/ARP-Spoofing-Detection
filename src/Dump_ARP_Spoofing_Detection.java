import java.io.FileInputStream;
import java.util.Properties;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.packet.format.FormatUtils;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.protocol.JProtocol;

public class Dump_ARP_Spoofing_Detection {

    // =========================================
    // 1. Network Configuration
	// =========================================

	private static String DEVICE_KEYWORD;
	private static String LOCAL_IP;
	private static String LOCAL_MAC;
	private static String GATEWAY_IP;
	private static String GATEWAY_MAC;
    // =========================================
    // 2. Detection Database
    // =========================================

    // 保存第一次觀察到的 IP-MAC Mapping
    private static final Map<String, String> ipMacTable =
            new HashMap<String, String>();

    // 避免相同異常組合重複告警
    private static final Set<String> alertedPairs =
            new HashSet<String>();
	// 記錄每種異常組合的發生次數
	private static Map<String, Integer> eventCounts =
			new HashMap<String, Integer>();

	// Separate log files for testing and live monitoring
	private static final String TEST_LOG_FILE =
			"ARP_Detection_Test_Log.csv";

	private static final String LIVE_LOG_FILE =
			"ARP_Detection_Live_Log.csv";

	// Default mode
	private static boolean TEST_MODE = false;

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
	// =========================================
	// Load Network Configuration
	// =========================================

	static void loadConfig() {

		Properties config = new Properties();

		try (FileInputStream input =
				new FileInputStream("config.properties")) {

			config.load(input);

			DEVICE_KEYWORD =
					config.getProperty("device.keyword");

			LOCAL_IP =
					config.getProperty("local.ip");

			LOCAL_MAC =
					config.getProperty("local.mac");

			GATEWAY_IP =
					config.getProperty("gateway.ip");

			GATEWAY_MAC =
					config.getProperty("gateway.mac");

			// Validate required parameters
			if (DEVICE_KEYWORD == null
					|| LOCAL_IP == null
					|| LOCAL_MAC == null
					|| GATEWAY_IP == null
					|| GATEWAY_MAC == null) {

				throw new IllegalArgumentException(
						"Missing required configuration parameters!"
				);
			}

			if (DEVICE_KEYWORD.trim().isEmpty()
					|| LOCAL_IP.trim().isEmpty()
					|| LOCAL_MAC.trim().isEmpty()
					|| GATEWAY_IP.trim().isEmpty()
					|| GATEWAY_MAC.trim().isEmpty()) {

				throw new IllegalArgumentException(
						"Configuration parameters cannot be empty!"
				);
			}

			System.out.println("[CONFIG] Configuration loaded successfully.");

		} catch (Exception e) {

			System.err.println("[CONFIG ERROR] " + e.getMessage());
			throw new IllegalStateException(
					"Cannot initialize network configuration.", e
			);
		}
	}
	// =========================================
	// Test Configuration (Offline Testing Only)
	// =========================================

	static void configureForTest() {

		DEVICE_KEYWORD = "OFFLINE_TEST";

		// Documentation-only test network
		LOCAL_IP = "192.0.2.2";
		LOCAL_MAC = "02:00:00:00:00:01";

		GATEWAY_IP = "192.0.2.1";
		GATEWAY_MAC = "02:00:00:00:00:A1";

		System.out.println(
			"[CONFIG] Offline test configuration loaded."
		);
	}
    // =========================================
    // 3. Main
    // =========================================

    public static void main(String[] args) {
		loadConfig();

        List<PcapIf> alldevs = new ArrayList<PcapIf>();
        StringBuilder errbuf = new StringBuilder();

        // 取得網路介面
        int result = Pcap.findAllDevs(alldevs, errbuf);

        if (result != Pcap.OK || alldevs.isEmpty()) {
            System.err.println(
                    "Cannot find network devices: " + errbuf);
            return;
        }

        System.out.println("========== Network Devices ==========");

        for (int i = 0; i < alldevs.size(); i++) {

            PcapIf d = alldevs.get(i);

            System.out.println("[" + i + "] "
                    + d.getName() + " ==> "
                    + d.getDescription());
        }

        // 依照網卡描述尋找指定介面
        PcapIf device = findDevice(alldevs, DEVICE_KEYWORD);

        if (device == null) {
            System.err.println();
            System.err.println("ERROR: Target network adapter not found!");
            System.err.println("Keyword: " + DEVICE_KEYWORD);
            return;
        }

        System.out.println("\nSelected device: "
                + device.getName());

        System.out.println("Description: "
                + device.getDescription());

        // 初始化本機 IP-MAC 基準
        ipMacTable.put(
                LOCAL_IP,
                normalizeMAC(LOCAL_MAC)
        );

        // =====================================
        // Open Pcap
        // =====================================

        int snaplen = 64 * 1024;
        int flags = Pcap.MODE_PROMISCUOUS;
        int timeout = 1000;

        Pcap pcap = Pcap.openLive(
                device.getName(),
                snaplen,
                flags,
                timeout,
                errbuf
        );

        if (pcap == null) {
            System.err.println(
                    "Open device failed: " + errbuf);
            return;
        }

        System.out.println("\n==========================================");
        System.out.println("       ARP SPOOFING DETECTION");
        System.out.println("==========================================");

        System.out.println("Monitoring interface: "
                + device.getName());

        System.out.println("Local IP      : " + LOCAL_IP);
        System.out.println("Local MAC     : " + LOCAL_MAC);

        System.out.println("Gateway IP    : " + GATEWAY_IP);
        System.out.println("Gateway MAC   : " + GATEWAY_MAC);

        System.out.println("------------------------------------------");
        System.out.println("Detection engine initialized.");
        System.out.println("Waiting for ARP packets...");
        System.out.println("==========================================\n");

        // =====================================
        // ARP Packet Handler
        // =====================================

        PcapPacketHandler<String> handler =
                new PcapPacketHandler<String>() {

            Ethernet eth = new Ethernet();
            Arp arp = new Arp();

             public void nextPacket(
					PcapPacket packet,
					String user) {

				processArpPacket(packet);
			}
        };

        // =====================================
        // Start Capture
        // =====================================

        try {

            int loopResult = pcap.loop(
                    Pcap.LOOP_INFINITE,
                    handler,
                    "ARP Detection"
            );

            System.out.println(
                    "pcap.loop returned: " + loopResult);

        } finally {

            pcap.close();

            System.out.println("Pcap closed.");
        }
    }

    // =========================================
    // 4. Find Network Adapter
    // =========================================

    private static PcapIf findDevice(
            List<PcapIf> devices,
            String keyword) {

        for (PcapIf device : devices) {

            String description = device.getDescription();

            if (description != null
                    && description.toLowerCase().contains(
                            keyword.toLowerCase())) {

                return device;
            }
        }

        return null;
    }

    // =========================================
    // 5. ARP Spoofing Detection
    // =========================================

    
	static void detectSpoofing(String ip, String mac) {

		mac = normalizeMAC(mac);

		if (mac == null) {
			return;
		}

		// =====================================
		// A. Gateway Protection
		// =====================================

		if (GATEWAY_IP.equals(ip)) {

			String trustedMAC = normalizeMAC(GATEWAY_MAC);

			if (trustedMAC.equals(mac)) {

				// Clear previous Gateway alert records
				boolean recovered = alertedPairs.removeIf(
						pair -> pair.startsWith("GATEWAY|" + ip + "|")
				);

				System.out.println(
						"[NORMAL] Trusted Gateway mapping");

				if (recovered) {
					System.out.println(
							"[RECOVERY] Previous Gateway alerts cleared");
				}

			} else {

				String alertKey =
						"GATEWAY|" + ip + "|" + mac;

				// 每次異常都累計並寫入 CSV
				int count = recordEvent(
						alertKey,
						"GATEWAY MAC MISMATCH",
						ip,
						trustedMAC,
						mac
				);

				// 同一異常組合只在 CMD 警告一次
				if (alertedPairs.add(alertKey)) {

					System.out.println();
					System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
					System.out.println("       ALERT: GATEWAY MAC MISMATCH");
					System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

					System.out.println("Gateway IP   : " + ip);
					System.out.println("Trusted MAC  : " + trustedMAC);
					System.out.println("Observed MAC : " + mac);
					System.out.println("Event Count  : " + count);

					System.out.println(
							"Status: Possible Gateway ARP Spoofing");

					System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
					System.out.println();
				}
			}

			return;
		}

		// =====================================
		// B. General IP-MAC Monitoring
		// =====================================

		String oldMAC = ipMacTable.get(ip);

		// First observation
		if (oldMAC == null) {

			ipMacTable.put(ip, mac);

			System.out.println("[LEARN] New IP-MAC mapping");

			System.out.println("  IP  : " + ip);
			System.out.println("  MAC : " + mac);

			return;
		}

		
        // Same IP and MAC
      
        // Same IP and MAC: Recovery / Normal state
        if (oldMAC.equals(mac)) {

            // Clear previous alert records for this Host IP
            boolean recovered = alertedPairs.removeIf(
                pair -> pair.startsWith("HOST|" + ip + "|")
            );

            System.out.println(
                "[NORMAL] IP-MAC mapping unchanged");

            // Show RECOVERY only if a previous alert existed
            if (recovered) {
                System.out.println(
                    "[RECOVERY] Previous Host alerts cleared");
            }

            return;
        }

		// =====================================
		// C. IP-MAC Change Alert
		// =====================================

		String alertKey =
				"HOST|" + ip + "|" + mac;

		int count = recordEvent(
				alertKey,
				"IP-MAC CHANGE",
				ip,
				oldMAC,
				mac
		);

		// 同一異常組合只在 CMD 警告一次
		if (alertedPairs.add(alertKey)) {

			System.out.println();
			System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			System.out.println("       WARNING: POSSIBLE ARP SPOOFING");
			System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

			System.out.println("IP Address   : " + ip);
			System.out.println("Original MAC : " + oldMAC);
			System.out.println("New MAC      : " + mac);
			System.out.println("Event Count  : " + count);

			System.out.println(
					"Status: Suspicious IP-MAC change");

			System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			System.out.println();
		}
	}
	
	
	// =========================================
	// Record Event to CSV
	// =========================================

	private static synchronized int recordEvent(
			String eventKey,
			String eventType,
			String ip,
			String originalMAC,
			String newMAC) {

		// 累計相同異常組合的次數
		int count = eventCounts.containsKey(eventKey)
				? eventCounts.get(eventKey) + 1
				: 1;

		eventCounts.put(eventKey, count);

		String timestamp =
				LocalDateTime.now().format(TIME_FORMAT);

		String source = TEST_MODE ? "TEST" : "LIVE";

		String logFile = TEST_MODE
				? TEST_LOG_FILE
				: LIVE_LOG_FILE;

		File file = new File(logFile);

		boolean writeHeader =
				!file.exists() || file.length() == 0;

		try (FileWriter writer =
				new FileWriter(file, true)) {

			// 第一次建立檔案時寫入欄位名稱
			if (writeHeader) {

				writer.write(
					"Timestamp,Source,Event Type,IP Address,"
					+ "Original MAC,New MAC,Event Count,Status\n"
				);
			}

			// 寫入事件
			writer.write(
				csv(timestamp) + ","
				+ csv(source) + ","
				+ csv(eventType) + ","
				+ csv(ip) + ","
				+ csv(originalMAC) + ","
				+ csv(newMAC) + ","
				+ count + ","
				+ csv("WARNING")
				+ "\n"
			);

			writer.flush();

		} catch (IOException e) {

			System.err.println(
					"[LOG ERROR] Cannot write CSV: "
					+ e.getMessage()
			);
		}

		return count;
	}
	static void setTestMode(boolean enabled) {
		TEST_MODE = enabled;
	}

	// =========================================
	// CSV Field Formatter
	// =========================================

	private static String csv(String value) {

		if (value == null) {
			value = "";
		}

		return "\"" + value.replace("\"", "\"\"") + "\"";
	}



    // =========================================
    // 6. MAC Address Formatter
    // =========================================

    private static String formatMAC(byte[] mac) {

        if (mac == null || mac.length != 6) {
            return null;
        }

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < mac.length; i++) {

            if (i > 0) {
                sb.append(":");
            }

            sb.append(String.format(
                    "%02X",
                    mac[i] & 0xFF
            ));
        }

        return sb.toString();
    }
	static void resetDetectionStateForTest() {

		ipMacTable.clear();
		alertedPairs.clear();
		eventCounts.clear();

	}

    // =========================================
    // 7. MAC Address Normalizer
    // =========================================

    private static String normalizeMAC(String mac) {

        if (mac == null) {
            return null;
        }

        String value = mac.replaceAll(
                "[^0-9A-Fa-f]",
                ""
        ).toUpperCase();

        if (value.length() != 12) {
            return null;
        }

        StringBuilder result = new StringBuilder();

        for (int i = 0; i < 12; i += 2) {

            if (i > 0) {
                result.append(":");
            }

            result.append(value.substring(i, i + 2));
        }

        return result.toString();
    }
	static void processArpPacket(JPacket packet) {

		Ethernet eth = new Ethernet();
		Arp arp = new Arp();

		// Check Ethernet Header
		if (!packet.hasHeader(eth)) {
			return;
		}

		// Only process ARP
		if (eth.type() != 0x0806) {
			return;
		}

		// Check ARP Header
		if (!packet.hasHeader(arp)) {
			return;
		}

		// Ethernet + IPv4 ARP
		if (arp.hlen() != 6 || arp.plen() != 4) {
			return;
		}

		int operation = arp.operation();

		String packetType;

		if (operation == 1) {
			packetType = "ARP Request";
		} else if (operation == 2) {
			packetType = "ARP Reply";
		} else {
			packetType = "ARP Other";
		}

		String senderIP = FormatUtils.ip(arp.spa());
		String senderMAC = formatMAC(arp.sha());

		if (senderIP == null
				|| senderMAC == null
				|| "0.0.0.0".equals(senderIP)) {
			return;
		}

		String targetIP = FormatUtils.ip(arp.tpa());
		String targetMAC = formatMAC(arp.tha());

		System.out.println("------------------------------------------");

		System.out.println(
			"[" + LocalDateTime.now().format(TIME_FORMAT)
			+ "] " + packetType
		);

		System.out.println("Sender IP  : " + senderIP);
		System.out.println("Sender MAC : " + senderMAC);
		System.out.println("Target IP  : " + targetIP);
		System.out.println("Target MAC : " + targetMAC);

		detectSpoofing(senderIP, senderMAC);
	}
}
