# ARP Spoofing Detection

A Java-based ARP monitoring and detection tool using **jNetPcap**. It captures ARP packets from a selected network interface, analyzes sender IP-to-MAC mappings, detects suspicious changes, and records security events in CSV files.

## Features

- **Live ARP Packet Capture** — Capture ARP traffic from a selected network interface using jNetPcap.
- **ARP Packet Parsing** — Extract ARP operation, sender IP/MAC, and target IP/MAC addresses.
- **Gateway MAC Verification** — Compare the observed gateway MAC address against a configured trusted MAC address.
- **Host IP-MAC Mapping** — Learn IP-to-MAC mappings and detect unexpected MAC address changes.
- **Duplicate Alert Suppression** — Avoid repeatedly displaying the same warning for an identical suspicious mapping.
- **Recovery Detection** — Clear an active alert when the gateway or host mapping returns to its trusted/original value.
- **CSV Event Logging** — Record suspicious events with timestamps, event types, IP addresses, MAC addresses, and event counts.
- **Offline Packet Testing** — Construct ARP packets in memory using `JMemoryPacket` and pass them through the packet-processing logic without transmitting packets onto a network.

## Project Structure

```text
ARP-Spoofing-Detection/
│
├── README.md
├── LICENSE
├── .gitignore
│
├── config/
│   └── config.example.properties
│
├── src/
│   └── Dump_ARP_Spoofing_Detection.java
│
└── test/
    ├── ARPDetectionLogicTest.java
    └── ARPOfflinePacketTest.java
```

## Requirements

- Windows
- Java Development Kit (JDK)
- jNetPcap JAR and its matching native DLL
- WinPcap or a compatible packet-capture driver
- A supported network interface

The jNetPcap JAR, native DLL, Java runtime, and operating-system architecture must be mutually compatible. The jNetPcap binaries are not included in this repository; obtain them from a source whose license permits your use.

Place `jnetpcap.jar` and the matching `jnetpcap.dll` in the project root, or adjust the classpath and native library path in the commands below.

## Configuration

The live program reads its network settings from a root-level file named `config.properties`. This file is intentionally excluded from version control because its values are specific to each network.

1. Copy the example file to the project root:

   ```cmd
   copy config\config.example.properties config.properties
   ```

2. Edit `config.properties` and provide the values for your own environment:

   | Property | Description |
   |---|---|
   | `device.keyword` | Text contained in the target network adapter description |
   | `local.ip` | Local computer IPv4 address |
   | `local.mac` | Local computer MAC address |
   | `gateway.ip` | Default gateway IPv4 address |
   | `gateway.mac` | Trusted default gateway MAC address |

3. Save the file. Do not commit your personal `config.properties` to the repository.

The example values are placeholders; do not assume they apply to your network. The unit and offline packet tests use documentation-only test addresses and do not require this live configuration file.

## Compilation

Open Command Prompt in the project directory. With `jnetpcap.jar` in the project root, compile the source and both test classes:

```cmd
javac -encoding UTF-8 -cp ".;jnetpcap.jar" -d . src\Dump_ARP_Spoofing_Detection.java test\ARPDetectionLogicTest.java test\ARPOfflinePacketTest.java
```

## Testing

### 1. Detection Logic Unit Tests

Run:

```cmd
java -Dfile.encoding=UTF-8 -Djava.library.path="." -cp ".;jnetpcap.jar" ARPDetectionLogicTest
```

The eight test cases cover:

1. Trusted gateway MAC
2. Gateway MAC mismatch
3. First observation of a host
4. Unchanged host IP-MAC mapping
5. Host MAC change
6. Duplicate alert suppression
7. Gateway recovery to the trusted MAC
8. Host recovery to its originally learned MAC

These tests use the test-only configuration in code and do not read your real network settings.

### 2. Offline ARP Packet Tests

Run:

```cmd
java -Dfile.encoding=UTF-8 -Djava.library.path="." -cp ".;jnetpcap.jar" ARPOfflinePacketTest
```

The offline test constructs ARP packets in memory with `JMemoryPacket` and sends them through the same `processArpPacket()` method used by live capture. Its test packets are not transmitted onto the network.

## Running Live Monitoring

After creating and editing `config.properties`, run:

```cmd
java -Dfile.encoding=UTF-8 -Djava.library.path="." -cp ".;jnetpcap.jar" Dump_ARP_Spoofing_Detection
```

Administrator privileges may be required for packet capture, depending on the capture driver and system configuration. Select a network adapter whose description matches `device.keyword`.

Live mode captures ARP traffic; it does not generate ARP spoofing traffic.

## Detection Logic

The detection mechanism maintains an IP-to-MAC mapping table.

When an ARP packet is received:

1. Parse the Ethernet and ARP headers.
2. Validate the ARP hardware and protocol address lengths.
3. Extract sender and target IP/MAC addresses.
4. Compare the sender IP/MAC mapping with the configured gateway identity or the previously learned host mapping.
5. Generate an alert when a suspicious mapping change is detected.
6. Record suspicious events in a CSV file.
7. Clear the active alert state when the trusted/original mapping is observed again.

A suspicious IP-MAC change is not definitive proof of an ARP spoofing attack. Legitimate events such as DHCP reassignment, network changes, and device replacement may also cause mapping changes.

## CSV Event Logs

The program generates separate CSV files for different operating modes:

| File | Purpose |
|---|---|
| `ARP_Detection_Live_Log.csv` | Events detected during live monitoring |
| `ARP_Detection_Test_Log.csv` | Events generated during tests |

The CSV columns are:

```text
Timestamp,Source,Event Type,IP Address,Original MAC,New MAC,Event Count,Status
```

Suspicious events are recorded; normal ARP mappings are not written to the event log.

## Security and Safety Notice

This project is designed for defensive ARP monitoring and detection.

- Live mode passively captures ARP traffic.
- Unit tests exercise detection logic using documentation-only IP/MAC values.
- Offline packet tests process constructed packets in memory and do not transmit them onto the network.
- Detection warnings indicate suspicious changes, not confirmed attacks.
- Perform network experiments only on networks and devices you own or are explicitly authorized to test.

## Limitations

- Live monitoring requires manually supplied network parameters in `config.properties`.
- The initial host IP-MAC mapping is learned from observed traffic and is not independently authenticated.
- Legitimate network changes may trigger warnings.
- Wi-Fi network interfaces may not expose all traffic between other wireless clients.
- Detection effectiveness depends on packet visibility and the correctness of the configured gateway information.

## License

This project is licensed under the terms of the license included in this repository.

---

**Author:** ericworking660-web

**Repository:** [ARP-Spoofing-Detection](https://github.com/ericworking660-web/ARP-Spoofing-Detection)

## Dependencies

The following jNetPcap files are not included in this repository:

- `jnetpcap.jar`
- `jnetpcap.dll`

Users must obtain compatible libraries separately and configure the Java classpath and native library path.
