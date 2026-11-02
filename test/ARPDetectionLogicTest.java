import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

public class ARPDetectionLogicTest {

    private static int totalTests = 0;
    private static int passedTests = 0;

    private static final String GATEWAY_IP = "192.0.2.1";
    private static final String TRUSTED_GATEWAY_MAC = "02:00:00:00:00:A1";
    private static final String FAKE_GATEWAY_MAC = "02:00:00:00:00:99";

    private static final String HOST_IP = "198.51.100.10";
    private static final String HOST_MAC = "02:00:00:00:10:01";
    private static final String CHANGED_HOST_MAC = "02:00:00:00:10:02";

    private static String captureOutput(Runnable test) {
        PrintStream originalOut = System.out;
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        try (PrintStream captured = new PrintStream(output)) {
            System.setOut(captured);
            test.run();
        } finally {
            System.setOut(originalOut);
        }

        return output.toString();
    }

    private static void check(
            String testName,
            boolean condition,
            String expected,
            String actual) {

        totalTests++;

        if (condition) {
            passedTests++;
            System.out.println("[PASS] " + testName);
        } else {
            System.out.println("[FAIL] " + testName);
            System.out.println("       Expected: " + expected);
            System.out.println("       Actual  : " + actual);
        }
    }

    private static void resetState() {
        Dump_ARP_Spoofing_Detection.resetDetectionStateForTest();
    }

    private static void testGatewayRecovery() {
        resetState();

        String output = captureOutput(() -> {
            Dump_ARP_Spoofing_Detection.detectSpoofing(
                    GATEWAY_IP, FAKE_GATEWAY_MAC);
            Dump_ARP_Spoofing_Detection.detectSpoofing(
                    GATEWAY_IP, TRUSTED_GATEWAY_MAC);
        });

        check(
                "TC07 Gateway recovery",
                output.contains("ALERT: GATEWAY MAC MISMATCH")
                        && output.contains("[RECOVERY] Previous Gateway alerts cleared"),
                "Gateway alert followed by recovery message",
                output
        );
    }

    private static void testHostRecovery() {
        resetState();

        String output = captureOutput(() -> {
            Dump_ARP_Spoofing_Detection.detectSpoofing(HOST_IP, HOST_MAC);
            Dump_ARP_Spoofing_Detection.detectSpoofing(
                    HOST_IP, CHANGED_HOST_MAC);
            Dump_ARP_Spoofing_Detection.detectSpoofing(HOST_IP, HOST_MAC);
        });

        check(
                "TC08 Host mapping recovery",
                output.contains("WARNING: POSSIBLE ARP SPOOFING")
                        && output.contains("[RECOVERY] Previous Host alerts cleared"),
                "Host change warning followed by recovery message",
                output
        );
    }

    private static int countOccurrences(String text, String keyword) {
        int count = 0;
        int index = 0;

        while ((index = text.indexOf(keyword, index)) != -1) {
            count++;
            index += keyword.length();
        }

        return count;
    }

    public static void main(String[] args) {

        // Use documentation-only test addresses; no local network config is needed.
        Dump_ARP_Spoofing_Detection.configureForTest();
        Dump_ARP_Spoofing_Detection.setTestMode(true);

        System.out.println();
        System.out.println("======================================");
        System.out.println("   ARP DETECTION LOGIC UNIT TEST");
        System.out.println("======================================");

        // TC01: Trusted gateway MAC
        resetState();
        String tc01 = captureOutput(() ->
                Dump_ARP_Spoofing_Detection.detectSpoofing(
                        GATEWAY_IP, TRUSTED_GATEWAY_MAC));
        check("TC01 Gateway correct MAC",
                tc01.contains("[NORMAL] Trusted Gateway mapping"),
                "Trusted gateway NORMAL", tc01);

        // TC02: Gateway MAC mismatch
        resetState();
        String tc02 = captureOutput(() ->
                Dump_ARP_Spoofing_Detection.detectSpoofing(
                        GATEWAY_IP, FAKE_GATEWAY_MAC));
        check("TC02 Gateway different MAC",
                tc02.contains("ALERT: GATEWAY MAC MISMATCH"),
                "Gateway mismatch alert", tc02);

        // TC03: First observation of a host
        resetState();
        String tc03 = captureOutput(() ->
                Dump_ARP_Spoofing_Detection.detectSpoofing(
                        HOST_IP, HOST_MAC));
        check("TC03 Host first observation",
                tc03.contains("[LEARN] New IP-MAC mapping"),
                "New mapping learned", tc03);

        // TC04: Same host and same MAC
        resetState();
        String tc04 = captureOutput(() -> {
            Dump_ARP_Spoofing_Detection.detectSpoofing(HOST_IP, HOST_MAC);
            Dump_ARP_Spoofing_Detection.detectSpoofing(HOST_IP, HOST_MAC);
        });
        check("TC04 Host same MAC",
                tc04.contains("[NORMAL] IP-MAC mapping unchanged"),
                "Unchanged mapping NORMAL", tc04);

        // TC05: Same host IP but a different MAC
        resetState();
        String tc05 = captureOutput(() -> {
            Dump_ARP_Spoofing_Detection.detectSpoofing(HOST_IP, HOST_MAC);
            Dump_ARP_Spoofing_Detection.detectSpoofing(
                    HOST_IP, CHANGED_HOST_MAC);
        });
        check("TC05 Host MAC changed",
                tc05.contains("WARNING: POSSIBLE ARP SPOOFING")
                        && tc05.contains("Original MAC : " + HOST_MAC)
                        && tc05.contains("New MAC      : " + CHANGED_HOST_MAC),
                "Host IP-MAC change warning", tc05);

        // TC06: Repeated identical suspicious mapping is warned only once
        resetState();
        String tc06 = captureOutput(() -> {
            Dump_ARP_Spoofing_Detection.detectSpoofing(HOST_IP, HOST_MAC);
            Dump_ARP_Spoofing_Detection.detectSpoofing(
                    HOST_IP, CHANGED_HOST_MAC);
            Dump_ARP_Spoofing_Detection.detectSpoofing(
                    HOST_IP, CHANGED_HOST_MAC);
        });
        int warningCount = countOccurrences(
                tc06, "WARNING: POSSIBLE ARP SPOOFING");
        check("TC06 Duplicate alert suppression",
                warningCount == 1,
                "Exactly one host warning", "Warning count = " + warningCount);

        // TC07: Gateway returns to its trusted MAC
        testGatewayRecovery();

        // TC08: Host returns to its originally learned MAC
        testHostRecovery();

        System.out.println();
        System.out.println("======================================");
        System.out.println("             TEST SUMMARY");
        System.out.println("======================================");
        System.out.println("Total tests : " + totalTests);
        System.out.println("Passed      : " + passedTests);
        System.out.println("Failed      : " + (totalTests - passedTests));

        if (passedTests == totalTests) {
            System.out.println();
            System.out.println("ALL TESTS PASSED!");
        } else {
            System.out.println();
            System.out.println("SOME TESTS FAILED!");
        }

        System.out.println("======================================");
    }
}
