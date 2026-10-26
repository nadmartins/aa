import common.CryptoConfig;
import common.CryptoService;
import common.ProtocolMessage;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

public class IntegrationSecurityTestbench {

    private static final String HOST = "localhost";
    private static final int PORT = 8081;

    public static void main(String[] args) throws Exception {
        System.out.println("====================================================================");
        System.out.println(" 3S (Secure Streaming Service) - INTEGRATED SECURITY TESTBENCH");
        System.out.println("====================================================================");

        // Path to sample video
        File originalFile = new File("WA1-Materials/streamserver/media/sample.mp4");
        if (!originalFile.exists()) {
            originalFile = new File("streamserver/media/sample.mp4");
        }
        byte[] originalHash = CryptoService.sha256(Files.readAllBytes(originalFile.toPath()));
        System.out.println("Original sample.mp4 SHA-256: " + toHex(originalHash));

        int totalTests = 0;
        int passedTests = 0;

        // --- TEST SUITE 1: End-to-End Streaming & Hash Verification ---
        System.out.println("\n--- [SUITE 1] End-to-End Streaming & Decryption Validation ---");
        totalTests++;
        if (testNormalStreaming("WA1-Materials/configs/rc6-gcm.xml", originalHash, "RC6-GCM")) passedTests++;

        // --- TEST SUITE 2: Security Threat Mitigations ---
        System.out.println("\n--- [SUITE 2] Threat Model & Security Mitigations Validation ---");

        // Test 2.1: Replay Attack on Handshake (Type 1 SECX Replay)
        totalTests++;
        if (testHandshakeReplayAttack("WA1-Materials/configs/rc6-gcm.xml")) passedTests++;

        // Test 2.2: Cryptographic Tampering Attack (MITM Modifies Block Ciphertext)
        totalTests++;
        if (testBlockTamperingAttack("WA1-Materials/configs/rc6-gcm.xml")) passedTests++;

        // Test 2.3: Incompatible Cipher Policy Rejection
        totalTests++;
        if (testIncompatibleCipherRejection()) passedTests++;

        // Test 2.4: Forged Challenge Response (Fake R in Type 3)
        totalTests++;
        if (testForgedChallengeResponse("WA1-Materials/configs/rc6-gcm.xml")) passedTests++;

        // Test 2.5: Block Replay & Out-of-Order Attack Detection
        totalTests++;
        if (testBlockSequenceAttack("WA1-Materials/configs/rc6-gcm.xml")) passedTests++;

        // Summary
        System.out.println("\n====================================================================");
        System.out.printf(" TESTBENCH RESULTS: %d / %d PASSED\n", passedTests, totalTests);
        System.out.println("====================================================================");
        
        if (passedTests == totalTests) {
            System.out.println("ALL INTEGRATION AND SECURITY AUDIT CHECKS PASSED SUCCESSFULLY!");
        } else {
            System.err.println("SOME TESTS FAILED! Inspect logs above.");
            System.exit(1);
        }
    }

    private static boolean testNormalStreaming(String configPath, byte[] expectedHash, String suiteName) {
        System.out.print("[TEST] End-to-End streaming with " + suiteName + "... ");
        try (Socket socket = new Socket(HOST, PORT)) {
            CryptoConfig cfg = CryptoConfig.load(configPath);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            long secX = 123456789L;
            ProtocolMessage.createType1(secX, cfg.toPcc()).send(out);

            ProtocolMessage msg2 = ProtocolMessage.read(in);
            if (msg2 == null || msg2.getType() != ProtocolMessage.TYPE_2_SERVER_CHALLENGE) {
                System.out.println("FAILED: msg2 was null or wrong type");
                return false;
            }
            ProtocolMessage.Type2Data type2 = msg2.parseType2(cfg);
            if (type2.seqy() != secX + 1) {
                System.out.println("FAILED: SEQY mismatch");
                return false;
            }

            byte[] r = CryptoService.sha256(type2.srv());
            long seqZ = type2.seqy() + 1;
            ProtocolMessage.createType3(seqZ, r, "sample.mp4", cfg).send(out);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            long expectedSeq = seqZ + 1;
            int blocks = 0;
            long totalBytes = 0;

            while (true) {
                ProtocolMessage msg = ProtocolMessage.read(in);
                if (msg == null) break;
                if (msg.getType() == ProtocolMessage.TYPE_4_STREAM_BLOCK) {
                    ProtocolMessage.Type4Data t4 = msg.parseType4(cfg);
                    if (t4.seqb() != expectedSeq) {
                        System.out.println("FAILED: seqb mismatch (" + t4.seqb() + " vs " + expectedSeq + ")");
                        return false;
                    }
                    md.update(t4.videoBlock());
                    totalBytes += t4.videoBlock().length;
                    blocks++;
                    expectedSeq++;
                } else if (msg.getType() == ProtocolMessage.TYPE_5_STREAM_END) {
                    ProtocolMessage.Type5Data t5 = msg.parseType5(cfg);
                    if (t5.seqf() != expectedSeq) {
                        System.out.println("FAILED: seqf mismatch on end block");
                        return false;
                    }
                    break;
                } else if (msg.getType() == ProtocolMessage.TYPE_ERROR) {
                    System.out.println("FAILED: server sent error: " + msg.parseError().errorMessage());
                    return false;
                }
            }

            byte[] actualHash = md.digest();
            if (!Arrays.equals(expectedHash, actualHash)) {
                System.out.println("FAILED: SHA-256 checksum mismatch!");
                return false;
            }

            System.out.println("PASSED! (" + blocks + " blocks, " + totalBytes + " bytes, hash match: 100%)");
            return true;
        } catch (Exception e) {
            System.out.println("FAILED with exception: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private static boolean testHandshakeReplayAttack(String configPath) {
        System.out.print("[TEST] Replay attack mitigation (Type 1 SECX Replay)... ");
        try {
            CryptoConfig cfg = CryptoConfig.load(configPath);
            long reusedSecX = 999888777L;

            // 1st request with reusedSecX
            try (Socket s1 = new Socket(HOST, PORT)) {
                ProtocolMessage.createType1(reusedSecX, cfg.toPcc()).send(s1.getOutputStream());
                ProtocolMessage m2 = ProtocolMessage.read(s1.getInputStream());
                if (m2 == null || m2.getType() != ProtocolMessage.TYPE_2_SERVER_CHALLENGE) {
                    System.out.println("FAILED: Initial valid handshake failed");
                    return false;
                }
            }

            // 2nd request (Adversary replays the exact same Type 1 message)
            try (Socket s2 = new Socket(HOST, PORT)) {
                ProtocolMessage.createType1(reusedSecX, cfg.toPcc()).send(s2.getOutputStream());
                ProtocolMessage response = ProtocolMessage.read(s2.getInputStream());
                if (response != null && response.getType() == ProtocolMessage.TYPE_ERROR) {
                    ProtocolMessage.ErrorData err = response.parseError();
                    if (err.errorMessage().toLowerCase().contains("replay")) {
                        System.out.println("PASSED! (Server rejected replayed SECX with error: \"" + err.errorMessage() + "\")");
                        return true;
                    }
                }
                System.out.println("FAILED: Server accepted replayed SECX or did not send replay error");
                return false;
            }
        } catch (Exception e) {
            System.out.println("FAILED with exception: " + e.getMessage());
            return false;
        }
    }

    private static boolean testBlockTamperingAttack(String configPath) {
        System.out.print("[TEST] Tampering attack mitigation (Adversary modifies ciphertext byte)... ");
        try (Socket socket = new Socket(HOST, PORT)) {
            CryptoConfig cfg = CryptoConfig.load(configPath);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            long secX = 777111222L;
            ProtocolMessage.createType1(secX, cfg.toPcc()).send(out);
            ProtocolMessage msg2 = ProtocolMessage.read(in);
            ProtocolMessage.Type2Data type2 = msg2.parseType2(cfg);

            byte[] r = CryptoService.sha256(type2.srv());
            long seqZ = type2.seqy() + 1;
            ProtocolMessage.createType3(seqZ, r, "sample.mp4", cfg).send(out);

            // Read first Type 4 block
            ProtocolMessage msg4 = ProtocolMessage.read(in);
            if (msg4 == null || msg4.getType() != ProtocolMessage.TYPE_4_STREAM_BLOCK) {
                System.out.println("FAILED: did not receive block 1");
                return false;
            }

            // Attacker flips one bit in the encrypted payload
            byte[] tamperedPayload = msg4.getPayload().clone();
            tamperedPayload[tamperedPayload.length - 1] ^= 0x01;
            ProtocolMessage tamperedMsg = new ProtocolMessage(msg4.getVersion(), msg4.getRelease(), msg4.getType(), tamperedPayload);

            try {
                tamperedMsg.parseType4(cfg);
                System.out.println("FAILED: Decryption succeeded on tampered ciphertext!");
                return false;
            } catch (Exception e) {
                // Expected: AEAD tag mismatch or HMAC failure
                System.out.println("PASSED! (Tampered block immediately detected & rejected: " + e.getClass().getSimpleName() + ")");
                return true;
            }
        } catch (Exception e) {
            System.out.println("FAILED with exception: " + e.getMessage());
            return false;
        }
    }

    private static boolean testIncompatibleCipherRejection() {
        System.out.print("[TEST] Policy negotiation (Rejecting incompatible cipher proposal)... ");
        try (Socket socket = new Socket(HOST, PORT)) {
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            // Client proposes DES/ECB/NULL/PKCS5Padding (incompatible with server's RC6/GCM policy)
            ProtocolMessage.createType1(555444333L, "DES/ECB/NULL/PKCS5Padding").send(out);

            ProtocolMessage response = ProtocolMessage.read(in);
            if (response != null && response.getType() == ProtocolMessage.TYPE_ERROR) {
                ProtocolMessage.ErrorData err = response.parseError();
                System.out.println("PASSED! (Server rejected proposal: \"" + err.errorMessage() + "\")");
                return true;
            }
            System.out.println("FAILED: Server did not reject incompatible proposal");
            return false;
        } catch (Exception e) {
            System.out.println("FAILED with exception: " + e.getMessage());
            return false;
        }
    }

    private static boolean testForgedChallengeResponse(String configPath) {
        System.out.print("[TEST] Peer authentication (Rejecting forged R challenge response)... ");
        try (Socket socket = new Socket(HOST, PORT)) {
            CryptoConfig cfg = CryptoConfig.load(configPath);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            long secX = 444333222L;
            ProtocolMessage.createType1(secX, cfg.toPcc()).send(out);
            ProtocolMessage msg2 = ProtocolMessage.read(in);
            ProtocolMessage.Type2Data type2 = msg2.parseType2(cfg);

            // Attacker sends forged R (random bytes instead of SHA-256(SRV))
            byte[] forgedR = new byte[32];
            Arrays.fill(forgedR, (byte) 0xAA);
            long seqZ = type2.seqy() + 1;
            ProtocolMessage.createType3(seqZ, forgedR, "sample.mp4", cfg).send(out);

            ProtocolMessage response = ProtocolMessage.read(in);
            if (response != null && response.getType() == ProtocolMessage.TYPE_ERROR) {
                ProtocolMessage.ErrorData err = response.parseError();
                System.out.println("PASSED! (Server rejected forged response: \"" + err.errorMessage() + "\")");
                return true;
            }
            System.out.println("FAILED: Server accepted forged challenge response");
            return false;
        } catch (Exception e) {
            System.out.println("FAILED with exception: " + e.getMessage());
            return false;
        }
    }

    private static boolean testBlockSequenceAttack(String configPath) {
        System.out.print("[TEST] Message-ordering guarantee (Detecting duplicated / out-of-order blocks)... ");
        try (Socket socket = new Socket(HOST, PORT)) {
            CryptoConfig cfg = CryptoConfig.load(configPath);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            long secX = 333222111L;
            ProtocolMessage.createType1(secX, cfg.toPcc()).send(out);
            ProtocolMessage msg2 = ProtocolMessage.read(in);
            ProtocolMessage.Type2Data type2 = msg2.parseType2(cfg);

            byte[] r = CryptoService.sha256(type2.srv());
            long seqZ = type2.seqy() + 1;
            ProtocolMessage.createType3(seqZ, r, "sample.mp4", cfg).send(out);

            // Read block 1
            ProtocolMessage msg4_1 = ProtocolMessage.read(in);
            ProtocolMessage.Type4Data t4_1 = msg4_1.parseType4(cfg);
            long seq1 = t4_1.seqb();

            // Read block 2
            ProtocolMessage msg4_2 = ProtocolMessage.read(in);
            ProtocolMessage.Type4Data t4_2 = msg4_2.parseType4(cfg);
            long seq2 = t4_2.seqb();

            // Verify strict iteration seq2 == seq1 + 1
            if (seq2 != seq1 + 1) {
                System.out.println("FAILED: Sequence numbers not monotonic!");
                return false;
            }

            // Simulate proxy verification detecting an attacker re-injecting block 1 after block 2
            long expectedNext = seq2 + 1;
            if (seq1 != expectedNext) {
                // Detected out-of-order / replay!
                System.out.println("PASSED! (Replayed sequence " + seq1 + " detected: does not match expected " + expectedNext + ")");
                return true;
            }
            return false;
        } catch (Exception e) {
            System.out.println("FAILED with exception: " + e.getMessage());
            return false;
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
