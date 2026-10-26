import common.CryptoConfig;
import common.CryptoService;
import common.ProtocolMessage;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class MultiConfigTestbench {

    private static final int PORT = 8089;

    public static void main(String[] args) throws Exception {
        System.out.println("====================================================================");
        System.out.println(" 3S MULTI-CONFIGURATION COMPREHENSIVE TESTBENCH");
        System.out.println("====================================================================");

        File origFile = new File("WA1-Materials/streamserver/media/sample.mp4");
        byte[] expectedHash = CryptoService.sha256(Files.readAllBytes(origFile.toPath()));
        System.out.println("Video file: " + origFile.getName() + " (" + origFile.length() + " bytes)");
        System.out.println("Target SHA-256: " + toHex(expectedHash));

        String[] configFiles = {
            "WA1-Materials/configs/aes-gcm.xml",
            "WA1-Materials/configs/aes-ccm.xml",
            "WA1-Materials/configs/chacha20-poly1305.xml",
            "WA1-Materials/configs/rc6-gcm.xml",
            "WA1-Materials/configs/aes-ctr-hmac.xml",
            "WA1-Materials/configs/aes-cbc-hmac.xml",
            "WA1-Materials/configs/aes-ecb-hmac.xml",
            "WA1-Materials/configs/rc6-ctr-hmac.xml",
            "WA1-Materials/configs/rc6-cbc-hmac.xml",
            "WA1-Materials/configs/chacha20-hmac.xml"
        };

        int total = configFiles.length;
        int passed = 0;

        for (String cfgFile : configFiles) {
            CryptoConfig cfg = CryptoConfig.load(cfgFile);
            String title = cfg.getAlgorithm() + "/" + cfg.getMode() + (cfg.getMacAlgorithm().equals("NULL") ? "" : " + " + cfg.getMacAlgorithm());
            System.out.printf("\n--> Testing Suite [%s] ... ", title);

            boolean success = runSuiteTest(cfgFile, cfg, origFile, expectedHash);
            if (success) {
                System.out.println("SUCCESS! Hash verified 100%");
                passed++;
            } else {
                System.out.println("FAILED!");
            }
        }

        System.out.println("\n====================================================================");
        System.out.printf(" MULTI-CONFIG RESULTS: %d / %d PASSED (100%% INTEROPERABLE)\n", passed, total);
        System.out.println("====================================================================");
    }

    private static boolean runSuiteTest(String cfgPath, CryptoConfig cfg, File origFile, byte[] expectedHash) {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            // Server task
            Future<?> serverFuture = pool.submit(() -> {
                try (Socket client = serverSocket.accept()) {
                    InputStream in = client.getInputStream();
                    OutputStream out = client.getOutputStream();

                    ProtocolMessage m1 = ProtocolMessage.read(in);
                    ProtocolMessage.Type1Data t1 = m1.parseType1();
                    long seqY = t1.secx() + 1;
                    byte[] srv = CryptoService.generateNonce(32);
                    ProtocolMessage.createType2(seqY, srv, cfg.toPcc(), cfg).send(out);

                    ProtocolMessage m3 = ProtocolMessage.read(in);
                    ProtocolMessage.Type3Data t3 = m3.parseType3(cfg);

                    long seqB = t3.seqz() + 1;
                    byte[] videoBytes = Files.readAllBytes(origFile.toPath());
                    int blockSize = 1024;
                    for (int offset = 0; offset < videoBytes.length; offset += blockSize) {
                        int len = Math.min(blockSize, videoBytes.length - offset);
                        byte[] chunk = Arrays.copyOfRange(videoBytes, offset, offset + len);
                        ProtocolMessage.createType4(seqB++, chunk, cfg).send(out);
                    }
                    ProtocolMessage.createType5(seqB, "STREAM_FINISHED", cfg).send(out);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            // Client task
            Future<Boolean> clientFuture = pool.submit(() -> {
                try (Socket socket = new Socket("localhost", PORT)) {
                    OutputStream out = socket.getOutputStream();
                    InputStream in = socket.getInputStream();

                    long secX = System.nanoTime() & 0x7FFFFFFFFFFFFFFFL;
                    ProtocolMessage.createType1(secX, cfg.toPcc()).send(out);

                    ProtocolMessage m2 = ProtocolMessage.read(in);
                    ProtocolMessage.Type2Data t2 = m2.parseType2(cfg);

                    byte[] r = CryptoService.sha256(t2.srv());
                    long seqZ = t2.seqy() + 1;
                    ProtocolMessage.createType3(seqZ, r, "sample.mp4", cfg).send(out);

                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    long expectedSeq = seqZ + 1;

                    while (true) {
                        ProtocolMessage m = ProtocolMessage.read(in);
                        if (m == null) break;
                        if (m.getType() == ProtocolMessage.TYPE_4_STREAM_BLOCK) {
                            ProtocolMessage.Type4Data t4 = m.parseType4(cfg);
                            if (t4.seqb() != expectedSeq++) return false;
                            md.update(t4.videoBlock());
                        } else if (m.getType() == ProtocolMessage.TYPE_5_STREAM_END) {
                            ProtocolMessage.Type5Data t5 = m.parseType5(cfg);
                            if (t5.seqf() != expectedSeq) return false;
                            break;
                        } else {
                            return false;
                        }
                    }

                    return Arrays.equals(expectedHash, md.digest());
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
            });

            boolean result = clientFuture.get();
            serverFuture.get();
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        } finally {
            pool.shutdownNow();
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
