import common.CryptoConfig;
import common.CryptoService;
import common.ProtocolMessage;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

public class ConcurrencyTestbench {

    private static final String HOST = "localhost";
    private static final int PORT = 8081;
    private static final int CONCURRENT_CLIENTS = 8;

    public static void main(String[] args) throws Exception {
        System.out.println("====================================================================");
        System.out.println(" 3S CONCURRENCY & PARALLEL STREAMING TESTBENCH");
        System.out.println("====================================================================");

        File origFile = new File("WA1-Materials/streamserver/media/sample.mp4");
        byte[] expectedHash = CryptoService.sha256(Files.readAllBytes(origFile.toPath()));

        ExecutorService pool = Executors.newFixedThreadPool(CONCURRENT_CLIENTS);
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch endGate = new CountDownLatch(CONCURRENT_CLIENTS);
        AtomicInteger successCount = new AtomicInteger(0);

        long startTime = System.currentTimeMillis();

        for (int i = 0; i < CONCURRENT_CLIENTS; i++) {
            final int id = i + 1;
            pool.submit(() -> {
                try {
                    startGate.await(); // Synchronize simultaneous launch
                    System.out.println("[Client " + id + "] Starting stream session...");

                    try (Socket socket = new Socket(HOST, PORT)) {
                        CryptoConfig cfg = CryptoConfig.load("WA1-Materials/configs/rc6-gcm.xml");
                        OutputStream out = socket.getOutputStream();
                        InputStream in = socket.getInputStream();

                        long secX = System.nanoTime() + id * 1000000L;
                        ProtocolMessage.createType1(secX, cfg.toPcc()).send(out);

                        ProtocolMessage m2 = ProtocolMessage.read(in);
                        ProtocolMessage.Type2Data t2 = m2.parseType2(cfg);

                        byte[] r = CryptoService.sha256(t2.srv());
                        long seqZ = t2.seqy() + 1;
                        ProtocolMessage.createType3(seqZ, r, "sample.mp4", cfg).send(out);

                        MessageDigest md = MessageDigest.getInstance("SHA-256");
                        long expectedSeq = seqZ + 1;
                        int blocks = 0;

                        while (true) {
                            ProtocolMessage m = ProtocolMessage.read(in);
                            if (m == null) break;
                            if (m.getType() == ProtocolMessage.TYPE_4_STREAM_BLOCK) {
                                ProtocolMessage.Type4Data t4 = m.parseType4(cfg);
                                if (t4.seqb() != expectedSeq++) break;
                                md.update(t4.videoBlock());
                                blocks++;
                            } else if (m.getType() == ProtocolMessage.TYPE_5_STREAM_END) {
                                ProtocolMessage.Type5Data t5 = m.parseType5(cfg);
                                if (t5.seqf() == expectedSeq) {
                                    if (Arrays.equals(expectedHash, md.digest())) {
                                        successCount.incrementAndGet();
                                        System.out.println("[Client " + id + "] COMPLETED SUCCESSFULLY! (" + blocks + " blocks)");
                                    }
                                }
                                break;
                            }
                        }
                    }
                } catch (Exception e) {
                    System.err.println("[Client " + id + "] Failed: " + e.getMessage());
                } finally {
                    endGate.countDown();
                }
            });
        }

        startGate.countDown(); // Launch all clients simultaneously
        endGate.await();
        pool.shutdown();

        long duration = System.currentTimeMillis() - startTime;
        System.out.println("====================================================================");
        System.out.printf(" CONCURRENCY RESULTS: %d / %d clients completed successfully in %d ms!\n", 
                successCount.get(), CONCURRENT_CLIENTS, duration);
        System.out.println("====================================================================");
    }
}
