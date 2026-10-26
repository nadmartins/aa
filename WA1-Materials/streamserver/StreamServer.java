package streamserver;

import common.CryptoConfig;
import common.CryptoService;
import common.ProtocolMessage;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

/**
 * Secure Stream Server for real-time media streaming.
 * Implements the 3S (Secure Streaming Service) protocol.
 * Usage: java streamserver.StreamServer [port=8081] [mediaDir=media] [configFile=sservercrypto.config]
 */
public class StreamServer {
    static final int BLOCK_SIZE = 1024;
    private static CryptoConfig serverConfig;
    
    // Replay attack protection: stores observed SECX nonces
    private static final Set<Long> seenNonces = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8081;
        Path root = Paths.get(args.length > 1 ? args[1] : "media").toAbsolutePath().normalize();
        
        // Fallback search for media dir if not found in current folder
        if (!Files.isDirectory(root)) {
            Path alt = Paths.get("WA1-Materials/streamserver/media").toAbsolutePath().normalize();
            if (Files.isDirectory(alt)) {
                root = alt;
            }
        }

        String configFile = args.length > 2 ? args[2] : "sservercrypto.config";
        serverConfig = CryptoConfig.load(configFile);

        System.out.println("=================================================");
        System.out.println(" 3S Secure Stream Server");
        System.out.println(" Port: " + port);
        System.out.println(" Media Directory: " + root);
        System.out.println(" Cipher Suite: " + serverConfig.toPcc());
        System.out.println(" AEAD Mode: " + serverConfig.isAead());
        System.out.println(" MAC Algorithm: " + serverConfig.getMacAlgorithm());
        System.out.println("=================================================");

        try (ServerSocket server = new ServerSocket(port)) {
            var pool = Executors.newCachedThreadPool();
            while (true) {
                Socket client = server.accept();
                final Path finalRoot = root;
                pool.submit(() -> handle(client, finalRoot));
            }
        }
    }

    static void handle(Socket socket, Path root) {
        String clientInfo = socket.getRemoteSocketAddress().toString();
        try (socket) {
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            // 1. Receive Type 1 Message (Handshake Proposal)
            ProtocolMessage msg1 = ProtocolMessage.read(in);
            if (msg1 == null || msg1.getType() != ProtocolMessage.TYPE_1_PROXY_PROPOSAL) {
                sendErrorAndClose(out, "Expected Type 1 handshake proposal message.");
                return;
            }

            // Verify Protocol Version & Release
            if (msg1.getVersion() != ProtocolMessage.CURRENT_VERSION || msg1.getRelease() != ProtocolMessage.CURRENT_RELEASE) {
                sendErrorAndClose(out, "Protocol version mismatch: expected " 
                        + ProtocolMessage.CURRENT_VERSION + "." + ProtocolMessage.CURRENT_RELEASE 
                        + ", received " + msg1.getVersion() + "." + msg1.getRelease());
                return;
            }

            ProtocolMessage.Type1Data type1 = msg1.parseType1();

            // Replay Attack Detection
            if (!seenNonces.add(type1.secx())) {
                sendErrorAndClose(out, "Replay attack detected: SECX nonce " + type1.secx() + " has already been used.");
                return;
            }

            // Cryptographic Negotiation & Compatibility Check
            if (!serverConfig.isPccCompatible(type1.pcc())) {
                sendErrorAndClose(out, "Proposed cryptographic configuration rejected: incompatible with server policy (" + type1.pcc() + ")");
                return;
            }

            System.out.println("[" + clientInfo + "] Handshake step 1 OK. Accepted PCC: " + type1.pcc());

            // 2. Send Type 2 Message (Server Challenge)
            long seqY = type1.secx() + 1;
            byte[] srv = CryptoService.generateNonce(32); // 256-bit challenge nonce
            String ccc = serverConfig.toPcc();

            ProtocolMessage msg2 = ProtocolMessage.createType2(seqY, srv, ccc, serverConfig);
            msg2.send(out);
            System.out.println("[" + clientInfo + "] Handshake step 2 OK. Sent challenge SEQY=" + seqY);

            // 3. Receive Type 3 Message (Proxy Request & Challenge Response)
            ProtocolMessage msg3 = ProtocolMessage.read(in);
            if (msg3 == null || msg3.getType() != ProtocolMessage.TYPE_3_PROXY_REQUEST) {
                sendErrorAndClose(out, "Expected Type 3 handshake request message.");
                return;
            }

            if (msg3.getVersion() != ProtocolMessage.CURRENT_VERSION || msg3.getRelease() != ProtocolMessage.CURRENT_RELEASE) {
                sendErrorAndClose(out, "Protocol version mismatch in Type 3.");
                return;
            }

            ProtocolMessage.Type3Data type3;
            try {
                type3 = msg3.parseType3(serverConfig);
            } catch (Exception e) {
                sendErrorAndClose(out, "Decryption or integrity verification failed on Type 3 message: " + e.getMessage());
                return;
            }

            // Verify Sequence Number SEQZ = SEQY + 1
            if (type3.seqz() != seqY + 1) {
                sendErrorAndClose(out, "Invalid sequence number in Type 3: expected " + (seqY + 1) + ", received " + type3.seqz());
                return;
            }

            // Verify SRV Challenge Response: R == SHA-256(SRV)
            byte[] expectedR = CryptoService.sha256(srv);
            if (!MessageDigest.isEqual(expectedR, type3.r())) {
                sendErrorAndClose(out, "Invalid SRV challenge response: authentication failed.");
                return;
            }

            // Verify Media File Path Traversal & Existence
            Path file = root.resolve(type3.media()).normalize();
            if (!file.startsWith(root) || !Files.isRegularFile(file)) {
                sendErrorAndClose(out, "Media file not found or path forbidden: " + type3.media());
                return;
            }

            System.out.println("[" + clientInfo + "] Handshake SUCCESS! Starting secure streaming of '" + type3.media() + "' (" + Files.size(file) + " bytes)");

            // 4. Stream Blocks (Type 4) and End Signaling (Type 5)
            serveFile(out, file, type3.seqz(), clientInfo);

        } catch (Exception e) {
            System.err.println("[" + clientInfo + "] Session error: " + e.getMessage());
        }
    }

    static void serveFile(OutputStream out, Path file, long lastSeqZ, String clientInfo) throws Exception {
        long size = Files.size(file);
        long seqB = lastSeqZ + 1;
        long totalBlocks = 0;
        long totalBytesSent = 0;

        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
            byte[] block = new byte[BLOCK_SIZE];
            long remaining = size;

            while (remaining > 0) {
                int n = raf.read(block, 0, (int) Math.min(block.length, remaining));
                if (n < 0) break;

                byte[] chunk = (n == block.length) ? block : Arrays.copyOf(block, n);
                ProtocolMessage msg4 = ProtocolMessage.createType4(seqB, chunk, serverConfig);
                msg4.send(out);

                remaining -= n;
                totalBytesSent += n;
                totalBlocks++;
                seqB++;
            }

            // Send Type 5: signaling end of stream
            ProtocolMessage msg5 = ProtocolMessage.createType5(seqB, "STREAM_FINISHED", serverConfig);
            msg5.send(out);
            System.out.println("[" + clientInfo + "] Stream completed successfully. Sent " + totalBlocks + " blocks (" + totalBytesSent + " bytes). Final SEQF=" + seqB);
        }
    }

    static void sendErrorAndClose(OutputStream out, String reason) {
        try {
            System.err.println("SECURITY ALERT / ERROR: " + reason);
            ProtocolMessage err = ProtocolMessage.createError(reason);
            err.send(out);
        } catch (IOException ignored) {}
    }
}
