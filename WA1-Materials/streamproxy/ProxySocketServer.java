package streamproxy;

import common.CryptoConfig;
import common.CryptoService;
import common.ProtocolMessage;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.Executors;

/**
 * Secure Proxy for real-time media streaming.
 * Implements the 3S (Secure Streaming Service) client-side protocol.
 * Decrypts encrypted media blocks from the Stream Server and forwards them to a standard browser.
 * Usage: java streamproxy.ProxySocketServer [port=8080] [originHost=localhost] [originPort=8081] [configFile=proxycrypto.config]
 */
public class ProxySocketServer {
    static final int BLOCK_SIZE = 1024;
    private static CryptoConfig proxyConfig;
    private static final SecureRandom RANDOM = new SecureRandom();

    static final String INDEX_HTML = """
            <!doctype html>
            <html>
            <head>
              <meta charset="utf-8">
              <title>3S - Secure Streaming Service</title>
              <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; background: #f8fafc; color: #1e293b; }
                .card { background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 1.5rem; margin-bottom: 1.5rem; }
                h1 { margin-top: 0; color: #0f172a; font-size: 1.5rem; }
                .input-group { display: flex; gap: 0.5rem; margin-bottom: 1rem; }
                input[type=text] { flex: 1; padding: 0.5rem 0.75rem; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 1rem; }
                button { padding: 0.5rem 1.25rem; background: #2563eb; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }
                button:hover { background: #1d4ed8; }
                video { width: 100%; border-radius: 6px; background: #000; }
                .badge { display: inline-block; padding: 0.25rem 0.5rem; background: #e0f2fe; color: #0369a1; border-radius: 4px; font-size: 0.875rem; font-weight: 500; }
              </style>
            </head>
            <body>
              <div class="card">
                <h1>3S &mdash; Secure Streaming Service Player</h1>
                <p>Media Stream secured with end-to-end authenticated cryptographic protocol.</p>
                <div class="input-group">
                  <input id="f" value="sample.mp4" placeholder="Enter video filename (e.g. sample.mp4)">
                  <button onclick="load()">Play Stream</button>
                </div>
                <video id="v" controls autoplay preload="metadata"></video>
              </div>
              <script>
                function load() {
                  const v = document.getElementById('v');
                  v.src = '/video/' + encodeURIComponent(document.getElementById('f').value);
                  v.load();
                }
                load();
              </script>
            </body>
            </html>
            """;

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        String originHost = args.length > 1 ? args[1] : "localhost";
        int originPort = args.length > 2 ? Integer.parseInt(args[2]) : 8081;
        String configFile = args.length > 3 ? args[3] : "proxycrypto.config";

        proxyConfig = CryptoConfig.load(configFile);

        System.out.println("=================================================");
        System.out.println(" 3S Secure Stream Proxy");
        System.out.println(" Listening: http://localhost:" + port + "/");
        System.out.println(" Target Origin Server: " + originHost + ":" + originPort);
        System.out.println(" Cipher Suite: " + proxyConfig.toPcc());
        System.out.println(" AEAD Mode: " + proxyConfig.isAead());
        System.out.println(" MAC Algorithm: " + proxyConfig.getMacAlgorithm());
        System.out.println("=================================================");

        try (ServerSocket server = new ServerSocket(port)) {
            var pool = Executors.newCachedThreadPool();
            while (true) {
                Socket client = server.accept();
                pool.submit(() -> handle(client, originHost, originPort));
            }
        }
    }

    static void handle(Socket browser, String originHost, int originPort) {
        try (browser) {
            InputStream in = browser.getInputStream();
            OutputStream out = browser.getOutputStream();

            String requestLine = HttpUtil.readLine(in);
            if (requestLine == null || !requestLine.startsWith("GET ")) {
                writeSimpleStatus(out, 400, "Bad Request");
                return;
            }

            String path = requestLine.split(" ")[1];
            String line;
            while ((line = HttpUtil.readLine(in)) != null && !line.isEmpty()) {
                // Drain headers
            }

            if (path.equals("/") || path.isEmpty()) {
                servePage(out);
                return;
            }

            if (!path.startsWith("/video/")) {
                writeSimpleStatus(out, 404, "Not Found");
                return;
            }

            String mediaName = path.substring("/video/".length());
            relaySecureStream(out, originHost, originPort, mediaName);

        } catch (IOException ignored) {
        }
    }

    static void servePage(OutputStream out) throws IOException {
        byte[] page = INDEX_HTML.getBytes(StandardCharsets.UTF_8);
        String headers = "HTTP/1.1 200 OK\r\n" +
                "Content-Type: text/html; charset=utf-8\r\n" +
                "Content-Length: " + page.length + "\r\n" +
                "Connection: close\r\n\r\n";
        out.write(headers.getBytes(StandardCharsets.US_ASCII));
        out.write(page);
        out.flush();
    }

    static void relaySecureStream(OutputStream browserOut, String originHost, int originPort, String mediaName) {
        long startTime = System.currentTimeMillis();
        long encryptedBlocksReceived = 0;
        long decryptedBlocksForwarded = 0;
        long totalBytesProcessed = 0;

        try (Socket origin = new Socket(originHost, originPort)) {
            OutputStream originOut = origin.getOutputStream();
            InputStream originIn = origin.getInputStream();

            // 1. Send Handshake Type 1 (Proxy Proposal)
            long secX = RANDOM.nextLong() & 0x7FFFFFFFFFFFFFFFL;
            ProtocolMessage msg1 = ProtocolMessage.createType1(secX, proxyConfig.toPcc());
            msg1.send(originOut);

            // 2. Receive Handshake Type 2 (Server Challenge)
            ProtocolMessage msg2 = ProtocolMessage.read(originIn);
            if (msg2 == null) {
                System.err.println("Origin server closed connection during handshake step 2.");
                writeSimpleStatus(browserOut, 502, "Bad Gateway");
                return;
            }

            if (msg2.getType() == ProtocolMessage.TYPE_ERROR) {
                ProtocolMessage.ErrorData err = msg2.parseError();
                System.err.println("Server rejected handshake with error: " + err.errorMessage());
                writeSimpleStatus(browserOut, 502, "Bad Gateway - " + err.errorMessage());
                return;
            }

            if (msg2.getType() != ProtocolMessage.TYPE_2_SERVER_CHALLENGE) {
                System.err.println("Unexpected message type during handshake step 2: " + msg2.getType());
                writeSimpleStatus(browserOut, 502, "Bad Gateway");
                return;
            }

            if (msg2.getVersion() != ProtocolMessage.CURRENT_VERSION || msg2.getRelease() != ProtocolMessage.CURRENT_RELEASE) {
                System.err.println("Protocol version mismatch in Type 2");
                ProtocolMessage.createError("Unsupported protocol version").send(originOut);
                writeSimpleStatus(browserOut, 502, "Bad Gateway");
                return;
            }

            ProtocolMessage.Type2Data type2;
            try {
                type2 = msg2.parseType2(proxyConfig);
            } catch (Exception e) {
                System.err.println("Failed to decrypt or authenticate Type 2 challenge: " + e.getMessage());
                ProtocolMessage.createError("Decryption/authentication error on Type 2").send(originOut);
                writeSimpleStatus(browserOut, 502, "Bad Gateway");
                return;
            }

            // Verify SEQY = SECX + 1
            if (type2.seqy() != secX + 1) {
                System.err.println("Invalid sequence number in Type 2: expected " + (secX + 1) + ", got " + type2.seqy());
                ProtocolMessage.createError("Sequence number mismatch in Type 2").send(originOut);
                writeSimpleStatus(browserOut, 502, "Bad Gateway");
                return;
            }

            // Verify Cryptographic Confirmation CCC
            if (!proxyConfig.isPccCompatible(type2.ccc())) {
                System.err.println("Server accepted incompatible cipher configuration: " + type2.ccc());
                ProtocolMessage.createError("Cryptographic configuration confirmation mismatch").send(originOut);
                writeSimpleStatus(browserOut, 502, "Bad Gateway");
                return;
            }

            // 3. Send Handshake Type 3 (Proxy Request & Challenge Response)
            byte[] responseR = CryptoService.sha256(type2.srv());
            long seqZ = type2.seqy() + 1;
            ProtocolMessage msg3 = ProtocolMessage.createType3(seqZ, responseR, mediaName, proxyConfig);
            msg3.send(originOut);

            // Send HTTP response headers to browser
            String httpHeader = "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nConnection: close\r\n\r\n";
            browserOut.write(httpHeader.getBytes(StandardCharsets.US_ASCII));
            browserOut.flush();

            // 4. Stream Blocks Processing
            long expectedSeq = seqZ + 1;
            boolean streamCompletedSuccessfully = false;

            while (true) {
                ProtocolMessage streamMsg = ProtocolMessage.read(originIn);
                if (streamMsg == null) {
                    System.out.println("Origin server closed stream connection.");
                    break;
                }

                if (streamMsg.getType() == ProtocolMessage.TYPE_4_STREAM_BLOCK) {
                    encryptedBlocksReceived++;
                    ProtocolMessage.Type4Data type4;
                    try {
                        type4 = streamMsg.parseType4(proxyConfig);
                    } catch (Exception e) {
                        System.err.println("SECURITY ALERT: Integrity check failed while decrypting block! Tampering detected: " + e.getMessage());
                        ProtocolMessage.createError("Integrity check failed: block tampering detected").send(originOut);
                        break;
                    }

                    // Message-ordering and sequence verification
                    if (type4.seqb() != expectedSeq) {
                        if (type4.seqb() < expectedSeq) {
                            System.err.println("SECURITY ALERT: Replayed or duplicated block detected! Expected: " + expectedSeq + ", got: " + type4.seqb());
                        } else {
                            System.err.println("SECURITY ALERT: Missing or out-of-order block detected! Expected: " + expectedSeq + ", got: " + type4.seqb());
                        }
                        ProtocolMessage.createError("Sequence number anomaly: block ordering violation").send(originOut);
                        break;
                    }

                    browserOut.write(type4.videoBlock());
                    browserOut.flush();
                    decryptedBlocksForwarded++;
                    totalBytesProcessed += type4.videoBlock().length;
                    expectedSeq++;

                } else if (streamMsg.getType() == ProtocolMessage.TYPE_5_STREAM_END) {
                    ProtocolMessage.Type5Data type5;
                    try {
                        type5 = streamMsg.parseType5(proxyConfig);
                    } catch (Exception e) {
                        System.err.println("SECURITY ALERT: Failed to decrypt or authenticate Type 5 stream end block: " + e.getMessage());
                        ProtocolMessage.createError("End block integrity failure").send(originOut);
                        break;
                    }

                    // Verify End Sequence Number to detect stream truncation attacks
                    if (type5.seqf() != expectedSeq) {
                        System.err.println("SECURITY ALERT: Stream truncation attack detected! Expected SEQF: " + expectedSeq + ", got: " + type5.seqf());
                        ProtocolMessage.createError("Stream truncation detected: premature end block").send(originOut);
                        break;
                    }

                    if (!"END".equals(type5.endSignal())) {
                        System.err.println("SECURITY ALERT: Invalid end block signal: " + type5.endSignal());
                        ProtocolMessage.createError("Invalid end block signal").send(originOut);
                        break;
                    }

                    streamCompletedSuccessfully = true;
                    System.out.println("End of stream signal verified successfully (SEQF=" + type5.seqf() + ", marker=" + type5.randomStr() + ")");
                    break;

                } else if (streamMsg.getType() == ProtocolMessage.TYPE_ERROR) {
                    ProtocolMessage.ErrorData err = streamMsg.parseError();
                    System.err.println("Received error alert from origin server: " + err.errorMessage());
                    break;
                } else {
                    System.err.println("SECURITY ALERT: Received unexpected message type: " + streamMsg.getType());
                    ProtocolMessage.createError("Unexpected message type").send(originOut);
                    break;
                }
            }

            printMetrics(encryptedBlocksReceived, decryptedBlocksForwarded, totalBytesProcessed, startTime, streamCompletedSuccessfully);

        } catch (Exception e) {
            System.err.println("Proxy streaming error: " + e.getMessage());
        }
    }

    private static void printMetrics(long received, long forwarded, long bytesProcessed, long startTime, boolean success) {
        long durationMs = Math.max(1, System.currentTimeMillis() - startTime);
        double seconds = durationMs / 1000.0;
        double throughputKB = (bytesProcessed / 1024.0) / seconds;
        double throughputMB = throughputKB / 1024.0;

        System.out.println("\n--- STREAMING SESSION METRICS ---");
        System.out.println("Stream status: " + (success ? "COMPLETED SUCCESSFUL" : "ABORTED / INCOMPLETE"));
        System.out.println("Number of encrypted blocks received: " + received);
        System.out.println("Number of decrypted blocks forwarded: " + forwarded);
        System.out.printf("Observed stream throughput: %.2f kB/s (%.2f MB/s)\n", throughputKB, throughputMB);
        System.out.println("Total volume of processed data: " + bytesProcessed + " bytes (" + String.format("%.2f", bytesProcessed / (1024.0 * 1024.0)) + " MB)");
        System.out.println("Total session time: " + durationMs + " ms");
        System.out.println("---------------------------------\n");
    }

    static void writeSimpleStatus(OutputStream out, int code, String reason) throws IOException {
        String resp = "HTTP/1.1 " + code + " " + reason + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        out.write(resp.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }
}
