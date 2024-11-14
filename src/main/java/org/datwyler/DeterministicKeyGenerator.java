package org.datwyler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.UUID;

public class DeterministicKeyGenerator {
    public byte[] generateSharedKey(String seedString) throws NoSuchAlgorithmException {
        var sha256 = MessageDigest.getInstance("SHA-256");
        return sha256.digest(seedString.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] generateSharedKey(UUID uuid) throws NoSuchAlgorithmException {
        return generateSharedKey(uuid.toString());
    }

    public byte[] generateSharedKey(Instant timestamp, UUID uuid) throws NoSuchAlgorithmException {
        String combinedString = timestamp.getEpochSecond() + uuid.toString();
        return generateSharedKey(combinedString);
    }


    public byte[] generateSharedKey(String timestamp, UUID uuid, String fileMD5) throws NoSuchAlgorithmException {
        String combinedString = timestamp + uuid.toString() + fileMD5;
        return generateSharedKey(combinedString);
    }

    private String getFileMD5(String filePath) throws IOException, NoSuchAlgorithmException {
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(fileBytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Utility method to convert byte array to hex string
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
