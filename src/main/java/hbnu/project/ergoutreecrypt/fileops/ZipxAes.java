package hbnu.project.ergoutreecrypt.fileops;

import net.lingala.zip4j.crypto.AESDecrypter;
import net.lingala.zip4j.crypto.AESEncrypter;
import net.lingala.zip4j.model.AESExtraDataRecord;
import net.lingala.zip4j.model.enums.AesKeyStrength;
import hbnu.project.ergoutreecrypt.volume.ProgressReporter;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.Arrays;

/** Streams WinZip AES using zip4j's existing, interoperable cipher implementation. */
final class ZipxAes {
    /** Prevents construction. */
    private ZipxAes() { }

    /**
     * Writes an AE-2 AES-256 payload with fresh salt and a 10-byte authentication tag.
     * @param input compressed plaintext
     * @param output encrypted payload
     * @param password archive password, encoded as UTF-8
     * @param reporter cancellation callback
     * @throws IOException encryption failed
     */
    static void encrypt(Path input, Path output, String password, ProgressReporter reporter) throws IOException {
        char[] chars = password.toCharArray();
        try {
            AESEncrypter aes = new AESEncrypter(chars, AesKeyStrength.KEY_STRENGTH_256, true);
            try (InputStream in = Files.newInputStream(input); OutputStream out = Files.newOutputStream(output)) {
                out.write(aes.getSaltBytes());
                out.write(aes.getDerivedPasswordVerifier());
                byte[] buffer = new byte[65536];
                int count;
                while ((count = in.readNBytes(buffer, 0, buffer.length)) > 0) {
                    checkCancelled(reporter);
                    aes.encryptData(buffer, 0, count);
                    out.write(buffer, 0, count);
                }
                out.write(Arrays.copyOf(aes.getFinalMac(), 10));
            }
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * Authenticates the complete ciphertext before its staged plaintext can be decoded.
     * @param input bounded raw ZIP entry stream
     * @param output private staged compressed plaintext
     * @param size complete encrypted entry size
     * @param strength AES key strength code, 1 through 3
     * @param password UTF-8 archive password
     * @param reporter cancellation callback
     * @throws IOException wrong password, truncation or authentication failure
     */
    static void decrypt(InputStream input, Path output, long size, int strength, String password,
                         ProgressReporter reporter) throws IOException {
        AesKeyStrength keyStrength = switch (strength) {
            case 1 -> AesKeyStrength.KEY_STRENGTH_128;
            case 2 -> AesKeyStrength.KEY_STRENGTH_192;
            case 3 -> AesKeyStrength.KEY_STRENGTH_256;
            default -> throw new IOException("Invalid ZIPX AES strength: " + strength);
        };
        int saltSize = strength * 4 + 4;
        long remaining = size - saltSize - 12;
        if (remaining < 0) throw new IOException("Truncated ZIPX AES payload");
        byte[] salt = readExact(input, saltSize);
        byte[] verifier = readExact(input, 2);
        AESExtraDataRecord record = new AESExtraDataRecord();
        record.setAesKeyStrength(keyStrength);
        char[] chars = password.toCharArray();
        try {
            AESDecrypter aes = new AESDecrypter(record, chars, salt, verifier, true);
            try (OutputStream out = Files.newOutputStream(output)) {
                byte[] buffer = new byte[65536];
                while (remaining > 0) {
                    checkCancelled(reporter);
                    int count = (int) Math.min(remaining, buffer.length);
                    if (input.readNBytes(buffer, 0, count) != count) throw new EOFException("Truncated ZIPX ciphertext");
                    aes.decryptData(buffer, 0, count);
                    out.write(buffer, 0, count);
                    remaining -= count;
                }
            }
            byte[] tag = readExact(input, 10);
            if (!MessageDigest.isEqual(tag, Arrays.copyOf(aes.getCalculatedAuthenticationBytes(0), 10))) {
                throw new IOException("ZIPX AES authentication failed: ciphertext corrupted");
            }
            if (input.read() != -1) throw new IOException("Unexpected ZIPX AES trailing data");
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * Reads a required fixed-length field.
     * @param input source stream
     * @param size required byte count
     * @return complete field bytes
     * @throws IOException truncated field
     */
    private static byte[] readExact(InputStream input, int size) throws IOException {
        byte[] bytes = input.readNBytes(size);
        if (bytes.length != size) throw new EOFException("Truncated ZIPX AES header or tag");
        return bytes;
    }

    /**
     * Responds to cancellation during large AES payload operations.
     * @param reporter optional cancellation callback
     * @throws IOException operation cancelled
     */
    private static void checkCancelled(ProgressReporter reporter) throws IOException {
        if (Thread.currentThread().isInterrupted() || (reporter != null && reporter.isCancelled())) {
            throw new IOException("ZIPX operation cancelled");
        }
    }
}
