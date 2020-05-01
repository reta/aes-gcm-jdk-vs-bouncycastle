package com.example.aes;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class AesJcaTest {
    @Test
    @DisplayName("encrypting / decrypting small text file (~40k)")
    public void text(@TempDir Path temp) throws Throwable {
        final SecureRandom secureRandom = new SecureRandom();
        
        final byte[] key = new byte[32];
        secureRandom.nextBytes(key);
        final SecretKey secretKey = new SecretKeySpec(key, "AES");
        
        final byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        
        final File original = new File(getClass().getResource("/text.txt").toURI());
        final File encrypted = temp.resolve("data.enc").toFile();
        final File decrypted = temp.resolve("data.dec").toFile();
        
        AesJcaCipher.encrypt(secretKey, iv, original, encrypted);
        AesJcaCipher.decrypt(secretKey, iv, encrypted, decrypted);
        
        assertContentIsIdentical(decrypted, original);
    }
    
    @Test
    @DisplayName("encrypting / decrypting binary file (~42Mb)")
    public void binary(@TempDir Path temp) throws Throwable {
        final SecureRandom secureRandom = new SecureRandom();
        
        final byte[] key = new byte[32];
        secureRandom.nextBytes(key);
        final SecretKey secretKey = new SecretKeySpec(key, "AES");
        
        final byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
                
        final File original = new File(getClass().getResource("/binary.bin").toURI());
        final File encrypted = temp.resolve("data.enc").toFile();
        final File decrypted = temp.resolve("data.dec").toFile();
        
        AesJcaCipher.encrypt(secretKey, iv, original, encrypted);
        AesJcaCipher.decrypt(secretKey, iv, encrypted, decrypted);
        
        assertContentIsIdentical(decrypted, original);
    }
    
    private final void assertContentIsIdentical(File actual, File expected) throws IOException {
        final byte[] actualContent = Files.readAllBytes(actual.toPath()); 
        final byte[] expectedContent = Files.readAllBytes(expected.toPath());
        assertThat(Arrays.equals(actualContent, expectedContent)).isTrue();
    }
}
