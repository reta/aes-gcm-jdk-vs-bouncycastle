package com.example.aes;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class AesJcaCipher {
    public static void encrypt(SecretKey secretKey, byte[] iv, final File input, final File output) throws Throwable {
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        try (final BufferedInputStream in = new BufferedInputStream(new FileInputStream(input))) {
            try (final BufferedOutputStream out = new BufferedOutputStream(new CipherOutputStream(new FileOutputStream(output), cipher))) {
                int length = 0;
                byte[] bytes = new byte[16 * 1024];

                while ((length = in.read(bytes)) != -1) {
                    out.write(bytes, 0, length);
                }
            }
        }
    }
    
    public static void decrypt(SecretKey secretKey, byte[] iv, final File input, final File output) throws Throwable {
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        
        try (final BufferedInputStream in = new BufferedInputStream(new CipherInputStream(new FileInputStream(input), cipher))) {
            try (final BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(output))) {
                int length = 0;
                byte[] bytes = new byte[16 * 1024];
                
                while ((length = in.read(bytes)) != -1) {
                    out.write(bytes, 0, length);
                }
            }
        }
    }
}
