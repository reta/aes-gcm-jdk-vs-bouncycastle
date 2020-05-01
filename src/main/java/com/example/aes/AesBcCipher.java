package com.example.aes;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class AesBcCipher {
    public static void encrypt(SecretKey secretKey, byte[] iv, final File input, final File output) throws Throwable {
        final GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        cipher.init(true, new AEADParameters(new KeyParameter(secretKey.getEncoded()), 128, iv));

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
        final GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        cipher.init(false, new AEADParameters(new KeyParameter(secretKey.getEncoded()), 128, iv));

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
