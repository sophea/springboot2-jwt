package com.sma.security.utils;



import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

@Slf4j
public final class EncrypterHelper {
    private static final String KEY = "#sma#key#Ra_3weqZ3owgPT9Y6Bcx";
    private static final String PBE_WITH_MD_5_AND_DES_MODE = "PBEWithMD5AndDES";
    public static final String UTF_8 = "UTF8";
    private static Cipher ecipher;
    private static Cipher dcipher;
    private static EncrypterHelper instance = new EncrypterHelper();


    /**
     * Constructor used to create this object. Responsible for setting
     * and initializing this object's encrypter and decrypter Chipher instances
     * given a Pass Phrase and algorithm.
     *
     */
    private EncrypterHelper() {
        // 8-bytes Salt
        final byte[] salt = {(byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32, (byte) 0x56, (byte) 0x34, (byte) 0xE3, (byte) 0x03};
        // Iteration count
        int iterationCount = 19;
        try {
            final KeySpec keySpec = new PBEKeySpec(KEY.toCharArray(), salt, iterationCount);
            final SecretKey key = SecretKeyFactory.getInstance(PBE_WITH_MD_5_AND_DES_MODE).generateSecret(keySpec);
            ecipher = Cipher.getInstance(PBE_WITH_MD_5_AND_DES_MODE);
            dcipher = Cipher.getInstance(PBE_WITH_MD_5_AND_DES_MODE);
            // Prepare the parameters to the cipthers
            final AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
            ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
            dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
        } catch (InvalidAlgorithmParameterException e) {
            log.error("EXCEPTION: InvalidAlgorithmParameterException");
        } catch (InvalidKeySpecException e) {
            log.error("EXCEPTION: InvalidKeySpecException");
        } catch (NoSuchPaddingException e) {
            log.error("EXCEPTION: NoSuchPaddingException");
        } catch (NoSuchAlgorithmException e) {
            log.error("EXCEPTION: NoSuchAlgorithmException");
        } catch (InvalidKeyException e) {
            log.error("EXCEPTION: InvalidKeyException");
        }
    }

    private static String encodeHasField(String hashField) {
        return String.format("##%s##", hashField);
    }

    public static String encrypt(String str, String hashField) {
        return instance.encrypt(String.format("%s%s%s", encodeHasField(hashField), str, KEY));
    }

    public static String decrypt(String encodeStr, String hashField) {
        // Decode using utf-8
        String decrypt = instance.decrypt(encodeStr);
        if (decrypt == null) {
            return null;
        }
        decrypt = decrypt.replace(KEY, "");
        final String result = decrypt.replace(encodeHasField(hashField), "");
        return result.equals(decrypt) ? null : result;
    }

    public static void main(String[] args) {
        //String text ="sophea";
        String encode = encrypt("testing-pawss", "test@gmail.com");
        //encrypt(text, text);
        System.out.println(encode);
        System.out.println("pwd:" + decrypt(encode, "test@gmail.com"));
    }

    /**
     * Takes a single String as an argument and returns an Encrypted version
     * of that String.
     *
     * @param str String to be encrypted
     * @return <code>String</code> Encrypted version of the provided String
     */
    public static String encrypt(String str) {
        try {
            // Encode the string into bytes using utf-8
            final byte[] utf8 = str.getBytes(UTF_8);
            // Encrypt
            final byte[] enc = ecipher.doFinal(utf8);
            // Encode bytes to base64 to get a string
            return javax.xml.bind.DatatypeConverter.printBase64Binary(enc);
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }

    /**
     * Takes a encrypted String as an argument, decrypts and returns the
     * decrypted String.
     *
     * @param str Encrypted String to be decrypted
     * @return <code>String</code> Decrypted version of the provided String
     */
    public static String decrypt(String str) {
        try {
            // Decode base64 to get bytes
            final byte[] dec = javax.xml.bind.DatatypeConverter.parseBase64Binary(str);
            // Decrypt
            final byte[] utf8 = dcipher.doFinal(dec);
            // Decode using utf-8
            return new String(utf8, UTF_8);
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }

}
