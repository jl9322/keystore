package com.jl9322.keystore;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.annotation.NonNull;

import com.google.appinventor.components.annotations.SimpleFunction;
import com.google.appinventor.components.runtime.AndroidNonvisibleComponent;
import com.google.appinventor.components.runtime.ComponentContainer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;


public class Keystore extends AndroidNonvisibleComponent {
    public Keystore(ComponentContainer container) {
        super(container.$form());
    }

    private static final String KEY_ALIAS = "KeystoreComponent"; /* Alias used to identify key. */

    @SimpleFunction(description = "AES encrypt.")
    public String Encyrpt(String text) {
        try {
            AESEncryption c = new AESEncryption(KEY_ALIAS);
            return c.encrypt(text); /* returns base 64 data: 'BASE64_DATA,BASE64_IV' */
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    @SimpleFunction(description = "AES decrypt.")
    public String Decyrpt(String encryptedText) {
        try {
            AESEncryption c = new AESEncryption(KEY_ALIAS);
            return c.decrypt(encryptedText);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
}

@TargetApi(Build.VERSION_CODES.M)
class AESEncryption {
    private static final String CIPHER = KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_GCM + "/" + KeyProperties.ENCRYPTION_PADDING_NONE;
    private static final String KEY_STORE = "AndroidKeyStore";
    private static final String SEPARATOR = ",";

    private final String keyName;
    private KeyStore keyStore;
    private SecretKey secretKey;

    public AESEncryption(String keyName) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException, InvalidAlgorithmParameterException {
        this.keyName = keyName;
        initKeystore();
        loadOrGenerateKey();
    }

    private void loadOrGenerateKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        getKey();
        if (secretKey == null) generateKey();
    }

    private void initKeystore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        keyStore = KeyStore.getInstance(KEY_STORE);
        keyStore.load(null);
    }

    private void getKey() {
        try {
            final KeyStore.SecretKeyEntry secretKeyEntry =
                    (KeyStore.SecretKeyEntry) keyStore.getEntry(keyName, null);
            // if no key was found -> generate new
            if (secretKeyEntry != null) secretKey = secretKeyEntry.getSecretKey();
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            // failed to retrieve -> will generate new
            e.printStackTrace();
        }
    }

    private void generateKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, KEY_STORE);
        final KeyGenParameterSpec keyGenParameterSpec =
                new KeyGenParameterSpec.Builder(
                        keyName,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .build();
        keyGenerator.init(keyGenParameterSpec);
        secretKey = keyGenerator.generateKey();
    }

    public String encrypt(@NonNull String toEncrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        final Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        String iv = Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP);
        String encrypted = Base64.encodeToString(
                cipher.doFinal(toEncrypt.getBytes(StandardCharsets.UTF_8)), Base64.NO_WRAP);
        return encrypted + SEPARATOR + iv;
    }

    public String decrypt(String toDecrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if (toDecrypt == null || toDecrypt.length() == 0)
            return "";
        String[] parts = toDecrypt.split(SEPARATOR);
        if (parts.length != 2)
            throw new AssertionError(
                    "String to decrypt must be of the form: 'BASE64_DATA" + SEPARATOR + "BASE64_IV'");
        byte[] encrypted = Base64.decode(parts[0], Base64.NO_WRAP),
                iv = Base64.decode(parts[1], Base64.NO_WRAP);
        final Cipher cipher = Cipher.getInstance(CIPHER);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
    }
}
