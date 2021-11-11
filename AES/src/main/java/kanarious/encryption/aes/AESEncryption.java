package kanarious.encryption.aes;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class AESEncryption {
    //Private Vars
    private static final int SIZE_OF_INT = 4;
    private static String ALIAS;
    private static final String PROVIDER = "AndroidKeyStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static SecretKey secretKey = null;

    /**
     * @brief AESEncryption Constructor
     * @detailed AESEncryption will try to find a key with its alias in the keystore. If one is not
     *           found then it will generate a new one. This is only meant for first time start up
     *           as the key can be recycled for performing the same type of encryption.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    @SuppressWarnings("JavaDoc")
    public AESEncryption(String alias) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        ALIAS = alias;
        //Get Stored Key
        try {
            secretKey = getKey();
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        //Key Does not Exist
        if(secretKey == null){
            secretKey = generateKey();
        }
    }

    /**
     * @brief Encrypts text with Android Cipher initialization vector.
     * @param text Text to be encrypted
     * @return AES encrypted text with Cipher initialization vector.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    @SuppressWarnings("JavaDoc")
    public byte[] encryptText(String text) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //Get Cipher Instance
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        //Initialize Cipher
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //Get Initialization Vector
        byte[] iv = cipher.getIV();
        //Get Initialization Vector Length as Byte Array
        byte[] ivLenArr = ByteBuffer.allocate(SIZE_OF_INT).putInt(iv.length).array();
        //Get Encrypted Text
        byte[] encryptedText = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
        //Initialize Result Length
        byte[] result = new byte[ivLenArr.length+iv.length+encryptedText.length];
        //Embed Initialization Vector Length and Initialization Vector into the Encrypted Text
        System.arraycopy(ivLenArr,0,result,0,ivLenArr.length);
        System.arraycopy(iv,0,result,ivLenArr.length,iv.length);
        System.arraycopy(encryptedText,0,result,ivLenArr.length+iv.length,encryptedText.length);
        //Return Encrypted Data
        return result;
    }

    /**
     * @brief Decodes encrypted text encoded by this class.
     * @param data encrypted text.
     * @return decoded text.
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    @SuppressWarnings("JavaDoc")
    public String decryptText(@NonNull byte[] data) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        //Parse Cipher Encryption Initialization Vector
        byte[] ivLenArr = Arrays.copyOfRange(data,0,SIZE_OF_INT);
        ByteBuffer buffer = ByteBuffer.wrap(ivLenArr);
        int ivLength = buffer.getInt();
        byte[] iv = Arrays.copyOfRange(data,SIZE_OF_INT,SIZE_OF_INT+ivLength);
        //Get Cipher Instance
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        //Create GCM Parameter Specifications
        final GCMParameterSpec spec = new GCMParameterSpec(128,iv);
        //Initialize Cipher
        cipher.init(Cipher.DECRYPT_MODE,secretKey,spec);
        //Parse Encrypted Data
        byte[] encryptedData = Arrays.copyOfRange(data,SIZE_OF_INT+ivLength,data.length);
        //Decode Data
        byte[] decodedData = cipher.doFinal(encryptedData);
        //Return Decoded Text
        return new String(decodedData,StandardCharsets.UTF_8);
    }

    /**
     * @brief Generates a secret key and is stored in the Android keystore with the specified alias.
     * @return Secret key.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     */
    @SuppressWarnings("JavaDoc")
    private static SecretKey generateKey() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        //Create Generator
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER);
        //Create Generator Parameters
        final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec
                .Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build();
        //Initialize Generator
        keyGenerator.init(keyGenParameterSpec);
        //Return Generated Key
        return keyGenerator.generateKey();
    }

    /**
     * @brief Retrieves Secret Key from Android key store with specified alias if it exists.
     * @return Secret key.
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws UnrecoverableEntryException
     */
    @SuppressWarnings("JavaDoc")
    private static SecretKey getKey() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
        //Get KeyStore Instance
        KeyStore keyStore = KeyStore.getInstance(PROVIDER);
        keyStore.load(null);
        //Get Secret Key Entry
        final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(ALIAS,null);
        //Return Secret Key
        if (secretKeyEntry == null){
            //Entry Does not Exist (First Time)
            return null;
        }
        else{
            //Return Key from Given Alias
            return secretKeyEntry.getSecretKey();
        }
    }
}
