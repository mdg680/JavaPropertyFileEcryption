package propertiescipher;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
/**
 * Class for encypting and decrypting properties files with the format of property entries: 'key=val'
 * @author Peter Svarre Holten Roenholt
 */
public class PropertiesEncryption {

    /**
     * Encrypts properties in file, format of property key, value pairs uses '=' as delimeter
     * ie. key=value
     * @param path path to file to be encrypted
     * @param properties properties to encrypt in file
     * @throws InvalidKeySpecException
     */
    public void encryptFile(Path path, List<String> properties) throws InvalidKeySpecException {
        try {
            Properties propertiesFromFile = loadPropertiesFromFile(path);
            Properties encryptedProperties = encrypt(propertiesFromFile, properties);
            writePropertiesToFile(path, encryptedProperties);
        } catch (IOException e ) {
            e.printStackTrace();  
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    /**
     * Encrypts properties in file, format of property key, value pairs uses '=' as delimeter
     * ie. key=value
     * @param filePath path to file to be encrypted
     * @param properties properties to encrypt in file
     * @throws InvalidKeySpecException
     */
    public void encryptFile(String filePath, List<String> properties) throws InvalidKeySpecException {
        encryptFile(Path.get(filePath), properties);
    }

    /**
     * decrypts properties in file, format of property key, value pairs uses '=' as delimeter
     * ie. key=value
     * @param path path to file to be encrypted
     * @param properties properties to encrypt in file
     * @throws InvalidKeySpecException
     */
    public void decryptFile(Path path, List<String> properties) {
        try {
            Properties propertiesFromFile = loadPropertiesFromFile(path);
            Properties decryptedProperties = decrypt(propertiesFromFile, properties);
            writePropertiesToFile(path, decryptedProperties);
        } catch (IOException e ) {
            e.printStackTrace();  
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    /**
     * decrypts properties in file, format of property key, value pairs uses '=' as delimeter
     * ie. key=value
     * @param filePath path to file to be encrypted
     * @param properties properties to encrypt in file
     * @throws InvalidKeySpecException
     */
    public void decryptFile(String filePath, List<String> properties) {
        decryptFile(Path.get(filePath), properties);
    }

    private void writePropertiesToFile(Path path, Properties properties) {
        File file = path.toFile();
        file.delete();

        try (BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file))) {
            for (Entry<Object, Object> entry : properties.entrySet()) {
                String line = String.join(
                    "=", 
                    entry.getKey().toString(), 
                    entry.getValue().toString());
                bufferedWriter.write(line);
                bufferedWriter.newLine();
            }
            bufferedWriter.flush();
            bufferedWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    /**
     * Prepares secret key spec for cipher, using a generated AES key, generation is based on a fixed salt value
     * @return SecretKeySpec using generated AES key
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    private SecretKeySpec getSecretKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        char[] password = System.getProperty("PropertyPassword").toCharArray();
        if (password == null) {
            throw new IllegalArgumentException("'-DPropertyPassword' not set");
        }

        int keyLength = 256;
        int iterationCount = 100;
        byte[] salt = "basecaresalt".getBytes(); // This can be whatever, here it is primarily used to generate a valid AES key from password input

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        SecretKey keyTmp = keyFactory.generateSecret(keySpec);

        return new SecretKeySpec(keyTmp.getEncoded(), "AES");
    }

    /**
     * 
     * @param properties properties loaded into a hashmap from a file
     * @param targetProperties properties set marked encryption
     * @return Properties object with marked properties encrypted
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeySpecException
     */
    public Properties encrypt(Properties properties, List<String> targetProperties) 
        throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
                BadPaddingException, UnsupportedEncodingException, InvalidKeySpecException {
        
        SecretKeySpec secretKeySpec = getSecretKey();
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        Properties result = properties;

        for(String entry : targetProperties) {
            if (!isEncrypted(result.getProperty(entry))) {
                byte[] encryptedValue = cipher.doFinal(result.getProperty(entry).getBytes("UTF-8"));
                String base64Value = Base64.getEncoder().encodeToString(encryptedValue);
              
                result.put(entry, "enc#" + base64Value);
            }
        }
        return result;
    }

    /**
     * 
     * @param properties properties loaded into a hashmap from a file
     * @param targetProperties properties set marked decryption
     * @return Properties object, with marked properties decrypted
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeySpecException
     */
    public Properties decrypt(Properties properties, List<String> targetProperties) 
        throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
                BadPaddingException, UnsupportedEncodingException, InvalidKeySpecException {
        
        SecretKeySpec secretKeySpec = getSecretKey();
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        Properties result = properties;

        for(String entry : targetProperties) {
            if (isEncrypted(result.getProperty(entry))) {
                
                String base64EncryptedValue = result.get(entry).toString().replace("enc#", "");
                byte[] encryptedValueInBytes = Base64.getDecoder().decode(base64EncryptedValue);
                byte[] decryptedValueInBytes = cipher.doFinal(encryptedValueInBytes);
                String decryptedValue = new String(decryptedValueInBytes, StandardCharsets.UTF_8);

                result.put(entry, decryptedValue);
            }
        }
        return result;
    }

    /**
     * Loads properties from file into HashMap
     * @param path
     * @return Properties object.
     * @throws IOException
     */
    public Properties loadPropertiesFromFile(Path path) throws IOException {
        Properties result = new Properties();
        for (String entry : Files.readAllLines(path)) {
            String [] keyValuePair = entry.split("=");
            String key = keyValuePair[0], value = keyValuePair[1];
            result.put(key, value);
        }

        return result;
    }

    /**
     * Check if file is already encrypted
     * @param propertiesEntry
     * @return boolean
     */
    private boolean isEncrypted(String propertiesEntry) {
        return propertiesEntry.startsWith("enc#");
    }
}
