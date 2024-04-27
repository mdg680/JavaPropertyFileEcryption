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
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

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
            HashMap<String, String> propertiesFromFile = loadPropertiesFromFile(path);
            HashMap<String, String> encryptedProperties = encrypt(propertiesFromFile, properties);
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
        encryptFile(Path.of(filePath), properties);
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
            HashMap<String, String> propertiesFromFile = loadPropertiesFromFile(path);
            HashMap<String, String> decryptedProperties = decrypt(propertiesFromFile, properties);
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
        decryptFile(Path.of(filePath), properties);
    }

    private void writePropertiesToFile(Path path, HashMap<String, String> encryptedProperties) {
        File file = path.toFile();
        file.delete();

        try (BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file))) {
            for (HashMap.Entry<String, String> entry : encryptedProperties.entrySet()) {
                String line = String.join("=", entry.getKey(), entry.getValue());
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
     * @param propertiesFromFile properties loaded into a hashmap from a file
     * @param properties properties set marked encryption
     * @return HashMap of properties, with marked properties encrypted
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeySpecException
     */
    public HashMap<String, String> encrypt(HashMap<String, String> propertiesFromFile, List<String> properties) 
        throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
                BadPaddingException, UnsupportedEncodingException, InvalidKeySpecException {
        
        SecretKeySpec secretKeySpec = getSecretKey();
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        HashMap<String, String> result = new HashMap<String, String>(propertiesFromFile);

        for(String entry : properties) {
            if (!isEncrypted(result.get(entry))) {
                
                byte[] encryptedValue = cipher.doFinal(result.get(entry).getBytes("UTF-8"));
                String base64Value = Base64.getEncoder().encodeToString(encryptedValue);
              
                result.put(entry, "enc#" + base64Value);
            }
        }
        return result;
    }

    /**
     * 
     * @param propertiesFromFile properties loaded into a hashmap from a file
     * @param properties properties set marked decryption
     * @return HashMap of properties, with marked properties decrypted
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeySpecException
     */
    public HashMap<String, String> decrypt(HashMap<String, String> propertiesFromFile, List<String> properties) 
        throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
                BadPaddingException, UnsupportedEncodingException, InvalidKeySpecException {
        
        SecretKeySpec secretKeySpec = getSecretKey();
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        HashMap<String, String> result = new HashMap<String, String>(propertiesFromFile);

        for(String entry : properties) {
            if (isEncrypted(result.get(entry))) {
                
                String base64EncryptedValue = result.get(entry).replace("enc#", "");
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
     * @return HashMap with properties as key, value pairs.
     * @throws IOException
     */
    public HashMap<String, String> loadPropertiesFromFile(Path path) throws IOException {
        HashMap<String, String> result = new HashMap<>();
        for (String entry : Files.readAllLines(path)) {
            String [] keyValuePair = entry.split("=");
            String key = keyValuePair[0], value = keyValuePair[1];
            result.put(key, value);
        }

        return result;
    }

    public String getPropertyFromFile(String propertyKey, Path filePath) 
        throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, 
                IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        
        HashMap<String, String> properties = loadPropertiesFromFile(filePath);

        return getPropertyFromPropertiesList(propertyKey, properties);
    }

    public String getPropertyFromPropertiesList(String propertyKey, HashMap<String, String> properties) 
        throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, 
                BadPaddingException, UnsupportedEncodingException, InvalidKeySpecException {
        List<String> markedProperties = new ArrayList<String>();
        markedProperties.add(propertyKey);
        String result = decrypt(properties, markedProperties).get(propertyKey);

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
