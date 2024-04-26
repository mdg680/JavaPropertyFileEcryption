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

public class PropertiesEncryption {

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

    public void encryptFile(String filePath, List<String> properties) throws InvalidKeySpecException {
        encryptFile(Path.of(filePath), properties);
    }

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

    public void decryptFile(String filePath, List<String> properties) {
        decryptFile(Path.of(filePath), properties);
    }

    public String getPropertyFrom(Path filePath, String propertyName) throws IOException {
        return loadPropertiesFromFile(filePath).get(propertyName);
    }

    private void writePropertiesToFile(Path path, HashMap<String, String> encryptedProperties) {
        File file =  path.toFile();
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

    private HashMap<String, String> encrypt(HashMap<String, String> propertiesFromFile, List<String> properties) 
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

    private HashMap<String, String> decrypt(HashMap<String, String> propertiesFromFile, List<String> properties) 
        throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
                BadPaddingException, UnsupportedEncodingException, InvalidKeySpecException {
        
        SecretKeySpec secretKeySpec = getSecretKey();
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        HashMap<String, String> result = new HashMap<String, String>(propertiesFromFile);

        for(String entry : properties) {
            if (isEncrypted(result.get(entry))) {
                
                String base64EncryptedValue = result.get(entry).replace("enc#", ""); //.split("#")[1]; // we only want the clean base64 string ie. [1] without prefix before conversion
                byte[] encryptedValueInBytes = Base64.getDecoder().decode(base64EncryptedValue);
                byte[] decryptedValueInBytes = cipher.doFinal(encryptedValueInBytes);
                String decryptedValue = new String(decryptedValueInBytes, StandardCharsets.UTF_8);

                result.put(entry, decryptedValue);
            }
        }
        return result;
    }

    private HashMap<String, String> loadPropertiesFromFile(Path path) throws IOException {
        HashMap<String, String> result = new HashMap<>();
        for (String entry : Files.readAllLines(path)) {
            String [] keyValuePair = entry.split("=");
            String key = keyValuePair[0], value = keyValuePair[1];
            result.put(key, value);
        }

        return result;
    }

    private boolean isEncrypted(String propertiesEntry) {
        return propertiesEntry.startsWith("enc#");
    }
}
