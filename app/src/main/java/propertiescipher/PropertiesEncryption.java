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
import java.util.HashMap;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class PropertiesEncryption {

    public void encryptFile(Path path, List<String> properties) {
        try {
            HashMap<String, String> propertiesFromFile = loadPropertiesFromFile(path);
            HashMap<String, String> encryptedProperties = encrypt(propertiesFromFile, properties);
            writeFile(path, encryptedProperties);
        } catch (IOException e ) {
            e.printStackTrace();  
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        
    }

    public void encryptFile(String path, List<String> properties) {
        encryptFile(Path.of(path), properties);
    }

    private void writeFile(Path path, HashMap<String, String> encryptedProperties) {
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
        throw new UnsupportedOperationException("Unimplemented method 'write'");
    }

    private HashMap<String, String> encrypt(HashMap<String, String> propertiesFromFile, List<String> properties) 
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
                   IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        String password = System.getProperty("PropertiesPassword");
        if (password == null) {
            throw new IllegalArgumentException("'-DPropertyPassword' not set");
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(password.getBytes(), password);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        HashMap<String, String> result = propertiesFromFile;

        for(String entry : properties) {
            if (!isEncrypted(result.get(entry))) {
                var new_val = cipher.doFinal(result.get(entry).getBytes("UTF-8"));
                result.put(entry, new String(new_val, StandardCharsets.UTF_8));
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
        return propertiesEntry.matches("enc\\([a-zA-Z0-9]+\\)");
    }
}
