/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package propertiescipher;

import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import propertiescipher.PropertiesEncryption;

public class App {
    public String getGreeting() {
        return "Hello from app!";
    }

    public void encrypt() throws InvalidKeySpecException {
        PropertiesEncryption p =  new PropertiesEncryption();
        List<String> list =  new ArrayList();
        list.add("password");
        p.encryptFile("C:\\Users\\monop\\source\\repos\\java_projects\\propertiesCipher\\app\\src\\main\\java\\propertiescipher\\prop", list);
    }
    public static void main(String[] args) throws InvalidKeySpecException {
        System.out.println(new App().getGreeting());
        new App().encrypt();
    }
}
