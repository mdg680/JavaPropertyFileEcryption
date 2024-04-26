# Properties file encryption.

## Description:
Simple library to encrypt/decrypt properties in a properties file.

## Requirements

### Tools
Java 1.8/8+

### Formats
property files most have entries in the format of key=value, example a property file could look like:

    password=some_password
    connection=some_connection

### VM arguments
A password for generating encryption and decryption keys must be supplied when run:
    
    -DPropertiesPassword=<password>

This password is used to generate a valid AES key, and is used to lock and unlock the data.

## Interface

Implementation has the following pulic interface for

encryption:

```java
public void encryptFile(Path path, List<String> properties)
public void encryptFile(String filePath, List<String> properties)
```

decryption:
```java
public void decryptFile(Path path, List<String> properties)
public void decryptFile(String filePath, List<String> properties)
```

## Example
Given we run the code with the follwing settings:

VM argument ``-DPropertyPassword=hello123`` argument is set

Our ``file`` looks like:

    password=some_password
    connection=some_connection

we define the properties to encrypt/decrypt somewhere in our wrapping code as:

```java
List<String> list =  new ArrayList();
list.add("password"); // property we will affect, we can add more if we want
```

running: 
```java
encryptFile("<path_to_file>", list);
````
should update out file to look something like:

    password=enc#BzBKaabPfL68iJpzNUi0sw==
    connection=some_connection

notice only the marked propaty `password` is changed, and `enc#` signifies that it is now an encrypted value

to reverse encryption we can call

```java
encryptFile("<path_to_file>", list); // list has password key marked for decryption
````

which should revert the file back to:

    password=some_password
    connection=some_connection

### Note that only files included in the list of marked property keys will be affected both forwards and backwards.