import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.crypto.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Request_Encryption {

    static String iv = "98361936631"; // random number (not being used presently)
    static String json = "{\"body\": \"this is a sample\"}";
    static String partner_key = "sample_partner_key";

    static String public_key_file_name = "kiteStore.p12";
    static String public_key_file_password = "abc123";

    static String private_key_file_name = "kiteStore.p12";
    static String private_key_file_password = "abc123";

    public static void main(String[] args) throws Exception {
        System.out.println("Before encryption");
        System.out.println("iv = " + iv);
        System.out.println("json = " + json);
        System.out.println("partner key = " + partner_key);
        System.out.println();

        /* Step 1 */
        SecretKey secretKey = generateSymmetricKey(); // note: currently iv is not being used in this process
        /* Step 2 */
        String encryptedJson = encryptRequestJson(secretKey);
        /* Step 3 */
        String encryptedSymmetricKey = encryptSymmetricKey(secretKey);
        /* Step 4 */
        String signedJson = signConstructedJson(encryptedJson);
        /* Step 5 */
        String encryptedPartnerKey = encryptPartnerKey();

        System.out.println("After encryption\n");
        System.out.println("Request Headers");
        System.out.println("iv = " + iv);
        System.out.println("key = " + encryptedSymmetricKey);
        System.out.println("token = " + signedJson);
        System.out.println("partner = " + encryptedPartnerKey);

        Map<String,String> requestBodyMap = new HashMap<>();
        requestBodyMap.put("body", encryptedJson);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        System.out.println("\nRequest Body\n" + gson.toJson(requestBodyMap));
    }

    /* Step 1: Generate Symmetric Key with key size of 128 bits using AES Algorithm.
               The random key should be generated for every transaction.
               The IV to use to create the cipher.
     */
    private static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128, SecureRandom.getInstanceStrong());
        return keyGen.generateKey();
    }

    /* Step 2: Encrypt the Constructed JSON String using Symmetric Key.
               Supported Cipher Algorithm Name/MODE/Padding for Encryption using
               Session Key with cipher algorithm is AES/CBC/PKCS5Padding.
               And convert the encrypted data as Base64 encoded String.
               # BODY #
     */
    private static String encryptRequestJson(SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
            BadPaddingException, IllegalBlockSizeException,
            InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedJson = cipher.doFinal(json.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedJson);
    }

    /* Step 3: Encrypt the generated Symmetric Key using Sodel's Public Key.
               And Supported Cipher Algorithm Name/ MODE/ Padding for Encryption
               of Session Key with cipher algorithm are RSA / ECB / PKCS1Padding
               and convert the output to Base64 Encoded String.
               # KEY #
     */
    private static String encryptSymmetricKey(SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
            CertificateException, KeyStoreException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
        return Base64.getEncoder().encodeToString(cipher.doFinal(secretKey.getEncoded()));
    }

    /* Step 4: Sign the constructed JSON String with Partner's Private Key and
               convert the output to Base64 Encoded String.
               Supported algorithm is SHA1withRSA
               # TOKEN #
     */
    private static String signConstructedJson(String encryptedJson) throws NoSuchAlgorithmException, UnrecoverableKeyException,
            CertificateException, KeyStoreException, IOException, SignatureException, InvalidKeyException {
        byte[] data = Base64.getDecoder().decode(encryptedJson);
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(getPrivateKey());
        signature.update(data);
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    /* Step 5: Encrypt the Partner Key using Sodel's Public Key.
               And Supported Cipher Algorithm Name/ MODE/ Padding
               for Encryption of Session Key with cipher algorithm
               are RSA / ECB / PKCS1Padding and convert the output
               to Base64 Encoded String
               # PARTNER #
     */
    private static String encryptPartnerKey() throws NoSuchPaddingException, NoSuchAlgorithmException, CertificateException,
            KeyStoreException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
        byte[] encoded = cipher.doFinal(partner_key.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encoded);
    }

    private static PublicKey getPublicKey() throws KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(public_key_file_name), public_key_file_password.toCharArray());
        java.security.cert.Certificate certificate = keyStore.getCertificate("fis-uat");
        return certificate.getPublicKey();
    }

    private static PrivateKey getPrivateKey() throws KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(private_key_file_name), private_key_file_password.toCharArray());
        return (PrivateKey) keyStore.getKey("kite-uat", private_key_file_password.toCharArray());
    }
}
