# Elliptic_curve-by-JAVA
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.buncycastle.jce.provider.BouncyCastleProvider;

public class ECDHExample {

	static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // Generate an EC key pair for Alice
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
        keyGen.initialize(256); // 使用するキーのビット長
        KeyPair aliceKeyPair = keyGen.generateKeyPair();
        
        // Generate an EC key pair for Bob
        KeyPair bobKeyPair = keyGen.generateKeyPair();

        // Alice creates and initializes her KeyAgreement object
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        aliceKeyAgree.init(aliceKeyPair.getPrivate());

        // Bob creates and initializes his KeyAgreement object
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        bobKeyAgree.init(bobKeyPair.getPrivate());

        // Alice encodes her public key, and Bob decodes it
        byte[] alicePubKeyEnc = aliceKeyPair.getPublic().getEncoded();
        PublicKey alicePubKey = KeyFactory.getInstance("EC", "BC").generatePublic(new X509EncodedKeySpec(alicePubKeyEnc));

        // Bob does the same with his public key
        byte[] bobPubKeyEnc = bobKeyPair.getPublic().getEncoded();
        PublicKey bobPubKey = KeyFactory.getInstance("EC", "BC").generatePublic(new X509EncodedKeySpec(bobPubKeyEnc));

        // Alice and Bob perform key agreement
        aliceKeyAgree.doPhase(bobPubKey, true);
        bobKeyAgree.doPhase(alicePubKey, true);

        // Both generate the shared secret
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
        byte[] bobSharedSecret = bobKeyAgree.generateSecret();

        System.out.println("Alice's secret: " + toHexString(aliceSharedSecret));
        System.out.println("Bob's secret: " + toHexString(bobSharedSecret));
    }

    private static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
