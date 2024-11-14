package org.datwyler;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;

import java.text.ParseException;

public class EncryptionUtils {

    public static String encrypt(Payload input, byte[] secretKey) throws JOSEException {
        // Create a JWS object with a header and the claims
        var jweObject = new JWEObject(
                new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256), input);

        // Encrypt
        jweObject.encrypt(new DirectEncrypter(secretKey));

        // Serialize the JWE object to a compact, URL-safe string
        return jweObject.serialize();
    }

    public static String encrypt(String input, byte[] secretKey) throws JOSEException {
        return encrypt(new Payload(input), secretKey);
    }

    public static String decrypt(String input, byte[] secretKey) throws ParseException, JOSEException {
        var jweObject = JWEObject.parse(input);

        // Decrypt
        jweObject.decrypt(new DirectDecrypter(secretKey));

        // Get the plain text
        var payload = jweObject.getPayload();

        return payload.toString();
    }

}
