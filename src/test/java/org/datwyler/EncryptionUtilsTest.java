package org.datwyler;

import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class EncryptionUtilsTest {

    @Test
    public void test() throws NoSuchAlgorithmException, JOSEException, ParseException {
        var keyGen = new DeterministicKeyGenerator();
        var key = keyGen.generateSharedKey("testkey");
        var encryptedStr = EncryptionUtils.encrypt("abc", key);
        var decryptedStr = EncryptionUtils.decrypt(encryptedStr, key);

        assertEquals("abc", decryptedStr);
    }
}
