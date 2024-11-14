package org.datwyler;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

public class Main {
    public static void main(String[] args) throws ParseException, NoSuchAlgorithmException, JOSEException {
        var encryptionKey = new DeterministicKeyGenerator().generateSharedKey("af5af7df-d86f-4f3a-9a60-1f8713e90b10");
        System.out.println("Shared key: " + bytesToHex(encryptionKey));

        var claims = generatePayload();
        var payload = new Payload(claims.toJSONObject());
        var encryptedJwt = EncryptionUtils.encrypt(payload, encryptionKey);

        System.out.println("Encrypted JWT:");
        System.out.println(encryptedJwt);

        var decryptedJwt = EncryptionUtils.decrypt(encryptedJwt, encryptionKey);

        System.out.println("Decrypted JWT:");
        System.out.println(decryptedJwt);

        var jwe = "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..Qc-SGtVIq8EJ1sAmavMrwA.KWzW_Ox6XHYo4w9tjALtIAm7GsL1YlsZi7VsFjVj1A93ySK3M8yWXvdLm6TVOqLABMgbBl5iTNvlmj7Lvs6z1asX21Emm-dPX-mM5qt2PttPd38vpRydmS0YTg4KDG9bst0IABZaZcJkFfHXR_jUHgksnL5ZSPqBIRyG3uiu9rT0MAMHKek5W9iykHqPKNLiV6I1c7JDu4-IzGY9jOGqywIRLcgZgG6GJI72Cztuivf2Sw5Wjm-gmbskNd0rPyeEuj79B7A6Hz7GoMwOW1wswrGNy9OmSLv6ZF4OS-L9XLSKATUa8S5Wuikyb8CmYwfaawBPpTm7JKPZcZx04CldgM8v-ekmqgA1VWpKF6DX2a7F8BvbZ1lFQZ1vqadDNZsnFaYzLjf2ZiFVUfgVEcXCdDZ514bau2Ft7-tSTsh6bnefh8LAkvzl2Di7hRZQ6U8RzKZdWW2NoqVUxs02CHqzsn8aboOd3yJYE-UMh-3_Kzl5MEQpplPqcQDb0H-iUus-2DmMH01l9HBHOTQ8wwRyyY75p1Isbr9qRXP9-rSdwnbpL1da59UGlJz5MpfoaKXw44TEh2xb2IBMPoz6ZawtK5BrlmnMvruf0_iVz-jelebe6M6I2KPphiSFlOj2M1JoqzK2_VBUpB_wJ8WXPbIxoRBvMD8hwlaerL16FX9kCU02tD9IdSA0gka-KQ-5JOcde2q9lcM7TjjXDP7xZPCJ5wXYxRhEbxXEMDxbdXlDFL7rGndUa4Zjw6h2xKMYxxr7ohPWZbiTbjQTgL8fRH9iGVBMgEjYo0CegRoXKobuud3Go_rGmU0OkDbOHiGKm3fBIQmfssJanH4RDgkcind1_UuMuFK0MCQKtMFGG6qM8mkIAS5fpdn8MTopweTEBFCz_-9XpsREDMgypiPwt-4k8y3xTx_aEOdRwMm81zqS9OCplUBScefadMuzVDD0jK3ssTQy9BedQzkOBdXpG1SwFbmYyfP1P7kpaMzNO-H_4ZPLYbkYcaMlfUacUV1hAMJ5z8PCbkFxDIqp2samYVa970PwlhRlDL3YsjWzNOIx4bfuRprT6JaeylZTXCM7k9eDsG3BSX7dWST79Lrc4bVyoqcuySM87yffXiBO0v_5WRw.KjxfrS54RbeEWvSU09-kZg";
        EncryptionUtils.decrypt(jwe, encryptionKey);
    }

    private static PrivateKey readPKCS8PrivateKey(File file) throws Exception {
        PEMParser pemParser = new PEMParser(new FileReader(file));
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        Object object = pemParser.readObject();
        KeyPair kp = converter.getKeyPair((PEMKeyPair) object);
        return kp.getPrivate();
    }

    private static RSAPublicKey readX509PublicKey(File file) throws IOException {
        try (FileReader keyReader = new FileReader(file)) {
            PEMParser pemParser = new PEMParser(keyReader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
            return (RSAPublicKey) converter.getPublicKey(publicKeyInfo);
        }
    }

    private static JWTClaimsSet generatePayload() {
        return new JWTClaimsSet.Builder()
                .issuer("https://synapse.seabix.com:443/13492")   // a case-sensitive string containing a String or URI to identify  the issuer
                .subject("f967fe9e-2863-4cc8-a9be-bdbecd7e2fac")    // license ID
                .audience("af5af7df-d86f-4f3a-9a60-1f8713e90b10")  // DME region tenant
                .issueTime(Date.from(Instant.parse("2024-11-13T11:56:35.974Z")))
                .expirationTime(Date.from(Instant.parse("2025-11-13T11:56:35.974Z")))
                .claim("tenantId", UUID.randomUUID().toString())
                .claim("tenantName", "Company XYZ")
                .claim("module", "dc")
                .claim("cabinets", 100)
                .claim("controllers", 25)
                .claim("users", 20)
                .claim("startTime", Instant.parse("2024-11-13T11:56:35.974Z").getEpochSecond())
                .claim("endTime", Instant.parse("2025-11-13T11:56:35.974Z").getEpochSecond()) // one year validity
                .build();
    }

    private static void prettyPrint(String serializedJwt) throws ParseException, JsonProcessingException {
        // Parse the serialized string back into a SignedJWT object
        var jwt = SignedJWT.parse(serializedJwt);

        // Retrieve the claims set from the PlainJWT
        JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();

        // Convert the claims set to a JSON string
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> claimsMap = claimsSet.getClaims();
        String json = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(claimsMap);

        // Print the JSON string
        System.out.println("JWT Claims as JSON:");
        System.out.println(json);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0'); // Ensure two characters for each byte
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}