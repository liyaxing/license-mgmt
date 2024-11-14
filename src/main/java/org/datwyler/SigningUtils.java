package org.datwyler;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.PrivateKey;

public class SigningUtils {


    public static String sign(JWTClaimsSet cliamSet, PrivateKey senderJWK) throws JOSEException {
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                cliamSet);

        // Sign the JWT
        signedJWT.sign(new RSASSASigner(senderJWK));
        return signedJWT.serialize();
    }
}
