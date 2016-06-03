package com.microsoft.aad.adal4j;


import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSHeader.Builder;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 *
 */
final class MSCAPIJwtHelper {
    /**
     * Builds JWT object.
     * 
     * @param credential
     * @return
     * @throws AuthenticationException
     */
    static ClientAssertion buildJwt(final MSCAPIAsymmetricKeyCredential credential,
            final String jwtAudience) throws AuthenticationException {
        if (credential == null) {
            throw new IllegalArgumentException("credential is null");
        }
        
      
        JWTClaimsSet claimsSet = new MSCAPIAdalJWTClaimsSet();
        final List<String> audience = new ArrayList<String>();
        audience.add(jwtAudience);
        claimsSet.setAudience(audience);
        claimsSet.setIssuer(credential.getClientId());
        final long time = System.currentTimeMillis();
        claimsSet.setNotBeforeTime(new Date(time));
        claimsSet
                .setExpirationTime(new Date(
                        time
                                + AuthenticationConstants.AAD_JWT_TOKEN_LIFETIME_SECONDS
                                * 1000));
        claimsSet.setSubject(credential.getClientId());
        SignedJWT jwt = null;
        try {
            JWSHeader.Builder builder = new Builder(JWSAlgorithm.RS256);
            List<Base64> certs = new ArrayList<Base64>();
            certs.add(new Base64(credential.getPublicCertificate()));
            builder.x509CertChain(certs);
            builder.x509CertThumbprint(new Base64URL(credential
                    .getPublicCertificateHash()));
            jwt = new SignedJWT(builder.build(), claimsSet);
            // Begin Updates by Rob Reilly 5/19/2016
            Key key = credential.getKey();
            JWSSigner signer = null;
            if (key instanceof RSAPrivateKey)
            {
            	signer = new RSASSASigner((RSAPrivateKey) key);
            }
            else if (key instanceof PrivateKey)
            {
            	signer = new MSCAPIRSASigner(
                        (PrivateKey) key);
            }
            
            jwt.sign(signer);
            // End Updates by Rob Reilly 5/19/2016
        }
        catch (final Exception e) {
            throw new AuthenticationException(e);
        }

        return new ClientAssertion(jwt.serialize());
    }
}
