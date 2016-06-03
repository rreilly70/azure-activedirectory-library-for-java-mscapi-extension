package com.microsoft.aad.adal4j;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;

import com.nimbusds.jose.util.Base64URL;

/**
 * RSA Signature-Scheme-with-Appendix (RSASSA) signer of 
 * {@link com.nimbusds.jose.JWSObject JWS objects}. 
 * This class add support for use of sunMSACPI provider for KeyStore. This class is thread-safe.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS512}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS512}
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @author Omer Levi Hevroni
 * @author Rob Reilly
 * @version 2016-02-25
 */
@ThreadSafe
public class MSCAPIRSASigner extends MSCAPIRSASSAProvider  implements JWSSigner{


	/**
	 * The private key wrapper from MSCAPI.
	 */
	private final PrivateKey privateKey;


	/**
	 * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) signer.
	 *
	 * @param privateKey The private key. Must not be {@code null}.
	 */
	public MSCAPIRSASigner(final PrivateKey privateKey) {

		if (privateKey == null) {

			throw new IllegalArgumentException("The private RSA key must not be null");
		}

		this.privateKey = privateKey;
	}


	/**
	 * Gets the private key wrapper from MSCAPI.
	 *
	 * @return The private key wrapper.
	 */
	public PrivateKey getPrivateKey() {

		return privateKey;
	}


	@Override
	public Base64URL sign(final JWSHeader header, final byte[] signingInput) throws JOSEException
		{

		Signature signer;
		Base64URL B64Sign = null;
		try {
			
			signer = getRSASignerAndVerifier(header.getAlgorithm(), provider);
		
			signer.initSign(privateKey);
			signer.update(signingInput);
			B64Sign =  Base64URL.encode(signer.sign());
		}	
		catch (InvalidKeyException e) {

			throw new JOSEException("Invalid private RSA key: " + e.getMessage(), e);

		} catch (SignatureException e) {

			throw new JOSEException("RSA signature exception: " + e.getMessage(), e);
		}

		return B64Sign;	

	}


}
