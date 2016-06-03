package com.microsoft.aad.adal4j;

import java.security.Provider;
import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSAlgorithmProvider;

public abstract class MSCAPIBaseJWSProvider implements JWSAlgorithmProvider  {

	/**
	 * The supported algorithms.
	 */
	private final Set<JWSAlgorithm> algs;


	/**
	 * The underlying cryptographic provider, {@code null} if not specified
	 * (implies default one).
	 */
	protected Provider provider = null;


	/**
	 * Creates a new base JWS provider.
	 *
	 * @param algs The supported JWS algorithms. Must not be {@code null}.
	 */
	public MSCAPIBaseJWSProvider(final Set<JWSAlgorithm> algs) {

		if (algs == null) {
			
			throw new IllegalArgumentException("The supported JWS algorithm set must not be null");
		}

		this.algs = Collections.unmodifiableSet(algs);
	}


	@Override
	public Set<JWSAlgorithm> supportedAlgorithms() {

		return algs;
	}

	//@Override
	public void setProvider(final Provider provider) {

		this.provider = provider;
	}
}
