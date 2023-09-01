package com.pingidentity.cdr.testharness.utils;

import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import org.json.simple.JSONObject;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.pingidentity.cdr.testharness.exception.PKIException;

public class JwtUtilities {
	
	public static String getKeyListWrappedJWK(String jwk)
	{
		StringBuffer jwksStringBuffer = new StringBuffer();

		jwksStringBuffer.append("{\"keys\":[");

		jwksStringBuffer.append(jwk);

		jwksStringBuffer.append("]}");
		
		return jwksStringBuffer.toString();
	}
	
	@SuppressWarnings("unchecked")
	public static String getClientJWTAuthentication(String clientId, String issuer, String audience, String jwk) throws PKIException {

		String decodedPrivateJWK = new String(Base64.getDecoder().decode(jwk));
		
		JSONObject base = new JSONObject();
		
		base.put("sub", clientId);
		
		try {
			String jwtRequest = getJWT(base, decodedPrivateJWK, issuer, audience);

			return jwtRequest;

		} catch (Throwable e) {
			throw new PKIException(8081, "Could not generate client assertion: " + e.getMessage(), e);
		}

	}

	public static String getJWT(JSONObject base, String jwk, String issuer, String audience) throws Throwable {
		JWK jwkObj = JWK.parse(jwk);
		String kid = jwkObj.getKeyID();

		// Create RSA-signer with the private key
		JWSSigner signer = new RSASSASigner((RSAKey) jwkObj);

		com.nimbusds.jwt.JWTClaimsSet.Builder jwtBuilder = new JWTClaimsSet.Builder().issuer(issuer)
				.expirationTime(new Date(new Date().getTime() + 360 * 1000)).audience(audience).issueTime(new Date(new Date().getTime())).jwtID(UUID.randomUUID().toString());

		for (Object key : base.keySet())
			jwtBuilder.claim(key.toString(), base.get(key));

		// Prepare JWT with claims set
		JWTClaimsSet claimsSet = jwtBuilder.build();

		JWSHeader header = new JWSHeader(JWSAlgorithm.RS256, JOSEObjectType.JWT, null, null, null, null, null, null, null, null, kid, null, null);

		SignedJWT signedJWT = new SignedJWT(header, claimsSet);

		signedJWT.sign(signer);
		return signedJWT.serialize();
	}

	public static JSONObject getJSONFromJWE(String jwt, String jwk) {
		
		String jwtStr = getSignedJWTFromEncrypted(jwt, jwk);
		
		JSONObject jsonObj;
		try {
			jsonObj = ControllerHelpers.getJSONObjectFromJWTUnverified(jwtStr);
		} catch (Exception e) {
			return null;
		}
		
		return jsonObj;

	}

	public static String getSignedJWTFromEncrypted(String jwt, String jwk) {
		
		if(jwt.split("\\.").length == 3)
		{
			return jwt;
		}
		
		try {

			JWK jwkObj = JWK.parse(jwk);

			// Create RSA-signer with the private key
			RSADecrypter decryptor = new RSADecrypter((RSAKey) jwkObj);

			JWEObject jwe = JWEObject.parse(jwt);

			jwe.decrypt(decryptor);

			Payload jwtPayload = jwe.getPayload();
			String jwtStr = jwtPayload.toString();
			
			return jwtStr;

		} catch (Exception e) {
			return null;
		}

	}
}
