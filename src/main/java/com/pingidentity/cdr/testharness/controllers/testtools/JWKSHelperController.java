package com.pingidentity.cdr.testharness.controllers.testtools;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.RSAKey;
import com.pingidentity.cdr.testharness.Constants;
import com.pingidentity.cdr.testharness.ca.JWKSStorage;
import com.pingidentity.cdr.testharness.utils.JwtUtilities;

@RestController
public class JWKSHelperController {
	
	@Autowired
	private JWKSStorage jwksStorage;
	
	public JWKSHelperController() throws IOException {
	}

	@RequestMapping(value = Constants.JWKS_SERVICE, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
	public String getJWKSPublic(@PathVariable(value = "kid") String kid) {
		
		RSAKey globalKey = jwksStorage.getKey(kid);
		
		return JwtUtilities.getKeyListWrappedJWK(globalKey.toPublicJWK().toJSONString());
	}

	@RequestMapping(value = Constants.JWKS_SERVICE_REVOCATION, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
	public String getJWKSPublicRevocation(@PathVariable(value = "kid") String kid) {		
		return JwtUtilities.getKeyListWrappedJWK("");
	}

	@RequestMapping(value = Constants.JWKS_SERVICE_PRIVATE, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
	public String getJWKSPrivate(@PathVariable(value = "kid") String kid) {
		
		RSAKey globalKey = jwksStorage.getKey(kid);
		
		return JwtUtilities.getKeyListWrappedJWK(globalKey.toJSONString());
	}

}