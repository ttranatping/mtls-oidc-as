package com.pingidentity.cdr.testharness.controllers.cdrregister;

import java.io.IOException;
import java.util.UUID;

import org.jboss.logging.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.RSAKey;
import com.pingidentity.cdr.testharness.Constants;
import com.pingidentity.cdr.testharness.ca.JWKSStorage;
import com.pingidentity.cdr.testharness.utils.JwtUtilities;

@RestController
public class MTLSOIDCServerControllerREST {

	private static Logger logger = Logger.getLogger(MTLSOIDCServerControllerREST.class);
	
	@Autowired
	private JWKSStorage jwksStorage;
	
	@Autowired
	private String baseUrl;
	
	public MTLSOIDCServerControllerREST() throws IOException {
	}

	@RequestMapping(value = Constants.DISCO_SERVICE, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
	public String getWellKnown() {
		
		return String.format("{\"token_endpoint\":\"%s/as/token.oauth2\", \"jwks_uri\":\"%s%s\"}", baseUrl, baseUrl, Constants.GLOBAL_JWKS_SERVICE);
	}

	@RequestMapping(value = Constants.GLOBAL_JWKS_SERVICE, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
	public String getJWKS() {
		
		RSAKey globalKey = jwksStorage.getKey(Constants.JWKS_GLOBAL_KID);
		
		return JwtUtilities.getKeyListWrappedJWK(globalKey.toPublicJWK().toJSONString());
	}

	@RequestMapping(value = "/as/token.oauth2", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
	public String getAccessToken(@RequestParam("client_id") String clientId) {

		
		return String.format("{\"access_token\":\"%s\"}", UUID.randomUUID().toString());
	}

}