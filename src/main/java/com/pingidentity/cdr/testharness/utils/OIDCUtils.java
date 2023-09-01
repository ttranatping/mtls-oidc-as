package com.pingidentity.cdr.testharness.utils;

import java.util.HashMap;
import java.util.Map;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class OIDCUtils {

	private static JSONParser parser = new JSONParser();
	
	private String tokenEndpoint, clientId;
	private String clientSecret = null;
	
	@SuppressWarnings("unused")
	private OIDCUtils()
	{
	}
	
	public OIDCUtils(String tokenEndpoint, String clientId, String clientSecret)
	{
		this.tokenEndpoint = tokenEndpoint;
		this.clientId = clientId;
		this.clientSecret = clientSecret;
	}
	
	public JSONObject validateBearerToken(String bearerToken)
	{
		
		Map<String, String> headers = new HashMap<String, String>();
		headers.put("Accept", "application/json");
		
		Map<String, String> params = new HashMap<String, String>();
		params.put("client_id", this.clientId);
		params.put("client_secret", this.clientSecret);
		params.put("token", bearerToken);
		
		try {
			HttpResponseObj responseObj = MASSLClient.executeHTTP(tokenEndpoint, "POST", headers, params, null, false, 30000);
			
			if(responseObj.getStatusCode() != 200)
				return null;
			
			String responseStr = responseObj.getResponseBody();
			Object responseJSON = parser.parse(responseStr);
			if(responseJSON instanceof JSONObject)
				return (JSONObject)responseJSON;			
			
		} catch (Exception e) {
			return null;
		}
		
		return null;
	}
}
