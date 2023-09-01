package com.pingidentity.cdr.testharness.utils;

import java.util.Base64;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class ControllerHelpers {

	public static JSONObject getJSONObjectFromJWTUnverified(String token) throws Exception
	{
		String [] tokenComponents = token.split("\\.");
		
		if(tokenComponents.length != 3)
			return null;
		
		String encodedMessage = tokenComponents[1];
		String decodedMessage = new String(Base64.getDecoder().decode(encodedMessage));
		
		JSONParser parser = new JSONParser();
		
		JSONObject idTokenObj = null;
		try {
			idTokenObj = (JSONObject) parser.parse(decodedMessage);
		} catch (ParseException e) {
			throw new Exception("Could not parse ID token - JSON parse error", e);
		}
		
		return idTokenObj;
	}
	
	public static String getJwtClaimUnverified(String token, String claim) throws Exception
	{
		JSONObject idTokenObj = getJSONObjectFromJWTUnverified(token);
		
		if(idTokenObj == null || !idTokenObj.containsKey(claim))
			return null;
		
		return String.valueOf(idTokenObj.get(claim));
	}
	
}
