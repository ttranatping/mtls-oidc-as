package com.pingidentity.cdr.testharness.ca;

import java.util.HashMap;
import java.util.Map;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.pingidentity.cdr.testharness.utils.PKITools;

public class JWKSStorage {
	
	private final int keySize;
	private final String keystoreCacheLocation;
	
	public JWKSStorage(int keySize, String keystoreCacheLocation)
	{
		this.keySize = keySize;
		this.keystoreCacheLocation = keystoreCacheLocation;
	}
	
	private final Map<String, RSAKey> _KEYLIST = new HashMap<String, RSAKey>();
	
	public RSAKey getKey(String kid)
	{
		if(!_KEYLIST.containsKey(kid))
			createNewGlobalKey(kid);
		
		return _KEYLIST.get(kid);
	}
	
	public synchronized void createNewGlobalKey(String kid)
	{
		if(_KEYLIST.containsKey(kid))
			return;
		
		JWSAlgorithm algorithm = null; //not setting algorithm
		KeyUse keyUse = null; //not setting keyUse
		
		RSAKey newKey = PKITools.make(keySize, keyUse, algorithm, kid, keystoreCacheLocation);
		
		_KEYLIST.put(kid, newKey);
	}

}
