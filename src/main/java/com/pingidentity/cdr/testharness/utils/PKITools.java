package com.pingidentity.cdr.testharness.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.operator.OperatorCreationException;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

public class PKITools {

	//TODO: Change this so that it is configurable
	private static final String KEYSTORE_PASSWORD = "P@ssword1";
	private static final String KEYSTORE_DEFAULT_CERT_DN = "CN=DEFAULTCN, OU=APAC, O=Ping, L=Melbourne, S=VIC, C=AI";
	private static final String KEYSTORE_ALIAS = "main";
	
	public static RSAKey load(Integer keySize, KeyUse keyUse, Algorithm keyAlg, String kid, String cachePath) {
    	String kpPath = cachePath + File.separator + kid + ".jks";
    	
    	try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSASSA-PSS");
			keyPairGenerator.initialize(4096);
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			
			keyStore.load(new FileInputStream(kpPath), KEYSTORE_PASSWORD.toCharArray());
			
    		KeyPair kp = getKeyPair(keyStore);
            return getRSAKey(kp, keySize, keyUse, keyAlg, kid);
		} catch (Exception e1) {
			return null;
		}

	}
	
	public static KeyPair getKeyPair(final KeyStore keystore) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		  final Key key = (PrivateKey) keystore.getKey(KEYSTORE_ALIAS, KEYSTORE_PASSWORD.toCharArray());

		  final Certificate cert = keystore.getCertificate(KEYSTORE_ALIAS);
		  final PublicKey publicKey = cert.getPublicKey();

		  return new KeyPair(publicKey, (PrivateKey) key);
		}
	
    public static RSAKey make(Integer keySize, KeyUse keyUse, Algorithm keyAlg, String kid, String cachePath) {

    	String kpPath = cachePath + File.separator + kid;
    	
        try {
        	KeyPair kp = CreateNewKeyPair(kpPath, "RSASSA-PSS", keySize);
            
            return getRSAKey(kp, keySize, keyUse, keyAlg, kid);
            
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }
    
    private static RSAKey getRSAKey(KeyPair kp, Integer keySize, KeyUse keyUse, Algorithm keyAlg, String kid)
    {
        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        
        RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(pub)
                .privateKey(priv)
                .keyUse(keyUse)
                .algorithm(keyAlg)
                .keyID(kid)
                .build();

        return rsaKey;
    }
    
    public static KeyPair CreateNewKeyPair(String kpPath, String algorithm, int keySize) throws NoSuchAlgorithmException
    {
    	KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(keySize);
        KeyPair kp = generator.generateKeyPair();
        
        try {
        	Certificate caCertificate = generateCertificate(KEYSTORE_DEFAULT_CERT_DN, kp, 365, "RSASSA-PSS");
	
			Certificate[] chain = { caCertificate };
			
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(null, null);
			keyStore.setKeyEntry(KEYSTORE_ALIAS, kp.getPrivate(), KEYSTORE_PASSWORD.toCharArray(), chain);

			FileOutputStream out = new FileOutputStream(kpPath + ".jks");
		    keyStore.store(out, KEYSTORE_PASSWORD.toCharArray());
		    out.close();
		} catch (Exception e) {
			System.out.println("");
		}
        
        return kp;
    }

	private static X509Certificate generateCertificate(String dn, KeyPair keyPair, int validity, String sigAlgName) throws OperatorCreationException, GeneralSecurityException, IOException {

		return BCX509CertificateFactoryImpl.generateCertificate(dn, keyPair, validity, sigAlgName);
	}
}
