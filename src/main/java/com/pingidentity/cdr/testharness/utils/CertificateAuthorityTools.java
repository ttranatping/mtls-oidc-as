package com.pingidentity.cdr.testharness.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Reader;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.operator.OperatorCreationException;

import com.pingidentity.cdr.testharness.Constants;

public class CertificateAuthorityTools {
	
	public static KeyStore createCertificateAuthorityKeystore(String certAlias, String password, String commonName,
			String organizationalUnit, String organization, String city, String state, String country, int validDays,
			String keystoreCacheLocation) throws IOException, GeneralSecurityException, OperatorCreationException {
		
		KeyStore keyStore = null;
		
		String keystoreFileName = keystoreCacheLocation + File.separator + Constants.CA_KEYSTORE_FILENAME;
		
		if(new File(keystoreFileName).exists())
		{
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(4096);
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			
			keyStore.load(new FileInputStream(keystoreFileName), Constants.CA_DEFAULT_KEYSTORE_PASSWORD.toCharArray());
		}
		
		if(keyStore == null)
		{
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(4096);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
	
			Certificate caCertificate = generateCertificate(String.format("CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s", commonName,
					organizationalUnit, organization, city, state, country), keyPair, 3650, Constants.CA_ALGORITHM);
	
			Certificate[] chain = { caCertificate };
	
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null, null);
			keyStore.setKeyEntry(certAlias, keyPair.getPrivate(), password.toCharArray(), chain);

			FileOutputStream out = new FileOutputStream(keystoreFileName);
		    keyStore.store(out, Constants.CA_DEFAULT_KEYSTORE_PASSWORD.toCharArray());
		    out.close();
		}

		return keyStore;
	}

	private static X509Certificate generateCertificate(String dn, KeyPair keyPair, int validity, String sigAlgName)
			throws GeneralSecurityException, IOException, OperatorCreationException {
		
		return BCX509CertificateFactoryImpl.generateCertificate(dn, keyPair, validity, sigAlgName);
	}

	public static String signCSR(Reader pemcsr, KeyStore keyStore, String certAlias, String password, int validity, KeyPurposeId keyUsage)
			throws Exception {
		return BCX509CertificateFactoryImpl.signCSR(pemcsr, keyStore, certAlias, password, validity, keyUsage);

	}

	public static String getPublicCertificate(KeyStore keyStore, String certAlias) throws IOException,
			NoSuchAlgorithmException, InvalidKeySpecException, CertificateEncodingException, KeyStoreException {
		return BCX509CertificateFactoryImpl.getPublicCertificate(keyStore, certAlias);
	}
	
	

}
