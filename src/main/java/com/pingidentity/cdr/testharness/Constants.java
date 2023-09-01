package com.pingidentity.cdr.testharness;

public class Constants {

	public static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";

	public static final String DEFAULT_PAGE_SIZE = "5";
	
	public static final String DISCO_SERVICE = "/.well-known/openid-configuration";
	
	public static final String GLOBAL_JWKS_SERVICE = DISCO_SERVICE + "/JWKS";
	
	public static final String JWKS_GLOBAL_KID = "_GLOBAL_";

	public static final String JWKS_SERVICE = "/helper/JWKS/{kid}";

	public static final String JWKS_SERVICE_REVOCATION = "/helper/JWKS/{kid}/revocation";

	public static final String JWKS_SERVICE_PRIVATE = "/helper/JWKS/{kid}/private";
	
	public static final String CA_ALGORITHM = "SHA256withRSA";

	public static final String CA_DEFAULT_KEYSTORE_PASSWORD = "P@ssword1";
	public static final String CA_KEYSTORE_FILENAME = "keystore.jks";
	
	public static final String CA_BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
	public static final String CA_END_CERT = "-----END CERTIFICATE-----";
	public final static String CA_LINE_SEPARATOR = System.getProperty("line.separator");
}
