package com.pingidentity.cdr.testharness;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import com.pingidentity.cdr.testharness.ca.JWKSStorage;
import com.pingidentity.cdr.testharness.utils.CertificateAuthorityTools;
import com.pingidentity.cdr.testharness.utils.ClassLoaderUtil;

@Configuration
@ComponentScan("com.pingidentity.cdr.testharness")
public class AppConfig {

	private final Properties configProps;

	public static AppConfig GetConfig() {
		return new AppConfig();
	}

	public AppConfig() {
		InputStream configPropsIS = ClassLoaderUtil.getResourceAsStream("application.properties", this.getClass());

		configProps = new Properties();
		try {
			configProps.load(configPropsIS);

		} catch (IOException e) {
		}
	}
	
	@Bean
	public String allowedRedirectUris()
	{
		String config = getConfig("allowed.redirecturis");
		return config;
	}

	@Bean
	public boolean isCertHeaderUrlEncoded() {
		String config = getConfig("certificate.isencoded");
		return Boolean.parseBoolean(config);
	}

	@Bean
	public String endCert() {
		String config = getConfig("certificate.endcertheader");
		return config;
	}

	@Bean
	public String beginCert() {
		String config = getConfig("certificate.begincertheader");
		return config;
	}

	@Bean
	public boolean isTerminatedProxy() {
		String config = getConfig("certificate.isterminateproxy");
		return Boolean.parseBoolean(config);
	}

	@Bean
	public String certHeaderNameChainPrefix() {
		String config = getConfig("certificate.header.chainprefix");
		return config;
	}

	@Bean
	public String certHeaderNameLeaf() {
		String config = getConfig("certificate.header.leaf");
		return config;
	}

	@Bean
	public String baseUrl() {
		String config = getConfig("server.baseurl");
		return config;
	}

	@Bean
	public int keySize() {
		String config = getConfig("key.size");

		return Integer.parseInt(config);
	}

	@Bean
	public int keyListSize() {
		String config = getConfig("key.list.size");

		return Integer.parseInt(config);
	}

	@Bean
	public String pkiServerBaseURL() {
		return getConfig("pki.base.url");

	}

	@Bean
	public String keystoreAlias() {
		return getConfig("ca.keystore.alias");
	}

	@Bean
	public String keystorePassword() {
		return getConfig("ca.keystore.password");
	}

	@Bean
	public JWKSStorage jwksStorage() {
		return new JWKSStorage(this.keySize(), this.keystoreCacheLocation());
	}

	@Bean
	public KeyStore caKeystore() {
		try {
			String commonName = getConfig("ca.keystore.commonname");
			String organizationalUnit = getConfig("ca.keystore.organizationalunit");
			String organization = getConfig("ca.keystore.organization");
			String city = getConfig("ca.keystore.city");
			String state = getConfig("ca.keystore.state");
			String country = getConfig("ca.keystore.country");
			int validDays = Integer.parseInt(getConfig("ca.keystore.validity"));
			String keystoreCacheLocation = keystoreCacheLocation();

			KeyStore keyStore = CertificateAuthorityTools.createCertificateAuthorityKeystore(keystoreAlias(),
					keystorePassword(), commonName, organizationalUnit, organization, city, state, country, validDays,
					keystoreCacheLocation);

			return keyStore;
		} catch (IOException | GeneralSecurityException | OperatorCreationException e) {
			return null;
		}
	}

	@Bean
	public String keystoreCacheLocation() {
		String cacheLocation = getConfig("keystore.cache.location");
		return cacheLocation;
	}

	private String getConfig(String configName) {
		String envName = "MTLS_OIDC_AS-" + configName.replaceAll("\\.", "-");

		if (System.getenv(envName) != null && !System.getenv(envName).isEmpty())
			return System.getenv(envName);

		envName = "MTLS_OIDC_AS_" + configName.replaceAll("\\.", "_");

		if (System.getenv(envName) != null && !System.getenv(envName).isEmpty())
			return System.getenv(envName);

		return configProps.getProperty(configName);
	}

}
