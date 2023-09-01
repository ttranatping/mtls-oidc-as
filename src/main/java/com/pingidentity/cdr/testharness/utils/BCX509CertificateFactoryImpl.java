package com.pingidentity.cdr.testharness.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import org.apache.commons.validator.routines.EmailValidator;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.pingidentity.cdr.testharness.Constants;

@SuppressWarnings("deprecation")
public class BCX509CertificateFactoryImpl {

	public static X509Certificate generateCertificate(String dn, KeyPair keyPair, int validity, String sigAlgName)
			throws GeneralSecurityException, IOException, OperatorCreationException {
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		BigInteger serial = new BigInteger(64, new SecureRandom());
		
		Provider BC = new BouncyCastleProvider();
		
		Date from = new Date();
		Date to = new Date(from.getTime() + validity * 1000L * 24L * 60L * 60L);

		// create the certificate
		ContentSigner sigGen = new JcaContentSignerBuilder(sigAlgName).build(privateKey);
		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(new X500Name(dn), // Issuer
				serial, // Serial
				from, // Valid from
				to, // Valid to
				new X500Name(dn), // Subject
				publicKey // Publickey to be associated with the certificate
		);
		
		BasicConstraints basicConstraints = new BasicConstraints(true);
		certGen.addExtension(Extension.basicConstraints, true, basicConstraints);
		
		X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));

		cert.checkValidity(new Date());

		ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
		CertificateFactory fact = CertificateFactory.getInstance("X.509", BC);

		return (X509Certificate) fact.generateCertificate(bIn);
	}

	public static String signCSR(Reader pemcsr, KeyStore keyStore, String certAlias, String password, int validity, KeyPurposeId keyUsage)
			throws Exception {
		PrivateKey cakey = (PrivateKey) keyStore.getKey(certAlias, password.toCharArray());
		X509Certificate cacert = (X509Certificate) keyStore.getCertificate(certAlias);

		PEMReader reader = new PEMReader(pemcsr);
		PKCS10CertificationRequest csr = new PKCS10CertificationRequest((CertificationRequest) reader.readObject());

		reader.close();

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(Constants.CA_ALGORITHM);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

		org.bouncycastle.asn1.x500.X500Name issuer = org.bouncycastle.asn1.x500.X500Name
				.getInstance(cacert.getSubjectX500Principal().getEncoded());

		org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name(
				csr.getSubject().toString());

		BigInteger serial = new BigInteger(64, new SecureRandom());

		Date from = new Date();
		Date to = new Date(from.getTime() + validity * 1000L * 24L * 60L * 60L);

		X509v3CertificateBuilder certgen = new X509v3CertificateBuilder(issuer, serial, from, to, subject,
				csr.getSubjectPublicKeyInfo());
		certgen.addExtension(X509Extension.basicConstraints, false, new BasicConstraints(false));
		
		if(keyUsage != null)
		{
			certgen.addExtension(X509Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
		}
		else
		{
			certgen.addExtension(X509Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
			certgen.addExtension(X509Extension.extendedKeyUsage, true, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));
			certgen.addExtension(X509Extension.authorityKeyIdentifier, false,
					new AuthorityKeyIdentifier(
							new GeneralNames(new GeneralName(new X509Name(cacert.getSubjectX500Principal().getName()))),
							cacert.getSerialNumber()));
		}
		
		certgen.addExtension(X509Extension.subjectKeyIdentifier, false,
				new SubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
		RDN subjectCN = subject.getRDNs(BCStyle.CN)[0];
		
		String subjectCNStr = subjectCN.getFirst().getValue().toString();
		
		if(!EmailValidator.getInstance(false).isValid(subjectCNStr))
		{
			String subjectCNNoWildcard = subjectCNStr.replace("*.", "");
			
		    DERSequence subjectAlternativeNames = new DERSequence(new ASN1Encodable[] {
		    		new GeneralName(GeneralName.dNSName, subjectCNStr), new GeneralName(GeneralName.dNSName, subjectCNNoWildcard)});
			
		    certgen.addExtension(X509Extension.subjectAlternativeName, false, subjectAlternativeNames);
		}
		
		ContentSigner signer = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
				.build(PrivateKeyFactory.createKey(cakey.getEncoded()));
		X509CertificateHolder holder = certgen.build(signer);
		byte[] certencoded = holder.toASN1Structure().getEncoded();

		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		signer = new JcaContentSignerBuilder(Constants.CA_ALGORITHM).build(cakey);
		generator.addSignerInfoGenerator(
				new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer,
						cacert));
		generator.addCertificate(new X509CertificateHolder(certencoded));
		generator.addCertificate(new X509CertificateHolder(cacert.getEncoded()));
		CMSTypedData content = new CMSProcessableByteArray(certencoded);
		CMSSignedData signeddata = generator.generate(content, true);
		
		return convertToPem(signeddata.getEncoded(), "PKCS #7 SIGNED DATA");

	}

	public static String getPublicCertificate(KeyStore keyStore, String certAlias) throws IOException,
			NoSuchAlgorithmException, InvalidKeySpecException, CertificateEncodingException, KeyStoreException {
		Certificate pub = keyStore.getCertificate(certAlias);
		byte[] data = pub.getEncoded();
		return convertToPem(data);
	}
	
	protected static String convertToPem(X509Certificate cert) throws CertificateEncodingException {
		
		 byte[] derCert = cert.getEncoded();
		 
		 return convertToPem(derCert);
	}
	
	private static String convertToPem(byte[] rawCrtText)
	{
		return convertToPem(rawCrtText, Constants.CA_BEGIN_CERT, Constants.CA_END_CERT);
	}
	
	private static String convertToPem(byte[] rawCrtText, String tag)
	{
		String beginTag = "-----BEGIN " + tag + "-----";
		String endTag = "-----END " + tag + "-----";
		
		return convertToPem(rawCrtText, beginTag, endTag);
	}
	
	private static String convertToPem(byte[] rawCrtText, String beginTag, String endTag)
	{
		java.util.Base64.Encoder encoder = java.util.Base64.getMimeEncoder(64, System.lineSeparator().getBytes());

	    final String encodedCertText = new String(encoder.encode(rawCrtText));
	    final String prettified_cert = beginTag + Constants.CA_LINE_SEPARATOR + encodedCertText + Constants.CA_LINE_SEPARATOR + endTag;
	    
	    return prettified_cert;
	}
}
