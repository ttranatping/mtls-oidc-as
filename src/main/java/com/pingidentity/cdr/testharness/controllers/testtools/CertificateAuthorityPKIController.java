package com.pingidentity.cdr.testharness.controllers.testtools;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.nimbusds.jose.JOSEException;
import com.pingidentity.cdr.testharness.exception.PKIException;
import com.pingidentity.cdr.testharness.utils.CertificateAuthorityTools;

@RestController
public class CertificateAuthorityPKIController {
	
	@Autowired
	private String keystoreAlias;
	
	@Autowired
	private String keystorePassword;
	
	@Autowired
	private KeyStore caKeystore;
	
	
	public CertificateAuthorityPKIController() throws IOException, KeyStoreException, JOSEException {
	}
	
	@RequestMapping(value = "/public/signPrint", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
	public String signCSR1(@RequestParam("csr") MultipartFile csr)
	{
		KeyPurposeId keyUsageObj = null;
		
		StringReader reader = null;
		try {
			reader = new StringReader(new String(csr.getBytes()));
		} catch (IOException e1) {
			throw new PKIException(5001, "Could not read csr upload", e1);
		}
		
		String csrResponse = null;
		
		try {
			csrResponse = CertificateAuthorityTools.signCSR(reader, caKeystore, keystoreAlias, keystorePassword, 365, keyUsageObj);
		} catch (Exception e) {
			throw new PKIException(5001, "Could not sign csr", e);
		}
		
		return "{\"response\": \"" + new String(Base64.getEncoder().encode(csrResponse.getBytes())) + "\"}";
	}
	
	@RequestMapping(value = "/public/sign")
    @ResponseBody
	public ResponseEntity<String> signCSR(@RequestParam("csr") MultipartFile csr)
	{
		KeyPurposeId keyUsageObj = null;
		
		StringReader reader = null;
		try {
			reader = new StringReader(new String(csr.getBytes()));
		} catch (IOException e1) {
			throw new PKIException(5001, "Could not read csr upload", e1);
		}
		
		String csrResponse = null;
		
		try {
			csrResponse = CertificateAuthorityTools.signCSR(reader, caKeystore, keystoreAlias, keystorePassword, 365, keyUsageObj);
		} catch (Exception e) {
			throw new PKIException(5001, "Could not sign csr", e);
		}
		
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"csrresponse.p7b\"").body(csrResponse);
	}
	
	@RequestMapping(value = "/public/signClientAuth")
    @ResponseBody
	public ResponseEntity<String> signCSRClientAuth(@RequestParam("csr") MultipartFile csr)
	{
		KeyPurposeId keyUsageObj = KeyPurposeId.id_kp_clientAuth;
		
		StringReader reader = null;
		try {
			reader = new StringReader(new String(csr.getBytes()));
		} catch (IOException e1) {
			throw new PKIException(5001, "Could not read csr upload", e1);
		}
		
		String csrResponse = null;
		
		try {
			csrResponse = CertificateAuthorityTools.signCSR(reader, caKeystore, keystoreAlias, keystorePassword, 365, keyUsageObj);
		} catch (Exception e) {
			throw new PKIException(5001, "Could not sign csr", e);
		}
		
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"csrresponse.p7b\"").body(csrResponse);
	}
	
	@RequestMapping(value = "/public/download")
    @ResponseBody
    public ResponseEntity<String> servePublicKeyFile() {

		String publicCert;
		try {
			publicCert = CertificateAuthorityTools.getPublicCertificate(caKeystore, keystoreAlias);
		} catch (CertificateEncodingException | NoSuchAlgorithmException | InvalidKeySpecException | KeyStoreException
				| IOException e) {
			throw new PKIException(5002, "Could not download public cert", e);
		}
		
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"public.cer\"").body(publicCert);
    }
	
}