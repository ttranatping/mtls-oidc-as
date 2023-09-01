package com.pingidentity.cdr.testharness.controllers.cdrregister;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.logging.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.nimbusds.jose.jwk.RSAKey;
import com.pingidentity.cdr.testharness.Constants;
import com.pingidentity.cdr.testharness.ca.JWKSStorage;
import com.pingidentity.cdr.testharness.utils.JwtUtilities;

@Controller
public class MTLSOIDCServerController {

	private static Logger logger = Logger.getLogger(MTLSOIDCServerController.class);
	public final static String LINE_SEPARATOR = System.getProperty("line.separator");
	
	@Autowired
	private String certHeaderNameLeaf;
	
	@Autowired
	private String certHeaderNameChainPrefix;
	
	@Autowired
	private boolean isTerminatedProxy;
	
	@Autowired
	private String beginCert;
	
	@Autowired
	private String endCert;
	
	@Autowired
	private boolean isCertHeaderUrlEncoded;
	
	@Autowired
	private String allowedRedirectUris;
	
	@Autowired
	private JWKSStorage jwksStorage;
	
	public MTLSOIDCServerController() throws IOException {
	}

	@RequestMapping(value = "/as/authorization.oauth2", method = RequestMethod.GET, produces = MediaType.TEXT_HTML_VALUE)
	public String getAuthorization(@RequestParam("client_id") String clientId, 
			@RequestParam("redirect_uri") String redirectUri, 
			HttpServletRequest request, HttpServletResponse response) throws Throwable {
		
		String state = request.getParameter("state");
		
		List<String> allowedRedirectUrisList = Arrays.asList(allowedRedirectUris.split(","));
		
		if(!allowedRedirectUrisList.contains(redirectUri))
		{
			setError(response, redirectUri, "invalid_redirect_uri", "Invalid redirect URI supplied", state);
			return null;
		}
		
		JSONObject authorizationCodeContent = new JSONObject();
		
		X509Certificate [] certArray = getCertificate(request);
		
		JSONArray certJSONArray = new JSONArray();
		
		if(certArray != null && certArray.length > 0)
		{
			
			X509Certificate leafCert = certArray[0];
			addCertToToken(leafCert, certJSONArray, "leaf");
			
			for(int i = 1; i < certArray.length; i++)
			{
				X509Certificate chainCert = certArray[i];
				addCertToToken(chainCert, certJSONArray, "chain" + (i-1));
			}
		}
		
		RSAKey globalKey = jwksStorage.getKey(Constants.JWKS_GLOBAL_KID);
		
		String issuer = request.getRequestURL().toString().replace("/as/authorization.oauth2", "");
		
		String authorizationCode = JwtUtilities.getJWT(authorizationCodeContent, globalKey.toJSONString(), issuer, clientId);

		setSuccess(response, redirectUri, authorizationCode, state);
		
		return null;
	}
	
	@SuppressWarnings("unchecked")
	private void addCertToToken(X509Certificate certificate, JSONArray jsonArray, String name) throws CertificateEncodingException
	{
		if(certificate == null)
		{
			return;
		}
		
		String certificateStr = formatCrtFileContents(certificate, beginCert, endCert);
		
		JSONObject newCert = new JSONObject();
		newCert.put("name", name);
		newCert.put("encoded", certificateStr);
		newCert.put("subjectDn", certificate.getSubjectDN());
		newCert.put("issuerDn", certificate.getIssuerDN());
		
		jsonArray.add(newCert);
		
	}

	private void setError(final HttpServletResponse response, final String redirectUri, final String errorCode, final String errorDescription, final String state) throws IOException
	{
		
		final String stateParamExt;
		
		if(state != null)
		{
			stateParamExt = String.format("&state=%s", URLEncoder.encode(state, "UTF-8"));
		}
		else
		{
			stateParamExt = "";
		}

		final String redirectUriError = String.format("%s?error=%s&error_description=%s%s", redirectUri, 
			URLEncoder.encode(errorCode, "UTF-8"), URLEncoder.encode(errorDescription, "UTF-8"), stateParamExt);
		
		response.setStatus(302);

		
		response.sendRedirect(redirectUriError);
	}

	private void setSuccess(final HttpServletResponse response, final String redirectUri, final String authorizationCode, final String state) throws IOException
	{
		
		final String stateParamExt;
		
		if(state != null)
		{
			stateParamExt = String.format("&state=%s", URLEncoder.encode(state, "UTF-8"));
		}
		else
		{
			stateParamExt = "";
		}

		final String redirectUriError = String.format("%s?code=%s%s", redirectUri, 
				authorizationCode, stateParamExt);
		
		response.setStatus(302);

		
		response.sendRedirect(redirectUriError);
	}
	
	private X509Certificate [] getCertificate(final HttpServletRequest request)
	{
	  if(isTerminatedProxy)
	  {
		  
		  X509Certificate leafCert = getCertClean(request, certHeaderNameLeaf);
		  
		  if(leafCert != null)
		  {
			  List<X509Certificate> certList = new ArrayList<X509Certificate>();
			  
			  certList.add(leafCert);
			  
			  int countCert = 0;
			  while(countCert < 10)
			  {
				  X509Certificate chainCert = getCertClean(request, certHeaderNameChainPrefix + countCert);
				  
				  if(chainCert == null)
				  {
					  break;
				  }
				  
				  certList.add(chainCert);
				  countCert++;
			  }
			  
			  return certList.toArray(new X509Certificate[certList.size()]);
			  
		  }
		  
		  return null;
	  }
	  
	  return getCertificateFromRequest(request);
	}
	
	private X509Certificate getCertClean(final HttpServletRequest request, final String headerName)
	{
	    final String certificateFromHeader = request.getHeader(headerName);
	    if(certificateFromHeader != null && !certificateFromHeader.isEmpty())
	    {
	      //before decoding we need to get rod off the prefix and suffix
	      String cleanStr = certificateFromHeader.replaceAll(beginCert, "").replaceAll(endCert, "").replaceAll("[\\n\\t ]", "");

	      if(isCertHeaderUrlEncoded)
	      {
	        try {
	          cleanStr = URLDecoder.decode(cleanStr, "UTF-8");
	        } catch (UnsupportedEncodingException e) {
	          logger.error("Unable to url decode header");
	        }
	      }

	      X509Certificate cert = parseCertificate(cleanStr);
	      
	      return cert;
	    }
	    
	    return null;
	}
	
	private X509Certificate [] getCertificateFromRequest(HttpServletRequest request)
	{
        String cipherSuite = (String) request.getAttribute("javax.servlet.request.cipher_suite");

        if (cipherSuite != null) {
            X509Certificate certChain[] = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
            if (certChain != null) {
                for (int i = 0; i < certChain.length; i++) {
                    System.out.println ("Client Certificate [" + i + "] = "
                            + certChain[i].toString());
                }
            }
            
            return certChain;
        }
        
        return null;
	}
	private X509Certificate parseCertificate(String cleanStr) {

	  byte [] decoded = Base64.getDecoder().decode(cleanStr);

	  try {
	    return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));
	  } catch (CertificateException e) {
	    return null;
	  }
	}


	public static String formatCrtFileContents(final Certificate certificate, final String beginCert, final String endCert) throws CertificateEncodingException {
	    final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());

	    final byte[] rawCrtText = certificate.getEncoded();
	    final String encodedCertText = new String(encoder.encode(rawCrtText));
	    final String prettified_cert = beginCert + LINE_SEPARATOR + encodedCertText + LINE_SEPARATOR + endCert;
	    return prettified_cert;
	}
}