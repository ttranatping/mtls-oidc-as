package com.pingidentity.cdr.testharness.utils;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;

public class HttpRequestHelper {

	private static String DEFAULT_HOST_HEADER = "X-Forwarded-Host";
	private static String DEFAULT_PROTO_HEADER = "X-Forwarded-Proto";
	
	public static String getOriginalHostHeader(HttpServletRequest request, String hostHeader)
	{
		if(hostHeader == null)
			hostHeader = DEFAULT_HOST_HEADER;
		
		if(!StringUtils.isEmpty(request.getHeader(hostHeader)))
			return request.getHeader(hostHeader);
		else
			return request.getHeader("Host");
	}
	
	public static String getOriginalProtoHeader(HttpServletRequest request, String protoHeader)
	{
		if(protoHeader == null)
			protoHeader = DEFAULT_PROTO_HEADER;
		
		if(!StringUtils.isEmpty(request.getHeader(protoHeader)))
			return request.getHeader(protoHeader);
		else
			return "https";
	}
}
