package com.pingidentity.cdr.testharness.exception;

public class PKIException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private final int code;
	
	public PKIException(int code, String message)
	{
		super(message);
		this.code = code;
	}
	
	public PKIException(int code, String message, Throwable ex)
	{
		super(message, ex);
		
		this.code = code;
	}

	public int getCode() {
		return code;
	}

}
