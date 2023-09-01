package com.pingidentity.cdr.testharness.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class BadRequestException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 3037337771929156850L;
	
	public BadRequestException(String msg)
	{
		super(msg);
	}
	
	public BadRequestException(String msg, Throwable t)
	{
		super(msg, t);
	}

	public int getCode() {
		return 400;
	}

}
