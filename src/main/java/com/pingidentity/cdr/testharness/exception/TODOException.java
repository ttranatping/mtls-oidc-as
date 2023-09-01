package com.pingidentity.cdr.testharness.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.BAD_REQUEST)
public class TODOException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 3037337771929156850L;
	
	public TODOException(String msg)
	{
		super("TODO: " + msg);
	}
	
	public TODOException(String msg, Throwable t)
	{
		super("TODO: " + msg, t);
	}

	public int getCode() {
		return 400;
	}

}
