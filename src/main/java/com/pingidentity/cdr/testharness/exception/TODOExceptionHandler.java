package com.pingidentity.cdr.testharness.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class TODOExceptionHandler extends ResponseEntityExceptionHandler {

	@ExceptionHandler(value = { TODOException.class })
	protected ResponseEntity<ErrorResponse> handleConflict(RuntimeException ex, WebRequest request) {
		return new ResponseEntity<ErrorResponse>(new ErrorResponse(ex.getMessage()), HttpStatus.BAD_REQUEST);
	}
}