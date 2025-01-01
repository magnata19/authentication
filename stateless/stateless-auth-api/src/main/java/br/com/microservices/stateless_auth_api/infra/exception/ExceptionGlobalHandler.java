package br.com.microservices.stateless_auth_api.infra.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ExceptionGlobalHandler {

  @ExceptionHandler(ValidationException.class)
  public ResponseEntity<?> handleValidationException(ValidationException validationException) {
    var exceptionDetails = new ExceptionDetails(HttpStatus.BAD_REQUEST.value(), validationException.getMessage());
    return new ResponseEntity<>(exceptionDetails, HttpStatus.BAD_REQUEST);
  }

  public ResponseEntity<?> handleAuthenticationException(AuthenticationException authenticationException) {
    var exceptionDetails = new ExceptionDetails(HttpStatus.UNAUTHORIZED.value(), authenticationException.getMessage());
    return new ResponseEntity<>(exceptionDetails, HttpStatus.UNAUTHORIZED);
  }
}
