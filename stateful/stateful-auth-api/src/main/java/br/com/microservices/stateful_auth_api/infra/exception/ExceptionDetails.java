package br.com.microservices.stateful_auth_api.infra.exception;

public record ExceptionDetails (int status, String message) {
}
