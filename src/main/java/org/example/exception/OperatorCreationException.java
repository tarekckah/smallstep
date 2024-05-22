package org.example.exception;

public class OperatorCreationException extends Exception {

  public OperatorCreationException(String message) {
    super(message);
  }

  public OperatorCreationException(String message, Throwable cause) {
    super(message, cause);
  }
}
