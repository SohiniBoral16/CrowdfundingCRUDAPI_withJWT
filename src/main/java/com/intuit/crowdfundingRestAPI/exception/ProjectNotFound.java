package com.intuit.crowdfundingRestAPI.exception;

public class ProjectNotFound extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public ProjectNotFound() {
		super();
		// TODO Auto-generated constructor stub
	}

	public ProjectNotFound(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
		// TODO Auto-generated constructor stub
	}

	public ProjectNotFound(String message, Throwable cause) {
		super(message, cause);
		// TODO Auto-generated constructor stub
	}

	public ProjectNotFound(String message) {
		super(message);
		// TODO Auto-generated constructor stub
	}

	public ProjectNotFound(Throwable cause) {
		super(cause);
		// TODO Auto-generated constructor stub
	}

}
