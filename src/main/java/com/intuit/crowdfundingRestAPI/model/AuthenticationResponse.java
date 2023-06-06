package com.intuit.crowdfundingRestAPI.model;

import java.io.Serializable;

public class AuthenticationResponse implements Serializable {

//    private final String jwt;
//
//    public AuthenticationResponse(String jwt) {
//        this.jwt = jwt;
//    }
//
//    public String getJwt() {
//        return jwt;
//    }
	
	private final String jwt;
    private final String refreshToken;

    public AuthenticationResponse(String jwt, String refreshToken) {
        this.jwt = jwt;
        this.refreshToken = refreshToken;
    }

    public String getJwt() {
        return jwt;
    }

    public String getRefreshToken() {
        return refreshToken;
    }
}
