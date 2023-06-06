package com.intuit.crowdfundingRestAPI.rest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import com.intuit.crowdfundingRestAPI.model.AuthenticationRequest;
import com.intuit.crowdfundingRestAPI.model.AuthenticationResponse;
import com.intuit.crowdfundingRestAPI.security.MyUserDetailsService;
import com.intuit.crowdfundingRestAPI.util.JwtUtil;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@CrossOrigin
public class HelloRestController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtUtil jwtTokenUtil;

	@Autowired
	private MyUserDetailsService userDetailsService;

	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest)
			throws Exception {

		System.out.println("inside Hello*******************");
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					authenticationRequest.getUsername(), authenticationRequest.getPassword()));
		} catch (BadCredentialsException e) {
			throw new Exception("Incorrect username or password", e);
		}

		final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());

		final String jwt = jwtTokenUtil.generateToken(userDetails);
		final String refreshToken = jwtTokenUtil.generateRefreshToken(userDetails);

		return ResponseEntity.ok(new AuthenticationResponse(jwt, refreshToken));
	}
	
	@PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> payload) throws Exception {
        String refreshToken = payload.get("refreshToken");
        if (refreshToken == null || !jwtTokenUtil.validateRefreshToken(refreshToken, userDetailsService.loadUserByUsername(jwtTokenUtil.extractUsernameFromRefreshToken(refreshToken)))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }

        // If the refresh token is valid, create a new JWT
        String username = jwtTokenUtil.extractUsernameFromRefreshToken(refreshToken);
        final UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        String newJwtToken = jwtTokenUtil.generateToken(userDetails);

        return ResponseEntity.ok().body(new AuthenticationResponse(newJwtToken, refreshToken));
    }
}
