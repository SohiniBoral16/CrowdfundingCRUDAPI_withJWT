package com.intuit.crowdfundingRestAPI.security;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.intuit.crowdfundingRestAPI.repo.UsersRepo;


@Service
public class MyUserDetailsService implements UserDetailsService {
	
	
    @Autowired
    private UsersRepo usersRepo;

	@Override
	public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
		//return new User("sohini.boral@example.com", "1234", new ArrayList<>());
		//return new User
		com.intuit.crowdfundingRestAPI.entity.User user = usersRepo.findByEmail(s);

        if (user == null) {
            throw new UsernameNotFoundException("Invalid User");

        } else {
//            Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
//            for (Role role : user.getRoles()){
//                grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_"+role.getName()));
//            }
        }
        return new org
                    .springframework
                    .security
                    .core
                    .userdetails
                    .User(user.getEmail(), user.getPasswordHash(), new ArrayList<>());
	}
}
