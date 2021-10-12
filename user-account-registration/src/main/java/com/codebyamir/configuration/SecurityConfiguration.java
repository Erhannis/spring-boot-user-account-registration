package com.codebyamir.configuration;

import com.codebyamir.model.User;
import com.codebyamir.service.UserService;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	private BCryptPasswordEncoder bCryptPasswordEncoder;
  	private UserService userService;

	@Autowired
	public SecurityConfiguration(BCryptPasswordEncoder bCryptPasswordEncoder, UserService userService) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
		this.userService = userService;
	}
    
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
        		.antMatchers("/register").permitAll()
    			.antMatchers("/confirm").permitAll()
				.antMatchers("/").permitAll()
				.anyRequest().authenticated()
				.and()
			.formLogin()
				.loginPage("/login")
				.permitAll()
				.and()
			.logout()
				.permitAll();
		 
	}

    @Autowired
    public void initialize(AuthenticationManagerBuilder builder, DataSource dataSource) throws Exception {
        builder.authenticationProvider(new AuthenticationProvider() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                String principal = (String)authentication.getPrincipal();
                String credentials = (String)authentication.getCredentials();
        		User userExists = userService.findByEmail(principal);
                if (userExists == null) {
                    throw new BadCredentialsException("Invalid credentials");
                }
                if (bCryptPasswordEncoder.matches(credentials, userExists.getPassword())) {
                    authentication.setAuthenticated(true);
                } else {
                    throw new BadCredentialsException("Invalid credentials");
                }
                return authentication;
            }

            @Override
            public boolean supports(Class<?> authentication) {
                if (authentication == UsernamePasswordAuthenticationToken.class) {
                    return true;
                }
                return false;
            }
        
        });
//                jdbcAuthentication()
//                .dataSource(dataSource)
//                .withUser("dave")
//                .password("secret")
//                .roles("USER");
    }
}