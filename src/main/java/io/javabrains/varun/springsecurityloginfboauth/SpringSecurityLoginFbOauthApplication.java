package io.javabrains.varun.springsecurityloginfboauth;

import org.apache.tomcat.util.net.AbstractEndpoint.Handler;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@SpringBootApplication
public class SpringSecurityLoginFbOauthApplication extends WebSecurityConfigurerAdapter {

	//reference guide for this demo on OAuth
	//https://spring.io/guides/tutorials/spring-boot-oauth2/

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityLoginFbOauthApplication.class, args);
	}

	@Override
    protected void configure(HttpSecurity http) throws Exception {
    	// @formatter:off
        http
            .authorizeRequests(a -> a
                .antMatchers("/", "/error", "/webjars/**").permitAll()
                .anyRequest().authenticated())
			.csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
			.logout(l -> l.logoutSuccessUrl("/").permitAll())
            .exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
			.oauth2Login( o -> o
				.failureHandler((request,response,exception) -> {
						request.getSession().setAttribute("error.message", exception.getMessage());	
						//handler.onAuthenticationFailure(request, response, exception);
				})
			);
    }

}
