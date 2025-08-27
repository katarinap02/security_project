//package com.pki.example.auth;
//
//import com.pki.example.util.TokenUtils;
//import io.jsonwebtoken.ExpiredJwtException;
//import org.apache.commons.logging.Log;
//import org.apache.commons.logging.LogFactory;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import javax.servlet.FilterChain;
//import javax.servlet.ServletException;
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//import java.io.IOException;
//
//// Filter koji ce presretati SVAKI zahtev klijenta ka serveru
//// (sem nad putanjama navedenim u WebSecurityConfig.configure(WebSecurity web))
//// Filter proverava da li JWT token postoji u Authorization header-u u zahtevu koji stize od klijenta
//// Ukoliko token postoji, proverava se da li je validan. Ukoliko je sve u redu, postavlja se autentifikacija
//// u SecurityContext holder kako bi podaci o korisniku bili dostupni u ostalim delovima aplikacije gde su neophodni
//public class TokenAuthenticationFilter extends OncePerRequestFilter {
//
//	private TokenUtils tokenUtils;
//	private UserDetailsService userDetailsService;
//	protected final Log LOGGER = LogFactory.getLog(getClass());
//
//	public TokenAuthenticationFilter(TokenUtils tokenUtils, UserDetailsService userDetailsService) {
//		this.tokenUtils = tokenUtils;
//		this.userDetailsService = userDetailsService;
//	}
//
//	@Override
//	protected void doFilterInternal(HttpServletRequest request,
//									HttpServletResponse response,
//									FilterChain chain) throws IOException, ServletException {
//
//		String authToken = tokenUtils.getToken(request);
//
//		try {
//			if (authToken != null) {
//				// 1. Validacija tokena preko Keycloak /userinfo
//				boolean valid = tokenUtils.validateKeycloakToken(authToken);
//
//				if (valid) {
//					// 2. Preuzimanje email-a iz Keycloak tokena
//					String email = tokenUtils.getEmailFromKeycloakToken(authToken);
//
//					if (email != null) {
//						// 3. Učitavanje korisnika iz baze (tvoje aplikacije)
//						UserDetails userDetails = userDetailsService.loadUserByUsername(email);
//
//						// 4. Postavljanje autentifikacije u SecurityContext
//						TokenBasedAuthentication authentication = new TokenBasedAuthentication(userDetails);
//						authentication.setToken(authToken);
//						SecurityContextHolder.getContext().setAuthentication(authentication);
//					}
//				}
//			}
//		} catch (Exception e) {
//			LOGGER.debug("Keycloak token invalid or expired!", e);
//		}
//
//		chain.doFilter(request, response);
//	}
//
//}