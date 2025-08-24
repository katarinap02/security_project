package com.pki.example.util;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pki.example.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;


import org.springframework.http.*;


import javax.servlet.http.HttpServletRequest;

import java.util.Date;


// Utility klasa za rad sa JSON Web Tokenima
@Component
public class TokenUtils {

	// Izdavac tokena
	@Value("spring-security-example")
	private String APP_NAME;

	// Tajna koju samo backend aplikacija treba da zna kako bi mogla da generise i proveri JWT https://jwt.io/
	@Value("somesecret")
	public String SECRET;

	// Period vazenja tokena - 30 minuta
	@Value("1800000")
	private int EXPIRES_IN;
	
	// Naziv headera kroz koji ce se prosledjivati JWT u komunikaciji server-klijent
	@Value("Authorization")
	private String AUTH_HEADER;
	
	// Moguce je generisati JWT za razlicite klijente (npr. web i mobilni klijenti nece imati isto trajanje JWT, 
	// JWT za mobilne klijente ce trajati duze jer se mozda aplikacija redje koristi na taj nacin)
	// Radi jednostavnosti primera, necemo voditi racuna o uređaju sa kojeg zahtev stiže.
	//	private static final String AUDIENCE_UNKNOWN = "unknown";
	//	private static final String AUDIENCE_MOBILE = "mobile";
	//	private static final String AUDIENCE_TABLET = "tablet";
	
	private static final String AUDIENCE_WEB = "web";

	// Algoritam za potpisivanje JWT
	private SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.HS512;
	

	// ============= Funkcije za generisanje JWT tokena =============
	
	/**
	 * Funkcija za generisanje JWT tokena.
	 * 
	 * @param email Email korisnika kojem se token izdaje
	 * @return JWT token
	 */
	public String generateToken(String email) {
		return Jwts.builder()
				.setIssuer(APP_NAME)
				.setSubject(email)
				.setAudience(generateAudience())
				.setIssuedAt(new Date())
				.setExpiration(generateExpirationDate())
				.signWith(SIGNATURE_ALGORITHM, SECRET).compact();
		

		// moguce je postavljanje proizvoljnih podataka u telo JWT tokena pozivom funkcije .claim("key", value), npr. .claim("role", user.getRole())
	}
	
	/**
	 * Funkcija za utvrđivanje tipa uređaja za koji se JWT kreira.
	 * @return Tip uređaja. 
	 */
	private String generateAudience() {
		
		//	Moze se iskoristiti org.springframework.mobile.device.Device objekat za odredjivanje tipa uredjaja sa kojeg je zahtev stigao.
		//	https://spring.io/projects/spring-mobile
				
		//	String audience = AUDIENCE_UNKNOWN;
		//		if (device.isNormal()) {
		//			audience = AUDIENCE_WEB;
		//		} else if (device.isTablet()) {
		//			audience = AUDIENCE_TABLET;
		//		} else if (device.isMobile()) {
		//			audience = AUDIENCE_MOBILE;
		//		}
		
		return AUDIENCE_WEB;
	}

	/**
	 * Funkcija generiše datum do kog je JWT token validan.
	 * 
	 * @return Datum do kojeg je JWT validan.
	 */
	private Date generateExpirationDate() {
		return new Date(new Date().getTime() + EXPIRES_IN);
	}
	
	// =================================================================
	
	// ============= Funkcije za citanje informacija iz JWT tokena =============
	
	/**
	 * Funkcija za preuzimanje JWT tokena iz zahteva.
	 * 
	 * @param request HTTP zahtev koji klijent šalje.
	 * @return JWT token ili null ukoliko se token ne nalazi u odgovarajućem zaglavlju HTTP zahteva.
	 */
	public String getToken(HttpServletRequest request) {
		String authHeader = getAuthHeaderFromHeader(request);

		// JWT se prosledjuje kroz header 'Authorization' u formatu:
		// Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
		
		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			return authHeader.substring(7); // preuzimamo samo token (vrednost tokena je nakon "Bearer " prefiksa)
		}

		return null;
	}
	
	/**
	 * Funkcija za preuzimanje vlasnika tokena (korisničko ime).
	 * @param token JWT token.
	 * @return Korisničko ime iz tokena ili null ukoliko ne postoji.
	 */
	public String getEmailFromToken(String token) {
		String email;
		
		try {
			final Claims claims = this.getAllClaimsFromToken(token);
			email = claims.getSubject();
		} catch (ExpiredJwtException ex) {
			throw ex;
		} catch (Exception e) {
			email = null;
		}
		
		return email;
	}

	/**
	 * Funkcija za preuzimanje datuma kreiranja tokena.
	 * @param token JWT token.
	 * @return Datum kada je token kreiran.
	 */
	public Date getIssuedAtDateFromToken(String token) {
		Date issueAt;
		try {
			final Claims claims = this.getAllClaimsFromToken(token);
			issueAt = claims.getIssuedAt();
		} catch (ExpiredJwtException ex) {
			throw ex;
		} catch (Exception e) {
			issueAt = null;
		}
		return issueAt;
	}

	/**
	 * Funkcija za preuzimanje informacije o uređaju iz tokena.
	 * 
	 * @param token JWT token.
	 * @return Tip uredjaja.
	 */
	public String getAudienceFromToken(String token) {
		String audience;
		try {
			final Claims claims = this.getAllClaimsFromToken(token);
			audience = claims.getAudience();
		} catch (ExpiredJwtException ex) {
			throw ex;
		} catch (Exception e) {
			audience = null;
		}
		return audience;
	}

	/**
	 * Funkcija za preuzimanje datuma do kada token važi.
	 * 
	 * @param token JWT token.
	 * @return Datum do kojeg token važi.
	 */
	public Date getExpirationDateFromToken(String token) {
		Date expiration;
		try {
			final Claims claims = this.getAllClaimsFromToken(token);
			expiration = claims.getExpiration();
		} catch (ExpiredJwtException ex) {
			throw ex;
		} catch (Exception e) {
			expiration = null;
		}
		
		return expiration;
	}
	
	/**
	 * Funkcija za čitanje svih podataka iz JWT tokena
	 * 
	 * @param token JWT token.
	 * @return Podaci iz tokena.
	 */
	private Claims getAllClaimsFromToken(String token) {
		Claims claims;
		try {
			claims = Jwts.parser()
					.setSigningKey(SECRET)
					.parseClaimsJws(token)
					.getBody();
		} catch (ExpiredJwtException ex) {
			throw ex;
		} catch (Exception e) {
			claims = null;
		}
		
		// Preuzimanje proizvoljnih podataka je moguce pozivom funkcije claims.get(key)
		
		return claims;
	}
	
	// =================================================================
	
	// ============= Funkcije za validaciju JWT tokena =============
	
	/**
	 * Funkcija za validaciju JWT tokena.
	 * 
	 * @param token JWT token.
	 * @param userDetails Informacije o korisniku koji je vlasnik JWT tokena.
	 * @return Informacija da li je token validan ili ne.
	 */
	public Boolean validateToken(String token, UserDetails userDetails) {
		User user = (User) userDetails;
		final String email = getEmailFromToken(token);
		final Date created = getIssuedAtDateFromToken(token);
		final Date lastPasswordResetDate = new Date(user.getLastPasswordResetDate().getTime());
		// Token je validan kada:
		return (email != null // Email nije null
			&& email.equals(user.getEmail()) // Email iz tokena se podudara sa korisnickom imenom koje pise u bazi
			&& !isCreatedBeforeLastPasswordReset(created, lastPasswordResetDate)); // nakon kreiranja tokena korisnik nije menjao svoju lozinku
	}
	
	/**
	 * Funkcija proverava da li je lozinka korisnika izmenjena nakon izdavanja tokena.
	 * 
	 * @param created Datum kreiranja tokena.
	 * @param lastPasswordReset Datum poslednje izmene lozinke.
	 * @return Informacija da li je token kreiran pre poslednje izmene lozinke ili ne.
	 */
	private Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
		return (lastPasswordReset != null && created.before(lastPasswordReset));
	}
	
	// =================================================================
	
	/**
	 * Funkcija za preuzimanje perioda važenja tokena.
	 * 
	 * @return Period važenja tokena.
	 */
	public int getExpiredIn() {
		return EXPIRES_IN;
	}

	/**
	 * Funkcija za preuzimanje sadržaja AUTH_HEADER-a iz zahteva.
	 * 
	 * @param request HTTP zahtev.
	 * 
	 * @return Sadrzaj iz AUTH_HEADER-a.
	 */
	public String getAuthHeaderFromHeader(HttpServletRequest request) {
		return request.getHeader(AUTH_HEADER);
	}



	/* ****************KEYCLOAK********************* */

	@Value("${keycloak.auth-server-url}")
	private String keycloakUrl;

	@Value("${keycloak.realm}")
	private String realm;

	@Value("${keycloak.resource}")
	private String keycloakResource;

	@Value("${keycloak.credentials.secret}")
	private String keycloakSecret;



	/**
	 * Login korisnika na Keycloak koristeći email i password
	 * @param email korisnikov email
	 * @param password korisnikova lozinka
	 * @return JWT token ako je uspešno, null ako nije
	 */
//
	public String loginToKeycloak(String email, String password) {
		try {
			String tokenEndpoint = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";

			RestTemplate restTemplate = new RestTemplate();
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

			MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
			body.add("grant_type", "password");
			body.add("client_id", keycloakResource);

			// dodaj secret samo ako je client confidential
			if (keycloakSecret != null && !keycloakSecret.isEmpty()) {
				body.add("client_secret", keycloakSecret);
			}

			body.add("username", email);
			body.add("password", password);

			HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

			ResponseEntity<String> response = restTemplate.postForEntity(tokenEndpoint, request, String.class);

			if (response.getStatusCode() == HttpStatus.OK) {
				ObjectMapper mapper = new ObjectMapper();
				JsonNode node = mapper.readTree(response.getBody());
				return node.get("access_token").asText(); // JWT token
			}

		} catch (HttpClientErrorException e) {
			System.err.println("Keycloak login failed: " + e.getStatusCode() + " " + e.getResponseBodyAsString());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}


	/**
	 * Validacija Keycloak tokena preko /userinfo
	 */
	public boolean validateKeycloakToken(String token) {
		try {
			String userInfoEndpoint = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/userinfo";

			RestTemplate restTemplate = new RestTemplate();
			HttpHeaders headers = new HttpHeaders();
			headers.setBearerAuth(token);

			HttpEntity<String> entity = new HttpEntity<>(headers);
			ResponseEntity<String> response = restTemplate.exchange(userInfoEndpoint, HttpMethod.GET, entity, String.class);

			return response.getStatusCode() == HttpStatus.OK;

		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * Preuzimanje email-a iz Keycloak JWT tokena
	 */
	public String getEmailFromKeycloakToken(String token) {
		try {
			String[] parts = token.split("\\.");
			if (parts.length < 2) return null;

			String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
			ObjectMapper mapper = new ObjectMapper();
			JsonNode node = mapper.readTree(payload);

			if (node.has("email")) return node.get("email").asText();
			if (node.has("preferred_username")) return node.get("preferred_username").asText();

		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}