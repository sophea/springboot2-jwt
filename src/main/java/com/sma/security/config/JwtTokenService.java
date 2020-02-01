package com.sma.security.config;

import com.sma.security.utils.WebHelper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtTokenService {

    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

    public static final String ROLES = "ROLES";

    @Value("${jwt.secret}")
    private String secret;

    //retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    //retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public List<String> getRoles(String token) {
       return getClaimFromToken(token, claims -> (List) claims.get(ROLES));
    }

    public String getIpAddress(String token) {
        return  getClaimFromToken(token, claims -> (String) claims.get("IP"));
    }

    public String getUserAgent(String token) {
        return  getClaimFromToken(token, claims -> (String) claims.get("UA"));
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    //for retrieving any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    //check if the token has expired
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public boolean isClientInfoMatch(HttpServletRequest request, String token) {
        return isClientIPMatched(request, token) && isUserAgentMatched(request, token);
    }

    public boolean isClientIPMatched(HttpServletRequest request, String token) {
        return WebHelper.getClientIpAddress(request).equals(getIpAddress(token));
    }

    public boolean isUserAgentMatched(HttpServletRequest request, String token) {
        return WebHelper.getUserAgent(request).equals(getUserAgent(token));
    }



    //generate token for user
    public String generateToken(Authentication authentication, HttpServletRequest request) {
        final Map<String, Object> claims = new HashMap<>();
        final UserDetails user = (UserDetails) authentication.getPrincipal();

        final List<String> roles = authentication.getAuthorities()
                                                 .stream()
                                                 .map(GrantedAuthority::getAuthority)
                                                 .collect(Collectors.toList());


        claims.put(ROLES, roles);
        claims.put("IP", WebHelper.getClientIpAddress(request));
        claims.put("UA", WebHelper.getUserAgent(request));
        return generateToken(claims, user.getUsername());
    }

    //while creating the token -
    //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.
    //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
    //   compaction of the JWT to a URL-safe string
    private String generateToken(Map<String, Object> claims, String subject) {
        final long now = System.currentTimeMillis();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    //validate token
    public Boolean validateToken(String token) {
        final String username = getUsernameFromToken(token);
        return username != null && !isTokenExpired(token);
    }
}