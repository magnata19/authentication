package br.com.microservices.stateless_auth_api.core.service;

import br.com.microservices.stateless_auth_api.core.model.User;
import br.com.microservices.stateless_auth_api.infra.exception.AuthenticationException;
import br.com.microservices.stateless_auth_api.infra.exception.ValidationException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;

import static org.apache.commons.lang3.ObjectUtils.isEmpty;

@Service
@RequiredArgsConstructor
public class JwtService {

  private static final String EMPTY_SPACE = " ";
  private static final Integer TOKEN_INDEX = 1;
  private static final Integer ONE_DAY_IN_HOURS = 24;

  @Value("${app.token.secret-key}")
  private String secretKey;

  public String createToken(User user) {
    var data = new HashMap<String, String>();
    data.put("id", user.getId().toString());
    data.put("username", user.getUsername());
    return Jwts.builder()
            .setClaims(data)
            .setExpiration(generateExpirateAt())
            .signWith(generateSign())
            .compact();
  }

  private Date generateExpirateAt () {
    return Date.from(
            LocalDateTime.now()
                    .plusHours(ONE_DAY_IN_HOURS)
                    .atZone(ZoneId.systemDefault())
                    .toInstant()
    );
  }

  private SecretKey generateSign() {
    return Keys.hmacShaKeyFor(secretKey.getBytes());
  }

  public void validateAccessToken(String token){
    var accessToken = extractToken(token);
    try {
      Jwts.parser()
              .setSigningKey(generateSign())
              .build()
              .parseClaimsJws(accessToken)
              .getBody();
    } catch (Exception e) {
      throw new AuthenticationException("Invalid Token %s".formatted(e.getMessage()));
    }
  }

  private String extractToken(String token){
    if(isEmpty(token)) {
      throw new ValidationException("The access token was not informed.");
    }
    if(token.contains(EMPTY_SPACE)) {
      return token.split(EMPTY_SPACE)[TOKEN_INDEX];
    }
    return token;
  }

}
