package com.bytmasoft.dss.security.filter;

import com.bytmasoft.dss.security.JwtUtil;
import com.bytmasoft.dss.security.authentication.JwtAuthenticationToken;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

import java.util.stream.Collectors;


@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtUtil jwtUtil;;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        logger.info("Authorization Header: {}", request.getHeader("Authorization"));

        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            try {
                username = jwtUtil.extractUsername(jwt);

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    if (jwtUtil.validateAccessToken(jwt, username)) {
                        List<String> roles = jwtUtil.extractRoles(jwt);

                        List<GrantedAuthority> authorities = roles.stream().map(role ->  new SimpleGrantedAuthority(role)).collect(Collectors.toList());

                        UserDetails userDetails = new User(username, "", authorities);

                        JwtAuthenticationToken authentication = new JwtAuthenticationToken(userDetails,null, userDetails.getAuthorities());

                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }

            }catch (ExpiredJwtException ex) {

                logger.error("JWT token has expired: {}", ex.getMessage());
                throw ex; // Make sure this is thrown so AuthControllerAdvice can catch it
            }
        }
        filterChain.doFilter(request, response);

    }
}
