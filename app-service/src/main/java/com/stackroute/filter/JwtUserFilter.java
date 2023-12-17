package com.stackroute.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.filter.GenericFilterBean;


import java.io.IOException;

/* This class implements the custom filter by extending org.springframework.web.filter.GenericFilterBean.
 * Override the doFilter method with ServletRequest, ServletResponse and FilterChain.
 * This is used to authorize the API access for the application.
 */
public class JwtUserFilter extends GenericFilterBean {
	
	@Value("${jwt.secret}")
	private String secret;
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;

        final String authHeader = request.getHeader("authorization");

        if ("OPTIONS".equals(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
            filterChain.doFilter(request, response);
        } else {
           
        		 /*
                 * Check if authHeader is null or does not start with "Bearer " then throw Exception
                 */
        		if(authHeader == null || !authHeader.startsWith("Bearer ")) {
        			throw new ServletException ("Missing or invalid Authorization header");
        		}
        		/*
                 * Extract token from authHeader
                 */
        		String token =authHeader.substring(7);
        		/*
                 * Obtain Claims by parsing the token with the signing key value "secret"
                 */
        		Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
        		 /*
                 * Extract role from Claims and check if it is "user" or "admin" and then allow only USER Role
                 */
        		String role = (String) claims.get("role");
        		if(!"user".equals(role)) {
        			throw new ServletException("Unauthorized: Only 'user' role is allowed");
        		}
        		/*
                 * Set Claims object obtained in previous step with key "claims" as request attribute
                 */
        		request.setAttribute("claims", claims);
        		 /*
                 * Set user id passed as request parameter with key "user" as request attribute
                 */
        		request.setAttribute("user", claims.getSubject());

            filterChain.doFilter(request, response);
        }
    }
}

