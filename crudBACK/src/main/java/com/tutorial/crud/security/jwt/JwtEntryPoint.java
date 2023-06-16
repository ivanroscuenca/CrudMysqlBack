package com.tutorial.crud.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//Clase comprobar si el token es válido, respuesta 401: non authorized
@Component
public class JwtEntryPoint implements AuthenticationEntryPoint {
    //variable instancia de registro compartida y accedida desde diferentes partes
    private final static Logger logger = LoggerFactory.getLogger(JwtEntryPoint.class);
    @Override
    public void commence(HttpServletRequest req, HttpServletResponse res, AuthenticationException e) throws IOException, ServletException {
    //Lanzamos el error
        logger.error("Failed in method commence");
        res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Non Authorized");
    }
}
