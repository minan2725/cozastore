package com.cybersoft.cozastore.filter;

import com.cybersoft.cozastore.utils.JWTHelperUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

@Component
//OncePerRequestFilter : co request yeu cau chung thuc thi deu chay vao filter nay
public class JwtFilter extends OncePerRequestFilter {

    /**
     * B1 : Lay token
     * B2 : Giai ma token
     * B3 : token hop le tao chung thuc cho security
     */

    @Autowired
    JWTHelperUtils jwtHelperUtils;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        try {
            // B1 : Lay token

            String token = header.substring(7); //cat chuoi de lay token (bo chu bearer)
            //Kiem tra token lay dc xem co phai do he thong sinh ra hay ko
            String data = jwtHelperUtils.validToken(token);
            if (!data.isEmpty()){ // ham isEmpty xem data co rong ko va tre ve kieu boolean
                //Tao chung thuc cho Security
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken("", "", new ArrayList<>());
                SecurityContext securityContext = SecurityContextHolder.getContext();
                securityContext.setAuthentication(authenticationToken);
            }
            System.out.println("Kiem tra " + data);
        }catch (Exception e){
            System.out.println("token ko hop le");
        }

        // cho phep di vao link nguoi dung muon truy cap
        filterChain.doFilter(request, response);

    }
}
