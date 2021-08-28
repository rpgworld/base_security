package com.midas.base_security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity // web 보안을 시작 하기위한 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        //== 폼 로그인 ==//
        http
                .formLogin()
                //.loginPage("/loginPage")                // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/")                 // 성공 페이지 이동
                .failureUrl("/login")                   // 실패 페이지 이동
                .usernameParameter("userId")            // 아이디 파라미터명
                .passwordParameter("passwd")            // 패스워드 파라미터명
                .loginProcessingUrl("/login")           // 로그인 폼 엑션 url
                // 로그인 성공 핸들러
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication" + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                // 로그인 실패 핸들러
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception" + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll(); // loginPage 는 인가를 받지 않아도 접근 가능 하도록!

            //== 로그아웃 ==//
            http
                    .logout()   // post 방식으로 해야됨!
                    .logoutUrl("/logout")                           // 로그아웃 처리 url
                    .logoutSuccessUrl("/login")                     // 로그아웃 성공 후 이동페이지
                    .deleteCookies("remember-me")                   // 로그아웃 후 쿠키 삭제
                    // 로그아웃 핸들러
                    .addLogoutHandler(new LogoutHandler() {
                        @Override
                        public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                            HttpSession session = request.getSession();
                            session.invalidate();
                        }
                    })
                    // 로그아웃 성공 후 핸들러
                    .logoutSuccessHandler(new LogoutSuccessHandler() {
                        @Override
                        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                            response.sendRedirect("/login");
                        }
                    });

            //== Remember me ==//
            http
                    .rememberMe()
                    .rememberMeParameter("remember")    // 기본 파라미터명: remember-me
                    .tokenValiditySeconds(3600)         // 만료일 : Default 14 day
                    .alwaysRemember(true)               // 활성화여부 : always
                    .userDetailsService(userDetailsService());
    }
}
