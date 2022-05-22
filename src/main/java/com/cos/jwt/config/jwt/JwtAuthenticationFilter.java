package com.cos.jwt.config.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있다.
// /login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 가 동작을 한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	private final AuthenticationManager authenticationManager;

	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		
		// 1. username과 password를 받아서 
		// 2. 정상인지 로그인시도를 한다. AuthenticationManager로 로그인 시도를 하면
		// 3. PrincipalDetailsService를 호출 loadUserByUsername() 함수가 실행된다.
		// 4. PrincipalDetails를 세션에 담고 (권한관리를 위해) 
		// 5. jwt 토큰을 만들어서 응답을 해준다.
		return super.attemptAuthentication(request, response);
	}
}
