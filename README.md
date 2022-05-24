# 스프링 시큐리티 + JWT
## 리엑트 연동 참고
https://bezkoder.com/spring-boot-react-jwt-auth/
## JWT 구조
![jwt구조](https://github.com/haeyonghahn/spring-security-jwt/blob/master/images/jwt%20%EA%B5%AC%EC%A1%B0.PNG)

## Filter
Spring Security는 `서블릿 필터 체인`을 자동으로 구성한다. 브라우저가 서버에게 요청을 보내면   
DispatcherServlet(FrontController)가 요청을 받기 이전에  ServletFilter 를 거치게 된다.   

![filter](https://github.com/haeyonghahn/spring-security-jwt/blob/master/images/securityFilter.PNG)
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final CorsFilter corsFilter;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class); // SecurityContextPersistenceFilter가 동작되기 전에 MyFilter3 실행
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session을 사용하지 않은 것
		...
	}
}
```
따로 필터를 걸 수도 있다.
```java
@Configuration
public class FilterConfig {

	@Bean
	public FilterRegistrationBean<MyFilter1> filter1() {
		FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<MyFilter1>(new MyFilter1());
		bean.addUrlPatterns("/*");
		bean.setOrder(0); // 낮은 번호가 필터중에서 가장 먼저 실행됨
		return bean;
	}
	
	@Bean
	public FilterRegistrationBean<MyFilter2> filter2() {
		FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<MyFilter2>(new MyFilter2());
		bean.addUrlPatterns("/*");
		bean.setOrder(1); // 낮은 번호가 필터중에서 가장 먼저 실행됨
		return bean;
	}
}
```
여기서 더 확인되는 사항은 Spring Security Filter가 전부 실행되고 나서 직접 커스텀한 Filter가 수행된다.
```console
필터3
필터1
필터2
```
## jwt 로그인 시도
`http://localhost:8080/login` 시도 시 권한 오류가 확인되는 것이 아니라, 페이지를 못찾는 오류가 확인이 된다.   
그 이유는 `security config` 설정에서 formLogin.disable()로 동작을 안하기 때문이다.

![권한확인](https://github.com/haeyonghahn/spring-security-jwt/blob/master/images/%EA%B6%8C%ED%95%9C%ED%99%95%EC%9D%B8.PNG)
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final CorsFilter corsFilter;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class); // SecurityContextPersistenceFilter가 동작되기 전에 실행
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session을 사용하지 않은 것
		.and()
		/*
		 * 모든 요청이 들어와도 CorsFilter를 거친다. @CrossOrigin(인증이 필요없을 때), 시큐리티 필터에 등록(인증이 필요할 때)
		 * Cross Origin 정책을 벗어난다. 모든 요청을 허용
		 * */
		.addFilter(corsFilter)
		.formLogin().disable()
		.httpBasic().disable()
		...
	}
}
```
그렇기 때문에 `UsernamePasswordAuthenticationFilter` 를 상속받은 클래스를 `security config` 설정에 filter를 추가하여 `/login`요청을 filter 한다.
```java
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	private final AuthenticationManager authenticationManager;

	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		return super.attemptAuthentication(request, response);
	}
}
```
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final CorsFilter corsFilter;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class); // SecurityContextPersistenceFilter가 동작되기 전에 실행
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session을 사용하지 않은 것
		.and()
		/*
		 * 모든 요청이 들어와도 CorsFilter를 거친다. @CrossOrigin(인증이 필요없을 때), 시큐리티 필터에 등록(인증이 필요할 때)
		 * Cross Origin 정책을 벗어난다. 모든 요청을 허용
		 * */
		.addFilter(corsFilter)
		.formLogin().disable()
		.httpBasic().disable()
		// WebSecurityConfigurerAdapter에 authenticationManager() 함수가 존재한다.
		.addFilter(new JwtAuthenticationFilter(authenticationManager()))
		...
	}
}
```
![로그인요청](https://github.com/haeyonghahn/spring-security-jwt/blob/master/images/%EB%A1%9C%EA%B7%B8%EC%9D%B8%EC%9A%94%EC%B2%AD.PNG)
![콘솔확인](https://github.com/haeyonghahn/spring-security-jwt/blob/master/images/%EC%BD%98%EC%86%94%ED%99%95%EC%9D%B8.PNG)

## JWT 서버 구축 완료
![Authrization값](https://github.com/haeyonghahn/spring-security-jwt/blob/master/images/Authorization%EA%B0%92.png)
![인가](https://github.com/haeyonghahn/spring-security-jwt/blob/master/images/%EC%9D%B8%EA%B0%80.png)
