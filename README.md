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
