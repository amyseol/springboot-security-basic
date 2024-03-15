package com.cos.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Controller
public class IndexController {
	@Autowired 
	private UserRepository userRepository;
	@Autowired 
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	// Authentication 에 저장된 일반 로그인 유저 정보 확인하는 방법 
	@GetMapping("/test/login")
	public @ResponseBody String loginTest(Authentication authentication, // 방법 1. Authentication를 DI(의존성 주입)해서 PrincipalDetails 로 다운 캐스팅 해서 User Object 찾기
			@AuthenticationPrincipal UserDetails userDetails, // 방법 2. @AuthenticationPrincipal 를 통해서 UserDetails 타입으로 User Object 받아오기 
			@AuthenticationPrincipal PrincipalDetails principal) { // 방법 2-1. PrincipalDetails는 userDetails를 구현하기 때문에 userDetails 타입이 될 수 있다. 그럼 getUser()를 받을 수 있다.
		System.out.println("/test/login========");
		// 방법 1-1. authentication.getPrincipal() 는 object 를 반환하기 때문에 UserDetails 를 구현하는 PrincipalDetails 타입으로 다운 캐스팅 해준다. 
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal(); // OAuth 로그인시 오류가 난다. 
		System.out.println("authentication : "+principalDetails.getUser()); // User 정보 반환 
		// 방법 2-2. 
		System.out.println("userDetails.getUsername : "+userDetails.getUsername()); // amy username만 반환
		System.out.println("userDetails : "+principal.getUser());  // User 정보 반환 
		return "세션 정보 확인하기"; 
	}
	
	// Authentication 에 저장된 OAuth 로그인 유저 정보 확인하는 방법 
	@GetMapping("/test/oauth/login")
	public @ResponseBody String testOAuthLogin(Authentication authentication, // 방법 1. Authentication를 DI(의존성 주입)해서 OAuth2User 로 다운 캐스팅하기 
			@AuthenticationPrincipal OAuth2User oauthUser) { // 방법 2. @AuthenticationPrincipal 을 통해 OAuth2User 타입으로 User Object 받아오기 
		System.out.println("/test/oauth/login========");
		OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
		System.out.println("authentication : "+oauth2User.getAttributes()); // User 정보 반환 
		System.out.println("oauth2User : "+oauthUser.getAttributes());
		return "OAuth 세션 정보 확인하기"; 
	}
	
	@GetMapping({"","/"})
	public String index() {
		return "index";
	}
	
	@GetMapping("/user")
	public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("principalDetails : "+principalDetails.getUser()); // User 정보 반환 
		return "user";
	}
	
	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "admin";
	}
	
	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "manager";
	}
	
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}
	
	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}
	
	@PostMapping("/join")
	public String join(User user) {
		user.setRole("ROLE_USER");
		String rawPassword = user.getPassword();
		String encodedPassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPassword(encodedPassword);
		userRepository.save(user);
		return "redirect:/loginForm";
	}
	
	@Secured("ROLE_ADMIN")
	@GetMapping("/info")
	public @ResponseBody String info() {
		return "개인 정보";
	}	
	
	@PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
	@GetMapping("/data")
	public @ResponseBody String data() {
		return "데이터 정보";
	}
}
