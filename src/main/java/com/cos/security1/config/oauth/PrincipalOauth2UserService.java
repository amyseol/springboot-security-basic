package com.cos.security1.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	@Autowired UserRepository userRepository;
	
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		System.out.println("getClientRegistration : "+userRequest.getClientRegistration()); 
		System.out.println("getAccessToken : "+userRequest.getAccessToken().getTokenValue());
		OAuth2User oauth2User = super.loadUser(userRequest);
		System.out.println("getAttributes : "+oauth2User.getAttributes());
		
		OAuth2UserInfo oAuth2UserInfo = null;
		if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
			System.out.println("구글 로그인 요청");
			oAuth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
		}else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
			System.out.println("페이스북 로그인 요청");
			oAuth2UserInfo = new FacebookUserInfo(oauth2User.getAttributes());
		}else {
			System.out.println("구글과 페이스북만 지원됩니다.");
		}
		
		String provider = oAuth2UserInfo.getProvider(); // userRequest.getClientRegistration().getRegistrationId(); // google,facebook
		String providerId = oAuth2UserInfo.getProviderId(); // oauth2User.getAttribute("sub"); // 39104758145908
		String username = provider + "_" + providerId; // google_39104758145908
		String password = bCryptPasswordEncoder.encode("getinthere"); // 비밀번호는 소셜 로그인시 크게 필요 없어서 대충 만든다.
		String email = oAuth2UserInfo.getEmail(); // oauth2User.getAttribute("email");
		String role = "ROLE_USER";
		
		User userEntity = userRepository.findByUsername(username);
		if(userEntity == null) { // userEntity 에 username 이 없으면 회원가입 시켜주기 
			System.out.println("구글 로그인이 최초입니다.");
			userEntity = User.builder()
					.username(username)
					.password(password)
					.email(email)
					.role(role)
					.provider(provider)
					.providerId(providerId)
					.build();
			userRepository.save(userEntity);
		} else {
			System.out.println("로그인을 이미 한 적이 있습니다.");
		}
		// PrincipalDetails 는 OAuth2User 타입이라 return 이 가능하다.
		// Authentication 에 해당 리턴 값이 들어가게 된다. 이 때 PrincipalDetails 는 User 와 attributes 라는 map 을 같이 들고 간다. 
		return new PrincipalDetails(userEntity, oauth2User.getAttributes());
	}
}
