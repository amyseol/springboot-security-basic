package com.cos.security1.config.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import com.cos.security1.model.User;
import lombok.Data;

@Data // controller 에서 DI 후 getUser, getAttributes 를 하기 위해 추가 
public class PrincipalDetails implements UserDetails, OAuth2User{
	private static final long serialVersionUID = 1L;
	private User user;
	private Map<String, Object> attributes;
	
	// 일반 로그인시 사용하는 생성자 
	public PrincipalDetails(User user) {
		this.user = user;
	}
	
	// OAuth 로그인시 사용하는 생성자 
	public PrincipalDetails(User user, Map<String, Object> attributes) {
		this.user = user;
		this.attributes = attributes;
	}
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> collect = new ArrayList<>();
		collect.add(new GrantedAuthority() {
			@Override
			public String getAuthority() {
				return user.getRole();
			}
		});
		return collect;
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}
	
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	@Override
	public String getName() {
		return null; // 필요하면 attributes.get("sub") 로 ID 를 가져올 수 있다. 
	}
}