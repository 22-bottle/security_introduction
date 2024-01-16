package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

//시큐리티가 /login을 낚아채서 로그인을 진행함
//로그인 진행이 완료되면 시큐리티 session을 만듦 (Security ContextHolder)
//이 session에 들어갈 수 있는 오브젝트가 정해져 있음 (Authentication 타입 객체)
//Authentication 안에는 User 정보가 있어야 함
//User 오브젝트 타입은 UserDetails 타입 객체여야 함
// Security Session => Authentication => UserDetails (PrincipalDetails)
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user;
    private Map<String, Object> attributes;

    //일반 로그인 할 때 사용하는 생성자
    public PrincipalDetails(User user) {
        this.user = user;
    }

    //OAuth 로그인 할 때 사용하는 생성자
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    // 해당 User의 권한을 리턴하는 곳
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
        //휴면 계정 처리 (ex. (현재 시간 - 로그인 시간)이 1년 이상인 경우 처리)
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return null;
    }
}