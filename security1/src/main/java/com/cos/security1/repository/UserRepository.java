package com.cos.security1.repository;

import com.cos.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

//JpaRepository가 기본적인 CRUD를 가지고 있음
//JpaRepository를 상속했기 때문에 @Repository 어노테이션 쓰지 않아도 됨
public interface UserRepository extends JpaRepository<User, Integer> {

    //findBy(규칙) + Username(찾을 대상)
    //select * from user where username = 1?
    //jpa query method 알아서 공부하셈
    public User findByUsername(String username);

}
