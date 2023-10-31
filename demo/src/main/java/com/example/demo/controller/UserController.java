package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.dto.ResponseDTO;
import com.example.demo.dto.UserDTO;
import com.example.demo.model.UserEntity;
import com.example.demo.security.TokenProvider;
import com.example.demo.service.UserService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/auth")
public class UserController {

  @Autowired
  private UserService userService;

  // Bean으로 작성해도 됨.
  private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


  @Autowired
  private TokenProvider tokenProvider;

  //회원가입
  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@RequestBody UserDTO userDTO) {//input 값(username과 password) 받아오기
    try {
      if(userDTO == null || userDTO.getPassword() == null ) { //input값이 제대로 받아지지 않은 경우
        throw new RuntimeException("Invalid Password value.");
      }

      //input값이 제대로 받아진 경우
      //DB에 저장할 유저 entity 만들기
      UserEntity user = UserEntity.builder()
          .username(userDTO.getUsername())
          .password(passwordEncoder.encode(userDTO.getPassword())) //password는 보안상 암호화해서 저장할 것
          .build();
      // 서비스를 이용해 레포지터리에 유저 저장(save) -> DB에 저장됨
      UserEntity registeredUser = userService.create(user);
      
      //DB에 저장된 값을 다시 받아와서 DTO를 리턴해주기
      //이때 필요한 값만 받아오면 됨. 즉, 암호는 필요 없음.
      // 유저 정보는 항상 하나이므로 리스트로 만들어야 하는 ResponseDTO를 사용하지 않고 그냥 UserDTO 리턴.
      UserDTO responseUserDTO = UserDTO.builder()
          .id(registeredUser.getId())
          .username(registeredUser.getUsername())
          .build();

      return ResponseEntity.ok().body(responseUserDTO);
    } catch (Exception e) {

      ResponseDTO responseDTO = ResponseDTO.builder().error(e.getMessage()).build();
      return ResponseEntity
          .badRequest()
          .body(responseDTO);
    }
  }

  //로그인
  @PostMapping("/signin")
  public ResponseEntity<?> authenticate(@RequestBody UserDTO userDTO) {
    System.out.println("!!!!!!!!!!!!!!!!!로그인 시의 인풋 userDTO : " + userDTO);
    UserEntity user = userService.getByCredentials(
        userDTO.getUsername(),
        userDTO.getPassword(),
        passwordEncoder);
    if(user != null) {
      // 토큰 생성
      final String token = tokenProvider.create(user);
      final UserDTO responseUserDTO = UserDTO.builder()
          .username(user.getUsername())
          .id(user.getId())
          .token(token)
          .build();
      return ResponseEntity.ok().body(responseUserDTO);
    } else {
      ResponseDTO responseDTO = ResponseDTO.builder()
          .error("Login failed.")
          .build();
      return ResponseEntity
          .badRequest()
          .body(responseDTO);
    }
  }


}