package com.security.example.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/root")
public class ControllerExample {

  @GetMapping("/hello")
  public String getExample() {
    return "Hello";
  }

  @GetMapping("/token")
  public String getToken() {
    return "AAA.BBB.CCC";
  }

}
