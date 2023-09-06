package com.example.security.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/student")
public class StudentController {


    @GetMapping("/get")
    public ResponseEntity<String> sayHello(){
        return ResponseEntity.ok("Hello from secure entity");
    }
}
