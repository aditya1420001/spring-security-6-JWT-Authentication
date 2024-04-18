package com.adhi.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/demo-controller")
public class DemoController {

    /** This controller is here to just test if it secured or not */
    @GetMapping
    public ResponseEntity<String> demoController() {
        return ResponseEntity.ok("hello world");
    }

}
