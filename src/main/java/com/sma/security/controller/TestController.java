package com.sma.security.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @RequestMapping({ "/secure" })
    @Secured("ROLE_USER")
    public String securePage() {
        return "Secure page";
    }

    @RequestMapping({ "/test" })
    public String test() {
        return "test page";
    }


}