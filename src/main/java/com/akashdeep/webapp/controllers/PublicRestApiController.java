package com.akashdeep.webapp.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/public")
public class PublicRestApiController {

	public PublicRestApiController() {
		// TODO Auto-generated constructor stub
	}

	@GetMapping("test1")
	public String test1() {
		return "API Test 1";
	}
	
	@GetMapping("test2")
	public String test2() {
		return "API Test 2";
	}
}
