/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.codebyamir.controller;

import com.codebyamir.model.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

/**
 *
 * @author erhannis
 */
@Controller
public class PageController {
	@RequestMapping(value="/", method = RequestMethod.GET)
	public String showIndex(){
		return "index";
	}
    
	@RequestMapping(value="/account", method = RequestMethod.GET)
	public ModelAndView showAccountPage(ModelAndView modelAndView, User user){
		modelAndView.addObject("user", user);
		modelAndView.setViewName("account");
		return modelAndView;
	}
}
