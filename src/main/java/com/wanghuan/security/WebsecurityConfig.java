package com.wanghuan.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

//springSecurity的主配置文件
@Configuration
@EnableWebSecurity
public class WebsecurityConfig extends WebSecurityConfigurerAdapter {

	//注入数据库验证信息,在访问/oauth/token...的时候首先会通过springSecurity的拦截，进入loadUserByUsername
	@Autowired
	private MyUserDetailsService userDetailsService;

//	@Autowired
//	public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
//		auth.userDetailsService(userDetailsService);
//	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//所有请求都要认证
		http.authorizeRequests().anyRequest().authenticated().and()
		//表单提交是失败的url放行
		.formLogin().failureUrl("/login?error").permitAll().and()
		//退出登入的url放行
		.logout().permitAll().and()
		//禁用csrf
		.csrf().disable();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		//配置密码验证的的userDetailsService为自定义实现的
		auth.userDetailsService(userDetailsService);
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

}
