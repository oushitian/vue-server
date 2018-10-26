package com.wanghuan.oauth2;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

/**
 * 认证服务器
 *
 * oauth验证大体主要分三步：
 * 1.根据客户端client信息  与数据库或内存中的client比较，如果一致就授权成功
 * 2.获取token  http://127.0.0.1:8081/oauth/token?grant_type=authorization_code&code=rTKETX&redirect_uri=http://127.0.0.1:8082/login/my&client_id=clientId&client_secret=secret
 * 3.最后带着返回的token去资源服务器访问资源
 */
@Configuration
@EnableAuthorizationServer
public class MyAuthorizationServerConfigurerAdapter extends AuthorizationServerConfigurerAdapter {

	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
		//设置签名对称加密只需要加入key等其他信息（自定义）
		accessTokenConverter.setSigningKey("smallsnail");
		return accessTokenConverter;
	}
	
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private RedisConnectionFactory redisConnection;
	
	@Autowired
    private DataSource dataSource;
	
	@Bean 
    public ClientDetailsService clientDetailsService() {
        return new JdbcClientDetailsService(dataSource);
    }

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		super.configure(security);
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		/*redis存储token*/
		endpoints.authenticationManager(authenticationManager).tokenStore(new MyRedisTokenStore(redisConnection));
		/*jwt方式*/
//		endpoints.accessTokenConverter(jwtAccessTokenConverter());
//		endpoints.authenticationManager(authenticationManager).tokenStore(new JwtTokenStore(jwtAccessTokenConverter()));
		/*jwt方式+redis存储token*/
		//设置存储token的形式为jwt方式+redis
		endpoints.accessTokenConverter(jwtAccessTokenConverter());
		//设置redisToken的具体信息
		endpoints.authenticationManager(authenticationManager).tokenStore(new MyRedisTokenStore(redisConnection));
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		//配置ClientDetailsServiceConfigurer为jdbc的形式，就是客户端的信息会动oauth_client_details里面读取，还有一种是客户端信息存在内存中clients.inMemory()
		clients.withClientDetails(clientDetailsService());
	}


}
