package com.istio.security.oauth2.configuration;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;



@EnableAuthorizationServer
@EnableConfigurationProperties(SecurityProperties.class)
@Configuration
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

	private final DataSource dataSource;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	private final SecurityProperties securityProperties;
	private final UserDetailsService userDetailsService;

	private static final String JWK_KID = "pet-shop-key-id";

	private TokenStore tokenStore;

	public AuthorizationServerConfiguration(final DataSource dataSource, final PasswordEncoder passwordEncoder,
			final AuthenticationManager authenticationManager, final SecurityProperties securityProperties,
			final UserDetailsService userDetailsService) {
		this.dataSource = dataSource;
		this.passwordEncoder = passwordEncoder;
		this.authenticationManager = authenticationManager;
		this.securityProperties = securityProperties;
		this.userDetailsService = userDetailsService;
	}

	@Bean
	public TokenStore tokenStore() {
		if (tokenStore == null) {
			tokenStore = new JwtTokenStore(jwtAccessTokenConverter());
		}
		return tokenStore;
	}

	@Bean
	public DefaultTokenServices tokenServices(final TokenStore tokenStore, final ClientDetailsService clientDetailsService) {
		DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setSupportRefreshToken(true);
		tokenServices.setTokenStore(tokenStore);
		tokenServices.setClientDetailsService(clientDetailsService);
		tokenServices.setAuthenticationManager(this.authenticationManager);
		return tokenServices;
	}

	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		Map<String, String> customHeaders = Collections.singletonMap("kid", JWK_KID);
		return new JwtCustomHeadersAccessTokenConverter(customHeaders, keyPair());
	}

	@Bean
	public KeyPair keyPair() {
		SecurityProperties.JwtProperties jwtProperties = securityProperties.getJwt();
		return keyPair(jwtProperties, keyStoreKeyFactory(jwtProperties));
	}

	@Bean
	public JWKSet jwkSet() {
		RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) keyPair().getPublic())
				                           .keyUse(KeyUse.SIGNATURE)
				                           .algorithm(JWSAlgorithm.RS256)
				                           .keyID(JWK_KID);
		return new JWKSet(builder.build());
	}

	@Override
	public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
		clients.jdbc(this.dataSource);
	}

	@Override
	public void configure(final AuthorizationServerEndpointsConfigurer endpoints) {
		endpoints.authenticationManager(this.authenticationManager)
		         .accessTokenConverter(jwtAccessTokenConverter())
				 .userDetailsService(this.userDetailsService)
				 .tokenStore(tokenStore());
	}

	@Override
	public void configure(final AuthorizationServerSecurityConfigurer oauthServer) {
		oauthServer.passwordEncoder(this.passwordEncoder)
		           .tokenKeyAccess("permitAll()")
				   .checkTokenAccess("isAuthenticated()");
	}

	private KeyPair keyPair(SecurityProperties.JwtProperties jwtProperties, KeyStoreKeyFactory keyStoreKeyFactory) {
		return keyStoreKeyFactory.getKeyPair(jwtProperties.getKeyPairAlias(),
				jwtProperties.getKeyPairPassword().toCharArray());
	}

	private KeyStoreKeyFactory keyStoreKeyFactory(SecurityProperties.JwtProperties jwtProperties) {
		return new KeyStoreKeyFactory(jwtProperties.getKeyStore(), jwtProperties.getKeyStorePassword().toCharArray());
	}
}
