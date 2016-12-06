package com.kristijangeorgiev.spring.boot.oauth2.jwt.configuration;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import com.kristijangeorgiev.spring.boot.oauth2.jwt.model.entity.User;

@Configuration
@EnableAuthorizationServer
public class OAuth2Configuration extends AuthorizationServerConfigurerAdapter {

	@Autowired
	@Qualifier("authenticationManagerBean")
	private AuthenticationManager authenticationManager;

	// TODO externalize token related data to configuration, store clients in DB
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory().withClient("webapp").authorizedGrantTypes("implicit", "refresh_token", "password")
				.authorities("ROLE_TRUSTED").resourceIds("ms/user").scopes("read", "write").autoApprove(true)
				.accessTokenValiditySeconds(60000).refreshTokenValiditySeconds(60000).and().withClient("server")
				.secret("secret").authorizedGrantTypes("refresh_token", "authorization_code")
				.authorities("ROLE_TRUSTED").resourceIds("app/admin").scopes("read", "write").autoApprove(true);
	}

	/*
	 * The endpoints can only be accessed by a not logged in user or a user with
	 * the specified role
	 */
	// TODO externalise configuration
	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		oauthServer.tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_TRUSTED')")
				.checkTokenAccess("hasAuthority('ROLE_TRUSTED')");
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.tokenStore(tokenStore()).tokenEnhancer(jwtAccessTokenConverter())
				.authenticationManager(authenticationManager);
	}

	@Bean
	public TokenStore tokenStore() {
		return new JwtTokenStore(jwtAccessTokenConverter());
	}

	// TODO encrypt password
	@Bean
	protected JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter converter = new CustomTokenEnhancer();
		converter.setKeyPair(
				new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "password".toCharArray()).getKeyPair("jwt"));
		converter.setAccessTokenConverter(new customAccessTokenConverter());
		return converter;
	}

	/*
	 * Add custom user principal information to the JWT token and merge user
	 * authorities with OAuth2 client authorities
	 */
	// TODO additional information fields should be get from configuration
	protected static class CustomTokenEnhancer extends JwtAccessTokenConverter {
		@Override
		public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
			User user = (User) authentication.getPrincipal();

			Map<String, Object> info = new LinkedHashMap<String, Object>(accessToken.getAdditionalInformation());

			info.put("email", user.getEmail());

			DefaultOAuth2AccessToken customAccessToken = new DefaultOAuth2AccessToken(accessToken);

			// Get the authorities from the user
			Set<GrantedAuthority> authoritiesSet = new HashSet<>(authentication.getAuthorities());

			// Get the authorities from the OAuth2 client and merge them with
			// the user
			authoritiesSet.addAll(authentication.getOAuth2Request().getAuthorities());

			// Generate String array
			String[] authorities = new String[authoritiesSet.size()];

			int i = 0;
			for (GrantedAuthority authority : authoritiesSet)
				authorities[i++] = authority.getAuthority();

			info.put("authorities", authorities);
			customAccessToken.setAdditionalInformation(info);

			return super.enhance(customAccessToken, authentication);
		}
	}

	/*
	 * Adds an option to set OAuth2 client authorities to the token when there's
	 * a user available
	 */
	protected static class customAccessTokenConverter extends DefaultAccessTokenConverter {

		private UserAuthenticationConverter userTokenConverter = new DefaultUserAuthenticationConverter();

		/*
		 * Flag to indicate if the grant type should be included in the
		 * converted token
		 */
		private boolean includeGrantType;

		// TODO externalise to configuration
		private static final boolean CLIENT_TO_USER_AUTHORITIES = true;

		@Override
		public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
			Map<String, String> parameters = new HashMap<String, String>();

			@SuppressWarnings("unchecked")
			Set<String> scope = new LinkedHashSet<String>(
					map.containsKey(SCOPE) ? (Collection<String>) map.get(SCOPE) : Collections.<String>emptySet());

			Authentication user = userTokenConverter.extractAuthentication(map);

			String clientId = (String) map.get(CLIENT_ID);
			parameters.put(CLIENT_ID, clientId);

			if (includeGrantType && map.containsKey(GRANT_TYPE))
				parameters.put(GRANT_TYPE, (String) map.get(GRANT_TYPE));

			Set<String> resourceIds = new LinkedHashSet<String>(
					map.containsKey(AUD) ? getAudience(map) : Collections.<String>emptySet());

			Collection<? extends GrantedAuthority> authorities = null;
			if ((user == null && map.containsKey(AUTHORITIES))
					|| (map.containsKey(AUTHORITIES) && CLIENT_TO_USER_AUTHORITIES)) {
				@SuppressWarnings("unchecked")
				String[] roles = ((Collection<String>) map.get(AUTHORITIES)).toArray(new String[0]);
				authorities = AuthorityUtils.createAuthorityList(roles);
			}

			return new OAuth2Authentication(
					new OAuth2Request(parameters, clientId, authorities, true, scope, resourceIds, null, null, null),
					user);
		}

		private Collection<String> getAudience(Map<String, ?> map) {
			Object auds = map.get(AUD);
			if (auds instanceof Collection) {
				@SuppressWarnings("unchecked")
				Collection<String> result = (Collection<String>) auds;
				return result;
			}
			return Collections.singleton((String) auds);
		}
	}

	/*
	 * Setup the refresh_token functionality to work with the custom
	 * UserDetailsService
	 */
	@Configuration
	protected static class GlobalAuthenticationManagerConfiguration extends GlobalAuthenticationConfigurerAdapter {
		@Autowired
		private UserDetailsService userDetailsService;

		@Autowired
		private PasswordEncoder passwordEncoder;

		@Override
		public void init(AuthenticationManagerBuilder auth) throws Exception {
			auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
		}
	}
}