# OAuth2 JWT using Spring Boot

Simple project on how to setup OAuth2 server and JWT tokens.

## In Short

Use [Spring Security OAuth](https://projects.spring.io/spring-security-oauth/) project. 

First things first. We must generate a KeyStore file. To do that, go your Java install dir and there you'll find a jar named "keytool". Now execute the following:
```
keytool -genkeypair -alias jwt -keyalg RSA -keypass password -keystore jwt.jks -storepass password
```
The command will generate a file called jwt.jks which contains the Public and Private keys.

Now let's export the public key:
```
keytool -list -rfc --keystore jwt.jks | openssl x509 -inform pem -pubkey
```
Copy from (including) "-----BEGIN PUBLIC KEY-----" to (including) "-----END PUBLIC KEY-----" and save it in a file. You'll need this later in your resource servers.

There's a custom [User](src/main/java/com/kristijangeorgiev/spring/boot/oauth2/jwt/model/entity/User.java) class which implements the UserDetails interface and has all the required methods and an additional "email" field;

The [User](src/main/java/com/kristijangeorgiev/spring/boot/oauth2/jwt/model/entity/User.java) has multiple [Roles](src/main/java/com/kristijangeorgiev/spring/boot/oauth2/jwt/model/entity/Role.java) and the [Roles](src/main/java/com/kristijangeorgiev/spring/boot/oauth2/jwt/model/entity/Role.java) have multiple [Permissions](src/main/java/com/kristijangeorgiev/spring/boot/oauth2/jwt/model/entity/Permission.java).

I'm using soft deletes in the database and in order to achieve that in our code, in the above entity classes I use the @Where and @WhereJoinTable annotations. 

Check [spring-boot-jpa-soft-delete](https://github.com/dzinot/spring-boot-jpa-soft-delete) project for more info.

There's the [UserRepository](src/main/java/com/kristijangeorgiev/spring/boot/oauth2/jwt/repository/) in which there are 2 methods, one for finding a [User](src/main/java/com/kristijangeorgiev/spring/boot/oauth2/jwt/model/entity/User.java) entity which is not deleted by username and the other by email.

In order to use our custom [User](src/main/java/com/kristijangeorgiev/spring/boot/oauth2/jwt/model/entity/User.java) object we must provide with a [CustomUserDetailsService](src/main/java/com/kristijangeorgiev/spring/boot/oauth2/jwt/service/) which implements the UserDetailsService. The "loadUserByUsername" method is overriden and set up to work with our logic.

Now we need to somehow configure OAuth2.

To do this, there's an [OAuth2Configuration](src/main/java/com/kristijangeorgiev/spring/boot/oauth2/jwt/configuration/) configuration class where we do the following:
```
@Configuration
@EnableAuthorizationServer
public class OAuth2Configuration extends AuthorizationServerConfigurerAdapter {...
```

There also must be an AuthenticationManager provided:
```
@Autowired
@Qualifier("authenticationManagerBean")
private AuthenticationManager authenticationManager;
```
To set up the OAuth2 clients we override the "configure(ClientDetailsServiceConfigurer clients)" method and define them there. We can also use a database for the clients.

To add additional data to the token you'll need to implement a custom JwtAccessTokenConverter.

Configure JwtAccessTokenConverter to use our KeyPair from jwt.jks, set up the custom JwtAccessTokenConverter and create a TokenStore bean:
```
@Bean
public TokenStore tokenStore() {
	return new JwtTokenStore(jwtAccessTokenConverter());
}

@Bean
protected JwtAccessTokenConverter jwtAccessTokenConverter() {
	JwtAccessTokenConverter converter = new CustomTokenEnhancer();
	converter.setKeyPair(
			new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "password".toCharArray()).getKeyPair("jwt"));
	return converter;
}
```

Next we set the refresh token to use the [CustomUserDetailsService](src/main/java/com/kristijangeorgiev/spring/boot/oauth2/jwt/service/).
```
@Configuration
protected static class GlobalAuthenticationManagerConfiguration extends GlobalAuthenticationConfigurerAdapter {
	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	public void init(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);T
	}
}
```

And least, here's the Spring [WebSecurityConfiguration](src/main/java/com/kristijangeorgiev/spring/boot/oauth2/jwt/configuration/WebSecurityConfiguration.java).

## Installing

Just clone or download the repo and import it as an existing maven project.

You'll also need to set up [Project Lombok](https://projectlombok.org/) or if you don't want to use this library you can remove the associated annotations from the code and write the getters, setters, constructors, etc. by yourself.

## Use
To test it I use [HTTPie](https://httpie.org/). It's similar to CURL.

To get a JWT token use the following command (webapp = the name of the OAuth2 client):
```
http --form POST webapp:@auth:9999/oauth/token grant_type=password username=user password=password
```
To access a resource use:
```
http resource:10000/resource/users 'Authorization: Bearer '$TOKEN
```
To use the refresh token functionality:
```
http --form POST webapp:@auth:9999/oauth/token 'Authorization: Bearer '$TOKEN grant_type=refresh_token refresh_token=$REFRESH_TOKEN
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
