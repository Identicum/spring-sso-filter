# spring-sso-filter
This is a sample Spring Filter to intercept requests with id_tokens to creates sessions. 
It was developed to test [Google One-Tap](https://developers.google.com/identity/one-tap/web) callbacks.

The filter must be inserted before the `OAuth2LoginAuthenticationFilter` to prevent OAuth redirects:

```java
@Override
public void configure(HttpSecurity http) throws Exception {
    http.csrf().disable()
            .addFilterBefore(new OidcSsoFilter(clientRegistrationRepository), OAuth2LoginAuthenticationFilter.class)
            .authorizeRequests(authorizeRequest -> authorizeRequest
                    .antMatchers("/", "/webjars/**", "/css/**", "/favicon.*", "/imgs/**").permitAll()
                    .anyRequest().authenticated())
            .oauth2Login(oauthLogin -> oauthLogin
                    .userInfoEndpoint()
                    .oidcUserService(new OidcUserService()));
}
```

## Configure
In order to deploy the demo application, you need to configure a number of parameters in the [configuration file](src/main/resources/application.yml).
Some of those parameters are endpoint URLs of your IdP.
Additionally, you need to create your client application in your IdP and configure the client_id and client_secret. 
The redirect_uri sent by the application is:

    <protocol>://<server-name>:8080/login/oauth2/code/<provider-name> 

The application.yml configuration file requires a name for the OIDC provider. This name is used in the redirect_uri:
```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          PROVIDER_NAME:
            client-id: client-id
            client-secret: client-secret
        provider:
          PROVIDER_NAME:
            user-name-attribute: name
```

## Build
The build process to compile the source code is based in Apache Maven.
To create the war file, go to the folder where you cloned the repository and run:

    mvn clean package

## Run

To build and run the code, in the folder where you cloned the repository, run:

    mvn spring-boot:run

## Test

1. Open a browser login to any Google services
2. Then go to

    http://localhost:8080/
    
3. Click "Continue as XXXXX" in the Google floating modal
4. User should be redirected to

    http://localhost:8080/user