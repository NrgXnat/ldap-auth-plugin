/*
 * web: XnatLdapAuthenticationProvider
 * XNAT http://www.xnat.org
 * Copyright (c) 2005-2017, Washington University School of Medicine and Howard Hughes Medical Institute
 * All Rights Reserved
 *
 * Released under the Simplified BSD.
 */

package org.nrg.xnatx.plugins.auth.ldap.provider;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.nrg.xdat.XDAT;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xft.security.UserI;
import org.nrg.xnat.security.provider.ProviderAttributes;
import org.nrg.xnat.security.provider.XnatAuthenticationProvider;
import org.nrg.xnat.security.tokens.XnatAuthenticationToken;
import org.nrg.xnatx.plugins.auth.ldap.XnatLdapUserDetailsMapper;
import org.nrg.xnatx.plugins.auth.ldap.tokens.XnatLdapUsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.stereotype.Component;

import javax.annotation.Nonnull;
import java.util.List;

@Component
@Slf4j
public class XnatLdapAuthenticationProvider extends LdapAuthenticationProvider implements XnatAuthenticationProvider {
    public static final String LDAP_ADDRESS           = "address";
    public static final String LDAP_USERDN            = "userdn";
    public static final String LDAP_PASSWORD          = "password";
    public static final String LDAP_SEARCH_BASE       = "search.base";
    public static final String LDAP_SEARCH_FILTER     = "search.filter";
    public static final String LDAP_VALIDATE_USERNAME = "validate.username";
    public static final String LDAP_VALIDATE_PASSWORD = "validate.password";

    public XnatLdapAuthenticationProvider(final ProviderAttributes attributes, final XdatUserAuthService userAuthService, final SiteConfigPreferences preferences) {
        this(attributes, getLdapAuthenticator(attributes), getContextMapper(attributes, userAuthService, preferences));
    }

    public XnatLdapAuthenticationProvider(final ProviderAttributes attributes, final LdapAuthenticator authenticator, final UserDetailsContextMapper contextMapper) {
        super(authenticator);

        setProviderId(attributes.getProviderId());
        setName(attributes.getName());
        setVisible(attributes.isVisible());
        setAutoEnabled(attributes.isAutoEnabled());
        setAutoVerified(attributes.isAutoVerified());
        if (contextMapper != null) {
            setUserDetailsContextMapper(contextMapper);
        }

        _attributes = attributes;
    }

    @SuppressWarnings("unused")
    protected XnatLdapAuthenticationProvider(final List<ProviderAttributes> attributesList, final XdatUserAuthService userAuthService, final SiteConfigPreferences preferences) {
        this(getPrimaryAttributes(attributesList), userAuthService, preferences);
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        log.debug("Authenticating auth object of type {}: name {}, details {}, is authenticated {}", authentication.getClass(), authentication.getName(), authentication.getDetails(), authentication.isAuthenticated());
        final Authentication processed = super.authenticate(authentication);
        log.debug("Found auth object of type: {} (principal is: {}), is authenticated {}", processed.getClass(), processed.getPrincipal().getClass(), processed.isAuthenticated());

        /*
         * Unlike the other authentication providers, we hafta do this check here. This class is on a different branch
         * of the class hierarchy, and so doesn't inherit additionalAuthenticationChecks.
         */
        final UserDetails userDetails = (UserDetails) processed.getPrincipal();
        log.debug("Found user details with username: {}", userDetails.getUsername());
        if (!UserI.class.isAssignableFrom(userDetails.getClass())) {
            throw new AuthenticationServiceException("User details class is not of a type I know how to handle: " + userDetails.getClass());
        }
        final UserI xdatUserDetails = (UserI) userDetails;
        if (!xdatUserDetails.isEnabled()) {
            log.debug("User details with username {} is not enabled", userDetails.getUsername());
            throw new DisabledException("Attempted login to disabled account: " + xdatUserDetails.getUsername());
        }
        if ((XDAT.getSiteConfigPreferences().getEmailVerification() && !xdatUserDetails.isVerified()) || !xdatUserDetails.isAccountNonLocked()) {
            throw new CredentialsExpiredException("Attempted login to unverified or locked account: " + xdatUserDetails.getUsername());
        }

        return processed;
    }

    @Override
    public String getName() {
        return _displayName;
    }

    public void setName(final String newName) {
        _displayName = newName;
    }

    @Override
    public String getProviderId() {
        return _providerId;
    }

    public void setProviderId(final String providerId) {
        _providerId = providerId;
    }

    @Override
    public String getAuthMethod() {
        return XdatUserAuthService.LDAP;
    }

    /**
     * Indicates whether the provider should be visible to and selectable by users. <b>false</b> usually indicates an
     * internal authentication provider, e.g. token authentication. The LDAP authentication provider is visible by
     * default.
     *
     * @return <b>true</b> if the provider should be visible to and usable by users.
     */
    @Override
    public boolean isVisible() {
        return _visible;
    }

    /**
     * Sets whether the provider should be visible or not as an option for user.
     *
     * @param visible Whether the provider should be visible to and usable by users.
     */
    @Override
    public void setVisible(final boolean visible) {
        _visible = visible;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAutoEnabled() {
        return _autoEnabled;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setAutoEnabled(final boolean autoEnabled) {
        _autoEnabled = autoEnabled;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAutoVerified() {
        return _autoVerified;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setAutoVerified(final boolean autoVerified) {
        _autoVerified = autoVerified;
    }

    /**
     * @deprecated Ordering of authentication providers is set through the {@link SiteConfigPreferences#getEnabledProviders()} property.
     */
    @Deprecated
    @Override
    public int getOrder() {
        log.info("The order property is deprecated and will be removed in a future version of XNAT.");
        return 0;
    }

    /**
     * @deprecated Ordering of authentication providers is set through the {@link SiteConfigPreferences#setEnabledProviders(List)} property.
     */
    @Deprecated
    @Override
    public void setOrder(final int order) {
        log.info("The order property is deprecated and will be removed in a future version of XNAT.");
    }

    @Override
    public XnatAuthenticationToken createToken(final String username, final String password) {
        return new XnatLdapUsernamePasswordAuthenticationToken(username, password, getProviderId());
    }

    /**
     * Indicates whether this provider supports the specified authentication token. The LDAP authentication provider
     * supports tokens that implement or extend the {@link XnatLdapUsernamePasswordAuthenticationToken} class. Note
     * that even that may not be sufficient: {@link XnatAuthenticationProvider} implementations also check the
     * {@link XnatAuthenticationToken#getProviderId() token's provider ID} to ensure that it matches the {@link
     * XnatAuthenticationProvider#getProviderId() provider implementation and configurations' ID}. That check is
     * supported by the {@link #supports(Authentication)} method.
     *
     * @param authentication The authentication token type to test.
     *
     * @return Returns <b>true</b> if this provider supports the submitted token type.
     */
    @Override
    public boolean supports(final Class<?> authentication) {
        return XnatLdapUsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Indicates whether this provider supports the specified authentication token. The LDAP authentication provider
     * supports tokens that implement or extend the {@link XnatLdapUsernamePasswordAuthenticationToken} class but this
     * method may also {@link XnatAuthenticationToken#getProviderId() token's provider ID} to ensure that it matches
     * the {@link XnatAuthenticationProvider#getProviderId() provider implementation and configurations' ID}.
     *
     * @param authentication The authentication token to test.
     *
     * @return Returns <b>true</b> if this provider supports the submitted token.
     */
    @Override
    public boolean supports(final Authentication authentication) {
        return supports(authentication.getClass()) &&
               authentication instanceof XnatLdapUsernamePasswordAuthenticationToken &&
               StringUtils.equals(getProviderId(), ((XnatLdapUsernamePasswordAuthenticationToken) authentication).getProviderId());
    }

    @Override
    public String toString() {
        return getName();
    }

    protected ProviderAttributes getAttributes() {
        return _attributes;
    }

    private static ProviderAttributes getPrimaryAttributes(final List<ProviderAttributes> attributesList) {
        return attributesList.isEmpty() ? NULL_ATTRIBUTES : attributesList.get(0);
    }

    @Nonnull
    private static LdapAuthenticator getLdapAuthenticator(@Nonnull final ProviderAttributes attributes) {
        if (StringUtils.equals(NULL_PROVIDER, attributes.getProviderId())) {
            return authentication -> {
                throw new ProviderNotFoundException("There is no valid LDAP service configured.");
            };
        }

        final String ldapAddress = attributes.getProperty(LDAP_ADDRESS);
        if (StringUtils.isBlank(ldapAddress)) {
            throw new ProviderNotFoundException("No LDAP address specified for provider " + attributes.getProviderId());
        }

        final String  userDn         = attributes.getProperty(LDAP_USERDN);
        final String  password       = attributes.getProperty(LDAP_PASSWORD);
        final boolean hasBindingInfo = StringUtils.isNoneBlank(userDn, password);
        if (!hasBindingInfo && !StringUtils.isAllBlank(userDn, password)) {
            throw new ProviderNotFoundException("If you specify a value for the userdn or password properties for LDAP binding, you must specify a value for *both* properties for provider " + attributes.getProviderId());
        }

        final DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(ldapAddress);
        if (hasBindingInfo) {
            contextSource.setUserDn(userDn);
            contextSource.setPassword(password);
        }
        contextSource.afterPropertiesSet();

        final BindAuthenticator ldapBindAuthenticator = new BindAuthenticator(contextSource);
        ldapBindAuthenticator.setUserSearch(new FilterBasedLdapUserSearch(attributes.getProperty(LDAP_SEARCH_BASE), attributes.getProperty(LDAP_SEARCH_FILTER), contextSource));
        return ldapBindAuthenticator;
    }

    private static UserDetailsContextMapper getContextMapper(final ProviderAttributes attributes, final XdatUserAuthService userAuthService, final SiteConfigPreferences preferences) {
        if (StringUtils.equals(NULL_PROVIDER, attributes.getProviderId())) {
            return null;
        }
        return new XnatLdapUserDetailsMapper(attributes.getProviderId(), userAuthService, preferences, attributes.getProperties());
    }

    private static final String             NULL_PROVIDER   = "null-ldap-provider";
    private static final ProviderAttributes NULL_ATTRIBUTES = new ProviderAttributes(NULL_PROVIDER, XdatUserAuthService.LDAP, NULL_PROVIDER, false, false, false, null);

    private final ProviderAttributes _attributes;

    private String  _displayName = "";
    private String  _providerId  = "";
    private boolean _visible     = true;
    private boolean _autoEnabled;
    private boolean _autoVerified;
}
