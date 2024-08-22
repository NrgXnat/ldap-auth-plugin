/*
 * web: XnatLdapUserDetailsMapper
 * XNAT http://www.xnat.org
 * Copyright (c) 2005-2017, Washington University School of Medicine and Howard Hughes Medical Institute
 * All Rights Reserved
 *
 * Released under the Simplified BSD.
 */

package org.nrg.xnatx.plugins.auth.ldap;

import com.google.common.collect.ImmutableMap;
import lombok.extern.slf4j.Slf4j;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xft.security.UserI;
import org.nrg.xnat.security.exceptions.NewAutoAccountNotAutoEnabledException;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Map;
import java.util.Properties;

@Component
@Slf4j
public class XnatLdapUserDetailsMapper extends LdapUserDetailsMapper implements LdapAuthoritiesPopulator {
    public XnatLdapUserDetailsMapper(final String providerId, final XdatUserAuthService userAuthService, final SiteConfigPreferences preferences, final Properties properties) {
        super();
        Assert.hasText(providerId, "You must provide an authentication provider ID.");
        Assert.notEmpty(properties, "You must provide the authentication provider properties.");
        log.info("Creating user details mapper with the provider ID [{}] and {}", providerId, (properties != null && properties.size() > 0 ? "mapping properties: " + properties.toString() : "default mapping properties"));

        _providerId = providerId;
        _userAuthService = userAuthService;
        _preferences = preferences;

        _properties = new Properties();
        if (properties == null || properties.size() == 0) {
            _properties.putAll(DEFAULT_PROPERTIES);
        } else {
            _properties.putAll(properties);
            if (!_properties.containsKey(PROPERTY_EMAIL)) {
                _properties.setProperty(PROPERTY_EMAIL, "mail");
            }
            if (!_properties.containsKey(PROPERTY_FIRST)) {
                _properties.setProperty(PROPERTY_FIRST, "givenName");
            }
            if (!_properties.containsKey(PROPERTY_LAST)) {
                _properties.setProperty(PROPERTY_LAST, "sn");
            }
        }
        if (!_properties.containsKey(PROPERTY_UID)) {
            _properties.setProperty(PROPERTY_UID, "uid");
        }
        if (!_properties.containsKey(PROPERTY_COMMONNAME)) {
            _properties.setProperty(PROPERTY_COMMONNAME, "cn");
        }
    }

    @Override
    public UserI mapUserFromContext(final DirContextOperations context, final String usernameAsOnFormEntry, final Collection<? extends GrantedAuthority> authorities) {
        final String adUsernameUID = (String) context.getObjectAttribute(_properties.getProperty(PROPERTY_UID));
        final String email     = (String) context.getObjectAttribute(_properties.getProperty(PROPERTY_EMAIL));
        final String givenName = (String) context.getObjectAttribute(_properties.getProperty(PROPERTY_FIRST));
        final String lastName  = (String) context.getObjectAttribute(_properties.getProperty(PROPERTY_LAST));
        final String commonName = (String) context.getObjectAttribute(_properties.getProperty(PROPERTY_COMMONNAME));
        String firstName = givenName;
        if (commonName != null && (givenName == null || givenName.isEmpty())) {
            firstName = commonName;
            int index = commonName.lastIndexOf(" " + lastName);
            if (index > 0) {
                firstName = commonName.substring(0, index).trim();
            }
        }
        final UserI userDetails = _userAuthService.getUserDetailsByNameAndAuth(adUsernameUID, XdatUserAuthService.LDAP, _providerId, email, lastName, firstName);

        try {
            final UserI xdatUser = Users.getUser(userDetails.getUsername());
            if ((!_preferences.getEmailVerification() || xdatUser.isVerified()) && userDetails.getAuthorization().isEnabled()) {
                return userDetails;
            } else {
                throw new NewAutoAccountNotAutoEnabledException(NOT_AUTO_ENABLED_MESSAGE, userDetails);
            }
        } catch (Exception e) {
            throw new NewAutoAccountNotAutoEnabledException(NOT_AUTO_ENABLED_MESSAGE, userDetails);
        }
    }

    @Override
    public void mapUserToContext(final UserDetails user, final DirContextAdapter contextAdapter) {
        throw new UnsupportedOperationException("LdapUserDetailsMapper only supports reading from a context.");
    }

    @Override
    public Collection<GrantedAuthority> getGrantedAuthorities(final DirContextOperations userData, final String username) {
        return Users.AUTHORITIES_USER;
    }

    private static final String NOT_AUTO_ENABLED_MESSAGE = "Successful first-time authentication via LDAP, but accounts are not auto.enabled or email verification required.  We'll treat this the same as we would a user registration";

    private static final String              PROPERTY_PREFIX           = "attributes.";
    private static final String              PROPERTY_EMAIL            = PROPERTY_PREFIX + "email";
    private static final String              PROPERTY_FIRST            = PROPERTY_PREFIX + "firstname";
    private static final String              PROPERTY_LAST             = PROPERTY_PREFIX + "lastname";
    private static final String              PROPERTY_UID              = PROPERTY_PREFIX + "uid";
    private static final String              PROPERTY_COMMONNAME       = PROPERTY_PREFIX + "cn";

    private static final Map<String, String> DEFAULT_PROPERTIES = ImmutableMap.of(PROPERTY_EMAIL, "mail", PROPERTY_FIRST, "givenName", PROPERTY_LAST, "sn", PROPERTY_UID, "uid", PROPERTY_COMMONNAME, "cn");

    private final String                _providerId;
    private final XdatUserAuthService   _userAuthService;
    private final SiteConfigPreferences _preferences;
    private final Properties            _properties;
}
