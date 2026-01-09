# XNAT LDAP Authentication Provider Plugin #

This is the XNAT Authentication Provider Plugin. It replaces previous support for LDAP inside of XNAT itself.

## Building ##

**Note:** Once this plugin is released, the preferred way to get the plugin is by downloading it from the [XNAT Marketplace](https://marketplace.xnat.org).

To build the XNAT LDAP authentication provider plugin:

1. If you haven't already, clone [this repository](https://bitbucket.org/xnatx/xnat-ldap-auth-plugin.git) and cd to the newly cloned folder.

1. Build the plugin:

    ```bash
    ./gradlew clean jar 
    ```
    
    On Windows, you can use the batch file:
    
    ```bash
    gradlew.bat clean jar
    ```
    
    This should build the plugin in the file **build/libs/xnat-ldap-auth-plugin-1.0.0-SNAPSHOT.jar** 
    (the version may differ based on updates to the code).
    
1. Copy the plugin jar to your plugins folder: 

    ```bash
    cp build/libs/xnat-ldap-auth-plugin-1.0.0-SNAPSHOT.jar /data/xnat/home/plugins
    ```

## Deploying the Plugin ##

Deploying the XNAT LDAP authentication provider plugin requires the following steps:

1. Copy the plugin jar to the **plugins** folder for your XNAT installation. The location of the 
**plugins** folder varies based on how and where you have installed your XNAT. If you are running 
a virtual machine created through the [XNAT Vagrant project](https://bitbucket/xnatdev/xnat-vagrant.git),
you can copy the plugin to the appropriate configuration folder and then copy it within the VM from 
**/vagrant** to **/data/xnat/home/plugins**.

1. Restart the Tomcat server. Your new plugin will be available as soon as the restart and initialization process is completed.

## Configuring LDAP Providers ##

XNAT searches for authentication server configurations by looking for files whose names match the pattern:

`*-provider.properties`
    
It looks in the following locations:

* On the classpath in the folder **META-INF/xnat/auth**
* In a folder named **auth** under the XNAT home folder (usually configured with the **xnat.home** system variable)

This plugin uses any entries located in any of those properties files where the property **auth.method** is set to [XdatUserAuthService.LDAP](https://bitbucket.org/xnatdev/xdat/src/master/src/main/java/org/nrg/xdat/services/XdatUserAuthService.java#XdatUserAuthService.java-21)
(which is just "ldap") to configure one or more LDAP repositories.

You can use the files [ldap1-provider-sample.properties](src/main/resources/ldap1-provider-sample.properties) and [ldap2-provider-sample.properties](src/main/resources/ldap2-provider-sample.properties)
as starting points for your own provider configurations. Just copy the files, omitting the "-sample" in the name. The values specified in those file have been tested 
and verified against two separate LDAP configurations:
 
* The configuration in [ldap1-provider-sample.properties](src/main/resources/ldap1-provider-sample.properties) works with the default configuration of the [XNAT LDAP Server Vagrant project](https://bitbucket.org/xnatdev/xnat-ldap-vagrant).
The only caveat is that you'll need to map the server name **ldap.xnat.org** to the IP address for that VM (by default, 10.1.1.22) to the hosts file on any machines 
that need to connect to the server (alternatively you can replace **ldap.xnat.org** with the IP address).

* The configuration in [ldap2-provider-sample.properties](src/main/resources/ldap2-provider-sample.properties) works with the LDAP test server provided by [Forum Systems](https://www.forumsys.com) and
[described in more detail here](https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/). 

The various configuration options for the XNAT LDAP authentication provider plugin are described below. Note that properties that are marked with an asterisk (like
this<sup>*</sup>) are default provider options and not specific to the LDAP plugin.

> **Important note when upgrading from earlier versions of XNAT:** Previous versions of XNAT uses the properties **id** and **type** to specify the provider ID and type of authentication. These properties are no longer 
> supported: **id** is replaced by **provider.id** and **type** by **auth.method**.

| Property                  | Description                                                                                                                                                                     |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| name<sup>*</sup>          | Defines a human-readable name for the provider. This should be unique on the system.                                                                                            |
| provider.id<sup>*</sup>   | Defines the ID for this provider. This _must_ be unique on the system. This value is to enable the provider in XNAT.                                                            |
| auth.method<sup>*</sup>   | Indicates the method to be used for authentication. This basically maps directly to the provider implementation. For the LDAP authentication provider, this is always **ldap**. |
| auto.enabled<sup>*</sup>  | Indicates whether user accounts that authenticate using the provider definition should automatically be enabled on the system. If true, users can use the system right away. If false, an administrator needs to review and enable the account manually before the user can access the system. |
| auto.verified<sup>*</sup> | Indicates whether user accounts that authenticate using the provider definition should automatically be verified on the system. If false, users must receive an email from the system and click the provided link before they can access the system.  |
| address                   | Specifies the address of the LDAP server for the provider definition. This should include the protocol (**ldap** or **ldaps**), the server address, and the port (only required if non-standard). |
| userdn                    | Contains the user DN for the authenticating account. |
| password                  | Contains the password for the authenticating account.  |
| search.base               | Indicates the top level to search in the LDAP structure for user account entries. |
| search.filter             | Indicates the format for the actual user account criteria in the LDAP query. |
| validate.username         | _For testing purposes only_. This is a regular user name on the LDAP server. This is used by the [ValidateLdap.groovy](src/main/resources/ValidateLdap.groovy) script to verify that the combination of address, user DN, password, and search base and filter are configured properly. |
| validate.password         | _For testing purposes only_. This is the password corresponding to the user name above. |

## Enabling LDAP Providers ##

Earlier versions of XNAT used a value set in a properties file to determine which configured providers should actually be enabled at run time. XNAT 1.7.5 has moved this to the **Security** section of
the **Site Administration** page. The specific setting is labeled **Enabled Authentication Providers**. All authentication providers that should be active and enabled should be specified by the 
**provider.id** value, with each provider separated by a comma. These changes go into effect as soon as you click the **Save** button, i.e. no Tomcat restart is required.

This is also scriptable through the REST API. The currently enabled providers can be retrieved through the REST path **/xapi/siteConfig/enabledProviders**. The enabled providers can be set by POSTing
a JSON list of the provider IDs. The code below queries and sets the enabled providers setting:

```bash 
$ http --session=admin --body --verify=no https://xnatdev.xnat.org/xapi/siteConfig/enabledProviders
HTTP/1.1 200 OK
[
    "localdb"
]

$ http --session=admin --body --verify=no POST https://xnatdev.xnat.org/xapi/siteConfig/enabledProviders <<< '["localdb", "xnatldap"]'
HTTP/1.1 200 OK

$ http --session=admin --body --verify=no https://xnatdev.xnat.org/xapi/siteConfig/enabledProviders
HTTP/1.1 200 OK
[
    "localdb",
    "xnatldap"
]

$ http --session=admin --verify=no POST https://xnatdev.xnat.org/xapi/siteConfig/enabledProviders <<< '["localdb"]'
HTTP/1.1 200 OK

$ http --session=admin --body --verify=no https://xnatdev.xnat.org/xapi/siteConfig/enabledProviders
[
    "localdb"
] 
```

## Testing Configurations ##

You can test provider properties against an LDAP server using the [ValidateLdap.groovy](src/main/resources/ValidateLdap.groovy) script (running this script requires
having [Groovy][https://groovy-lang.org] installed and the plugin jar available). To run the test script, use following syntax:

```bash
groovy 'jar:file:path/to/ldap-auth-plugin-1.0.0-SNAPSHOT.jar!/ValidateLdap.groovy' [properties-file]
```

On Linux or OS X, the "'" characters are required to prevent the "!" character from being detected by the shell interpreter. You can prefix the "!"
with a backslash ("\\") instead.

If you don't specify a properties file, the validate script will use the same default values as specified in **ldap1-provider-sample.properties**, along with 
the default user **asmith** and password **password**. You can specify a properties file that only overrides a few properties in the sample configuration as 
well, otherwise inheriting the values for the default properties. The username and password properties aren't normally configured in the provider properties
definition but can be specified for the LDAP validator with the properties **user** and **pass** (note that password is already used in the provider 
definition, but indicates the password for the LDAP binding account and stays the same regardless of the specific username and password being validated). 

The output from a successful validation looks something like this:

```bash
$ groovy 'jar:file:build/libs/ldap-auth-plugin-1.0.0-SNAPSHOT.jar!/ValidateLdap.groovy'
Dec 06, 2017 3:18:45 PM org.springframework.security.ldap.DefaultSpringSecurityContextSource <init>
INFO:  URL 'ldap://ldap.xnat.org', root DN is ''
User asmith authentication state: true
```