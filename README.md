# KieServer Access Control Filter
This custom servlet filter gives you more granular security controls over the KieServer's REST API.
### How to use:
1) Build the project
```sh
$ mvn clean install
```
2) Copy built jar and dependencies into $EAP_HOME/standalone/deployments/kie-server.war/WEB-INF/lib
```sh
$ cp KieServerFilter/target/kie-server-filter-1.0.0.jar $EAP_HOME/standalone/deployments/kie-server.war/WEB-INF/lib/
```
```sh
$ cp KieServerFilter/target/lib/* $EAP_HOME/standalone/deployments/kie-server.war/WEB-INF/lib/
```
3) Create your access control list.  This is a YAML file that specifies access to resources.  Here is an example:
```
access-control-list:
  - path: \/kie-server\/services\/rest\/server\/containers\/.*
    methods:
      - PUT
    all:
      - kie-server
    any:
      - admin-role
  - path: \/kie-server\/services\/rest\/server\/.*
    methods:
      - POST
      - GET
      - PUT
      - DELETE
    all:
      - kie-server
```
path - regex expression to match the url extension
method - http methods at this endpoint being restrited to these roles
any - a user must have any of these roles
all - a user must have all of these roles
NOTE: if both any and all are specified, then a user must satisfy both.
4) Configure filter and point to access control list YAML file
```  <filter>
    <filter-name>KieServerFilter</filter-name>
    <filter-class>org.rhc.svm.KieServerFilter</filter-class>
    <init-param>
      <param-name>config-location</param-name>
      <param-value>/WEB-INF/acl.yml</param-value>
    </init-param>
  </filter>

  <filter-mapping>
      <filter-name>KieServerFilter</filter-name>
      <url-pattern>/services/rest/*</url-pattern>
  </filter-mapping>
  ```
5) Restart KieServer