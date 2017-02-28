# KieServer Access Control Extension
This KieServer extension gives you more granular security controls over the REST API. It also allows you to include access control list files in your KJARs for hot deployment. 
### How to use:
###### 1) Build the project
```sh
$ mvn clean install
```
###### 2) Copy built jar and dependencies into $EAP_HOME/standalone/deployments/kie-server.war/WEB-INF/lib
```sh
$ cp KieServerFilter/target/kie-server-filter-1.0.0.jar $EAP_HOME/standalone/deployments/kie-server.war/WEB-INF/lib/
```
```sh
$ cp KieServerFilter/target/lib/* $EAP_HOME/standalone/deployments/kie-server.war/WEB-INF/lib/
```
###### 3) Create your access control list.  This is a YAML file that specifies access to resources.  Here is an example:
```
access-control-list:
  - path: \/server\/containers.*
    methods:
      - PUT
    all:
      - kie-server
    any:
      - admin-role
  - path: \/server.*
    methods:
      - POST
      - GET
      - PUT
      - DELETE
    all:
      - kie-server
```
* path - regex expression to match the url extension
* method - http methods at this endpoint being restrited to these roles
* any - a user must have any of these roles
* all - a user must have all of these roles
* NOTE: if both any and all are specified, then a user must satisfy both.

###### 4) Copy `acl.yml` to your JBoss configuration folder (`$JBOSS_HOME/standalone/configuration`)
###### 5) Restart KieServer

###### 6) KJAR specific access control list
If you include an `acl.yml` file into your KJAR under the `META-INF` folder it will be picked up and used instead of the system access control file for any operations on that KieContainer. The syntax is the same as the system access control list.
