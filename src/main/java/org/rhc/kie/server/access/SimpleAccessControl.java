package org.rhc.kie.server.access;

import java.util.List;
import java.util.Map;

import javax.ws.rs.container.ContainerRequestContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleAccessControl {
    private static final Logger LOG = LoggerFactory.getLogger(SimpleAccessControl.class);
	private List<Map<String, Object>> accessControlList;

	public SimpleAccessControl(List<Map<String, Object>> yamlList) {
		this.accessControlList = yamlList;
		if (this.accessControlList == null) {
			throw new IllegalArgumentException(
					"Access control list not defined, must start with 'access-control-list'");
		}
	}


    /**
     * Process access control list to determine if user has access to this resource (path and method)
     * @param request
     * @return
     */
    public boolean userHasPermission(ContainerRequestContext ctx){

    	String uri = ctx.getUriInfo().getPath();
    	String method = ctx.getMethod();
    	LOG.info("Checking uri=" + uri + ", method=" + method);
        for(Map<String, Object> rule : accessControlList){
        	LOG.info("-path=" + rule.get("path"));
            if(uri.matches(rule.get("path").toString())){
                if(((List<String>) rule.get("methods")).contains(method)){
                    boolean hasPermission=true;
                    if(rule.get("any")!=null){
                        hasPermission &= userInAnyRoles(ctx, (List<String>) rule.get("any"));
                    }
                    if(rule.get("all")!=null){
                        hasPermission &= userInAllRoles(ctx, (List<String>) rule.get("all"));
                    }
                    return hasPermission;
                } else {
                	LOG.info("No method match in uri=" + uri);
                }
            }
        }
        LOG.info("No rule for uri, defaulting to denied");
        return false;
    }

	
	
    /**
     * Return true if user is in ALL of these roles
     * @param request
     * @param roles
     * @return
     */
    private boolean userInAllRoles(ContainerRequestContext ctx, List<String> roles){
        for(String role : roles){
            if(!ctx.getSecurityContext().isUserInRole(role)){
            	LOG.info("user not in role=" + role + " , from required=" + roles);
                return false;
            }
        }
        LOG.info("user is in all roles=" + roles);
        return true;
    }

    /**
     * Return true if user is in ANY of these roles
     * @param request
     * @param roles
     * @return
     */
    private boolean userInAnyRoles(ContainerRequestContext ctx, List<String> roles){
        for(String role : roles){
            if(ctx.getSecurityContext().isUserInRole(role)){
            	LOG.info("user is in role=" + role + " from any list=" + roles);
                return true;
            }
        }
        LOG.info("user not in any of these roles=" + roles);
        return false;
    }
}
