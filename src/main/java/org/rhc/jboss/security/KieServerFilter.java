package org.rhc.jboss.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

/**
 * Created by Nick Balkissoon on 2/15/17.
 */
public class KieServerFilter implements Filter{

    private static final Logger LOG = LoggerFactory.getLogger(KieServerFilter.class);

    private List<Map<String,Object>> accessControlList;

    public void init(FilterConfig filterConfig) throws ServletException {

        String resourcePath = filterConfig.getInitParameter("config-location");
        if(resourcePath==null){
            throw new ServletException("config-location filter config parameter not set");
        }
        try {
            InputStream inputStream =  filterConfig.getServletContext().getResourceAsStream(resourcePath);
            Object obj = new Yaml().load(inputStream);
            this.accessControlList = ((Map<String, List<Map<String, Object>>>) obj).get("access-control-list");
            if(this.accessControlList==null){
                throw new ServletException("Access control list not defined, must start with 'access-control-list'");
            }
        }
        catch(Exception e){
            throw new ServletException("Error initializing filter, check that access control list file exists and has proper YAML format",e);
        }
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) servletRequest;
        LOG.debug("Request url: "+req.getRequestURI());

        if(!userHasPermission(req)){
            HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            LOG.debug("access denied");
        }
        else{
            LOG.debug("access granted");
        }
        filterChain.doFilter(servletRequest,servletResponse);
    }

    /**
     * Process access control list to determine if user has access to this resource (path and method)
     * @param request
     * @return
     */
    private boolean userHasPermission(HttpServletRequest request){
        for(Map<String, Object> rule : accessControlList){
            if(request.getRequestURI().matches(rule.get("path").toString())){
                if(((List<String>) rule.get("methods")).contains(request.getMethod())){
                    boolean hasPermission=true;
                    if(rule.get("any")!=null){
                        hasPermission &= userInAnyRoles(request, (List<String>) rule.get("any"));
                    }
                    if(rule.get("all")!=null){
                        hasPermission &= userInAllRoles(request, (List<String>) rule.get("all"));
                    }
                    return hasPermission;
                }
            }
        }
        return false;
    }

    /**
     * Return true if user is in ALL of these roles
     * @param request
     * @param roles
     * @return
     */
    private boolean userInAllRoles(HttpServletRequest request, List<String> roles){
        for(String role : roles){
            if(!request.isUserInRole(role)){
                return false;
            }
        }
        return true;
    }

    /**
     * Return true if user is in ANY of these roles
     * @param request
     * @param roles
     * @return
     */
    private boolean userInAnyRoles(HttpServletRequest request, List<String> roles){
        for(String role : roles){
            if(request.isUserInRole(role)){
                return true;
            }
        }
        return false;
    }

    public void destroy() {

    }
}
