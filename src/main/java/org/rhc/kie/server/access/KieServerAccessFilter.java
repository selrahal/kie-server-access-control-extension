package org.rhc.kie.server.access;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import org.kie.server.services.api.KieContainerInstance;
import org.kie.server.services.api.KieServerRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

public class KieServerAccessFilter implements ContainerRequestFilter {
	private static final Logger LOG = LoggerFactory.getLogger(KieServerAccessFilter.class);
	
	protected KieServerRegistry registry;
	protected SimpleAccessControl defaultAccessControl;
	public Pattern containerPathRegex = Pattern.compile("\\/server\\/containers\\/(.*)");

	@Context
	private HttpServletRequest servletRequest;
	
	public KieServerAccessFilter(KieServerRegistry registry) {
		this.registry = registry;
		String fileName = System.getProperty("jboss.server.config.dir") + "/acl.yml";
		try {
			this.defaultAccessControl = getAclFromResource(new FileInputStream(fileName), new PassthroughAccessControl());
		} catch (FileNotFoundException e) {
			LOG.warn("File not found, defaulting to pass through", e);
			this.defaultAccessControl = new PassthroughAccessControl();
		}
	}

	public void filter(ContainerRequestContext ctx) {
		
		String path = ctx.getUriInfo().getPath();
		LOG.info("************* IN ACL ");
		

		boolean allowed = false;
		Matcher m = containerPathRegex.matcher(path);
		if (m.matches()) {
			String containerId = m.group(1);
			if (containerId.contains("/")) {
				containerId = containerId.split("/")[0];
			}
			LOG.info(" ID: " + containerId);

			KieContainerInstance kieContainerInstance = registry.getContainer(containerId);
			if (kieContainerInstance != null) {
				SimpleAccessControl kjarAcl = getAclFromResource(kieContainerInstance.getKieContainer().getClassLoader()
					.getResourceAsStream("META-INF/acl.yml"), defaultAccessControl);
				allowed = kjarAcl.userHasPermission(ctx);
			} else {
				LOG.info("Container not deployed yet, using system permissions");
				allowed = defaultAccessControl.userHasPermission(ctx);
			}
		} else {
			// no KieContainerID
			allowed = defaultAccessControl.userHasPermission(ctx);
		}

		if (!allowed) {
			ctx.abortWith(Response.status(Response.Status.UNAUTHORIZED).entity("User is not authorized!").build());
		}

	}

	private SimpleAccessControl getAclFromResource(InputStream inputStream, SimpleAccessControl fallback) {
		SimpleAccessControl toReturn;
		try {
			Object obj = new Yaml().load(inputStream);
			List<Map<String, Object>> yamlList = ((Map<String, List<Map<String, Object>>>) obj)
					.get("access-control-list");
			if (yamlList == null) {
				LOG.warn("No access-control-list found in file, falling back to passthrough");
				toReturn = fallback;
			} else {
				toReturn = new SimpleAccessControl(yamlList);
			}
		} catch (Exception e) {
			LOG.warn("Access control list not defined, falling back to passthrough");
			toReturn = fallback;
		}
		return toReturn;
	}

}