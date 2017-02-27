package org.rhc.kie.server.access;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.kie.server.services.api.KieServerApplicationComponentsService;
import org.kie.server.services.api.KieServerRegistry;
import org.kie.server.services.api.SupportedTransports;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KieServerAccessControlExtension implements KieServerApplicationComponentsService {
	private static final Logger LOG = LoggerFactory.getLogger(KieServerAccessControlExtension.class);
	public static final String OWNER_EXTENSION_NAME = "jBPM";

	public Collection<Object> getAppComponents(String extension, SupportedTransports type, Object... services) {
		LOG.info("******IN KSACE, " + extension);
		// skip calls from other than owning extension
		if (!OWNER_EXTENSION_NAME.equals(extension)) {
			return Collections.emptyList();
		}

		KieServerRegistry context = null;

		for (Object object : services) {
			if (KieServerRegistry.class.isAssignableFrom(object.getClass())) {
				context = (KieServerRegistry) object;
				LOG.info("***Found context");
			}
		}

		List<Object> components = new ArrayList<Object>(1);
		if (SupportedTransports.REST.equals(type)) {
			components.add(new KieServerAccessFilter(context));
		}

		return components;
	}

}
