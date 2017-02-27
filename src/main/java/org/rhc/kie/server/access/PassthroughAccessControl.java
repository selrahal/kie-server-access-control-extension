package org.rhc.kie.server.access;

import java.util.Collections;

import javax.ws.rs.container.ContainerRequestContext;

public class PassthroughAccessControl extends SimpleAccessControl {
	public PassthroughAccessControl() {
		super(Collections.EMPTY_LIST);
	}

	public boolean userHasPermission(ContainerRequestContext ctx) {
		return true;
	}
}
