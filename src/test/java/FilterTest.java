import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.internal.stubbing.defaultanswers.ReturnsDeepStubs;
import org.rhc.jboss.security.KieServerFilter;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;
import java.util.Enumeration;

/**
 * Created by Nick Balkissoon on 2/16/17.
 */
public class FilterTest {

    @Mock
    private HttpServletRequest req;
    @Mock
    private HttpServletResponse res;
    @Mock
    private FilterChain fc;

    private KieServerFilter ksv;

    @Before
    public void setUp(){
        ksv = new KieServerFilter();
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void FilterYmlLoaderTest(){

        try{
            ksv.init(createFilterConfig());
        }
        catch(Exception e){
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void userHasAdminAccessShouldAccessGrantedTest(){

        Mockito.when(req.getRequestURI()).thenReturn("/kie-server/services/rest/server/containers/myContainer");
        Mockito.when(req.getMethod()).thenReturn("PUT");
        Mockito.when(req.isUserInRole("admin-role")).thenReturn(true);
        Mockito.when(req.isUserInRole("kie-server")).thenReturn(true);

        try{
            ksv.init(createFilterConfig());
            ksv.doFilter(req,res,fc);

            // verify unauthorized error is never sent
            Mockito.verify(res, Mockito.never()).sendError(Mockito.any(Integer.class));
        }
        catch(Exception e){
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void userDoesNotHaveAdminAccessShouldDenyTest(){

        Mockito.when(req.getRequestURI()).thenReturn("/kie-server/services/rest/server/containers/myContainer");
        Mockito.when(req.getMethod()).thenReturn("PUT");
        Mockito.when(req.isUserInRole("kie-server")).thenReturn(true);

        try{
            ksv.init(createFilterConfig());
            ksv.doFilter(req,res,fc);

            Mockito.verify(res, Mockito.atLeastOnce()).sendError(Mockito.any(Integer.class));
        }
        catch(Exception e){
            Assert.fail();
        }
    }

    @Test
    public void userHasGenericAccessSoShouldGrantAccessTest(){

        Mockito.when(req.getRequestURI()).thenReturn("/kie-server/services/rest/server/query/tasks/instances");
        Mockito.when(req.getMethod()).thenReturn("GET");
        Mockito.when(req.isUserInRole("kie-server")).thenReturn(true);

        try{
            ksv.init(createFilterConfig());
            ksv.doFilter(req,res,fc);

            Mockito.verify(res, Mockito.never()).sendError(Mockito.any(Integer.class));
        }
        catch(Exception e){
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void userAdminEndpointNonRestrictedMethodTest(){

        Mockito.when(req.getRequestURI()).thenReturn("/kie-server/services/rest/server/containers/myContainer");
        Mockito.when(req.getMethod()).thenReturn("POST");
        Mockito.when(req.isUserInRole("kie-server")).thenReturn(true);


        try{
            ksv.init(createFilterConfig());
            ksv.doFilter(req,res,fc);

            Mockito.verify(res, Mockito.never()).sendError(Mockito.any(Integer.class));
        }
        catch(Exception e){
            Assert.fail();
        }
    }

    @Test
    public void userHasAnyRolesButNotAllRolesSoShouldDenyTest(){

        Mockito.when(req.getRequestURI()).thenReturn("/kie-server/services/rest/server/containers/myContainer");
        Mockito.when(req.getMethod()).thenReturn("POST");
        Mockito.when(req.isUserInRole("admin-role")).thenReturn(true);

        try{
            ksv.init(createFilterConfig());
            ksv.doFilter(req,res,fc);

            Mockito.verify(res, Mockito.atLeastOnce()).sendError(Mockito.any(Integer.class));
        }
        catch(Exception e){
            Assert.fail();
        }
    }

    @Test
    public void urlNotMatchedShouldDenyAccessTest(){

        Mockito.when(req.getRequestURI()).thenReturn("/some/random/url");
        Mockito.when(req.getMethod()).thenReturn("GET");
        Mockito.when(req.isUserInRole("kie-server")).thenReturn(true);
        Mockito.when(req.isUserInRole("admin-role")).thenReturn(true);

        try{
            ksv.init(createFilterConfig());
            ksv.doFilter(req,res,fc);

            Mockito.verify(res, Mockito.atLeastOnce()).sendError(Mockito.any(Integer.class));
        }
        catch(Exception e){
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void invalidFilePathShouldThrowExceptionTest(){
        try{
            ksv.init(new FilterConfig() {
                public String getFilterName() {
                    return null;
                }

                public ServletContext getServletContext() {
                    return null;
                }

                public String getInitParameter(String s) {
                    if(s.equals("config-location")){
                        return "fake-file.yml";
                    }
                    else{
                        return null;
                    }
                }

                public Enumeration getInitParameterNames() {
                    return null;
                }
            });
            Assert.fail();
        }
        catch(Exception e){

        }
    }

    @Test
    public void emptyConfigParameterShouldThrowExceptionTest(){
        try{
            ksv.init(new FilterConfig() {
                public String getFilterName() {
                    return null;
                }

                public ServletContext getServletContext() {
                    return null;
                }

                public String getInitParameter(String s) {
                    return null;
                }

                public Enumeration getInitParameterNames() {
                    return null;
                }
            });
            Assert.fail();
        }
        catch(Exception e){

        }
    }

    private FilterConfig createFilterConfig() throws IOException{

        FilterConfig mockFC = Mockito.mock(FilterConfig.class, new ReturnsDeepStubs());
        Mockito.when(mockFC.getServletContext().getResourceAsStream("acl.yml")).thenReturn(getClass().getClassLoader().getResource("acl.yml").openStream());
        Mockito.when(mockFC.getInitParameter("config-location")).thenReturn("acl.yml");
        return mockFC;
    }
}
