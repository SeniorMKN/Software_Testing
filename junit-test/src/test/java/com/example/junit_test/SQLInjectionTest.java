package com.example.junit_test;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Response;
import org.apache.http.entity.ContentType;
import org.apache.http.message.BasicHeader;

public class SQLInjectionTest {
	
	// Headers
    private BasicHeader hostHeader;
    private BasicHeader contentTypeHeader;
    private BasicHeader acceptHeader;
    private BasicHeader userAgentHeader;
    private BasicHeader refererHeader;

	@Before
    public void setUpHeaders() {
        // Set up headers
        hostHeader = new BasicHeader("Host", "localhost");
        contentTypeHeader = new BasicHeader("Content-Type", "application/x-www-form-urlencoded");
        acceptHeader = new BasicHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
        userAgentHeader = new BasicHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36");
        refererHeader = new BasicHeader("Referer", "http://localhost:3000/login");
    }
	
	@Before
    public void waitBetweenTests() throws InterruptedException {
        Thread.sleep(2000); // Wait for 1 second (1000 milliseconds)
    }
	
	
    
	@Test
    public void testLoginOK() throws Exception {
        // Payload per inizializzare l'SQL Injection
        String username = "user1";
        String password = "password1";

        // Invio di una POST request al server mock con il payload creato sopra
        Response response = Request.Post("http://localhost:3000/login")
                .addHeader(hostHeader)
                .addHeader(contentTypeHeader)
                .addHeader(acceptHeader)
                .addHeader(userAgentHeader)
                .addHeader(refererHeader)
                .bodyString("username=" + username + "&password=" + password, ContentType.APPLICATION_FORM_URLENCODED)
                .execute();

        // Si controlla se la response contiene "Login successful"
        assertTrue(response.returnContent().asString().contains("Login successful"));
    }
    
	@Test
	public void testLoginWrongCreds() throws Exception {
	    // Payload to initialize the SQL Injection
	    String username = "usernonexistent";
	    String password = "password1";

	    // Sending a POST request to the mock server with the payload created above
	    Response response = Request.Post("http://localhost:3000/login")
	            .addHeader(hostHeader)
	            .addHeader(contentTypeHeader)
	            .addHeader(acceptHeader)
	            .addHeader(userAgentHeader)
	            .addHeader(refererHeader)
	            .bodyString("username=" + username + "&password=" + password, ContentType.APPLICATION_FORM_URLENCODED)
	            .execute();

	    // Assert that the response code is 401 (Unauthorized)
	    assertEquals(401, response.returnResponse().getStatusLine().getStatusCode());
	}
	
	@Test
    public void testSQLBasicInjection() throws Exception {
        // Payload per inizializzare l'SQL Injection
        String username = "user' OR 1=1--";
        String password = "password1";

        // Invio di una POST request al server mock con il payload creato sopra
        Response response = Request.Post("http://localhost:3000/login")
                .addHeader(hostHeader)
                .addHeader(contentTypeHeader)
                .addHeader(acceptHeader)
                .addHeader(userAgentHeader)
                .addHeader(refererHeader)
                .bodyString("username=" + username + "&password=" + password, ContentType.APPLICATION_FORM_URLENCODED)
                .execute();

        // Si controlla se la response contiene "Nice attempt. SQL Injection Detected"
        assertTrue(response.returnContent().asString().contains("Nice attempt. SQL Injection Detected"));
    }
	
	@Test
    public void testSQLBlindInjection() throws Exception {
        // Payload per inizializzare l'SQL Injection
        String username = "user' OR 1=1--";
        String password = "password1";

        // Invio di una POST request al server mock con il payload creato sopra
        Response response = Request.Post("http://localhost:3000/login")
                .addHeader(hostHeader)
                .addHeader(contentTypeHeader)
                .addHeader(acceptHeader)
                .addHeader(userAgentHeader)
                .addHeader(refererHeader)
                .bodyString("username=" + username + "&password=" + password, ContentType.APPLICATION_FORM_URLENCODED)
                .execute();

        // Si controlla se la response contiene "Nice attempt. SQL Injection Detected"
        assertTrue(response.returnContent().asString().contains("Nice attempt. SQL Injection Detected"));
    }
	
	@Test
    public void testSQLInjectionVersionDetection() throws Exception {
        // Payload per inizializzare l'SQL Injection
        String username = "user' UNION SELECT sqlite_version()--";
        String password = "password1";

        // Invio di una POST request al server mock con il payload creato sopra
        Response response = Request.Post("http://localhost:3000/login")
                .addHeader(hostHeader)
                .addHeader(contentTypeHeader)
                .addHeader(acceptHeader)
                .addHeader(userAgentHeader)
                .addHeader(refererHeader)
                .bodyString("username=" + username + "&password=" + password, ContentType.APPLICATION_FORM_URLENCODED)
                .execute();

        // Si controlla se la response contiene "Nice attempt. SQL Injection Detected"
        assertTrue(response.returnContent().asString().contains("Nice attempt. SQL Injection Detected"));
    }
	
	@Test
    public void testSQLInjectionNumOfColumns() throws Exception {
        // Payload per inizializzare l'SQL Injection
        String username = "user' UNION SELECT NULL--";
        String password = "password1";

        // Invio di una POST request al server mock con il payload creato sopra
        Response response = Request.Post("http://localhost:3000/login")
                .addHeader(hostHeader)
                .addHeader(contentTypeHeader)
                .addHeader(acceptHeader)
                .addHeader(userAgentHeader)
                .addHeader(refererHeader)
                .bodyString("username=" + username + "&password=" + password, ContentType.APPLICATION_FORM_URLENCODED)
                .execute();

        // Si controlla se la response contiene "Nice attempt. SQL Injection Detected"
        assertTrue(response.returnContent().asString().contains("Nice attempt. SQL Injection Detected"));
    }
	
	@Test
    public void testSQLInjectionListTableNames() throws Exception {
        // Payload per inizializzare l'SQL Injection
        String username = "user' UNION SELECT tbl_name FROM sqlite_master--";
        String password = "password1";

        // Invio di una POST request al server mock con il payload creato sopra
        Response response = Request.Post("http://localhost:3000/login")
                .addHeader(hostHeader)
                .addHeader(contentTypeHeader)
                .addHeader(acceptHeader)
                .addHeader(userAgentHeader)
                .addHeader(refererHeader)
                .bodyString("username=" + username + "&password=" + password, ContentType.APPLICATION_FORM_URLENCODED)
                .execute();

        // Si controlla se la response contiene "Nice attempt. SQL Injection Detected"
        assertTrue(response.returnContent().asString().contains("Nice attempt. SQL Injection Detected"));
    }
	
	@Test
    public void testSQLInjectionListColumnNames() throws Exception {
        // Payload per inizializzare l'SQL Injection
        String username = "user' UNION SELECT tbl_name FROM sqlite_master--";
        String password = "password1";

        // Invio di una POST request al server mock con il payload creato sopra
        Response response = Request.Post("http://localhost:3000/login")
                .addHeader(hostHeader)
                .addHeader(contentTypeHeader)
                .addHeader(acceptHeader)
                .addHeader(userAgentHeader)
                .addHeader(refererHeader)
                .bodyString("username=" + username + "&password=" + password, ContentType.APPLICATION_FORM_URLENCODED)
                .execute();

        // Si controlla se la response contiene "Nice attempt. SQL Injection Detected"
        assertTrue(response.returnContent().asString().contains("Nice attempt. SQL Injection Detected"));
    }
	
	@Test
    public void testSQLInjectionDumpingTables() throws Exception {
        // Payload per inizializzare l'SQL Injection
        String username = "user' UNION SELECT table_name FROM table_name--";
        String password = "password1";

        // Invio di una POST request al server mock con il payload creato sopra
        Response response = Request.Post("http://localhost:3000/login")
                .addHeader(hostHeader)
                .addHeader(contentTypeHeader)
                .addHeader(acceptHeader)
                .addHeader(userAgentHeader)
                .addHeader(refererHeader)
                .bodyString("username=" + username + "&password=" + password, ContentType.APPLICATION_FORM_URLENCODED)
                .execute();

        // Si controlla se la response contiene "Nice attempt. SQL Injection Detected"
        assertTrue(response.returnContent().asString().contains("Nice attempt. SQL Injection Detected"));
    }
	
	@Test
    public void testSQLInjectionCommandInjection() throws Exception {
        // Payload per inizializzare l'SQL Injection
        String username = "user' UNION SELECT NULL,sys_eval('whoami') FROM users-- -";
        String password = "password1";

        // Invio di una POST request al server mock con il payload creato sopra
        Response response = Request.Post("http://localhost:3000/login")
                .addHeader(hostHeader)
                .addHeader(contentTypeHeader)
                .addHeader(acceptHeader)
                .addHeader(userAgentHeader)
                .addHeader(refererHeader)
                .bodyString("username=" + username + "&password=" + password, ContentType.APPLICATION_FORM_URLENCODED)
                .execute();

        // Si controlla se la response contiene "Nice attempt. SQL Injection Detected"
        assertTrue(response.returnContent().asString().contains("Nice attempt. SQL Injection Detected"));
    }
}
