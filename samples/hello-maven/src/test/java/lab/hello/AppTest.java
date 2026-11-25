package lab.hello;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.sun.net.httpserver.HttpServer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class AppTest {
    private static HttpServer server;
    private static final HttpClient CLIENT = HttpClient.newHttpClient();

    @BeforeAll
    static void startServer() throws Exception {
        server = App.start(0);
    }

    @AfterAll
    static void stopServer() {
        server.stop(0);
    }

    private static HttpResponse<String> get(String path) throws Exception {
        URI uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path);
        return CLIENT.send(HttpRequest.newBuilder(uri).build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void greetsTheWorldByDefault() {
        assertEquals("Hello, world!", App.greeting(null));
        assertEquals("Hello, world!", App.greeting("  "));
    }

    @Test
    void readsTheNameFromTheQuery() {
        assertEquals("Ada Lovelace", App.queryParameter("x=1&name=Ada%20Lovelace", "name"));
        assertNull(App.queryParameter(null, "name"));
    }

    @Test
    void helloAnswersWithJson() throws Exception {
        HttpResponse<String> response = get("/hello?name=Talos");
        assertEquals(200, response.statusCode());
        assertEquals("application/json", response.headers().firstValue("Content-Type").orElse(""));
        assertEquals("{\"message\":\"Hello, Talos!\"}", response.body());
    }

    @Test
    void healthSaysOk() throws Exception {
        assertEquals("{\"status\":\"ok\"}", get("/health").body());
    }
}
