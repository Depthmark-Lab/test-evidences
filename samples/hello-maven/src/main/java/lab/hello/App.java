package lab.hello;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** Hello World web service: GET /hello?name=... and GET /health. */
public final class App {
    private static final ObjectMapper JSON = new ObjectMapper();

    private App() {
    }

    static String greeting(String name) {
        return "Hello, " + (name == null || name.isBlank() ? "world" : name.strip()) + "!";
    }

    static String queryParameter(String rawQuery, String wanted) {
        if (rawQuery == null) {
            return null;
        }
        for (String pair : rawQuery.split("&")) {
            String[] parts = pair.split("=", 2);
            if (parts[0].equals(wanted)) {
                return parts.length == 2 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
            }
        }
        return null;
    }

    /** Starts the server on port, or on a free port when port is 0. */
    public static HttpServer start(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/hello", exchange ->
                reply(exchange, Map.of("message", greeting(queryParameter(exchange.getRequestURI().getRawQuery(), "name")))));
        server.createContext("/health", exchange -> reply(exchange, Map.of("status", "ok")));
        server.start();
        return server;
    }

    private static void reply(HttpExchange exchange, Map<String, String> body) throws IOException {
        byte[] bytes = JSON.writeValueAsBytes(body);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        start(port);
        System.out.println("hello-maven listening on " + port);
    }
}
