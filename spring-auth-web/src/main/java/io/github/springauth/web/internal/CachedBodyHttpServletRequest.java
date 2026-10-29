package io.github.springauth.web.internal;

import java.io.ByteArrayInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.springframework.util.StreamUtils;

/**
 * Buffers the request body so it can be read twice.
 *
 * <p>A servlet input stream is consumable once. Verifying an HMAC over the body means reading it in
 * a filter, which would leave the controller with an empty stream. This wrapper reads it once,
 * keeps the bytes, and hands out a fresh stream on every call.
 *
 * <p>The body is held entirely in memory, so only wrap requests that are actually signed. The
 * signature filter does exactly that.
 */
public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private final byte[] cachedBody;

    public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        this.cachedBody = StreamUtils.copyToByteArray(request.getInputStream());
    }

    /** The raw bytes, for signature verification. */
    public byte[] getCachedBody() {
        return cachedBody;
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream source = new ByteArrayInputStream(cachedBody);
        return new ServletInputStream() {

            @Override
            public boolean isFinished() {
                return source.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                throw new UnsupportedOperationException("Asynchronous reads are not supported here");
            }

            @Override
            public int read() {
                return source.read();
            }
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(cachedBody), StandardCharsets.UTF_8));
    }
}
