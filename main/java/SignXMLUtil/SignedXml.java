package SignXMLUtil;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Represents a signed XML
 */
public class SignedXml {

    private String content;

    public SignedXml(String content) {
        this.content = content;
    }

    public String getContent() {
        return content;
    }

    public String toBase64() {
        return Base64.getEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8));
    }
}
