package XMLResponse;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;

public class AuthnStatement implements Serializable {

    private static final long serialVersionUID = 1L;
    private AuthnContext authnContext;
    private String authnInstant;

    @XmlElement(name = "AuthnContext")
    public AuthnContext getAuthnContext() {
        return authnContext;
    }

    public void setAuthnContext(AuthnContext authnContext) {
        this.authnContext = authnContext;
    }

    @XmlAttribute(name = "AuthnInstant")
    public String getAuthnInstant() {
        return authnInstant;
    }

    public void setAuthnInstant(String authnInstant) {
        this.authnInstant = authnInstant;
    }

    @Override
    public String toString() {
        return "AuthnStatement [authnContext=" + authnContext + "]";
    }
}
