package XMLResponse;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlElement;

public class AuthnContext implements Serializable {

    private static final long serialVersionUID = 1L;
    private String AuthnContextClassRef;

    @XmlElement(name = "AuthnContextClassRef")
    public String getAuthnContextClassRef() {
        return AuthnContextClassRef;
    }

    public void setAuthnContextClassRef(String authnContextClassRef) {
        AuthnContextClassRef = authnContextClassRef;
    }

    @Override
    public String toString() {
        return "AuthnContext [AuthnContextClassRef=" + AuthnContextClassRef + "]";
    }
}
