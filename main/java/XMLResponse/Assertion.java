package XMLResponse;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import org.eclipse.persistence.oxm.annotations.XmlPath;

@XmlType(propOrder = { "issuer", "subject", "conditions", "authnStatement", "attributeStatement" })
public class Assertion implements Serializable {

    private static final long serialVersionUID = 1L;
    private String xmlns;
    private String version;
    private String id;
    private String issueInstant;
    private String issuerVersion;
    private String issuer;
    private Subject subject;
    // private String NotBefore;
    // private String NotOnOrAfter;
    private Conditions conditions;
    private String AuthnInstant;
    private AuthnStatement authnStatement;
    private AttributeStatement attributeStatement;

    @XmlAttribute(name = "xmlns")
    public String getXmlns() {
        return xmlns;
    }

    public void setXmlns(String xmlns) {
        this.xmlns = xmlns;
    }

    @XmlAttribute(name = "Version")
    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    @XmlAttribute(name = "ID")
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @XmlAttribute(name = "IssueInstant")
    public String getIssueInstant() {
        return issueInstant;
    }

    public void setIssueInstant(String issueInstant) {
        this.issueInstant = issueInstant;
    }

    // @XmlAttribute(name = "Version")
    // public String getIssuerVersion() {
    // return issuerVersion;
    // }

    // public void setIssuerVersion(String issuerVersion) {
    // this.issuerVersion = issuerVersion;
    // }

    @XmlElement(name = "Issuer")
    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    @XmlElement(name = "Subject")
    public Subject getSubject() {
        return subject;
    }

    public void setSubject(Subject subject) {
        this.subject = subject;
    }

    // @XmlPath("Conditions/@NotBefore")
    // public String getNotBefore() {
    // return NotBefore;
    // }

    // public void setNotBefore(String notBefore) {
    // NotBefore = notBefore;
    // }

    // @XmlPath("Conditions/@NotOnOrAfter")
    // public String getNotOnOrAfter() {
    // return NotOnOrAfter;
    // }

    // public void setNotOnOrAfter(String notOnOrAfter) {
    // NotOnOrAfter = notOnOrAfter;
    // }

    @XmlElement(name = "Conditions")
    public Conditions getConditions() {
        return conditions;
    }

    public void setConditions(Conditions conditions) {
        this.conditions = conditions;
    }

    // @XmlPath("AuthnStatement/@AuthnInstant")
    // public String getAuthnInstant() {
    // return AuthnInstant;
    // }

    // public void setAuthnInstant(String authnInstant) {
    // AuthnInstant = authnInstant;
    // }

    @XmlElement(name = "AuthnStatement")
    public AuthnStatement getAuthnStatement() {
        return authnStatement;
    }

    public void setAuthnStatement(AuthnStatement authnStatement) {
        this.authnStatement = authnStatement;
    }

    @XmlElement(name = "AttributeStatement")
    public AttributeStatement getAttributeStatement() {
        return attributeStatement;
    }

    public void setAttributeStatement(AttributeStatement attributeStatement) {
        this.attributeStatement = attributeStatement;
    }

    @Override
    public String toString() {
        return "Assertion [xmlns=" + xmlns + ", version=" + version + ", id=" + id + ", issueInstant=" + issueInstant
                + ", issuerVersion=" + issuerVersion + ", issuer=" + issuer + ", subject=" + subject + ", conditions="
                + conditions + ", AuthnInstant="
                + AuthnInstant + ", authnStatement=" + authnStatement + ", attributeStatement=" + attributeStatement
                + "]";
    }
}
