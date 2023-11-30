package XMLResponse;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "Response")
@XmlType(propOrder = { "issuer", "status", "assertion"})
public class SamlSchema implements Serializable {

	private static final long serialVersionUID = 1L;

	private String xmlns;
	private String nsxsi;
	private String nsxsd;
	private String id;
	private String inresponseto;
	private String version;
	private String issueinstant;
	private String destination;
	private Status status;
	private Issuer issuer;
	private Assertion assertion;

	@XmlAttribute(name = "xmlns")
	public String getXmlns() {
		return xmlns;
	}

	public void setXmlns(String xmlns) {
		this.xmlns = xmlns;
	}

	@XmlAttribute(name = "xmlns:xsi")
	private String getNsxsi() {
		return nsxsi;
	}

	public void setNsxsi(String nsxsi) {
		this.nsxsi = nsxsi;
	}

	@XmlAttribute(name = "xmlns:xsd")
	public String getNsxsd() {
		return nsxsd;
	}

	public void setNsxsd(String nsxsd) {
		this.nsxsd = nsxsd;
	}

	@XmlAttribute(name = "ID")
	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	@XmlAttribute(name = "InResponseTo")
	public String getInresponseto() {
		return inresponseto;
	}

	public void setInresponseto(String inresponseto) {
		this.inresponseto = inresponseto;
	}

	@XmlAttribute(name = "Version")
	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	@XmlAttribute(name = "IssueInstant")
	public String getIssueinstant() {
		return issueinstant;
	}

	public void setIssueinstant(String issueinstant) {
		this.issueinstant = issueinstant;
	}

	@XmlAttribute(name = "Destination")
	public String getDestination() {
		return destination;
	}

	public void setDestination(String destination) {
		this.destination = destination;
	}
	
	@XmlElement(name = "Issuer")
	public Issuer getIssuer() {
		return issuer;
	}
	
	public void setIssuer(Issuer issuer) {
		this.issuer = issuer;
	}
	
	@XmlElement(name = "Status")
	public Status getStatus() {
		return status;
	}
	
	public void setStatus(Status status) {
		this.status = status;
	}
	

	@XmlElement(name = "Assertion")
	public Assertion getAssertion() {
		return assertion;
	}

	public void setAssertion(Assertion assertion) {
		this.assertion = assertion;
	}

	@Override
	public String toString() {
		return "SamlSchema [nsxsi=" + nsxsi + ", nsxsd=" + nsxsd + ", id=" + id + ", inresponseto=" + inresponseto
				+ ", version=" + version + ", issueinstant=" + issueinstant + ", destination=" + destination
				+ "status=" + status + ", assertion=" + assertion + "]";
	}

}