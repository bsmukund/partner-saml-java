package XMLResponse;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlType(propOrder = { "audienceRestriction" })
public class Conditions implements Serializable {

	private static final long serialVersionUID = 1L;
	private AudienceRestriction audienceRestriction;
	private String NotBefore;
	private String NotOnOrAfter;

	@XmlAttribute(name = "NotBefore")
	public String getNotBefore() {
		return NotBefore;
	}

	public void setNotBefore(String notBefore) {
		this.NotBefore = notBefore;
	}

	@XmlAttribute(name = "NotOnOrAfter")
	public String getNotOnOrAfter() {
		return NotOnOrAfter;
	}

	public void setNotOnOrAfter(String notOnOrAfter) {
		this.NotOnOrAfter = notOnOrAfter;
	}

	@XmlElement(name = "AudienceRestriction")
	public AudienceRestriction getAudienceRestriction() {
		return audienceRestriction;
	}

	public void setAudienceRestriction(AudienceRestriction audienceRestriction) {
		this.audienceRestriction = audienceRestriction;
	}

	@Override
	public String toString() {
		return "Conditions [audienceRestriction=" + audienceRestriction + "]";
	}
}
