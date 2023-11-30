package XMLResponse;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlElement;

public class AudienceRestriction implements Serializable {

	private static final long serialVersionUID = 1L;
	private String audience;

	@XmlElement(name = "Audience")
	public String getAudience() {
		return audience;
	}

	public void setAudience(String audience) {
		this.audience = audience;
	}

	@Override
	public String toString() {
		return "AudienceRestriction [audience=" + audience + "]";
	}
}
