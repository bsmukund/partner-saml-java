package XMLResponse;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlValue;


public class Issuer implements Serializable {
	
	private static final long serialVersionUID = 1L;
	private String xmlns;
	private String issuer;
	
	@XmlAttribute(name = "xmlns")
	public String getXmlns(){
		return xmlns;
	}
	
	public void setXmlns(String xmlns){
		this.xmlns = xmlns;
	}
	
	@XmlValue
	public String getIssuer() {
		return this.issuer;
	}
	
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

}
