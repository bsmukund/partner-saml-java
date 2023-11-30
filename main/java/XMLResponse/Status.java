package XMLResponse;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlElement;


public class Status implements Serializable {

	private static final long serialVersionUID = 1L;
	private StatusCode statusCode;
	

	@XmlElement(name = "StatusCode")
	public StatusCode getStatusCode() {
		return statusCode;
	}

	public void setStatusCode(StatusCode name) {
		this.statusCode = name;
	}

	@Override
	public String toString() {
		return "Status [StatusCode=" + statusCode + "]";
	}
}
