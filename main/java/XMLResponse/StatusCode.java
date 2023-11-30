package XMLResponse;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAttribute;

public class StatusCode  implements Serializable {
	private static final long serialVersionUID = 1L;
	private String value;
	

	@XmlAttribute(name = "Value")
	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	@Override
	public String toString() {
		return "StatusCode [Value=" + value + "]";
	}

}
