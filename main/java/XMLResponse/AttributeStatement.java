package XMLResponse;

import java.io.Serializable;
import java.util.List;

import javax.xml.bind.annotation.XmlElement;

public class AttributeStatement implements Serializable {

	private static final long serialVersionUID = 1L;
	private List<Attribute> attribute;

	@XmlElement(name = "Attribute")
	public List<Attribute> getAttribute() {
		return attribute;
	}

	public void setAttribute(List<Attribute> attribute) {
		this.attribute = attribute;
	}

	@Override
	public String toString() {
		return "AttributeStatement [attribute=" + attribute + "]";
	}
}
