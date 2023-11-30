package XMLResponse;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import org.eclipse.persistence.oxm.annotations.XmlPath;

@XmlType(propOrder = { "subjectConfirmation" })
public class Subject implements Serializable {

	private static final long serialVersionUID = 1L;

	// private String nameIdFormat;
	private String nameID;
	// private String subjectConfirmationMethod;
	private SubjectConfirmation subjectConfirmation;

	// @XmlPath("NameID/@Format")
	// // @XmlAttribute(name = "NameID/@Format")
	// public String getNameIdFormat() {
	// return nameIdFormat;
	// }

	// public void setNameIdFormat(String nameIdFormat) {
	// this.nameIdFormat = nameIdFormat;
	// }

	// @XmlElement(name = "NameID")
	// public String getNameID() {
	// return nameID;
	// }

	// public void setNameID(String nameID) {
	// this.nameID = nameID;
	// }

	// @XmlPath("SubjectConfirmation/@Method")
	// public String getSubjectConfirmationMethod() {
	// return subjectConfirmationMethod;
	// }

	// public void setSubjectConfirmationMethod(String subjectConfirmationMethod) {
	// this.subjectConfirmationMethod = subjectConfirmationMethod;
	// }

	@XmlElement(name = "SubjectConfirmation")
	public SubjectConfirmation getSubjectConfirmation() {
		return subjectConfirmation;
	}

	public void setSubjectConfirmation(SubjectConfirmation subjectConfirmation) {
		this.subjectConfirmation = subjectConfirmation;
	}

	@Override
	public String toString() {
		return "Subject [nameID=" + nameID + ", subjectConfirmation=" + subjectConfirmation
				+ ", subjectConfirmation=" + subjectConfirmation + "]";
	}
}
