package XMLResponse;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import org.eclipse.persistence.oxm.annotations.XmlPath;

public class SubjectConfirmation implements Serializable {

	private static final long serialVersionUID = 1L;
	private String NotOnOrAfter;
	private String Recipient;
	private String InResponseTo;
	private SubjectConfirmationData subjectConfirmationData;
	private String Method;

	@XmlPath("SubjectConfirmationData/@NotOnOrAfter")
	public String getNotOnOrAfter() {
		return NotOnOrAfter;
	}

	public void setNotOnOrAfter(String notOnOrAfter) {
		NotOnOrAfter = notOnOrAfter;
	}

	@XmlPath("SubjectConfirmationData/@Recipient")
	public String getRecipient() {
		return Recipient;
	}

	public void setRecipient(String recipient) {
		Recipient = recipient;
	}

	@XmlPath("SubjectConfirmationData/@InResponseTo")
	public String getInResponseTo() {
		return InResponseTo;
	}

	public void setInResponseTo(String inResponseTo) {
		InResponseTo = inResponseTo;
	}

	@XmlElement(name = "SubjectConfirmationData")
	public SubjectConfirmationData getSubjectConfirmationData() {
		return subjectConfirmationData;
	}

	public void setSubjectConfirmationData(SubjectConfirmationData subjectConfirmationData) {
		this.subjectConfirmationData = subjectConfirmationData;
	}

	@XmlAttribute(name = "Method")
	public String getMethod() {
		return Method;
	}

	public void setMethod(String method) {
		Method = method;
	}

	@Override
	public String toString() {
		return "SubjectConfirmation [subjectConfirmationData=" + subjectConfirmationData + "]";
	}
}
