package com.saml;

import XMLResponse.*;
import util.ParserXML;

import SignXMLUtil.SignedXml;
import SignXMLUtil.XmlSigner;

import java.util.ArrayList;

import java.util.List;
import java.util.UUID;

public class Main {

    public static void main(String[] args) {

        System.out.println("Hello world!");

        String strResponse = "Test";
        String strTelVirtual = "553970543";
        String strAffId = "911";

        String jks = "/Users/mukundbs/saml/samlresponse/src/store.keys";
        // String jksString = jks.toString();
        String alias = "shared";
        String password = "Test1234";

        SamlSchema samlSchema = new SamlSchema();
        samlSchema.setXmlns("urn:oasis:names:tc:SAML:2.0:protocol");
        //samlSchema.setNsxsi("http://www.w3.org/2001/XMLSchema-instance");
        //samlSchema.setNsxsd("http://www.w3.org/2001/XMLSchema");
        String responseUUID = "_" + UUID.randomUUID().toString();
        samlSchema.setId(responseUUID);
        samlSchema.setInresponseto(strResponse);
        samlSchema.setVersion("2.0");
        samlSchema.setIssueinstant(java.time.LocalDateTime.now() + "Z");
        samlSchema.setDestination("https://id.mcafee.com/login/callback?connection=saml-testsp");
        Issuer issuer = new Issuer();
        issuer.setIssuer("https://partner.site.com");
        issuer.setXmlns("urn:oasis:names:tc:SAML:2.0:assertion");
        samlSchema.setIssuer(issuer);
        StatusCode statusCode = new StatusCode();
        statusCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");
        Status status = new Status();
        status.setStatusCode(statusCode);
        samlSchema.setStatus(status);
        Assertion assertion = new Assertion();
        assertion.setXmlns("urn:oasis:names:tc:SAML:2.0:assertion");
        assertion.setVersion("2.0");
        String refURI = "_" + UUID.randomUUID().toString();
        assertion.setId(refURI);
        // assertion.setIssuerVersion("2.0");
        assertion.setIssuer("https://partner.site.com");
        assertion.setIssueInstant(java.time.LocalDateTime.now() + "Z");
        // assertion.setNotBefore(java.time.LocalDateTime.now() + "Z");
        // assertion.setNotOnOrAfter(java.time.LocalDateTime.now() + "Z");
        // assertion.setAuthnInstant(java.time.LocalDateTime.now() + "Z");
        samlSchema.setAssertion(assertion);
        Subject subject = new Subject();
        // subject.setNameIdFormat("urn:oasis:names:tc:SAML:1.1:nameid -
        // format:unspecified");
        // subject.setNameID("test");
        // subject.setSubjectConfirmationMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
        SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationData();
        subjectConfirmationData.setInResponseTo(strResponse);
        subjectConfirmationData.setRecipient("https://id.mcafee.com/login/callback?connection=saml-testsp");
        subjectConfirmationData.setNotOnOrAfter(java.time.LocalDateTime.now() + "Z");
        SubjectConfirmation subjectConfirmation = new SubjectConfirmation();
        // subjectConfirmation.setNotOnOrAfter(java.time.LocalDateTime.now() + "Z");
        // subjectConfirmation.setRecipient("https://id.mcafee.com/login/callback?connection=saml-testsp");
        // subjectConfirmation.setInResponseTo(strResponse);
        // subjectConfirmation.setSubjectConfirmationData("");
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.setSubjectConfirmation(subjectConfirmation);
        samlSchema.getAssertion().setSubject(subject);
        Conditions conditions = new Conditions();
        AudienceRestriction audienceRestriction = new AudienceRestriction();
        audienceRestriction.setAudience("https://id.mcafee.com");
        conditions.setAudienceRestriction(audienceRestriction);
        conditions.setNotBefore(java.time.LocalDateTime.now() + "Z");
        conditions.setNotOnOrAfter(java.time.LocalDateTime.now() + "Z");
        samlSchema.getAssertion().setConditions(conditions);
        AuthnStatement authnStatement = new AuthnStatement();
        AuthnContext authnContext = new AuthnContext();
        authnContext.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");
        authnStatement.setAuthnContext(authnContext);
        authnStatement.setAuthnInstant(java.time.LocalDateTime.now() + "Z");
        samlSchema.getAssertion().setAuthnStatement(authnStatement);
        AttributeStatement attributeStatement = new AttributeStatement();
        List<Attribute> attributes = new ArrayList<>();
        Attribute attributeCCID = new Attribute();
        attributeCCID.setName("ccid");
        attributeCCID.setAttributeValue(strTelVirtual.replaceFirst("^0+(?!$)", ""));
        attributes.add(attributeCCID);
        Attribute attributeAFFID = new Attribute();
        attributeAFFID.setName("affid");
        // attributeAFFID.setAttributeValue(parametros.get("AFFID"));
        attributeAFFID.setAttributeValue(strAffId);
        attributes.add(attributeAFFID);
        Attribute attributeCLT = new Attribute();
        attributeCLT.setName("culture");
        attributeCLT.setAttributeValue("es-mx");
        attributes.add(attributeCLT);
        attributeStatement.setAttribute(attributes);
        samlSchema.getAssertion().setAttributeStatement(attributeStatement);

        String samlResponse;
        String samlAssertion;
        // String xmlSigned;
        try {
            samlResponse = ParserXML
                    .convertFromObjectToStringXML(samlSchema, SamlSchema.class);
            
            System.out.println("Trying to generate now....");
            samlAssertion = samlResponse;
            SignedXml signedXml = new XmlSigner()
                    .withXml(samlAssertion) // it supports InputStream as well
                    .withKeyStore(jks, alias, password)
                    .withIdAssert(refURI)
                    //.signAssertion();
                    .oneLoginSign();
            System.out.println("\n\n--------Signed XML is : --------\n\n" + signedXml.toBase64());
        } catch (Exception e) {
            // TODO: handle exception
            System.out.println("Exception is " + e);
        }

    }
}