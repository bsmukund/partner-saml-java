package SignXMLUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.io.IOUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.XMLUtils;
//import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentFragment;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.onelogin.saml2.util.Util;

import XMLResponse.SamlSchema;
import util.ParserXML;

/**
 * Responsible for signing a specific XML using private key certificate
 */
public class XmlSigner {

    private static final String C14NEXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private static final String C14EXC = CanonicalizationMethod.EXCLUSIVE; // C14NTransform.W3C_C14N;

    private KeyStoreInfo keyStoreInfo;
    private InputStream sourceXml;
    private String strIdAssert = "";

    static {
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");
        org.apache.xml.security.Init.init();
        // com.sun.org.apache.xml.internal.security.Init.init();
    }

    /**
     * Signs a specific XML using a private key via Java Key Store format
     *
     * @throws KeyException
     */
    public SignedXml sign()
            throws NoSuchAlgorithmException, KeyStoreException, IOException, InvalidAlgorithmParameterException,
            ParserConfigurationException, SAXException, MarshalException, XMLSignatureException, TransformerException,
            TransformerFactoryConfigurationError, UnrecoverableEntryException, KeyException {

        KeyStore keyStore = keyStoreInfo.getKeyStore();
        String alias = keyStoreInfo.getAlias();
        char[] password = keyStoreInfo.getPassword().toCharArray();

        // Create a DOM XMLSignatureFactory that will be used to
        // generate the enveloped signature.
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Create a Reference to the enveloped document (in this case,
        // you are signing the whole document, so a URI of "" signifies
        // that, and also specify the SHA1 digest algorithm and
        // the ENVELOPED Transform.
        Transform envelopedTransform = fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
        Transform c14NEXCTransform = fac.newTransform(C14EXC, (TransformParameterSpec) null);
        List<Transform> transforms = Arrays.asList(envelopedTransform, c14NEXCTransform);

        DigestMethod digestMethod = fac.newDigestMethod(DigestMethod.SHA256, null);
        //Reference ref = fac.newReference("", digestMethod, transforms, null, null);
        Reference ref = fac.newReference("#" + strIdAssert, digestMethod, transforms, null, null);

        // Create the SignedInfo.
        CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                (C14NMethodParameterSpec) null);
        SignedInfo si = fac.newSignedInfo(canonicalizationMethod,
                fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null), Collections.singletonList(ref));

        // Create the KeyInfo containing the X509Data.
        KeyInfoFactory keyInfoFactory = fac.getKeyInfoFactory();
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);

        // X509Data newX509Data =
        // keyInfoFactory.newX509Data(Arrays.asList(certificate));
        // X509IssuerSerial issuer =
        // keyInfoFactory.newX509IssuerSerial(certificate.getIssuerX500Principal().getName(),
        // certificate.getSerialNumber());

        // List<XMLStructure> data = Arrays.asList(newX509Data, issuer);
        // KeyInfo keyInfo = keyInfoFactory.newKeyInfo(data);

        KeyValue aKeyValue = keyInfoFactory.newKeyValue(certificate.getPublicKey());
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(aKeyValue));

        // Converts XML to Document
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(sourceXml);

        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element.
        Key key = keyStore.getKey(alias, password);
        if (key == null) {
            throw new XmlSigningException("Private Key not found for alias '" + alias + "'");
        }

        DOMSignContext dsc = new DOMSignContext(key, doc.getDocumentElement());

        // Adds <Signature> tag before a specific tag inside XML - with or without
        // namespace
        /*
         * Node assertionTag = doc.getElementsByTagName("saml2:Assertion").item(0);
         * Node afterTag = doc.getElementsByTagName("saml2:Subject").item(0);
         * DOMSignContext dsc = new DOMSignContext(key, assertionTag, afterTag);
         * dsc.setDefaultNamespacePrefix("ds");
         */

        // Create the XMLSignature, but don't sign it yet.
        XMLSignature signature = fac.newXMLSignature(si, keyInfo);
        signature.sign(dsc); // Marshal, generate, and sign the enveloped signature.

        NamedNodeMap attr = doc.getElementsByTagName("Reference").item(0).getAttributes();
        attr.getNamedItem("URI").setTextContent("#" + strIdAssert);

        addNodeAfter(doc.getElementsByTagName("Signature").item(0), doc.getElementsByTagName("Issuer").item(0));

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        TransformerFactory.newInstance()
                .newTransformer()
                .transform(new DOMSource(doc), new StreamResult(output));

        String rawSignedXml = new String(output.toByteArray());

        SignedXml xml = new SignedXml(rawSignedXml);
        return xml;
    }

    public void addNodeAfter(Node newNode, Node refChild) {
        Node parent = refChild.getParentNode();
        parent.insertBefore(newNode, refChild);
        refChild = parent.removeChild(refChild);
        parent.insertBefore(refChild, newNode);
    }

    public XmlSigner withKeyStore(String keyStore, String alias, String password) throws Exception {

        if (keyStore == null)
            throw new XmlSigningException("KeyStore without private key");

        KeyStoreInfo ksi = new KeyStoreInfo(alias, password);
        ksi.load(new FileInputStream(keyStore));

        this.keyStoreInfo = ksi;
        return this;
    }

    public XmlSigner withXml(InputStream sourceXml) {

        if (sourceXml == null)
            throw new XmlSigningException("XML can not be null");

        this.sourceXml = sourceXml;
        return this;
    }

    public XmlSigner withXml(String sourceXml) {
        InputStream input = IOUtils.toInputStream(sourceXml, StandardCharsets.UTF_8);
        return withXml(input);
    }

    public XmlSigner withIdAssert(String strRef) {
        this.strIdAssert = strRef;
        return this;
    }
    
    public SignedXml oneLoginSign() throws ParserConfigurationException, SAXException, IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, XPathExpressionException, XMLSecurityException, TransformerFactoryConfigurationError, TransformerException {
    	
    	// Converts XML to Document
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        
        
        Document document = builder.parse(sourceXml);
        
        KeyStore keyStore = keyStoreInfo.getKeyStore();
        String alias = keyStoreInfo.getAlias();
        char[] password = keyStoreInfo.getPassword().toCharArray();

        // Create a DOM XMLSignatureFactory that will be used to
        // generate the enveloped signature.
        // XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Create a Reference to the enveloped document (in this case,
        // you are signing the whole document, so a URI of "" signifies
        // that, and also specify the SHA1 digest algorithm and
        // the ENVELOPED Transform.
        

        // Create the KeyInfo containing the X509Data.
        // KeyInfoFactory keyInfoFactory = fac.getKeyInfoFactory();
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        
        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element.
        Key key = keyStore.getKey(alias, password);
        if (key == null) {
            throw new XmlSigningException("Private Key not found for alias '" + alias + "'");
        }
        
        // signs the response
        //String signedResponse = Util.addSign(document, (PrivateKey) key, certificate, null);
        XPathFactory xPathfactory = XPathFactory.newInstance();
        // Retrieve Assertion Node to be signed.
        XPath xpath = xPathfactory.newXPath();
        XPathExpression exprAssertion = xpath.compile("//*[local-name()='Response']//*[local-name()='Assertion']");
        
        Node assertionNode = (Node) exprAssertion.evaluate(document, XPathConstants.NODE);
        String signedResponse = Util.addSign(assertionNode, (PrivateKey) key, certificate, null);
              
        System.out.println("\n\n Assertion node sign doc element : \n" + signedResponse);
        
        InputStream stream = new ByteArrayInputStream(Util.convertDocumentToString(document).getBytes(StandardCharsets.UTF_8));
        Document finalDocument = builder.parse(stream);
        XPath finalDocumentXPath = xPathfactory.newXPath();
        XPathExpression finalDocumentExprAssertion = finalDocumentXPath.compile("//*[local-name()='Response']//*[local-name()='Assertion']");
        Node finalDocumentAssertionNode = (Node) finalDocumentExprAssertion.evaluate(finalDocument, XPathConstants.NODE);
        
        
        Element signedAssertionNode = builder.parse(new ByteArrayInputStream(signedResponse.getBytes())).getDocumentElement();
        
        
        //Approach1: Update the existing document by replacing the Assertion node before and after signature generation 
        finalDocument.getFirstChild().replaceChild(finalDocument.importNode(signedAssertionNode.cloneNode(true), true), finalDocumentAssertionNode);
        document.getFirstChild().replaceChild(document.importNode(signedAssertionNode.cloneNode(true), true), assertionNode);
        String finalResponse = Util.convertDocumentToString(document, true);
        System.out.println("\n\n The replaced document is ----------- \n" + finalResponse);
        
        
        //Approach2: Create a new response object and add generated signAssertion to it
        
        /*SamlSchema samlSchema = new SamlSchema();
        samlSchema.setXmlns("urn:oasis:names:tc:SAML:2.0:protocol");
        //samlSchema.setNsxsi("http://www.w3.org/2001/XMLSchema-instance");
        //samlSchema.setNsxsd("http://www.w3.org/2001/XMLSchema");
        String responseUUID = "_" + UUID.randomUUID().toString();
        samlSchema.setId(responseUUID);
        samlSchema.setInresponseto("testreturn");
        samlSchema.setVersion("2.0");
        samlSchema.setIssueinstant(java.time.LocalDateTime.now() + "Z");
        samlSchema.setDestination("https://idpartner.mcafee.com/login/callback?connection=saml-testsp");
        
        String finalSamlResponse = ParserXML
                .convertFromObjectToStringXML(samlSchema, SamlSchema.class);
        //samlResponse = ParserXML
        XmlSigner finalSignedXml = new XmlSigner()
                .withXml(finalSamlResponse);
		
        Document finalDocumentTry = builder.parse(finalSignedXml.sourceXml);
        //System.out.println("\n---------------The finalDocumentTry is " + Util.convertDocumentToString(finalDocumentTry) + "\n----------\n");
        finalDocumentTry.getFirstChild().appendChild(finalDocumentTry.importNode(signedAssertionNode.cloneNode(true), true));
        System.out.println("\n---------------The finalDocumentTry is " + new SignedXml(Util.convertDocumentToString(finalDocumentTry, true)).toBase64() + "\n----------\n");
        */
        
        //return new SignedXml(signedResponse);
        return new SignedXml(finalResponse);
    	
    	
    }
}
