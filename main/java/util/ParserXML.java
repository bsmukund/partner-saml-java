package util;

//import java.io.Serializable;
import java.io.StringWriter;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.*;
import javax.xml.bind.JAXB;
//import javax.xml.bind.JAXBContext;
//import javax.xml.bind.Marshaller;

public class ParserXML {
    public static <T> String convertFromObjectToStringXML(Object object, Class<T> class1) {
        // JAXBContext jaxbContext = JAXBContext.newInstance(type);
        StringWriter sw = new StringWriter();
        JAXB.marshal(object, sw);
        // System.out.println(
        // "The string XML is " + sw.toString().replaceAll("\r\n", "").replace("\r",
        // "").replace("\n", "")
        // .replaceAll("\\s\\s+", ""));
        // return sw.toString();
        return sw.toString().replaceAll("\r\n", "").replace("\r", "").replace("\n", "").replaceAll("\\s\\s+", "");
        //return sw.toString();
    }
    
    public static String compactifyXML(String xml) throws TransformerException {
    	final String xslt = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
    	        "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">\n" +
    	        "    <xsl:output indent=\"no\"/>\n" +
    	        "    <xsl:strip-space elements=\"*\"/>\n" +
    	        "    <xsl:template match=\"@*|node()\">\n" +
    	        "        <xsl:copy>\n" +
    	        "            <xsl:apply-templates select=\"@*|node()\"/>\n" +
    	        "        </xsl:copy>\n" +
    	        "    </xsl:template>\n" +
    	        "</xsl:stylesheet>";
    	/* prepare XSLT transformer from String */
        Source xsltSource = new StreamSource(new StringReader(xslt));
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer(xsltSource);

        /* where to read the XML? */
        Source source = new StreamSource(new StringReader(xml));

        /* where to write the XML? */
        StringWriter stringWriter = new StringWriter();
        Result result = new StreamResult(stringWriter);

        /* transform XML to one line */
        transformer.transform(source, result);

        return stringWriter.toString();
    }

}
