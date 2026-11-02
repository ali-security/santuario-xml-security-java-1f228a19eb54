/*
 * Copyright 2021 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.apache.xml.security.test.transforms.implementations;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.xml.security.exceptions.XMLSecurityRuntimeException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.w3c.dom.Document;

/**
 * Unit test for {@link org.apache.xml.security.transforms.implementations.TransformXPath}
 *
 * Checks that errors raised while evaluating an XPath transform (or while
 * converting its input to a node-set) do not leak the content of the
 * transformed document through the exception (CVE-2021-40690).
 */
public class TransformXPathTest extends TestCase {

    private static final String SECRET = "TopSecretFileContent4711";

    private static final String SECRET_ELEMENT = "TopSecretElementName4711";

    /**
     * An XPath expression that only fails (the here() function cannot be
     * evaluated against a node of another document) once the evaluation
     * reaches a text node of the transformed document.
     */
    private static final String FAILING_XPATH = "self::text() and here()";

    public static Test suite() {
        return new TestSuite(TransformXPathTest.class);
    }

    public TransformXPathTest(String name) {
        super(name);
    }

    public static void main(String[] args) {
        String[] testCaseName = { "-noloading", TransformXPathTest.class.getName() };
        junit.textui.TestRunner.main(testCaseName);
    }

    private static Document createDocument() throws Exception {
        DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
        dfactory.setNamespaceAware(true);
        DocumentBuilder db = dfactory.newDocumentBuilder();
        return db.newDocument();
    }

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
        dfactory.setNamespaceAware(true);
        DocumentBuilder db = dfactory.newDocumentBuilder();
        return db.parse(new ByteArrayInputStream(xml.getBytes("UTF-8")));
    }

    private static Transforms createXPathTransforms(String xpath) throws Exception {
        Document doc = createDocument();
        Transforms transforms = new Transforms(doc);
        doc.appendChild(transforms.getElement());
        XPathContainer xpathC = new XPathContainer(doc);
        xpathC.setXPath(xpath);
        transforms.addTransform(Transforms.TRANSFORM_XPATH,
                                xpathC.getElementPlusReturns());
        return transforms;
    }

    private static void assertNoLeak(Throwable t, String secret) {
        String message = t.getMessage();
        assertTrue("Exception message leaks document content: " + message,
                   message == null || message.indexOf(secret) == -1);
        String str = t.toString();
        assertTrue("Exception leaks document content: " + str,
                   str.indexOf(secret) == -1);
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        assertTrue("Exception stack trace leaks document content",
                   sw.toString().indexOf(secret) == -1);
    }

    /**
     * An error while evaluating the XPath expression must not expose the
     * current node (e.g. the content of a text node) in the exception.
     */
    public void testXPathErrorDoesNotLeakNodeContent() throws Exception {
        String content = "<root><data>" + SECRET + "</data></root>";
        XMLSignatureInput input =
            new XMLSignatureInput(new ByteArrayInputStream(content.getBytes("UTF-8")));

        Transforms transforms = createXPathTransforms(FAILING_XPATH);
        XMLSignatureInput output = transforms.performTransforms(input);

        try {
            output.getBytes();
            fail("Expected failure evaluating the XPath expression");
        } catch (XMLSecurityRuntimeException ex) {
            assertNoLeak(ex, SECRET);
            assertNull(ex.getOriginalException());
        }
    }

    /**
     * An error while converting the input of an XPath transform to a
     * node-set must not expose the parser error (which can contain parts of
     * the document) in the exception.
     */
    public void testNodesetConversionErrorDoesNotLeakContent() throws Exception {
        String content = "<root><" + SECRET_ELEMENT + "></root>";
        XMLSignatureInput input =
            new XMLSignatureInput(new ByteArrayInputStream(content.getBytes("UTF-8")));

        Transforms transforms = createXPathTransforms("self::text()");

        try {
            transforms.performTransforms(input);
            fail("Expected failure converting the input to a node-set");
        } catch (XMLSecurityRuntimeException ex) {
            assertNoLeak(ex, SECRET_ELEMENT);
            assertNull(ex.getOriginalException());
        }
    }

    /**
     * A RetrievalMethod pointing to a local file, combined with an XPath
     * transform, must not leak the content of that file through the
     * exception thrown while resolving the key.
     */
    public void testRetrievalMethodXPathDoesNotLeakLocalFile() throws Exception {
        File secretFile = File.createTempFile("xmlsec-secret", ".xml");
        secretFile.deleteOnExit();
        FileOutputStream fos = new FileOutputStream(secretFile);
        try {
            fos.write(("<root><data>" + SECRET + "</data></root>").getBytes("UTF-8"));
        } finally {
            fos.close();
        }

        try {
            String fileURI = secretFile.toURL().toString();
            String baseURI = secretFile.getParentFile().toURL().toString();
            String keyInfoXml =
                "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                + "<ds:RetrievalMethod URI=\"" + fileURI + "\""
                + " Type=\"http://www.w3.org/2000/09/xmldsig#rawX509Certificate\">"
                + "<ds:Transforms>"
                + "<ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\">"
                + "<ds:XPath>" + FAILING_XPATH + "</ds:XPath>"
                + "</ds:Transform>"
                + "</ds:Transforms>"
                + "</ds:RetrievalMethod>"
                + "</ds:KeyInfo>";
            Document doc = parse(keyInfoXml);

            KeyInfo keyInfo = new KeyInfo(doc.getDocumentElement(), baseURI);
            try {
                keyInfo.getPublicKey();
                fail("Expected failure evaluating the XPath expression");
            } catch (XMLSecurityRuntimeException ex) {
                assertNoLeak(ex, SECRET);
            }
        } finally {
            secretFile.delete();
        }
    }

    static {
        org.apache.xml.security.Init.init();
    }
}
