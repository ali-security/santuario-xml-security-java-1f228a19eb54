/*
 * Copyright  2013 The Apache Software Foundation.
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
package org.apache.xml.security.test.signature;

import java.io.ByteArrayInputStream;
import java.util.Iterator;
import java.util.Set;

import javax.crypto.SecretKey;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.implementations.Canonicalizer20010315OmitComments;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 * Tests for CVE-2013-4517: if secure validation is enabled, XML data which is
 * parsed internally while canonicalizing or applying transforms must not
 * contain a document type declaration (DTD), so that a crafted DTD (such as
 * the "billion laughs" entity expansion) cannot exhaust memory or CPU.
 * Without secure validation DTDs are still processed as before.
 */
public class SecureValidationDTDTest extends TestCase {

    static {
        org.apache.xml.security.Init.init();
    }

    /** "Billion laughs": the entities expand to 10^9 times "lol" */
    private static final String BILLION_LAUGHS = billionLaughs();

    /** A small DTD whose entities expand to 1000 characters */
    private static final String SMALL_DTD =
        "<!DOCTYPE doc [\n"
        + " <!ENTITY a \"aaaaaaaaaa\">\n"
        + " <!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">\n"
        + " <!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">\n"
        + "]>\n"
        + "<doc>&c;</doc>";

    /** The canonical form of SMALL_DTD, with the entities expanded */
    private static final String SMALL_DTD_C14N = "<doc>" + repeat('a', 1000) + "</doc>";

    /** A document without a DTD */
    private static final String NO_DTD = "<doc attr=\"value\">text</doc>";

    private static final String XSLT_STRING_LENGTH =
        "<xslt:stylesheet version=\"1.0\""
        + " xmlns:xslt=\"http://www.w3.org/1999/XSL/Transform\">"
        + "<xslt:template match=\"/\">"
        + "<out><xslt:value-of select=\"string-length(/doc)\"/></out>"
        + "</xslt:template>"
        + "</xslt:stylesheet>";

    private static final byte[] HMAC_KEY = "secret-hmac-key".getBytes();

    public SecureValidationDTDTest(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(SecureValidationDTDTest.class);
    }

    public void testCreateDocumentBuilder() throws Exception {
        assertEquals(SMALL_DTD_C14N.length() - "<doc></doc>".length(),
            textLength(XMLUtils.createDocumentBuilder(false, false).parse(
                new ByteArrayInputStream(getBytes(SMALL_DTD)))));
        assertEquals(4, textLength(XMLUtils.createDocumentBuilder(false, true).parse(
                new ByteArrayInputStream(getBytes(NO_DTD)))));
        try {
            XMLUtils.createDocumentBuilder(false, true).parse(
                new ByteArrayInputStream(getBytes(BILLION_LAUGHS)));
            fail("DTD accepted although DTDs are disallowed");
        } catch (SAXException expected) {
        }
        // DTDs are disallowed by default
        try {
            XMLUtils.createDocumentBuilder(false).parse(
                new ByteArrayInputStream(getBytes(SMALL_DTD)));
            fail("DTD accepted although DTDs are disallowed");
        } catch (SAXException expected) {
        }
    }

    public void testCanonicalizerDefaultProcessesDTD() throws Exception {
        Canonicalizer c14n =
            Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        assertFalse(c14n.isSecureValidation());
        assertEquals(SMALL_DTD_C14N,
            new String(c14n.canonicalize(getBytes(SMALL_DTD)), "UTF-8"));
    }

    public void testCanonicalizerSecureValidationRejectsDTD() throws Exception {
        Canonicalizer c14n =
            Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        c14n.setSecureValidation(true);
        assertTrue(c14n.isSecureValidation());
        // a document without a DTD is still accepted
        assertEquals(NO_DTD, new String(c14n.canonicalize(getBytes(NO_DTD)), "UTF-8"));

        c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        c14n.setSecureValidation(true);
        try {
            c14n.canonicalize(getBytes(SMALL_DTD));
            fail("DTD accepted although secure validation is enabled");
        } catch (SAXException expected) {
        }
        try {
            c14n.canonicalize(getBytes(BILLION_LAUGHS));
            fail("DTD accepted although secure validation is enabled");
        } catch (SAXException expected) {
        }
    }

    public void testCanonicalizerSpiSecureValidationRejectsDTD() throws Exception {
        Canonicalizer20010315OmitComments c14n =
            new Canonicalizer20010315OmitComments();
        assertFalse(c14n.isSecureValidation());
        assertEquals(SMALL_DTD_C14N,
            new String(c14n.engineCanonicalize(getBytes(SMALL_DTD)), "UTF-8"));

        c14n = new Canonicalizer20010315OmitComments();
        c14n.setSecureValidation(true);
        try {
            c14n.engineCanonicalize(getBytes(BILLION_LAUGHS));
            fail("DTD accepted although secure validation is enabled");
        } catch (SAXException expected) {
        }
    }

    public void testXMLSignatureInputDefaultProcessesDTD() throws Exception {
        XMLSignatureInput input = new XMLSignatureInput(getBytes(SMALL_DTD));
        assertFalse(input.isSecureValidation());
        assertEquals(1000, textLength(input.getNodeSet()));
    }

    public void testXMLSignatureInputSecureValidationRejectsDTD() throws Exception {
        XMLSignatureInput input = new XMLSignatureInput(getBytes(NO_DTD));
        input.setSecureValidation(true);
        assertTrue(input.isSecureValidation());
        assertEquals(4, textLength(input.getNodeSet()));

        input = new XMLSignatureInput(getBytes(BILLION_LAUGHS));
        input.setSecureValidation(true);
        try {
            input.getNodeSet();
            fail("DTD accepted although secure validation is enabled");
        } catch (SAXException expected) {
        }
    }

    public void testC14NTransformDefaultProcessesDTD() throws Exception {
        Document doc = XMLUtils.createDocumentBuilder(false).newDocument();
        Transform c14n =
            Transform.getInstance(doc, Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
        assertFalse(c14n.isSecureValidation());
        XMLSignatureInput output =
            c14n.performTransform(new XMLSignatureInput(getBytes(SMALL_DTD)));
        assertFalse(output.isSecureValidation());
        assertEquals(SMALL_DTD_C14N, new String(output.getBytes(), "UTF-8"));
    }

    public void testC14NTransformsSecureValidationRejectDTD() throws Exception {
        Document doc = XMLUtils.createDocumentBuilder(false).newDocument();
        String[] algorithms = {
            Transforms.TRANSFORM_C14N_OMIT_COMMENTS,
            Transforms.TRANSFORM_C14N_WITH_COMMENTS,
            Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS,
            Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS,
            Transforms.TRANSFORM_C14N11_OMIT_COMMENTS,
            Transforms.TRANSFORM_C14N11_WITH_COMMENTS
        };
        for (int i = 0; i < algorithms.length; i++) {
            Transform c14n = Transform.getInstance(doc, algorithms[i]);
            c14n.setSecureValidation(true);
            assertTrue(c14n.isSecureValidation());
            XMLSignatureInput output =
                c14n.performTransform(new XMLSignatureInput(getBytes(NO_DTD)));
            assertTrue(algorithms[i], output.isSecureValidation());
            try {
                c14n.performTransform(new XMLSignatureInput(getBytes(BILLION_LAUGHS)));
                fail("DTD accepted by " + algorithms[i]
                     + " although secure validation is enabled");
            } catch (CanonicalizationException expected) {
            }
        }
    }

    /**
     * The secure validation flag of the input travels with the data through
     * the transforms: the octets produced by a Base64 transform are parsed by
     * the following c14n transform without accepting a DTD.
     */
    public void testSecureValidationPropagatesThroughTransforms() throws Exception {
        Document doc = XMLUtils.createDocumentBuilder(false).newDocument();
        Transform base64 =
            Transform.getInstance(doc, Transforms.TRANSFORM_BASE64_DECODE);
        Transform c14n =
            Transform.getInstance(doc, Transforms.TRANSFORM_C14N_OMIT_COMMENTS);

        XMLSignatureInput input = new XMLSignatureInput(
            getBytes(Base64.encode(getBytes(BILLION_LAUGHS))));
        input.setSecureValidation(true);
        XMLSignatureInput decoded = base64.performTransform(input);
        assertTrue(decoded.isSecureValidation());
        try {
            c14n.performTransform(decoded);
            fail("DTD accepted although secure validation is enabled");
        } catch (CanonicalizationException expected) {
        }
    }

    public void testXSLTTransformSecureValidationRejectsDTD() throws Exception {
        Document doc = XMLUtils.createDocumentBuilder(false).parse(
            new ByteArrayInputStream(getBytes(XSLT_STRING_LENGTH)));
        Transform xslt = Transform.getInstance(
            doc, Transforms.TRANSFORM_XSLT, doc.getDocumentElement());

        XMLSignatureInput output =
            xslt.performTransform(new XMLSignatureInput(getBytes(SMALL_DTD)));
        assertTrue(new String(output.getBytes(), "UTF-8").indexOf("<out>1000</out>") != -1);

        xslt.setSecureValidation(true);
        output = xslt.performTransform(new XMLSignatureInput(getBytes(NO_DTD)));
        assertTrue(output.isSecureValidation());
        assertTrue(new String(output.getBytes(), "UTF-8").indexOf("<out>4</out>") != -1);
        try {
            xslt.performTransform(new XMLSignatureInput(getBytes(BILLION_LAUGHS)));
            fail("DTD accepted although secure validation is enabled");
        } catch (TransformationException expected) {
        }
    }

    /**
     * A signed Reference whose Base64 + c14n transforms parse a DTD: the
     * signature validates by default, but the DTD is rejected if the
     * signature is validated with secure validation - also after an attacker
     * replaced the signed data by a "billion laughs" document.
     */
    public void testSignatureSecureValidationRejectsDTD() throws Exception {
        Document doc = XMLUtils.createDocumentBuilder(false).newDocument();
        Element root = doc.createElementNS(null, "root");
        doc.appendChild(root);

        XMLSignature sig =
            new XMLSignature(doc, "", XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
        root.appendChild(sig.getElement());

        ObjectContainer object = new ObjectContainer(doc);
        object.setId("payload");
        Node payload = doc.createTextNode(Base64.encode(getBytes(SMALL_DTD)));
        object.appendChild(payload);
        sig.appendObject(object);

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_BASE64_DECODE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
        sig.addDocument("#payload", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        SecretKey key = sig.createSecretKey(HMAC_KEY);
        sig.sign(key);

        Element sigElement = sig.getElement();
        assertTrue(new XMLSignature(sigElement, "").checkSignatureValue(key));
        assertTrue(new XMLSignature(sigElement, "", false).checkSignatureValue(key));

        try {
            new XMLSignature(sigElement, "", true).checkSignatureValue(key);
            fail("DTD accepted although secure validation is enabled");
        } catch (XMLSecurityException expected) {
        }

        payload.setNodeValue(Base64.encode(getBytes(BILLION_LAUGHS)));
        try {
            new XMLSignature(sigElement, "", true).checkSignatureValue(key);
            fail("DTD accepted although secure validation is enabled");
        } catch (XMLSecurityException expected) {
        }
    }

    private static int textLength(Set nodes) {
        int length = 0;
        for (Iterator i = nodes.iterator(); i.hasNext(); ) {
            Node node = (Node) i.next();
            if (node.getNodeType() == Node.TEXT_NODE) {
                length += node.getNodeValue().length();
            }
        }
        return length;
    }

    private static int textLength(Node node) {
        int length = 0;
        if (node.getNodeType() == Node.TEXT_NODE) {
            length += node.getNodeValue().length();
        }
        for (Node child = node.getFirstChild(); child != null;
             child = child.getNextSibling()) {
            length += textLength(child);
        }
        return length;
    }

    private static byte[] getBytes(String s) throws Exception {
        return s.getBytes("UTF-8");
    }

    private static String repeat(char c, int count) {
        StringBuffer sb = new StringBuffer(count);
        for (int i = 0; i < count; i++) {
            sb.append(c);
        }
        return sb.toString();
    }

    private static String billionLaughs() {
        StringBuffer sb = new StringBuffer();
        sb.append("<?xml version=\"1.0\"?>\n");
        sb.append("<!DOCTYPE lolz [\n");
        sb.append(" <!ENTITY lol \"lol\">\n");
        for (int i = 1; i <= 9; i++) {
            String previous = (i == 1) ? "lol" : "lol" + (i - 1);
            sb.append(" <!ENTITY lol" + i + " \"");
            for (int j = 0; j < 10; j++) {
                sb.append("&" + previous + ";");
            }
            sb.append("\">\n");
        }
        sb.append("]>\n");
        sb.append("<lolz>&lol9;</lolz>");
        return sb.toString();
    }
}
