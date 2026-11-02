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
package javax.xml.crypto.test.dsig;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.TestCase;

import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Tests for CVE-2013-4517: if the
 * <code>org.apache.jcp.xml.dsig.secureValidation</code> property is set,
 * XML data which is parsed internally while applying transforms must not
 * contain a document type declaration (DTD), so that a crafted DTD (such as
 * the "billion laughs" entity expansion) cannot exhaust memory or CPU.
 * Without the property DTDs are still processed as before.
 */
public class SecureValidationDTDTest extends TestCase {

    static {
        Security.insertProviderAt
            (new org.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    private static final String SECURE_VALIDATION =
        "org.apache.jcp.xml.dsig.secureValidation";

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

    /** A document without a DTD */
    private static final String NO_DTD = "<doc attr=\"value\">text</doc>";

    private static final Key KEY =
        new SecretKeySpec("secret-hmac-key".getBytes(), "HmacSHA1");

    private XMLSignatureFactory fac;
    private DocumentBuilderFactory dbf;

    public SecureValidationDTDTest(String name) {
        super(name);
    }

    public void setUp() {
        fac = XMLSignatureFactory.getInstance
            ("DOM", new org.jcp.xml.dsig.internal.dom.XMLDSigRI());
        dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
    }

    /**
     * Canonicalizing an octet stream with the CanonicalizationMethod
     * TransformService parses the octets.
     */
    public void testCanonicalizationTransformService() throws Exception {
        Document doc = dbf.newDocumentBuilder().newDocument();
        doc.appendChild(doc.createElementNS(null, "context"));

        DOMValidateContext context =
            new DOMValidateContext(KEY, doc.getDocumentElement());
        String c14n = canonicalize(getBytes(SMALL_DTD), context);
        assertEquals("<doc>" + repeat('a', 1000) + "</doc>", c14n);

        context = new DOMValidateContext(KEY, doc.getDocumentElement());
        context.setProperty(SECURE_VALIDATION, Boolean.TRUE);
        assertEquals(NO_DTD, canonicalize(getBytes(NO_DTD), context));
        try {
            canonicalize(getBytes(SMALL_DTD), context);
            fail("DTD accepted although secure validation is enabled");
        } catch (TransformException expected) {
        }
        try {
            canonicalize(getBytes(BILLION_LAUGHS), context);
            fail("DTD accepted although secure validation is enabled");
        } catch (TransformException expected) {
        }

        context = new DOMValidateContext(KEY, doc.getDocumentElement());
        context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
        try {
            canonicalize(getBytes(BILLION_LAUGHS), context);
            fail("DTD accepted although secure validation is enabled");
        } catch (TransformException expected) {
        }
    }

    /**
     * A signed Reference whose Base64 + c14n transforms parse a DTD: the
     * signature validates by default, but the DTD is rejected if the
     * signature is validated with secure validation - also after an attacker
     * replaced the signed data by a "billion laughs" document.
     */
    public void testSignatureSecureValidationRejectsDTD() throws Exception {
        Document doc = dbf.newDocumentBuilder().newDocument();

        List transforms = new ArrayList();
        transforms.add(fac.newTransform
            (Transform.BASE64, (TransformParameterSpec) null));
        transforms.add(fac.newTransform
            (CanonicalizationMethod.INCLUSIVE, (TransformParameterSpec) null));
        Reference ref = fac.newReference("#payload",
            fac.newDigestMethod(DigestMethod.SHA1, null), transforms, null, null);
        SignedInfo si = fac.newSignedInfo(
            fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                (C14NMethodParameterSpec) null),
            fac.newSignatureMethod(SignatureMethod.HMAC_SHA1, null),
            Collections.singletonList(ref));
        XMLObject obj = fac.newXMLObject(Collections.singletonList(
            new DOMStructure(doc.createTextNode(Base64.encode(getBytes(SMALL_DTD))))),
            "payload", null, null);
        XMLSignature signature = fac.newXMLSignature
            (si, null, Collections.singletonList(obj), null, null);
        signature.sign(new DOMSignContext(KEY, doc));

        Element sigElement = doc.getDocumentElement();
        Element objElement = (Element) doc.getElementsByTagNameNS
            (XMLSignature.XMLNS, "Object").item(0);

        assertTrue(validate(sigElement, objElement, null));
        try {
            validate(sigElement, objElement, SECURE_VALIDATION);
            fail("DTD accepted although secure validation is enabled");
        } catch (XMLSignatureException expected) {
        }

        while (objElement.getFirstChild() != null) {
            objElement.removeChild(objElement.getFirstChild());
        }
        objElement.appendChild(
            doc.createTextNode(Base64.encode(getBytes(BILLION_LAUGHS))));
        try {
            validate(sigElement, objElement, SECURE_VALIDATION);
            fail("DTD accepted although secure validation is enabled");
        } catch (XMLSignatureException expected) {
        }
    }

    private boolean validate(Element sigElement, Element objElement,
        String property) throws Exception {
        DOMValidateContext vc = new DOMValidateContext(KEY, sigElement);
        vc.setIdAttributeNS(objElement, null, "Id");
        if (property != null) {
            vc.setProperty(property, Boolean.TRUE);
        }
        XMLSignature signature = fac.unmarshalXMLSignature(vc);
        return signature.validate(vc);
    }

    private static String canonicalize(byte[] bytes, DOMValidateContext context)
        throws Exception {
        TransformService ts =
            TransformService.getInstance(CanonicalizationMethod.INCLUSIVE, "DOM");
        ts.init((TransformParameterSpec) null);
        Data data = ts.transform
            (new OctetStreamData(new ByteArrayInputStream(bytes)), context);
        byte[] result = org.jcp.xml.dsig.internal.dom.Utils.readBytesFromStream
            (((OctetStreamData) data).getOctetStream());
        return new String(result, "UTF-8");
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
