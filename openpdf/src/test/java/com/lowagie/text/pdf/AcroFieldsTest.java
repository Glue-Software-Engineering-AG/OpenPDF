package com.lowagie.text.pdf;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Security;
import java.util.ArrayList;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import com.lowagie.text.Document;
import com.lowagie.text.PageSize;

public class AcroFieldsTest {

    /**
     * This test fails, because signatureCoversWholeDocument does only check the
     * last signed block.
     */
    @Test
    public void testGetSignatures() throws Exception {
        // for algorithm SHA256 (without dash)
        Security.addProvider(new BouncyCastleProvider());
        InputStream moddedFile = AcroFieldsTest.class.getResourceAsStream("/siwa.pdf");
        PdfReader reader = new PdfReader(moddedFile);
        Document document = new Document(PageSize.A4);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PdfWriter writer = PdfWriter.getInstance(document, out);

        AcroFields fields = new AcroFields(reader, writer);
        ArrayList<String> names = fields.getSignatureNames();
        Assert.assertEquals(1, names.size());

        for (String signName : names) {
            Assert.assertFalse(fields.signatureCoversWholeDocument(signName));
            PdfPKCS7 pdfPkcs7 = fields.verifySignature(signName, "BC");
            Assert.assertTrue(pdfPkcs7.verify());
        }

    }

}
