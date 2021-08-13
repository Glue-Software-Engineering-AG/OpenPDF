package com.lowagie.text.pdf;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Security;
import java.security.SignatureException;
import java.util.ArrayList;

public class PdfPKCS7Test
{
  @Test public void test_sha512_signature_rsa_pss() throws IOException, SignatureException
  {
    Security.addProvider(new BouncyCastleProvider());
    PdfReader reader = new PdfReader(PdfPKCS7Test.class.getResourceAsStream("/rsapss/sha512_rsa_pss.pdf"));
    AcroFields fields = reader.getAcroFields();
    ArrayList<String> sigNames = fields.getSignatureNames();
    for (String sigName : sigNames)
    {
      PdfPKCS7 result = fields.verifySignature(sigName, "BC");
      Assert.assertTrue(result.verify());
    }
  }

  @Test public void test_sha256_signature_rsa_pss() throws SignatureException, IOException
  {
    Security.addProvider(new BouncyCastleProvider());
    PdfReader reader = new PdfReader(PdfPKCS7Test.class.getResourceAsStream("/rsapss/sha256_rsa_pss.pdf"));
    AcroFields fields = reader.getAcroFields();
    ArrayList<String> sigNames = fields.getSignatureNames();
    for (String sigName : sigNames)
    {
      PdfPKCS7 result = fields.verifySignature(sigName, "BC");
      Assert.assertTrue(result.verify());
    }
  }

  /**
   * Dumps the ASN1 structure to System.out or a File.
   * <p>
   * Also see: https://stackoverflow.com/a/10550879/5658642
   *
   * @throws IOException
   */
  @Test public void dump_asn1() throws IOException
  {
    Security.addProvider(new BouncyCastleProvider());
    PdfReader reader = new PdfReader(PdfPKCS7Test.class.getResourceAsStream("/rsapss/sha512_rsa_pss.pdf"));
    AcroFields fields = reader.getAcroFields();
    ArrayList<String> sigNames = fields.getSignatureNames();
    for (String sigName : sigNames)
    {
      PdfDictionary signatureDictionary = fields.getSignatureDictionary(sigName);
      byte[] pkcsAsBytes = signatureDictionary.get(PdfName.CONTENTS).getBytes();
      ASN1InputStream bIn = new ASN1InputStream(new ByteArrayInputStream(pkcsAsBytes));
      ASN1Primitive obj = bIn.readObject();
      System.out.println(ASN1Dump.dumpAsString(obj, true));
      //      FileOutputStream fos = new FileOutputStream("asn1_dump.txt");
      //      fos.write(ASN1Dump.dumpAsString(obj, true).getBytes(StandardCharsets.UTF_8));
    }

  }

}
