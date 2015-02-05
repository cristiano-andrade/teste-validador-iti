package io.cristiano.signature.validator;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import java.io.InputStream;
import java.util.logging.Logger;

public class SignatureTestCase {

    private static final Logger LOGGER = Logger.getLogger("SignatureTestCase");

    @Test
    public void shouldSignatureADRV() throws Exception {
        InputStream signedData = getClass().getResourceAsStream("/pkcs7/ADRV.p7s");
        CMSSignedData cmsSignedData = new CMSSignedData(IOUtils.toByteArray(signedData));

        SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos();

        for (Object obj : signerInformationStore.getSigners()) {

            SignerInformation signerInfo = (SignerInformation) obj;

            //1.2.840.113549.1.9.16.2.21
            //1.2.840.113549.1.9.16.2.22
            AttributeTable attributeTable = signerInfo.getUnsignedAttributes();

            Attribute certificateRefs = attributeTable.get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs);

            LOGGER.info("###### CertificateRefs: " +
                    ASN1Dump.dumpAsString(certificateRefs));

            Attribute revocationRefs = attributeTable.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);

            LOGGER.info("###### RevocationRefs: " +
                    ASN1Dump.dumpAsString(revocationRefs));

            Assert.assertNotNull(certificateRefs.getAttrValues().getObjectAt(0));
            Assert.assertNotNull(revocationRefs.getAttrValues().getObjectAt(0));
        }
    }

    @Test
    public void shouldSignatureADRT() throws Exception {
        InputStream signedData = getClass().getResourceAsStream("/pkcs7/ADRT.p7s");
        CMSSignedData cmsSignedData = new CMSSignedData(IOUtils.toByteArray(signedData));

        SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos();

        for (Object obj : signerInformationStore.getSigners()) {

            SignerInformation signerInfo = (SignerInformation) obj;

            AttributeTable attributeTable = signerInfo.getUnsignedAttributes();

            Attribute signatureTimeStampToken = attributeTable.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);

            LOGGER.info("###### TimeStampToken: " +
                    ASN1Dump.dumpAsString(signatureTimeStampToken));


            TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(signatureTimeStampToken.getAttrValues()
                    .getObjectAt(0).getDERObject().getDEREncoded()));

            Assert.assertNotNull(timeStampToken);

            LOGGER.info("Serial Number: " + timeStampToken.getTimeStampInfo().getSerialNumber());
            LOGGER.info("AlgOID: " + timeStampToken.getTimeStampInfo().getMessageImprintAlgOID());
        }
    }


    @Test
    public void shouldSignerCertificateIsSignerOnly() throws Exception {
        InputStream signedData = getClass().getResourceAsStream("/pkcs7/ADRT.p7s");
        CMSSignedData cmsSignedData = new CMSSignedData(IOUtils.toByteArray(signedData));

        SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos();

        for (Object obj : signerInformationStore.getSigners()) {

            SignerInformation signerInfo = (SignerInformation) obj;

            AttributeTable attributeTable = signerInfo.getSignedAttributes();

            Attribute signerCertificate = attributeTable
                    .get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);

            SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2((ASN1Sequence) signerCertificate.getAttrValues().getObjectAt(0).getDERObject());

            Assume.assumeNotNull(signingCertificateV2);
            //signerOnly
            Assert.assertEquals(signingCertificateV2.getCerts().length,1);
        }
    }


}

