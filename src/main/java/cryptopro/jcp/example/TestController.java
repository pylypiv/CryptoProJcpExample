package cryptopro.jcp.example;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.Certificate;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
//import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.CloseShieldInputStream;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.cms.SignedDataParser;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.objsys.asn1j.runtime.Asn1BerDecodeBuffer;
import com.sun.xml.internal.ws.server.provider.ProviderArgumentsBuilder;

import CAdES.VerifyExample;
import CAdES.VerifyExample.SignatureType;
import CAdES.configuration.IConfiguration;
import CAdES.configuration.SimpleConfiguration;
import CAdES.configuration.container.Container2012_512;
import ru.CryptoPro.AdES.AdESConfig;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESSigner;
import ru.CryptoPro.CAdES.CAdESSignerFactory;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.CAdES.EnvelopedSignature;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignedData;




@RestController
public class TestController {

    private final String SAMPLE_TEXT = "t";

    @Autowired
    private CertificateService certificateService;

    @RequestMapping("/")
    @ResponseBody
    StringBuilder home() throws Exception {
        StringBuilder response = new StringBuilder();
        final byte[] signEL = certificateService.sign(Constants.SIGN_EL_ALG_2012_256,
                SAMPLE_TEXT.getBytes());
        response.append("Value of signature (signEL) is:");
        response.append(System.getProperty("line.separator"));
        response.append(Constants.toHexString(signEL));
        response.append(System.getProperty("line.separator"));
        // Проверка подписи
        final boolean signELver = certificateService.verify(Constants.SIGN_EL_ALG_2012_256,
                SAMPLE_TEXT.getBytes(), signEL);
        response.append("Signature verifies (signEL) is: " + signELver);
        
        
        
        // Задаем провайдер подписи и хеширования Java CSP.
      //  System.setProperty(AdESConfig.DEFAULT_PROVIDER, "JCSP");
        
        return response;
    }
    
    
    @RequestMapping(method = RequestMethod.POST, consumes="text/plain",  value = "/api/identity/decrypt_back")
	@ResponseBody
    public String  decryptBack(@RequestBody String decrypt) throws Exception {
    	System.out.println("decrypt_back "+ decrypt);
    	//byte data[] = org.bouncycastle.util.encoders.Base64.encode(decrypt.getBytes());
    	byte data[] = decrypt.getBytes();
    	ByteArrayOutputStream envelopedByteArrayOutStream = new ByteArrayOutputStream();
    	
    	// получение сертификата которым будем зашифровывать данные
	      final List<X509Certificate> certs = new ArrayList<X509Certificate>();
	      certs.add(certificateService.getCertificate("pylypiv.cer"));
	      
	      EnvelopedSignature signature = new EnvelopedSignature();
	      signature.addKeyTransRecipient(certs.get(0));
	      
	      signature.open(envelopedByteArrayOutStream);
	        signature.update(data);

	        signature.close();
    	
    	return "{\"crypt_back\":\""+new String(org.bouncycastle.util.encoders.Base64.encode(envelopedByteArrayOutStream.toByteArray())) +"\"}";
    }
    
    @RequestMapping(method = RequestMethod.POST, consumes="text/plain",  value = "/api/identity/decrypt")
	@ResponseBody
	public String  decrypt(@RequestBody String decrypt) throws Exception {
    	System.out.println("TEST " + decrypt);
    	
    	PrivateKey pk = certificateService.getPrivateKey(certificateService.getSTORE_PATH_2012_256(), certificateService.getALIAS_2012_256());
    	java.security.cert.Certificate crt = certificateService.getCertificate();
    	
    	 // Буфер для сохранения расшифрованных данных
    	 ByteArrayOutputStream decryptedByteDataStream = new ByteArrayOutputStream();
    	 // Прочитанное в буфер сообщение формата Enveloped CMS
    	 byte[] envelopedByteData = org.bouncycastle.util.encoders.Base64.decode(decrypt.getBytes());
    	
        EnvelopedSignature signatureStream = new EnvelopedSignature(new ByteArrayInputStream(envelopedByteData));
         signatureStream.decrypt((X509Certificate) crt, pk, decryptedByteDataStream);
        
        // Расшифрование подписи на закрытом ключе получателя с записью
        // расшифрованных данных в буфер decryptedByteDataStream
       // signature.decrypt(recipientCertificate, recipientPrivateKey, decryptedByteDataStream);

        // Получение расшифрованных данных - строки или CMS, которую можно
        // далее проверить с помощью CMSVerify (samples.jar) или CAdES.jar
        byte[] decryptedByteData = decryptedByteDataStream.toByteArray();
        System.out.println("decrypt "+ new String(decryptedByteData));
        
        decryptedByteDataStream.close();
        
        
		return "{\"decode\":\""+new String(decryptedByteData)+"\"}"; 
    }
    
	@RequestMapping(method = RequestMethod.POST, consumes="text/plain",  value = "/api/identity/auth")
	@ResponseBody
	public String  auth(@RequestBody String sign) throws Exception {
		
		try {
			
		  InputStream cadesCmsStream = new ByteArrayInputStream(org.bouncycastle.util.encoders.Base64.decode(sign.getBytes())); 
	      InputStream dataOfSign = new ByteArrayInputStream("test".getBytes(StandardCharsets.UTF_8)); // test dGVzdA==
	      
	      CAdESSignature cadesSignature = new CAdESSignature(cadesCmsStream, null, CAdESType.CAdES_BES);

	      
	      // определение списка сертификатов, из которых осуществляется построение цепочки
	      // путем эксперемента определил что достаточно корневой сертификат. (при корневой<>пользовательский) 
	      final List<X509Certificate> certs = new ArrayList<X509Certificate>();
	      certs.add(certificateService.getCertificate("chainPsr0"));
	      
	      
	      /**
	       * Список СОС для проверки подписи.
	       */
	      Set<X509CRL> crlList = new HashSet<X509CRL>();
	      File crlFile = new File("/home/psr/Рабочий стол/certcrl.crl");
          X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new FileInputStream(crlFile));
          crlList.add(crl);

	      cadesSignature.verify(certs, crlList);
	      System.out.println("Signed content: "+certificateService.getSignedContent(sign));
	      
	      cadesCmsStream.close();
	      dataOfSign.close();
	        
	      certificateService.printSignatureInfo(cadesSignature);
	        
	      CAdESSigner[] signers = cadesSignature.getCAdESSignerInfos();
	      certificateService.printCAdESSignersInfo(signers);
	        
		}catch (Exception e) {
			e.printStackTrace();
			return "{\"test\":\"FAIL\"}";
		}
		return certificateService.testRespose("{\"test\":\"LUCK\"}"); 
	}
}
