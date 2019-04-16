package cryptopro.jcp.example;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
//import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESSigner;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.CAdES.EnvelopedSignature;




@RestController
public class TestController {

    private final String SAMPLE_TEXT = "t";

    @Autowired
    private CertificateService certificateService;
	@Autowired
	ObjectMapper mapper;

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
    
    
    /**
     * Шифрование данных на сертификате клиента для дальнейшей расшифровки в Browser Plugin.
     * 
     * @param decrypt - данные для шифрования
     * @return - защифрованные данные
     * @throws Exception - исключения в процессе шифрования
     */
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
    
    /**
     * Расшфрование данных. Шифротекст формируется на клиенте (Browser Plugin) при помощи сертификата получателя (сервера)
     * 
     * @param decrypt - зашифрованные данные в формате base64
     * @return - расщифрованные данные
     * @throws Exception - исключения в процессе расщифровки
     */
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
    
	/**
	 * Проверка attached подписи с клиента (работает и Browser Plugin).
	 * В ответ от сервера так же отдается attached подпись сервера для дальнейшей проверки на клиенте.
	 * 
	 * @param body - данные в фомате {sign: "MUsadfzf=", data: "Mdsae23q==="}
	 * @return - ответ подписанный сервером в формате {sign: "MUsadfzf=", data: "Mdsae23q==="}  
	 * @throws Exception - исключения в процесс формирования подписиния/проверки
	 */
	@RequestMapping(method = RequestMethod.POST, consumes="application/json",  value = "/api/identity/auth_detach")
	@ResponseBody
	public String  auth_detach(@RequestBody String body) throws Exception {
		
	    JsonNode actualObj = mapper.readTree(body);
	    JsonNode jsonNode1 = actualObj.get("sign");
	    JsonNode jsonNode2 = actualObj.get("data");
	    String sign = jsonNode1.textValue();
	    String data  = jsonNode2.textValue();
	    
	    System.out.println("sign  "+ sign);
	    System.out.println("data  "+ data);
	    
	    try {
			
			  InputStream cadesCmsStream = new ByteArrayInputStream(org.bouncycastle.util.encoders.Base64.decode(sign.getBytes())); 
		      InputStream dataOfSign = new ByteArrayInputStream(org.bouncycastle.util.encoders.Base64.decode(data.getBytes())); 
		      
		      CAdESSignature cadesSignature = new CAdESSignature(cadesCmsStream, dataOfSign , CAdESType.CAdES_BES);

		      
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
		      //System.out.println("Signed content: "+certificateService.getSignedContent(sign));
		      
		      cadesCmsStream.close();
		      dataOfSign.close();
		        
		      certificateService.printSignatureInfo(cadesSignature);
		        
		      CAdESSigner[] signers = cadesSignature.getCAdESSignerInfos();
		      certificateService.printCAdESSignersInfo(signers);
		        
			}catch (Exception e) {
				e.printStackTrace();
				return "{\"test\":\"FAIL\"}";
			}
			return certificateService.testRespose(); 

	}
    
	/**
	 * Проверка attached подписи и ответ в виде подписанного сервером respons'а.(совместимо с подписью с Browser Plugin)
	 * Клиент отправляет подписанный контент (с приложенным личным сертификатом), сервер проверяет
	 * подпись и отдает подписанный сервером  ответ на клиента.
	 *  
	 * @param sign - подписанный тест в формате base64
	 * @return - при успешной проверки входящей подписи, формируется подписанный сервером ответ 
	 * @throws Exception - исключения в процессе проверки и формирования
	 */
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
		return certificateService.testRespose(); 
	}
}
