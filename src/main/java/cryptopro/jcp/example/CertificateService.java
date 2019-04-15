package cryptopro.jcp.example;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import com.objsys.asn1j.runtime.Asn1Boolean;
import com.objsys.asn1j.runtime.Asn1ObjectIdentifier;
import com.objsys.asn1j.runtime.Asn1OctetString;

import org.apache.commons.io.Charsets;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.CollectionStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Extension;
import ru.CryptoPro.CAdES.CAdESConfig;
import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.CAdESSigner;
import ru.CryptoPro.CAdES.CAdESSignerXLT1;
import ru.CryptoPro.CAdES.CAdESType;
import ru.CryptoPro.CAdES.exception.CAdESException;
import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.Random.BioRandomConsole;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.JCPRequest.GostCertificateRequest;

import javax.annotation.PostConstruct;

/**
 * Сервис, для работы с сертификатами и подписями. Содержит методы чтения сертификата, записи сертификата и приватного ключа,
 * генерации электронной подписи и проверки электронной подписи.
 */
@Service
public class CertificateService {
    /**
     * уникальное имя записываемого сертификата
     */
    @Value("${certificate.alias_2012_256}")
    private String ALIAS_2012_256;
    /**
     * имя субъекта для генерирования запроса на сертификат
     */
    @Value("${certificate.dname_2012_256}")
    private String DNAME_2012_256;
    /**
     * http-адрес центра центра сертификации
     */
    @Value("${ocsp.http_address}")
    private String HTTP_ADDRESS;
    /**
     * путь к файлу хранилища сертификатов
     */
    @Value("${certificate.store_path_2012_256}")
    private String STORE_PATH_2012_256;

	/**
     * имя ключевого носителя для инициализации хранилища
     */
    private final String STORE_TYPE = Constants.KEYSTORE_TYPE;
    /**
     * устанавливаемый пароль на хранилище сертификатов
     */
    private final char[] STORE_PASS = new char[] {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    /**
     * алгоритм ключа (ГОСТ Р 34.10-2012, 256)
     */
    private static final String KEY_ALG_2012_256 = Constants.SIGN_KEY_PAIR_ALG_2012_256;

    @Autowired
    private KeyPairGeneratorService keyPairGeneratorService;

    /**
     * Инициализация хранилища сертификатов, если оно не существует.
     * В течении инициализации создается пара ключей(приватный и публичный), и сохраняются в хранилище,
     * которое содержится в файле STORE_PATH_2012_256
     * @throws Exception
     */
    @PostConstruct
    private void initCertificatesStorage() throws Exception {
        BioRandomConsole.main(null);
        System.out.println("STORE_PATH_2012_256 " + STORE_PATH_2012_256);
        Optional<Certificate> optional = readCertSample(STORE_PATH_2012_256, ALIAS_2012_256);
        if (!optional.isPresent()) {
            //получение сертификата и запись его в хранилище
            writeCertSample(JCP.GOST_DH_2012_256_NAME, JCP.GOST_SIGN_2012_256_NAME,
                    ALIAS_2012_256, STORE_PATH_2012_256, DNAME_2012_256);
            System.out.println("Storage with certificate and private key " + STORE_PATH_2012_256 + " has been created");
        } else {
            System.out.println("Storage " + STORE_PATH_2012_256 + " exists");
        }
    }

    /**
     * Возвращает сертификат
     * @return сертификат из хранилища, определенного в файле STORE_PATH_2012_256
     * @throws Exception
     */
    public Certificate getCertificate() throws Exception {
        Optional<Certificate> optional = readCertSample(STORE_PATH_2012_256, ALIAS_2012_256);
        return optional.orElse(null);
    }

    /**
     * Создание подписи
     *
     * @param alghorithmName алгоритм подписи
     * @param data подписываемые данные
     * @return подпись
     * @throws Exception /
     */
    public byte[] sign(String alghorithmName, byte[] data) throws Exception {
        return sign(alghorithmName,getPrivateKey(STORE_PATH_2012_256, ALIAS_2012_256), data);
    }
    
	/**
	 * Вывод информации о подписи: кто подписал, тип подписи, штампы времени.
	 * 
	 * @param signature CAdES подпись.
	 * @throws IOException 
	 */
	public void printSignatureInfo(CAdESSignature signature) throws IOException {

        System.out.println("$$$ Print signature information $$$");

		// Список подписей.
		int signerIndex = 1;
		for (CAdESSigner signer : signature.getCAdESSignerInfos()) {
			printSignerInfo(signer, signerIndex++, "");
		}
	}

    /**
     * Проверка подписи на открытом ключе
     *
     * @param alghorithmName алгоритм подписи
     * @param data подписываемые данные
     * @param signature подпись
     * @return true - верна, false - не верна
     * @throws Exception /
     */
    public boolean verify(String alghorithmName,
                                 byte[] data, byte[] signature) throws Exception {
        return verify(alghorithmName, getPublicKey(STORE_PATH_2012_256, ALIAS_2012_256), data, signature);
    }

    /**
     * Пример генерирования запроса, отправки запроса центру сертификации и записи
     * полученного от центра сертификата в хранилище доверенных сертификатов
     *
     * @param keyAlg Алгоритм ключа.
     * @param signAlg Алгоритм подписи.
     * @param alias Алиас ключа для сохранения.
     * @param storePath Путь к хранилищу сертификатов.
     * @param dnName DN-имя сертификата.
     * @throws Exception /
     */
    private void writeCertSample(String keyAlg, String signAlg,
                                       String alias, String storePath, String dnName) throws Exception {
    	
        OID keyOid = new OID("1.2.643.7.1.1.1.1");
        OID signOid = new OID("1.2.643.2.2.35.2");
        OID digestOid = new OID("1.2.643.7.1.1.2.2");
        //OID cryptOid = new OID("1.2.643.7.1.2.5.1.1");
        OID cryptOid = new OID("1.2.643.2.2.31.1");
        
    	
        /* Генерирование ключевой пары в соответствии с которой будет создан запрос
        на сертификат*/
        KeyPair keypair = keyPairGeneratorService.genKey(keyAlg);
    	//KeyPair keypair = keyPairGeneratorService.genKeyWithParams(JCP.GOST_EL_2012_256_NAME, keyOid, signOid, digestOid, cryptOid);
        // отправка запроса центру сертификации и получение от центра
        // сертификата в DER-кодировке
        byte[] encoded = createRequestAndGetCert(keypair, signAlg, JCP.PROVIDER_NAME, dnName);

        // инициализация генератора X509-сертификатов
        CertificateFactory cf = CertificateFactory.getInstance(Constants.CF_ALG);
        // генерирование X509-сертификата из закодированного представления сертификата
        Certificate cert =
                cf.generateCertificate(new ByteArrayInputStream(encoded));

        /* Запись полученного от центра сертификата*/
        // инициализация хранилища доверенных сертификатов именем ключевого носителя
        // (жесткий диск)
        KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
        // загрузка содержимого хранилища (предполагается, что инициализация
        // хранилища именем CertStoreName производится впервые, т.е. хранилища
        // с таким именем пока не существует)
        keyStore.load(null, null);

        //удаляем если уже существует
        if(keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias);
        }
        // запись сертификата в хранилище доверенных сертификатов
        // (предполагается, что на носителе с именем CertStoreName не существует
        // ключа с тем же именем alias)
        keyStore.setCertificateEntry(alias, cert);
        keyStore.setKeyEntry(alias, keypair.getPrivate(), STORE_PASS, new Certificate[]{cert});

        // определение пути к файлу для сохранения в него содержимого хранилища
        File file = new File(storePath);
        if (!file.exists()) {
            file.getParentFile().mkdirs();
        }
        // сохранение содержимого хранилища в файл
        keyStore.store(new FileOutputStream(file), STORE_PASS);
    }

    /**
     * Пример чтения сертификата из хранилища и записи его в файл
     *
     * @param storePath Путь к хранилищу сертификатов.
     * @param alias Алиас ключа подписи.
     * @throws Exception /
     */
    private Optional<Certificate> readCertSample(String storePath, String alias) throws Exception {
    /* Чтение сертификата их хранилища доверенных сертификатов */
        // инициализация хранилища доверенных сертификатов именем ключевого носителя
        // (жесткий диск)
        final KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
        // определение пути к файлу для чтения содержимого хранилища
        // и последующего его сохранения
        final File file = new File(storePath);
        if (!file.exists()) {
            return Optional.empty();
        }
        // загрузка содержимого хранилища (предполагается, что хранилище,
        // проинициализированное именем CertStoreName существует)
        keyStore.load(new FileInputStream(file), STORE_PASS);

        // чтение сертификата из хранилища доверенных сертификатов
        // (предполагается, что на носителе с именем CertStoreName не существует
        // ключа с тем же именем alias)
        final Certificate cert = keyStore.getCertificate(alias);

        // сохранение содержимого хранилища в файл с тем же паролем
        keyStore.store(new FileOutputStream(file), STORE_PASS);
        return Optional.of(cert);
    }

    public PrivateKey getPrivateKey(String storePath, String alias) throws KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        final KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
        final File file = new File(storePath);
        if (!file.exists()) {
           throw new FileNotFoundException("File " + STORE_TYPE + " not found while retrieving private key");
        }
        keyStore.load(new FileInputStream(file), STORE_PASS);
        return (PrivateKey) keyStore.getKey(alias, STORE_PASS);
    }

    public PublicKey getPublicKey(String storePath, String alias) throws KeyStoreException, IOException,
            CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        final KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
        final File file = new File(storePath);
        if (!file.exists()) {
            throw new FileNotFoundException("File " + STORE_TYPE + " not found while retrieving public key");
        }
        keyStore.load(new FileInputStream(file), STORE_PASS);
        Certificate certificate = keyStore.getCertificate(alias);
        if (certificate == null) {
            throw new CertificateException("Certificate with alias " + alias + " not found while retrieving public key");
        }
        return certificate.getPublicKey();
    }

    /**
     * Функция формирует запрос на сертификат, отправляет запрос центру сертификации
     * и получает от центра сертификат.
     *
     * @param pair ключевая пара. Открытый ключ попадает в запрос на сертификат,
     * секретный ключ для подписи запроса.
     * @param signAlgorithm Алгоритм подписи.
     * @param signatureProvider Провайдер подписи.
     * @param dnName DN-имя сертификата.
     * @return сертификат в DER-кодировке
     * @throws Exception errors
     */
    private byte[] createRequestAndGetCert(KeyPair pair, String signAlgorithm,
                                                 String signatureProvider, String dnName) throws Exception {

        // формирование запроса
        GostCertificateRequest request = createRequest(pair,
                signAlgorithm, signatureProvider, dnName);

        // отправка запроса центру сертификации и получение от центра
        // сертификата в DER-кодировке
        return request.getEncodedCert(HTTP_ADDRESS);
    }

    /**
     * Функция формирует запрос на сертификат.
     *
     * @param pair ключевая пара. Открытый ключ попадает в запрос на сертификат,
     * секретный ключ для подписи запроса.
     * @param signAlgorithm Алгоритм подписи.
     * @param signatureProvider Провайдер подписи.
     * @param dnName DN-имя сертификата.
     * @return запрос
     * @throws Exception errors
     */
    private GostCertificateRequest createRequest(KeyPair pair, String signAlgorithm,
                                                       String signatureProvider, String dnName) throws Exception {
    /* Генерирование запроса на сертификат в соответствии с открытым ключом*/
        // создание генератора запроса на сертификат
        GostCertificateRequest request = new GostCertificateRequest(signatureProvider);
        // инициализация генератора
        // @deprecated с версии 1.0.48
        // вместо init() лучше использовать setKeyUsage() и addExtKeyUsage()
        // request.init(KEY_ALG);

    /*
    Установить keyUsage способ использования ключа можно функцией
    setKeyUsage. По умолчанию для ключа подписи, т.е. для указанного в первом
    параметре функции init() алгоритма "GOST3410EL" используется комбинация
    DIGITAL_SIGNATURE | NON_REPUDIATION. Для ключа шифрования, т.е. для
    алгоритма "GOST3410DHEL" добавляется KEY_ENCIPHERMENT | KEY_AGREEMENT.
    */
   /*     final String keyAlgorithm = pair.getPrivate().getAlgorithm();
        if (keyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_DEGREE_NAME) ||
                keyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_256_NAME) ||
                keyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_512_NAME)) {
            int keyUsage = GostCertificateRequest.DIGITAL_SIGNATURE |
                    GostCertificateRequest.NON_REPUDIATION;
            request.setKeyUsage(keyUsage);
        }
        else {*/
            int keyUsage = GostCertificateRequest.DIGITAL_SIGNATURE |
                    GostCertificateRequest.NON_REPUDIATION |
                    GostCertificateRequest.KEY_ENCIPHERMENT |
                    GostCertificateRequest.KEY_AGREEMENT |
                    GostCertificateRequest.DATA_ENCIPHERMENT;
            request.setKeyUsage(keyUsage);
        //}

    /*
    Добавить ExtendedKeyUsage можно так. По умолчанию для ключа подписи,
    т.е. для алгоритма "GOST3410EL" список будет пустым. Для ключа
    шифрования, т.е. для алгоритма "GOST3410DHEL" добавляется OID
    INTS_PKIX_CLIENT_AUTH "1.3.6.1.5.5.7.3.2", а при установленном в true
    втором параметре функции init() еще добавляется INTS_PKIX_SERVER_AUTH
    "1.3.6.1.5.5.7.3.1"
    */
        request.addExtKeyUsage(GostCertificateRequest.INTS_PKIX_EMAIL_PROTECTION);

        // определение параметров и значения открытого ключа
        request.setPublicKeyInfo(pair.getPublic());
        // определение имени субъекта для создания запроса
        request.setSubjectInfo(dnName);
        // подпись сертификата на закрытом ключе и кодирование запроса
        request.encodeAndSign(pair.getPrivate(), signAlgorithm);

        return request;
    }

    private byte[] sign(String alghorithmName, PrivateKey privateKey,
                        byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature sign = Signature.getInstance(alghorithmName);
        sign.initSign(privateKey);
        sign.update(data);
        return sign.sign();
    }

    private boolean verify(String alghorithmName, PublicKey publicKey,
                           byte[] data, byte[] signature) throws Exception {
        final Signature sig = Signature.getInstance(alghorithmName);
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }
    
	/**
	 * Вывод информации об отдельной подписи.
	 * 
	 * @param signer Подпись.
	 * @param index Индекс подписи.
	 * @param tab Отступ для удобства печати.
	 * @throws IOException 
	 */
	private void printSignerInfo(CAdESSigner signer, int index, String tab) throws IOException {
		
		X509Certificate signerCert = signer.getSignerCertificate();
		
		System.out.println(tab + " Signature #" + index + " (" + 
			CAdESType.getSignatureTypeName(signer.getSignatureType()) + ")" + 
			(signerCert != null ? (" verified by " + signerCert.getSubjectDN()) : "" ));

		if ( signer.getSignatureType().equals(CAdESType.CAdES_X_Long_Type_1) ) {
							
			TimeStampToken signatureTimeStamp = ((CAdESSignerXLT1)signer).getEarliestValidSignatureTimeStampToken();
			TimeStampToken cadesCTimeStamp = ((CAdESSignerXLT1)signer).getEarliestValidCAdESCTimeStampToken();
			
			if (signatureTimeStamp != null) {
				System.out.println(tab + "***" + " Signature timestamp set: " + 
					signatureTimeStamp.getTimeStampInfo().getGenTime());
			} // if
			
			if (cadesCTimeStamp != null) {
				System.out.println(tab + "***" + " CAdES-C timestamp set: " + 
					cadesCTimeStamp.getTimeStampInfo().getGenTime());
			} // if

		} // if

        printSignerAttributeTableInfo(index, signer.getSignerSignedAttributes(), "signed");

        printSignerAttributeTableInfo(index, signer.getSignerUnsignedAttributes(), "unsigned");

        printCountersignerInfos(signer.getCAdESCountersignerInfos());
	}
	
    /**
     * Вывод содержимого таблицы аттрибутов.
     *
     * @param i Номер подписанта.
     * @param table Таблица с аттрибутами.
     * @param type Тип таблицы: "signed" или "unsigned".
     * @throws IOException 
     */
    public  void printSignerAttributeTableInfo(int i, AttributeTable table,
        String type) throws IOException {

        if (table == null) {
            return;
        } // if

        System.out.println("Signer #" + i + " has " + table.size() + " " +
            type + " attributes.");

        Hashtable attributes = table.toHashtable();
        Enumeration attributesEnum = attributes.elements();

        while (attributesEnum.hasMoreElements()) {

            Attribute attribute = Attribute.getInstance(attributesEnum.nextElement());
            System.out.println(" Attribute" +
                "\n\ttype : " + attribute.getAttrType().getId() +
                "\n\tvalue: " + attribute.getAttrValues());
            
            
        } // while
    }
    
	/**
	 * Вывод информации о заверителях отдельной подписи.
	 * 
	 * @param countersigners Список заверителей.
	 * @throws IOException 
	 */
	private void printCountersignerInfos(CAdESSigner[] countersigners) throws IOException {

        System.out.println("$$$ Print counter signature information $$$");

		// Заверяющие подписи.
		int countersignerIndex = 1;
		for (CAdESSigner countersigner : countersigners) {
			printSignerInfo(countersigner, countersignerIndex++, "***");
		}
	}
	
    /**
     * Вывод информации о подписантах.
     *
     * @param signers Список подписантов.
     * @throws Exception
     */
    public void printCAdESSignersInfo(CAdESSigner[] signers)
        throws Exception {

        for (int i = 0; i < signers.length; i++) {

            CAdESSigner signer = signers[i];
            
            if (signer instanceof CAdESSignerXLT1) {

                CAdESSignerXLT1 cAdESSignerXLT1 = (CAdESSignerXLT1) signer;
                System.out.println("Check timestamps #" + i + ":");

                TimeStampToken signTimestamp = cAdESSignerXLT1.getEarliestValidSignatureTimeStampToken();
                if (signTimestamp == null) {
                    throw new Exception("Signature timestamp is null");
                } // if

                TimeStampToken cdsCTimestamp = cAdESSignerXLT1.getEarliestValidCAdESCTimeStampToken();
                if (cdsCTimestamp == null) {
                    throw new Exception("CAdES-C timestamp is null");
                } // if

                List<TimeStampToken> signatureTimeStampTokens = cAdESSignerXLT1.getSignatureTimestampTokens();
                if (signatureTimeStampTokens == null) {
                    throw new Exception("Signature timestamp list is null");
                } // if

                int sz = signatureTimeStampTokens.size();
                if (sz != 1) {
                    throw new Exception("It is weird... Size of signature timestamp " +
                        "list is more than 1 (" + sz + ")");
                } // if

                List<TimeStampToken> cadesCTimeStampTokens = cAdESSignerXLT1.getCAdESCTimestampTokens();
                if (cadesCTimeStampTokens == null) {
                    throw new Exception("CAdES-C timestamp list is null");
                } // if

                sz = cadesCTimeStampTokens.size();
                if (sz != 1) {
                    throw new Exception("It is weird... Size of CAdES-C timestamp " +
                        "list is more than 1 (" + sz + ")");
                } // if

            } // if

        } // for

    }

	public String getSignedContent(String sign) throws CMSException {
		
      CMSSignedData signature = new CMSSignedData(org.bouncycastle.util.encoders.Base64.decode(sign.getBytes()));
      CMSProcessable sc = signature.getSignedContent();
      byte[] data = (byte[]) sc.getContent();
      
      return new String(data);
	}

	
	
	public String testRespose(String string) throws Exception {
		
		PrivateKey pk = getPrivateKey(STORE_PATH_2012_256, ALIAS_2012_256);
		CAdESSignature cadesSignature = new CAdESSignature(false); // совмещенная
		
	      // определение списка сертификатов, из которых осуществляется построение цепочки
	      // путем эксперемента определил что достаточно корневой сертификат. (при корневой<>пользовательский) 
	      final List<X509Certificate> certs = new ArrayList<X509Certificate>();
	      certs.add((X509Certificate) getCertificate());
	      //certs.add(getCertificate("chainserv11"));
	      //certs.add(getCertificate("chainserv10"));
	      
	      /**
	       * Список СОС для проверки подписи.
	       */
	      Set<X509CRL> crlList = new HashSet<X509CRL>();
	      File crlFile = new File("/home/psr/Рабочий стол/certcrl.crl");
          X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new FileInputStream(crlFile));
          crlList.add(crl);
          
          /**
           * Добавление сертификатов в подпись
           */
          Collection<X509CertificateHolder> holderList = new ArrayList<X509CertificateHolder>();
          for (X509Certificate cert : certs) {
        	  	holderList.add(new X509CertificateHolder(cert.getEncoded()));
          } 
          cadesSignature.setCertificateStore(new CollectionStore(holderList));
          
          
          final Hashtable table = new Hashtable();
          Attribute attr = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date())));
          table.put(attr.getAttrType(), attr);
	      
		String digest = getDigestOid(pk);
		String publickeyOID = getPublicKeyOid(pk);
		
		/**
		  
		        provider - Криптопровайдер для хеширования и подписи.
			    digestAlgorithm - Идентификатор алгоритма хэширования.
			    encryptionAlgorithm - Идентификатор алгоритма шифрования.
			    privateKey - Закрытый ключ для подписи.
			    chain - Цепочка сертификатов подписанта. Должна содержать как минимум один сертификат (сертификат подписи).
			    signatureType - Тип создаваемой подписи.
			    tsaUrl - Адрес TSA службы (для CAdES-T или CAdES-X Long Type 1). Может быть null.
			    countersignature - True, если подпись заверяющая.
			    signedAttributes - Таблица подписанных аттрибутов для добавления в подпись. Может быть null.
			    unsignedAttributes - Таблица неподписанных аттрибутов для добавления в подпись. Может быть null.
			    cRLs - Список CRL для проверки цепочки сертификатов подписанта или цепочки сертификатов штампа времени при создании подписи формата CAdES-BES или CAdES-T. Может быть null.
		 * */
		
		cadesSignature.addSigner(JCP.PROVIDER_NAME, digest, publickeyOID, pk, certs, CAdESType.CAdES_BES, null, false, new  AttributeTable(table), null, crlList);
		
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		cadesSignature.open(baos);
		cadesSignature.update("тест".getBytes());
		// Создание подписи с выводом в baos
		cadesSignature.close();
		baos.close();
		
		byte [] sign = org.bouncycastle.util.encoders.Base64.encode(baos.toByteArray());
		
		System.out.println(new String(sign));
		
		return "{\"sign\":\""+new String(sign)+"\"}";		
		
//		return "{\"sign\":\"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\"}";
	}
    
	
	  public String getDigestOid(PrivateKey privateKey) {

	        String privateKeyAlgorithm = privateKey.getAlgorithm();

	        if (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_256_NAME) ||
	            privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_DH_2012_256_NAME)) {
	            return JCP.GOST_DIGEST_2012_256_OID;
	        } // if
	        else if (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_512_NAME) ||
	            privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_DH_2012_512_NAME)) {
	            return JCP.GOST_DIGEST_2012_512_OID;
	        } // if

	        return JCP.GOST_DIGEST_OID;
	    }
	  
	  
	    public String getPublicKeyOid(PrivateKey privateKey) {

	        String privateKeyAlgorithm = privateKey.getAlgorithm();

	        if (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_256_NAME)) {
	            return JCP.GOST_PARAMS_SIG_2012_256_KEY_OID;
	        } // if
	        if (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_DH_2012_256_NAME)) {
	            return JCP.GOST_PARAMS_EXC_2012_256_KEY_OID;
	        } // if
	        else if (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_2012_512_NAME)) {
	            return JCP.GOST_PARAMS_SIG_2012_512_KEY_OID;
	        } // if
	        else if (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_DH_2012_512_NAME)) {
	            return JCP.GOST_PARAMS_EXC_2012_512_KEY_OID;
	        } // if
	        else if (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_DEGREE_NAME)) {
	            return JCP.GOST_EL_KEY_OID;
	        } // if
	        else if (privateKeyAlgorithm.equalsIgnoreCase(JCP.GOST_EL_DH_NAME)) {
	            return JCP.GOST_EL_DH_OID;
	        } // if

	        return privateKeyAlgorithm;

	    }
	    
		/**
		 * Получить корневой сертификат из преднастроенного хранилища
		 * 
		 * @param alias - название корневого сертификата
		 * @return - корневой сертификат из хранилища 
		 * @throws KeyStoreException
		 * @throws NoSuchProviderException
		 * @throws NoSuchAlgorithmException
		 * @throws CertificateException
		 * @throws FileNotFoundException
		 * @throws IOException
		 */
		public  X509Certificate getCertificate(String alias) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
			
		      KeyStore keyStore = KeyStore.getInstance("CertStore","JCP");
		      
		      // определение пути к файлу для чтения содержимого хранилища
		      // и последующего его сохранения
		      final File file = new File("/root/store");
		      
		      keyStore.load(new FileInputStream(file), "password".toCharArray());
		      
		      X509Certificate  mainCert = (X509Certificate) keyStore.getCertificate(alias);
		      
		      return mainCert;
		}	    
	    
	    public String getALIAS_2012_256() {
			return ALIAS_2012_256;
		}

		public String getSTORE_PATH_2012_256() {
			return STORE_PATH_2012_256;
		} 

}
