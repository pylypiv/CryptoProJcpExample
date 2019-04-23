/**
 * $RCSfile$
 * version $Revision$
 * created 23.09.2005 20:05:23 by elvira
 * last modified $Date$ by $Author$
 * (C) ООО Крипто-Про 2004-2005.
 *
 * Программный код, содержащийся в этом файле, предназначен
 * для целей обучения. Может быть скопирован или модифицирован
 * при условии сохранения абзацев с указанием авторства и прав.
 *
 * Данный код не может быть непосредственно использован
 * для защиты информации. Компания Крипто-Про не несет никакой
 * ответственности за функционирование этого кода.
 */
package userSamples;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;

/**
 * В данном примере осуществляется зашифрование и расшифрование данных по
 * классической схеме (на симметричных ключах согласования).
 */
public class ClassicEncrypt {
/**
 * текст
 */
private static final String SAMPLE_TEXT = "Classic encryption/decryption";
/**
 * длина вектора
 */
private static final int RND_LENGTH = 8;
/**
 * Алгоритм шифрования
 */
private static final String CIPHER_ALG = "GOST28147/CFB/NoPadding";

/**
 * @param args null
 * @throws Exception
 */
public static void main(String[] args) throws Exception {
    //main_(Constants.EXCH_KEY_PAIR_ALG_2001);
    main_(Constants.EXCH_KEY_PAIR_ALG_2012_256);
    //main_(Constants.EXCH_KEY_PAIR_ALG_2012_512);
}

/**
 * Зашифрование/расшифрование на ключах согласования.
 *
 * @param keyAlg Алгоритм ключа.
 * @throws Exception
 */
public static void main_(String keyAlg) throws Exception {

    final byte[] data = SAMPLE_TEXT.getBytes();

    /**На каждой стороне должны присутствовать:
     * - свой закрытый ключ
     * - открытый ключ второй стороны (сертификат)**/

    /* Генерирование закрытых ключей сторон */
    final KeyPair alisaPair = KeyPairGen.genKeyAllowDh(keyAlg);
    final KeyPair bobPair = KeyPairGen.genKeyAllowDh(keyAlg);
    
    System.out.println("Private key "+alisaPair.getPrivate().getAlgorithm());

    /* Генерирование самоподписанных сертификатов сторон */
    final Certificate alisaCert = KeyPairGen.genSelfCert(alisaPair, "CN=ALISA_CERTIFICATE, O=CryptoPro, C=RU");
    final Certificate bobCert = KeyPairGen.genSelfCert(bobPair, "CN=BOB_CERTIFICATE, O=CryptoPro, C=RU");

    /* Генерирование начальной синхропосылки для выработки ключа согласования*/
    final byte[] sv = new byte[RND_LENGTH];
    final SecureRandom random = SecureRandom.getInstance(Constants.RANDOM_ALG);
    random.nextBytes(sv);
    final IvParameterSpec ivspec = new IvParameterSpec(sv);

    /* Выработка ключа согласования алисы c SV*/
    final KeyAgreement alisaKeyAgree =
            KeyAgreement.getInstance(keyAlg);
    alisaKeyAgree.init(alisaPair.getPrivate(), ivspec, null);
    alisaKeyAgree.doPhase(bobCert.getPublicKey(), true);
    final SecretKey alisaAgree =
            alisaKeyAgree.generateSecret(Constants.CHIPHER_ALG);

    /*Зашифрование текста на ключе согласования алисы*/
    Cipher cipher = Cipher.getInstance(CIPHER_ALG);
    cipher.init(Cipher.ENCRYPT_MODE, alisaAgree);
    // передача вектора инициализации бобу
    final byte[] iv = cipher.getIV();
    final byte[] encryptedtext = cipher.doFinal(data, 0, data.length);

    /* Выработка ключа согласования боба с тем же SV. */
    final KeyAgreement bobKeyAgree =
            KeyAgreement.getInstance(keyAlg);
    bobKeyAgree.init(bobPair.getPrivate(), ivspec, null);
    bobKeyAgree.doPhase(alisaCert.getPublicKey(), true);
    final SecretKey bobAgree =
            bobKeyAgree.generateSecret(Constants.CHIPHER_ALG);

    /*Расшифрование текста на ключе согласования боба. IV передан от алисы*/
    cipher = Cipher.getInstance(CIPHER_ALG);
    cipher.init(Cipher.DECRYPT_MODE, bobAgree, new IvParameterSpec(iv), null);
    final byte[] decryptedtext = cipher
            .doFinal(encryptedtext, 0, encryptedtext.length);

    // проверка результата.
    if (decryptedtext.length != data.length)
        throw new Exception("Error in crypting");
    for (int i = 0; i < decryptedtext.length; i++)
        if (data[i] != decryptedtext[i])
            throw new Exception("Error in crypting");

    System.out.println("OK");
}
//передача открытого ключа вне сертификата не рекомендуется
//final PublicKey pubKey;
//final KeyFactory keyFactory = KeyFactory.getInstance(pubKey.getAlgorithm());
//final X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKey.getEncoded());
//final PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
}
