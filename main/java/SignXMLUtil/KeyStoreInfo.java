package SignXMLUtil;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Holds information about the Java Key Store
 */
public class KeyStoreInfo {

    private static final String KEY_STORE_TYPE = "JKS";

    private String alias;
    private String password;
    private KeyStore keyStore;

    public KeyStoreInfo(String alias, String password) {
        this.alias = alias;
        this.password = password;
    }

    /**
     * Loads KeyStore from the given Private Key
     * 
     * @throws Exception
     */
    public void load(InputStream privateKey) {
        try {
            this.keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            this.keyStore.load(privateKey, password.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
            throw new XmlSigningException("Error loading KeyStore", e);
        }
    }

    public String getAlias() {
        return alias;
    }

    public String getPassword() {
        return password;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

}