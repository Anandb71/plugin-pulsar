package io.kestra.plugin.pulsar;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.apache.pulsar.client.api.CryptoKeyReader;
import org.apache.pulsar.client.api.EncryptionKeyInfo;

public class PemCryptoKeyReader implements CryptoKeyReader {
    private final String publicKeyPem;
    private final String privateKeyPem;
    private final String keyName;

    public PemCryptoKeyReader(String publicKeyPem, String privateKeyPem, String keyName) {
        this.publicKeyPem = publicKeyPem;
        this.privateKeyPem = privateKeyPem;
        this.keyName = keyName;
    }

    @Override
    public EncryptionKeyInfo getPublicKey(String keyName, Map<String, String> metadata) {
        if (!this.keyName.equals(keyName) || publicKeyPem == null) {
            return null;
        }

        return new EncryptionKeyInfo(publicKeyPem.getBytes(StandardCharsets.UTF_8), metadata);
    }

    @Override
    public EncryptionKeyInfo getPrivateKey(String keyName, Map<String, String> metadata) {
        if (!this.keyName.equals(keyName) || privateKeyPem == null) {
            return null;
        }

        return new EncryptionKeyInfo(privateKeyPem.getBytes(StandardCharsets.UTF_8), metadata);
    }
}
