package io.kestra.plugin.pulsar;

import java.util.HashMap;
import java.util.Map;

import org.apache.pulsar.client.api.EncryptionKeyInfo;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class PemCryptoKeyReaderTest {
    private static final String PUBLIC_KEY = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwZ4ibo+FoRIyCrai3hQp
        pz8j/cLVvQdHb0AJbsJ7zNCfIVfEt2U5XjpkLYifkB4RZKwiB6inqwH1CshPeH6a
        7uazstcv+NSS1pb/u2sHpgDUejJQLs1UX/H56p7C/kx07vYcnMabczyYQwunA5M4
        YNTHbqENlePMkMHa51FNoJ21/XYh7ajjnY3wun7TMRWhndC3wM3Uwm4vj6eUzWke
        EFAvGLBQw3QZ6qiqtkgCC4WhH/42EEVozcO0wmVErfELIscGDUd3zKxo8RKRDv6a
        5MwzY5/eU/Ib+u91mf6uXOgEOij68OXfSnMiXTH9QYen0netYbEUtlRV40+mz6CK
        nQIDAQAB
        -----END PUBLIC KEY-----
        """;

    private static final String PRIVATE_KEY = """
        -----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBniJuj4WhEjIK
        tqLeFCmnPyP9wtW9B0dvQAluwnvM0J8hV8S3ZTleOmQtiJ+QHhFkrCIHqKerAfUK
        yE94fpru5rOy1y/41JLWlv+7awemANR6MlAuzVRf8fnqnsL+THTu9hycxptzPJhD
        C6cDkzhg1MduoQ2V48yQwdrnUU2gnbX9diHtqOOdjfC6ftMxFaGd0LfAzdTCbi+P
        p5TNaR4QUC8YsFDDdBnqqKq2SAILhaEf/jYQRWjNw7TCZUSt8QsixwYNR3fMrGjx
        EpEO/prkzDNjn95T8hv673WZ/q5c6AQ6KPrw5d9KcyJdMf1Bh6fSd61hsRS2VFXj
        T6bPoIqdAgMBAAECggEAGyicNNJN+2uAIyTo5eosc5N1ms1UdOj1+g11+pguNxXB
        FIi+r75I/0Yv3NE6we5DIKd34zIi9BJYtdP7jcUt5LqYqfU++zzk11P5TZKe+91G
        8K2+YJTts8L5/DvxJyxAr2+h+33CZWDdDMkwJV4REkgWghag6g247p86nlLhvC3U
        rNdMCWSr/5SG4qx07D1Izm/9Ccg9dCK1Wr5luPoV+4fOFJoZ0VaNhWcZO2cDzu/w
        kTEE97kN9doL9g7hhqT9S60PFnA3percMZWA3dzho0A8gaDTsTJtdGaKU2MUsvEe
        YKd2UCGjiQnWPDctzq6MNVMRt8hVh26/QW5lCgYpQwKBgQDiIhRYr6XkhnIQSRH8
        9xHv0mXPpGsJ2X9PUiC1lV+1ZWpbSJNl7EzlMwuGGX9CTENyOmojmcjG6nB12jTM
        +C4kFGPvyfmhSlSrP9hatxoRJWXyoKXOUZ4/xOIiavdKaP4kMsFa98mF+/k9xcIH
        z+Jc9IuhdFBwlndBh6Rkyh+PZwKBgQDbMKhEgVBhEM9Y68A7zPKNjJblxy65gPyc
        HLEi8+0pvgVsGLKiRoUgYVx9mslDUeXlQRtk25B7lNJ0eCJeoeMKYsK2qou8ir92
        KrU1QHAgA+YxQ3Kpj6NHINF5SA/eITCarivJGzYxDDKFTxT4W59DBtKdoYcqG0xT
        f3ofDmVHWwKBgHEQmRu+tzOMBXwfDN9uqYk/qagojVxfY0hFyBUCmtgX3RXHM+vC
        OrBe1WQ3W2nKt+5lRqyGN909Wv2SHNRfQrLHfzBlzGrYv3zgb0zsQBxSlqa5rC18
        oaNAzdBnqz2JQYjX19WkDx7u3bAFMP628neHzkjr30xr7zTUnV3HsgABAoGBAM+e
        NjS1fGqE3rJulGbQiYu0eJZr5gFGgYBp2Quvm5ynZkFu333AaIc0UcST4kIHCEjw
        M7+EDkZQwEwcIwoaM5F53M/jmXrcveBzMbOgNtTMfLV7Gtgru1A7cM99h7IzI/PQ
        OJ9ETD+HOy90qftZ5fA6PTOcdghXVSPeItHZ8+rzAoGAYrwyU9LaPJ+9l15CcQ99
        yzJDKpJueLyFFw88N6q6VkMvnfVu1XmoAN+cilXyJYUTYhNQPdX+/AKfvJavHa0J
        QZt6NYBPXUc7kPzAJqGX/Y6hS6KL2qr92CLOy7fq0auLpk7gL2BKuSESnKTlbeBS
        hkSW+Y8ofvCSVsij1PJF44o=
        -----END PRIVATE KEY-----
        """;

    @Test
    void testPublicKeyLoading() {
        String keyName = "test-key";
        PemCryptoKeyReader reader = new PemCryptoKeyReader(PUBLIC_KEY, null, keyName);
        Map<String, String> metadata = new HashMap<>();

        EncryptionKeyInfo keyInfo = reader.getPublicKey(keyName, metadata);

        assertNotNull(keyInfo);
        assertNotNull(keyInfo.getKey());
        assertThat(keyInfo.getKey().length, greaterThan(0));
        String pemContent = new String(keyInfo.getKey(), java.nio.charset.StandardCharsets.UTF_8);
        assertThat(pemContent, containsString("BEGIN PUBLIC KEY"));
    }

    @Test
    void testPrivateKeyLoading() {
        String keyName = "test-key";
        PemCryptoKeyReader reader = new PemCryptoKeyReader(null, PRIVATE_KEY, keyName);
        Map<String, String> metadata = new HashMap<>();

        EncryptionKeyInfo keyInfo = reader.getPrivateKey(keyName, metadata);

        assertNotNull(keyInfo);
        assertNotNull(keyInfo.getKey());
        assertThat(keyInfo.getKey().length, greaterThan(0));
        String pemContent = new String(keyInfo.getKey(), java.nio.charset.StandardCharsets.UTF_8);
        assertThat(pemContent, containsString("BEGIN PRIVATE KEY"));
    }

    @Test
    void testWrongKeyNameReturnsNull() {
        String keyName = "test-key";
        PemCryptoKeyReader reader = new PemCryptoKeyReader(PUBLIC_KEY, PRIVATE_KEY, keyName);
        Map<String, String> metadata = new HashMap<>();

        EncryptionKeyInfo publicKeyInfo = reader.getPublicKey("wrong-key", metadata);
        EncryptionKeyInfo privateKeyInfo = reader.getPrivateKey("wrong-key", metadata);

        assertNull(publicKeyInfo);
        assertNull(privateKeyInfo);
    }

    @Test
    void testMissingPublicKeyReturnsNull() {
        String keyName = "test-key";
        PemCryptoKeyReader reader = new PemCryptoKeyReader(null, PRIVATE_KEY, keyName);
        Map<String, String> metadata = new HashMap<>();

        EncryptionKeyInfo publicKeyInfo = reader.getPublicKey(keyName, metadata);

        assertNull(publicKeyInfo);
    }

    @Test
    void testMissingPrivateKeyReturnsNull() {
        String keyName = "test-key";
        PemCryptoKeyReader reader = new PemCryptoKeyReader(PUBLIC_KEY, null, keyName);
        Map<String, String> metadata = new HashMap<>();

        EncryptionKeyInfo privateKeyInfo = reader.getPrivateKey(keyName, metadata);

        assertNull(privateKeyInfo);
    }
}
