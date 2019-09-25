package com.pentacomp.signer;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Map;
import java.util.TreeMap;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;

import org.eclipse.swt.widgets.Shell;

public class KeyStoreManager {
    private KeyStore keyStore;
    private Map<String, String> aliasMap;
    private static Boolean java9SunPKCS11;

    public static KeyStoreManager initialize(Shell shell) throws GeneralSecurityException {
        KeyStoreManager ksm = new KeyStoreManager();
        ksm.init(shell);
        return ksm;
    }

    private void init(Shell shell) throws GeneralSecurityException {
        try {
            if (isWindows()) {
                this.keyStore = KeyStore.getInstance("Windows-MY");
                this.keyStore.load(null, null);
                fixAliases();
            } else {
                this.keyStore = process(shell);
            }

            this.aliasMap = new TreeMap();
            Enumeration<String> aliases = this.keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                System.out.println("! " + alias + ": " + this.keyStore.isKeyEntry(alias) + " / " + this.keyStore.isCertificateEntry(alias));
                X509Certificate cert = (X509Certificate) this.keyStore.getCertificate(alias);
                if (cert != null) {
                    this.aliasMap.put(extractName(cert.getSubjectX500Principal()) + " (" + extractName(cert.getIssuerX500Principal()) + " / " + cert.getSerialNumber().toString(16) + ")", alias);
                }
            }
        } catch (Exception e) {
            throw new GeneralSecurityException("Błąd podczas ładowania keystore'a", e);
        }
    }

    private KeyStore process(Shell shell) throws Exception {
        String libpath = System.getProperty("pz.signer.pkcs11.libpath");
        long[] slots = listSlots(libpath);
        for (int i = slots.length - 1; i >= 0; i--) {
            System.out.println("!!! slot " + slots[i]);
            try {
                Provider provider;
                do {
                    String cfg = "library=" + libpath + "\nname=XaDESAppletCrypto\nslot=" + slots[i] + "\n";
                    provider = createPkcs11Provider(new ByteArrayInputStream(cfg.getBytes()));
                } while (provider.getService("KeyStore", "PKCS11") == null);
                if (Security.getProvider(provider.getName()) != null) {
                    Security.removeProvider(provider.getName());
                }
                Security.addProvider(provider);
                KeyStore.Builder keystoreBuilder = KeyStore.Builder.newInstance("PKCS11", provider, new KeyStore.CallbackHandlerProtection(new Kallback(shell)));
                return keystoreBuilder.getKeyStore();
            } catch (Exception e) {
                e.printStackTrace();

                if (!e.getMessage().contains("CKR_TOKEN_NOT_RECOGNIZED")) {
                    throw e;
                }
            }
        }

        return null;
    }

    private class Kallback implements CallbackHandler {
        private char[] pin;
        private Shell shell;

        public Kallback(Shell shell) {
            this.shell = shell;
        }

        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof PasswordCallback) {
                    System.out.println("!!! callback... pin.length='" + ((this.pin != null) ? Integer.valueOf(this.pin.length) : null) + "'");
                    PasswordCallback pc = (PasswordCallback) callback;
                    if (this.pin == null || this.pin.length == 0) {
                        PinDialog dlg = new PinDialog(this.shell);
                        dlg.open();
                        if (dlg.getPin() != null) {
                            this.pin = dlg.getPin();
                            pc.setPassword(this.pin);
                        }
                    }
                } else {
                    throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
                }
            }
        }
    }

    private void fixAliases() {
        try {
            Field field = this.keyStore.getClass().getDeclaredField("keyStoreSpi");
            field.setAccessible(true);
            KeyStoreSpi keyStoreVeritable = (KeyStoreSpi) field.get(this.keyStore);
            if ("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName())) {
                field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
                field.setAccessible(true);
                Collection entries = (Collection) field.get(keyStoreVeritable);
                for (Object entry : entries) {
                    field = entry.getClass().getDeclaredField("certChain");
                    field.setAccessible(true);
                    X509Certificate[] certificates = (X509Certificate[]) field.get(entry);
                    String hashCode = Integer.toString(certificates[0].hashCode(), 16);
                    field = entry.getClass().getDeclaredField("alias");
                    field.setAccessible(true);
                    String alias = (String) field.get(entry);
                    if (!alias.equals(hashCode)) {
                        field.set(entry, alias.concat("-").concat(hashCode));
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").toUpperCase().contains("WINDOWS");
    }

    private static long[] listSlots(String path) throws Exception {
        Method[] methods = Class.forName("sun.security.pkcs11.wrapper.PKCS11").getMethods();
        for (Method method : methods) {
            if (method.getName().equals("getInstance")) {
                Object o = method.invoke(null, new Object[]{path, "C_GetFunctionList", null, Boolean.valueOf(false)});
                Method m = o.getClass().getMethod("C_GetSlotList", new Class[]{boolean.class});
                if (!m.isAccessible()) {
                    m.setAccessible(true);
                }
                return (long[]) m.invoke(o, new Object[]{Boolean.valueOf(true)});
            }
        }
        return new long[0];
    }

    private static boolean isJava9SunPKCS11() {
        if (java9SunPKCS11 != null) {
            return java9SunPKCS11;
        }
        java9SunPKCS11 = Boolean.FALSE;
        try {
            Provider provider = Security.getProvider("SunPKCS11");
            if (provider != null) {
                provider.getClass().getMethod("configure", String.class);
                java9SunPKCS11 = Boolean.TRUE;
            }
        } catch (NoSuchMethodException ignore) {
        }
        return java9SunPKCS11;
    }

    private static Provider createPkcs11ProviderJava9(InputStream configStream) throws Exception {
        Provider provider = Security.getProvider("SunPKCS11");
        Method configure = provider.getClass().getMethod("configure", String.class);
        File configFile = File.createTempFile("pkcs11", ".cfg");
        configFile.deleteOnExit();
        Files.copy(configStream, configFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        return (Provider) configure.invoke(provider, configFile.getAbsolutePath());
    }

    private static Provider createPkcs11ProviderJava8(InputStream configStream) throws Exception {
        Class providerClass = Class.forName("sun.security.pkcs11.SunPKCS11");
        Constructor<Provider> ctor = providerClass.getConstructor(new Class[]{InputStream.class});
        return (Provider) ctor.newInstance(new Object[]{configStream});
    }

    private static Provider createPkcs11Provider(InputStream configStream) throws Exception {
        if (isJava9SunPKCS11()) {
            return createPkcs11ProviderJava9(configStream);
        } else {
            return createPkcs11ProviderJava8(configStream);
        }
    }

    private static String extractName(X500Principal p) {
        String[] parts = p.getName().split(",");
        for (String part : parts) {
            String[] el = part.split("=");
            if ("cn".equals(el[0].trim().toLowerCase())) {
                return el[1].trim().replaceAll("\\\\00", "");
            }
        }
        return p.getName().replaceAll("\\\\00", "");
    }

    public Collection<String> getAliasLabels() {
        return this.aliasMap.keySet();
    }

    public String getAlias(String text) {
        return (String) this.aliasMap.get(text);
    }

    public PrivateKey getPrivateKey(String alias) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        return (PrivateKey) this.keyStore.getKey(alias, null);
    }

    public X509Certificate getCertificate(String alias) throws KeyStoreException {
        return (X509Certificate) this.keyStore.getCertificate(alias);
    }
}
