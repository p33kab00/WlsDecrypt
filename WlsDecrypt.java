import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

public class WlsDecrypt {

    public static byte[] readBytes(InputStream is) throws IOException {
        int len = is.read();
        if (len < 0) {
            throw new IOException("SerializedSystemIni is empty");
        }
        byte bytes[] = new byte[len];
        int readin = 0;
        int justread = 0;
        do {
            if (readin >= len) {
                break;
            }
            justread = is.read(bytes, readin, len - readin);
            if (justread == -1) {
                break;
            }
            readin += justread;
        } while (true);
        return bytes;
    }

    public static void main(String... args) throws Exception {
        if (args.length < 2 || "-h".equals(args[1])) {
            System.out.println("Usage:");
            System.out.println("java -cp CLASSPATH WlsDecrypt DOMAIN_PATH {AES}ENCRYPTED_STR");
            System.exit(0);
        }

        System.out.println("[*] WlsDecrypt 0.1");
        System.out.println("[*] by p33kab00 (mudnorb@gmail.com)\n");

        String systemIni = args[0] + System.getProperty("file.separator") + "security" + System.getProperty("file.separator") + "SerializedSystemIni.dat";
        byte[] salt = null;
        byte[] encryptedSecretKey = null;
        byte[] aesEncryptedSecretKey = null;

        try {
            InputStream is = new FileInputStream(new File(systemIni));
            salt = WlsDecrypt.readBytes(is);
            int version = is.read();
            if (version != -1) {
                encryptedSecretKey = WlsDecrypt.readBytes(is);
                if (version >= 2)
                    aesEncryptedSecretKey = WlsDecrypt.readBytes(is);
            }

            weblogic.security.internal.encryption.EncryptionService encService = weblogic.security.internal.encryption.JSafeEncryptionServiceImpl.getFactory().getEncryptionService(salt, "0xccb97558940b82637c8bec3c770f86fa3a391a56", encryptedSecretKey, aesEncryptedSecretKey);
            weblogic.security.internal.encryption.ClearOrEncryptedService service = new weblogic.security.internal.encryption.ClearOrEncryptedService(encService);

            System.out.println("Decrypted value: " + service.decrypt((String) args[1]));
        } catch (FileNotFoundException fnfe) {
            System.err.print("Decryption failed. Check the domain path: " + systemIni);
        } catch (Exception e) {
            System.err.println("Decryption failed (" + e.getMessage() + ")");
        }
    }

}
