
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class FileUtil {

    // Save secret key to file
    public static void saveKey(SecretKey key, File file) throws Exception {
        byte[] keyBytes = key.getEncoded();
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(keyBytes);
        }
    }

    // Load secret key from a file
    public static SecretKey loadKey(File file) throws Exception {
        byte[] keyBytes = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(keyBytes);
        }

        return new SecretKeySpec(keyBytes, "AES");
    }
}
