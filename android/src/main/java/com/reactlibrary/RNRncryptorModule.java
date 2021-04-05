
package com.reactlibrary;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import android.util.Base64;
import org.cryptonode.jncryptor.*;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import android.net.Uri;
import java.io.File;

public class RNRncryptorModule extends ReactContextBaseJavaModule {

  private final ReactApplicationContext reactContext;

  public RNRncryptorModule(ReactApplicationContext reactContext) {
    super(reactContext);
    this.reactContext = reactContext;
  }

  @Override
  public String getName() {
    return "RNRncryptor";
  }

  @ReactMethod
  public void encrypt(String text, String password, Promise promise) {
    JNCryptor cryptor = new AES256JNCryptor();
    byte[] plaintext = text.getBytes();

    try {
      byte[] ciphertext = cryptor.encryptData(plaintext, password.toCharArray());
      String base64 = Base64.encodeToString(ciphertext, Base64.DEFAULT);
      promise.resolve(base64);
    } catch (CryptorException e) {
      e.printStackTrace();
      promise.reject(e);
    }
  }

  @ReactMethod
  public void encryptFromBase64(String b64, String password, Promise promise) {
    JNCryptor cryptor = new AES256JNCryptor();
    byte[] data = Base64.decode(b64, Base64.DEFAULT);

    try {
      byte[] ciphertext = cryptor.encryptData(data, password.toCharArray());
      String base64 = Base64.encodeToString(ciphertext, Base64.DEFAULT);
      promise.resolve(base64);
    } catch (CryptorException e) {
      e.printStackTrace();
      promise.reject(e);
    }
  }

  @ReactMethod
  public void encryptFile(String filepath, String password, Promise promise) {
    try {
      InputStream inputStream = getInputStream(filepath);
      byte[] inputData = getInputStreamBytes(inputStream);
      
      JNCryptor cryptor = new AES256JNCryptor();
      byte[] text = cryptor.encryptData(inputData, password.toCharArray());
      String b64 = Base64.encodeToString(text, Base64.DEFAULT);
      promise.resolve(b64);
    } catch (Exception ex) {
      ex.printStackTrace();
      filereject(promise, filepath, ex);
    }
  }

  @ReactMethod
  public void decrypt(String encrypted, String password, Promise promise) {
    JNCryptor cryptor = new AES256JNCryptor();
    byte[] data = Base64.decode(encrypted, Base64.DEFAULT);

    try {
      byte[] text = cryptor.decryptData(data, password.toCharArray());
      promise.resolve(new String(text));
    } catch (CryptorException e) {
      e.printStackTrace();
      promise.reject(e);
    }
  }

  @ReactMethod
  public void decryptToBase64(String encrypted, String password, Promise promise) {
    JNCryptor cryptor = new AES256JNCryptor();
    byte[] data = Base64.decode(encrypted, Base64.DEFAULT);

    try {
      byte[] text = cryptor.decryptData(data, password.toCharArray());
      String b64 = Base64.encodeToString(text, Base64.DEFAULT);
      promise.resolve(b64);
    } catch (CryptorException e) {
      e.printStackTrace();
      promise.reject(e);
    }
  }

  @ReactMethod
  public void readEncryptedFile(String filepath, String password, Promise promise) {
    try {
      InputStream inputStream = getInputStream(filepath);
      byte[] inputData = getInputStreamBytes(inputStream);
      
      JNCryptor cryptor = new AES256JNCryptor();
      byte[] text = cryptor.decryptData(inputData, password.toCharArray());
      String b64 = Base64.encodeToString(text, Base64.DEFAULT);
      promise.resolve(b64);
    } catch (Exception ex) {
      ex.printStackTrace();
      filereject(promise, filepath, ex);
    }
  }

  @ReactMethod
  public void decryptFileAndSave(String filepath, String password, String extension, Promise promise) {
    try {
      InputStream inputStream = getInputStream(filepath);
      byte[] inputData = getInputStreamBytes(inputStream);
      
      JNCryptor cryptor = new AES256JNCryptor();
      byte[] bytes = cryptor.decryptData(inputData, password.toCharArray());
      
      String newpath = filepath+"_decrypted";
      if(extension != null && !extension.isEmpty()) {
        newpath += "." + extension;
      }
      OutputStream outputStream = getOutputStream(newpath, false);
      outputStream.write(bytes);
      outputStream.close();
      promise.resolve(newpath);
    } catch (Exception ex) {
      ex.printStackTrace();
      filereject(promise, filepath, ex);
    }
  }

  @ReactMethod
  public void decryptFileAndSaveReturningContent(String filepath, String password, String extension, Promise promise) {
    try {
      InputStream inputStream = getInputStream(filepath);
      byte[] inputData = getInputStreamBytes(inputStream);
      
      JNCryptor cryptor = new AES256JNCryptor();
      byte[] bytes = cryptor.decryptData(inputData, password.toCharArray());
      String ret = new String(bytes);

      String newpath = filepath+"_decrypted";
      if(extension != null && !extension.isEmpty()) {
        newpath += "." + extension;
      }
      OutputStream outputStream = getOutputStream(newpath, false);
      outputStream.write(bytes);
      outputStream.close();

      promise.resolve(ret);
    } catch (Exception ex) {
      ex.printStackTrace();
      filereject(promise, filepath, ex);
    }
  }

  // https://github.com/itinance/react-native-fs/blob/master/android/src/main/java/com/rnfs/RNFSManager.java
  @ReactMethod
  public void readFile(String filepath, Promise promise) {
    try {
      InputStream inputStream = getInputStream(filepath);
      byte[] inputData = getInputStreamBytes(inputStream);
      String base64Content = Base64.encodeToString(inputData, Base64.NO_WRAP);

      promise.resolve(base64Content);
    } catch (Exception ex) {
      ex.printStackTrace();
      filereject(promise, filepath, ex);
    }
  }

  private InputStream getInputStream(String filepath) throws IORejectionException {
    Uri uri = getFileUri(filepath, false);
    InputStream stream;
    try {
      stream = reactContext.getContentResolver().openInputStream(uri);
    } catch (FileNotFoundException ex) {
      throw new IORejectionException("ENOENT", "ENOENT: " + ex.getMessage() + ", open '" + filepath + "'");
    }
    if (stream == null) {
      throw new IORejectionException("ENOENT", "ENOENT: could not open an input stream for '" + filepath + "'");
    }
    return stream;
  }

  private static byte[] getInputStreamBytes(InputStream inputStream) throws IOException {
    byte[] bytesResult;
    ByteArrayOutputStream byteBuffer = new ByteArrayOutputStream();
    int bufferSize = 1024;
    byte[] buffer = new byte[bufferSize];
    try {
      int len;
      while ((len = inputStream.read(buffer)) != -1) {
        byteBuffer.write(buffer, 0, len);
      }
      bytesResult = byteBuffer.toByteArray();
    } finally {
      try {
        byteBuffer.close();
      } catch (IOException ignored) {
      }
    }
    return bytesResult;
  }

  private OutputStream getOutputStream(String filepath, boolean append) throws IORejectionException {
    Uri uri = getFileUri(filepath, false);
    OutputStream stream;
    try {
      stream = reactContext.getContentResolver().openOutputStream(uri, append ? "wa" : "w");
    } catch (FileNotFoundException ex) {
      throw new IORejectionException("ENOENT", "ENOENT: " + ex.getMessage() + ", open '" + filepath + "'");
    }
    if (stream == null) {
      throw new IORejectionException("ENOENT", "ENOENT: could not open an output stream for '" + filepath + "'");
    }
    return stream;
  }

  private Uri getFileUri(String filepath, boolean isDirectoryAllowed) throws IORejectionException {
    Uri uri = Uri.parse(filepath);
    if (uri.getScheme() == null) {
      // No prefix, assuming that provided path is absolute path to file
      File file = new File(filepath);
      if (!isDirectoryAllowed && file.isDirectory()) {
        throw new IORejectionException("EISDIR", "EISDIR: illegal operation on a directory, read '" + filepath + "'");
      }
      uri = Uri.parse("file://" + filepath);
    }
    return uri;
  }

  private void filereject(Promise promise, String filepath, Exception ex) {
    if (ex instanceof FileNotFoundException) {
      rejectFileNotFound(promise, filepath);
      return;
    }
    if (ex instanceof IORejectionException) {
      IORejectionException ioRejectionException = (IORejectionException) ex;
      promise.reject(ioRejectionException.getCode(), ioRejectionException.getMessage());
      return;
    }

    promise.reject(null, ex.getMessage());
  }

  private void rejectFileNotFound(Promise promise, String filepath) {
    promise.reject("ENOENT", "ENOENT: no such file or directory, open '" + filepath + "'");
  }

}

class IORejectionException extends Exception {
    private String code;

    public IORejectionException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}