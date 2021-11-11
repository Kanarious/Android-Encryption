package kanarious.encryption.example;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.example.messagesutil.UIMessages;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import kanarious.encryption.aes.AESEncryption;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";
    private static AESEncryption encryptor;
    EditText inputEDT;
    EditText outputEDT;
    private static byte[] encryptedData;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //Set Views
        inputEDT = findViewById(R.id.InputTextEDT);
        outputEDT = findViewById(R.id.ResultTextEDT);

        //Initialize Encryptor
        try {
            encryptor = new AESEncryption("TEST");
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public void AesEncryptionClick(View v){
        //Get input Text
        String text = inputEDT.getText().toString();

        if (text.length() > 0){
            try{
                encryptedData = encryptor.encryptText(text);
                UIMessages.showToast(this, "Text Encrypted");
            }
            catch(Exception e){
                Log.e(TAG, "AesEncryptionClick: "+e.getMessage());
                UIMessages.showToast(this,"Failed to Encrypt Text");
            }
        }
        else{
            UIMessages.showToast(this, "Enter Text to Encrypt");
        }
    }

    public void AesDecryptionClick(View v){
        //Get Decrypted Text
        try {
            String text = encryptor.decryptText(encryptedData);
            outputEDT.setText(text, TextView.BufferType.EDITABLE);
            UIMessages.showToast(this,"Data Decrypted");
        }
        catch (Exception e){
            Log.e(TAG, "AesDecryptionClick: "+e.getMessage());
            UIMessages.showToast(this,"Failed to Decrypt Data");
        }
    }
}