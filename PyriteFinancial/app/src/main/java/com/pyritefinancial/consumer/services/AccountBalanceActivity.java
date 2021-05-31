package com.pyritefinancial.consumer.services;

/* Copyright (c) 2020 BlackBerry Limited.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import com.blackberry.security.file.FileInputStream;
import com.blackberry.security.file.FileOutputStream;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;

//AccountBalanceActivity demonstrates the use of the BlackBerry Spark SDK secure file system.

public class AccountBalanceActivity extends AppCompatActivity {

    private static final String TAG = AccountBalanceActivity.class.getSimpleName();

    private final String FOLDER_NAME = "Account_Details";
    private final String FILE_NAME = "Account_Balance.txt";

    TextView textViewAccountBalance;
    EditText editTextDollarAmount;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_account_balance);

        textViewAccountBalance = findViewById(R.id.textViewAccountBalance);
        editTextDollarAmount = findViewById(R.id.editTextDollarAmount);
        readAccountBalance();
    }

    public void onDeposit(View view)
    {
        try {
            float accountBalance = Float.parseFloat(textViewAccountBalance.getText().toString());
            float dollarChange = Float.parseFloat(editTextDollarAmount.getText().toString());

            accountBalance += dollarChange;
            writeAccountBalance(accountBalance);
            readAccountBalance();
        }
        catch (NumberFormatException nfe)
        {
            Log.d(TAG, "Invalid number");
        }
    }

    public void onWithdraw(View view)
    {
        try {
            float accountBalance = Float.parseFloat(textViewAccountBalance.getText().toString());
            float dollarChange = Float.parseFloat(editTextDollarAmount.getText().toString());

            accountBalance -= dollarChange;
            writeAccountBalance(accountBalance);
            readAccountBalance();
        }
        catch (NumberFormatException nfe)
        {
            Log.d(TAG, "Invalid number");
        }
    }

    //Reset the stored value to 0.
    public void onResetBalance(View view)
    {
        writeAccountBalance((float) 0);
        readAccountBalance();
    }

    //Reads the account balance from BlackBerry Spark SDK secure storage.
    private void readAccountBalance()
    {
        final String filePath = FOLDER_NAME + "/" + FILE_NAME;
        String dataFromFile = "0.00";
        byte[] data;
        try {
            final InputStream inputStream = new FileInputStream(filePath);
            if (inputStream.available() > 0) {
                data = new byte[inputStream.available()];
                inputStream.read(data);
                dataFromFile = new String(data, StandardCharsets.UTF_8);
                inputStream.close();

                DecimalFormat df = new DecimalFormat();
                df.setMaximumFractionDigits(2);
                dataFromFile = df.format(Float.valueOf(dataFromFile));
            }
            Log.i(TAG, "Read from file success!");
        } catch (final IOException ioException) {
            dataFromFile = "0.00";
            ioException.printStackTrace();
            Log.e(TAG, "readData FAILED " + ioException.toString());
        }

        textViewAccountBalance.setText(dataFromFile);
    }

    //Writes the account balance out to BlackBerry Spark SDK secure storage.
    private void writeAccountBalance(Float balance) {

        try {
            com.good.gd.file.File file = new com.good.gd.file.File(FOLDER_NAME);

            if(!file.exists()){
                file.mkdir();
            }

            FileOutputStream out = new FileOutputStream(FOLDER_NAME + "/" + FILE_NAME, false);
            out.write(balance.toString().getBytes());
            out.flush();
            out.close();
            Log.i("SparkStorage", "Write to file success");

        } catch (IOException e) {
            Log.e("Exception", "writeToFile FAILED" + e.toString());
        }
    }
}