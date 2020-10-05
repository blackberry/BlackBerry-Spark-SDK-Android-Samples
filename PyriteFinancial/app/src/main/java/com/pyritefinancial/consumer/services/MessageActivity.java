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

package com.pyritefinancial.consumer.services;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import com.blackberry.security.detect.ContentChecker;

import java.util.HashMap;

//MessageActivity demonstrates:
// Checks if URLs, IP addresses or messages called or used within your application are safe.
// Implements checks which help protect your app users from malicious websites, phishing attempts,
// malware, adware, and other web sources that pose a threat to your data.

public class MessageActivity extends AppCompatActivity {

    private static final String TAG = MessageActivity.class.getSimpleName();

    private ContentCheckerWrapper ccWrapper = new ContentCheckerWrapper();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_message);
    }


    public void onClickBadUrl(View view)
    {
        TextView urlView = (TextView)view;
        // This is fake malicious URL marked as unsafe in BlackBerry Spark.
        String theUrl = "https://blackberry.com/safe_browsing_test_fake_bad_url";
        ccWrapper.checkURLFunc(theUrl);
    }

    public void onClickGoodUrl(View view)
    {
        TextView urlView = (TextView)view;
        String theUrl = "https://www.blackberry.com";
        ccWrapper.checkURLFunc(theUrl);
    }

    //Used to simulate a bad URL for non-existent URLs.
    //Not currently used in the sample.  Included for demo purposes.
    public void onClickFakeBadUrl(View view)
    {
        //URL is not safe.  Display warning to user.
        AlertDialog.Builder builder = new AlertDialog.Builder(MessageActivity.this);
        builder.setTitle("Security Check Failed");
        builder.setMessage("A connection attempt to a potentially fraudulent web site has been detected and blocked. Your account remains safe, no action is required on your behalf.");
        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int id) {
                dialog.dismiss();
            }
        });
        builder.setIcon(R.drawable.fail_dialog_icon);
        builder.create().show();
    }

    enum CheckType {
        URL,
        IP,
        MESSAGE
    }

    class ContentCheckerWrapper extends ContentChecker {

        private HashMap<Long, CheckType> checkMap = new HashMap<>();
        private HashMap<Long, String> urlMap = new HashMap<>();

        void checkIPFunc(String ip) {
            Log.d(TAG, "Start checking IP");
            long id = checkIP(ip);
            Log.d(TAG, "IP check request id " + id);
            checkMap.put(id, CheckType.IP);
        }

        void checkURLFunc(String url) {
            Log.d(TAG, "Start checking URL");
            long id = checkURL(url);
            Log.d(TAG, "URL check request id " + id);
            checkMap.put(id, CheckType.URL);
            urlMap.put(id, url);
        }

        void checkMessageFunc(String body, String sender) {
            Log.d(TAG, "Start checking message");
            long id = checkMessage(body, sender, MsgType.GENERIC);
            Log.d(TAG, "Message check request id " + id);
            checkMap.put(id, CheckType.MESSAGE);
        }

        @Override
        public void resultOfScanning(long requestID, Result result) {
            if (result == null) {
                Log.d(TAG, "Unexpected null result");
                return;
            }
            CheckType type = checkMap.get(requestID);
            if (type != null) {
                switch (type) {
                    default:
                        Log.d(TAG, "Invalid check type");
                        break;
                    case IP:
                        switch (result) {
                            case SAFE:
                                Log.d(TAG, "IP is safe");
                                break;
                            case UNSAFE:
                                Log.d(TAG, "IP is unsafe");
                                break;
                            case UNAVAILABLE:
                                Log.d(TAG, "Service is unavailable");
                                break;
                        }
                        break;
                    case URL:
                        switch (result) {
                            case SAFE:
                                Log.d(TAG, "URL is safe");
                                //URL is safe, open in the default browser.
                                Intent i = new Intent(Intent.ACTION_VIEW);
                                i.setData(Uri.parse(urlMap.get(requestID)));
                                startActivity(i);
                                break;
                            case UNSAFE:
                                Log.d(TAG, "URL is unsafe");
                                //URL is not safe, show a warning to the user.
                                showBadUrlWarning(urlMap.get(requestID));
                                break;
                            case UNAVAILABLE:
                                Log.d(TAG, "Service is unavailable");
                                break;
                        }
                        break;
                    case MESSAGE:
                        switch (result) {
                            case SAFE:
                                Log.d(TAG, "MESSAGE is safe");
                                break;
                            case UNSAFE:
                                Log.d(TAG, "MESSAGE is unsafe");
                                break;
                            case UNAVAILABLE:
                                Log.d(TAG, "Service is unavailable");
                                break;
                        }
                        break;
                }
            } else {
                Log.d(TAG, "Invalid request id");
            }
        }

        private void showBadUrlWarning(final String badUrl)
        {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    //URL is not safe.  Display warning to user.
                    AlertDialog.Builder builder = new AlertDialog.Builder(MessageActivity.this);
                    builder.setTitle("Security Check Failed");
                    builder.setMessage("A connection attempt to a potentially fraudulent web site has been detected and blocked. Your account remains safe, no action is required on your behalf.\n\nBlocked URL: " + badUrl);
                    builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int id) {
                            dialog.dismiss();
                        }
                    });
                    builder.setIcon(R.drawable.fail_dialog_icon);
                    builder.create().show();
                }
            });
        }

    }
}