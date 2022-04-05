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
import androidx.appcompat.widget.Toolbar;

import android.annotation.SuppressLint;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;

import com.blackberry.security.auth.AppAuthentication;
import com.blackberry.security.content.Preferences;

//IconActivity demonstrates:
// BlackBerry Spark SDK secure shared preference storage.
// Enabling of biometric authentication.

public class IconActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_icon);
        Toolbar myToolbar = findViewById(R.id.iconToolbar);
        setSupportActionBar(myToolbar);

        //Read the preference from a BlackBerry Spark SDK secure preference file.
        Preferences p = new Preferences();
        SharedPreferences prefs = p.getSharedPreferences(BlackBerrySecurityAgent.SHARED_PREFS_NAME, MODE_PRIVATE);

        final boolean bioOptedOut = prefs.getBoolean(BlackBerrySecurityAgent.BIOMETRIC_AUTH_OPT_OUT, false);

        //Check if the user opted out of using biometrics, if not set up if needed.
        if (!bioOptedOut) {
            doBiometricsSetup();
        }
    }

    //Sets up biometric authentication if it hasn't be set up yet and is supported by the device.
    private void doBiometricsSetup()
    {
        final AppAuthentication appAuth = new AppAuthentication();

        //Check if biometrics is available and hasn't been set up yet.
        if (appAuth.isBiometricsAvailable() && (!appAuth.isBiometricsSetup() || appAuth.hasBiometryBeenInvalidatedByChange())) {
            String userMessage = "";

            if (appAuth.hasBiometryBeenInvalidatedByChange()) {
                userMessage = "Would you like to re-enable biometric authentication? Any face or fingerprint registered on this device will be able to access the application.";
            } else  if (!appAuth.isBiometricsSetup()) {
                userMessage = "The BlackBerry Spark SDK supports biometric authentication. Do you wish to set this up now?";
            } else {
                userMessage = "Biometrics is in an unknown state.";
            }

            //Ask user if they wish to enable biometric authentication.
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle("Enable Biometric Authentication?");
            builder.setMessage(userMessage);
            builder.setPositiveButton("Enable Biometrics", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int id) {
                    //Enable biometric authentication.
                    if (!appAuth.setupBiometrics()) {
                        android.app.AlertDialog alertDialog = new android.app.AlertDialog.Builder(IconActivity.this).create();
                        alertDialog.setTitle("Error!");
                        alertDialog.setMessage("Failed to start biometric setup.");
                        alertDialog.setButton(android.app.AlertDialog.BUTTON_NEUTRAL, "OK",
                                new DialogInterface.OnClickListener() {
                                    public void onClick(DialogInterface dialog, int which) {
                                        dialog.dismiss();
                                    }
                                });
                        alertDialog.show();
                    }
                    dialog.dismiss();
                }
            });
            builder.setNeutralButton("Ask Me Later", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int id) {
                    dialog.dismiss();
                }
            });
            builder.setNegativeButton("Dismiss", new DialogInterface.OnClickListener() {
                @SuppressLint("ApplySharedPref")
                public void onClick(DialogInterface dialog, int id) {
                    //Store their preference in a BlackBerry Spark SDK secure preference file.
                    Preferences p = new Preferences();
                    SharedPreferences prefs = p.getSharedPreferences(BlackBerrySecurityAgent.SHARED_PREFS_NAME, MODE_PRIVATE);
                    prefs.edit().putBoolean(BlackBerrySecurityAgent.BIOMETRIC_AUTH_OPT_OUT, true).commit();
                    dialog.dismiss();
                }
            });
            builder.create().show();
        }
    }

    @Override
    public void onBackPressed() {
        //Disabling back
    }

    public void onClickMessages(View view)
    {
        Intent messageListIntent = new Intent(this, MessageListActivity.class);
        startActivity(messageListIntent);
    }

    public void onClickAccountBalance(View view)
    {
        Intent accountBalanceIntent = new Intent(this, AccountBalanceActivity.class);
        startActivity(accountBalanceIntent);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.settings_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.action_settings) {// User chose the "Settings" item, show the app settings UI...
            Intent settingsIntent = new Intent(this, SettingsActivity.class);
            startActivity(settingsIntent);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}