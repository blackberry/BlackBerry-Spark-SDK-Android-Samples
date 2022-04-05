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

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import android.Manifest;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.CompoundButton;
import android.widget.TextView;

import com.blackberry.security.auth.AppAuthentication;
import com.blackberry.security.config.ManageFeatures;
import com.blackberry.security.config.ManageRules;
import com.blackberry.security.content.Preferences;
import com.blackberry.security.identity.AppIdentity;
import com.blackberry.security.threat.ThreatType;
import com.blackberry.security.util.Diagnostics;

//SettingsActivity demonstrates:
// Uploading of BlackBerry Spark SDK logs to a BlackBerry data center for troubleshooting.
// Displays the BlackBerry Spark SDK app instance identifier. This ID is to uniquely identify an
//   app instance to your server.
// Allows for manual display of DeviceChecksActivity.
// Enabling and disabling of biometric authentication.

public class SettingsActivity extends AppCompatActivity {

    private Diagnostics mDiagnostics;
    ManageRules mRules;

    public static final int WIFI_LOCATION_PERMISSIONS = 1000;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        mDiagnostics = new Diagnostics();
        mRules = new ManageRules();

        TextView textViewSDKVersion = findViewById(R.id.textViewSDKVersion);
        textViewSDKVersion.setText(mDiagnostics.getRuntimeVersion());

        TextView textViewUUID = findViewById(R.id.textViewUUID);
        AppIdentity identity = new AppIdentity();

        //Display the BlackBerry Spark SDK app instance identifier. This ID is to uniquely identify an
        //app instance to your server. This identifier is never sent to BlackBerry.
        textViewUUID.setText(identity.getAppInstanceIdentifier());

        SwitchCompat biometricSwitch = findViewById(R.id.biometricSwitch);
        AppAuthentication appAuth = new AppAuthentication();
        if (appAuth.isBiometricsSetup())
        {
            biometricSwitch.setChecked(true);
        }

        //Configure or disable biometric authentication.
        biometricSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                AppAuthentication appAuth = new AppAuthentication();

                //Read the preference from a BlackBerry Spark SDK secure preference file.
                Preferences p = new Preferences();
                SharedPreferences prefs = p.getSharedPreferences(BlackBerrySecurityAgent.SHARED_PREFS_NAME, MODE_PRIVATE);

                if (isChecked) {
                    if (appAuth.isBiometricsAvailable()) {
                        prefs.edit().putBoolean(BlackBerrySecurityAgent.BIOMETRIC_AUTH_OPT_OUT, false).apply();

                        if (!appAuth.setupBiometrics()) {
                            AlertDialog alertDialog = new AlertDialog.Builder(SettingsActivity.this).create();
                            alertDialog.setTitle("Error!");
                            alertDialog.setMessage("Failed to start biometric setup.");
                            alertDialog.setButton(AlertDialog.BUTTON_NEUTRAL, "OK",
                                    new DialogInterface.OnClickListener() {
                                        public void onClick(DialogInterface dialog, int which) {
                                            dialog.dismiss();
                                        }
                                    });
                            alertDialog.show();
                            buttonView.setChecked(false);
                        }
                    } else {
                        AlertDialog alertDialog = new AlertDialog.Builder(SettingsActivity.this).create();
                        alertDialog.setTitle("Error!");
                        alertDialog.setMessage("Biometric authentication is not available on your device.");
                        alertDialog.setButton(AlertDialog.BUTTON_NEUTRAL, "OK",
                                new DialogInterface.OnClickListener() {
                                    public void onClick(DialogInterface dialog, int which) {
                                        dialog.dismiss();
                                    }
                                });
                        alertDialog.show();
                        buttonView.setChecked(false);
                    }
                } else {
                    prefs.edit().putBoolean(BlackBerrySecurityAgent.BIOMETRIC_AUTH_OPT_OUT, true).apply();
                    appAuth.deactivateBiometrics();
                }
            }
        });

        SwitchCompat wifiSecuritySwitch = findViewById(R.id.wifiSecuritySwitch);
        ManageFeatures manageFeatures = new ManageFeatures();

        if (manageFeatures.getFeature(ThreatType.WiFiSecurity) == ManageFeatures.FeatureStatus.ENABLED)
        {
            wifiSecuritySwitch.setChecked(true);
        }

        //Enable or disable WiFi security monitoring.
        wifiSecuritySwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {

                if (isChecked) {
                    //Enable WiFi Security monitoring.
                    //Warn the user that location permission is required if it is not yet enabled.
                    //ACCESS_BACKGROUND_LOCATION permission is not applicable to API levels below 29.
                    if (( ContextCompat.checkSelfPermission(
                            SettingsActivity.this, android.Manifest.permission.ACCESS_COARSE_LOCATION )
                            == PackageManager.PERMISSION_DENIED) ||
                            ( ContextCompat.checkSelfPermission(
                                    SettingsActivity.this, Manifest.permission.ACCESS_WIFI_STATE )
                                    == PackageManager.PERMISSION_DENIED) ||
                            ( ContextCompat.checkSelfPermission(
                                    SettingsActivity.this, Manifest.permission.ACCESS_FINE_LOCATION )
                                    == PackageManager.PERMISSION_DENIED) ||
                            (((ContextCompat.checkSelfPermission(
                                    SettingsActivity.this, Manifest.permission.ACCESS_BACKGROUND_LOCATION )
                                    == PackageManager.PERMISSION_DENIED)) && android.os.Build.VERSION.SDK_INT >= 29)) {

                        androidx.appcompat.app.AlertDialog.Builder builder = new
                                androidx.appcompat.app.AlertDialog.Builder(SettingsActivity.this);
                        builder.setTitle("Location Permission Required");
                        builder.setMessage("WiFi Security checking requires permission to access this device's location. You will be prompted to allow location permission now.");
                        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                dialog.dismiss();

                                //Request Location and WiFi Permission.
                                ActivityCompat.requestPermissions( SettingsActivity.this,
                                        new String[] {  android.Manifest.permission.ACCESS_COARSE_LOCATION,
                                                Manifest.permission.ACCESS_FINE_LOCATION,
                                                Manifest.permission.ACCESS_WIFI_STATE},
                                        WIFI_LOCATION_PERMISSIONS );
                            }
                        });
                        builder.create().show();
                    } else {
                        //Permissions are granted, enabled WiFi Security monitoring.
                        manageFeatures.enableFeature(ThreatType.WiFiSecurity);
                    }
                } else {
                    //Disable WiFi Security monitoring.
                    manageFeatures.disableFeature(ThreatType.WiFiSecurity);
                }
            }
        });
    }

    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        int LOCATION_BACKGROUND_PERMISSIONS = 2000;
        if (WIFI_LOCATION_PERMISSIONS == requestCode) {

            if (grantResults.length == 3) {
                int coarseLocation = grantResults[0];
                int fineLocation = grantResults[1];
                int accessWiFiState = grantResults[2];

                //ACCESS_BACKGROUND_LOCATION permission is not applicable to API levels below 29.
                //Assume granted for lower API levels.
                if (ContextCompat.checkSelfPermission(
                        SettingsActivity.this, Manifest.permission.ACCESS_BACKGROUND_LOCATION )
                        == PackageManager.PERMISSION_DENIED && android.os.Build.VERSION.SDK_INT >= 29){

                    //ACCESS_BACKGROUND_LOCATION can only be requested after fine and coarse location permission has been granted.
                    //Ask for background access here.
                    ActivityCompat.requestPermissions( SettingsActivity.this,
                            new String[] {Manifest.permission.ACCESS_BACKGROUND_LOCATION},
                            LOCATION_BACKGROUND_PERMISSIONS);

                } else if (coarseLocation == PackageManager.PERMISSION_GRANTED &&
                    fineLocation == PackageManager.PERMISSION_GRANTED &&
                    accessWiFiState == PackageManager.PERMISSION_GRANTED) {

                    //Permissions have been granted, enable WiFi Security monitoring.
                    ManageFeatures manageFeatures = new ManageFeatures();
                    manageFeatures.enableFeature(ThreatType.WiFiSecurity);
                    SwitchCompat wifiSecuritySwitch = findViewById(R.id.wifiSecuritySwitch);
                    wifiSecuritySwitch.setChecked(true);
                }
            }
        } else if (LOCATION_BACKGROUND_PERMISSIONS == requestCode) {
            if (grantResults[0] == PackageManager.PERMISSION_GRANTED){
                //Permissions have been granted, enable WiFi Security monitoring.
                ManageFeatures manageFeatures = new ManageFeatures();
                manageFeatures.enableFeature(ThreatType.WiFiSecurity);
                SwitchCompat wifiSecuritySwitch = findViewById(R.id.wifiSecuritySwitch);
                wifiSecuritySwitch.setChecked(true);
            }
        }
    }

    public void onClickUploadLogs(View view) {
        scheduleLogUpload();
    }

    //Display the threat status level using DeviceChecksActivity.
    public void onDisplayThreatStatus(View view) {
        Intent loginIntent = new Intent(SettingsActivity.this, DeviceChecksActivity.class);
        startActivity(loginIntent);
    }

    //Upload BlackBerry Spark SDK logs to a BlackBerry data center for analysis.
    private void scheduleLogUpload() {
        String reason = "Add your own reason why this log upload was triggered.";

        mDiagnostics.uploadLogs(reason, new Diagnostics.LogsUploadFinishedListener() {
            @Override
            public void onLogsUploadFinished(final Diagnostics.LogsUploadFinishedStatus logsUploadFinishedStatus) {
                new Handler(Looper.getMainLooper()).post(new Runnable() {
                    @Override
                    public void run() {
                        //If the user closes the Settings activity and the app attempts to display one of the dialogs
                        //below as the activity is finishing, a fatal exception will occur.  Check isFinishing to prevent this.
                        if (!isFinishing()) {

                            if (Diagnostics.LogsUploadFinishedStatus.COMPLETED == logsUploadFinishedStatus) {
                                //Upload was a success, allow the user to copy the container ID to the clipboard.
                                //This container ID will be required by BlackBerry Support to locate logs uploaded from this
                                //application instance.
                                androidx.appcompat.app.AlertDialog.Builder builder = new androidx.appcompat.app.AlertDialog.Builder(SettingsActivity.this);
                                builder.setTitle("Logs Upload");
                                builder.setMessage("Logs were uploaded using unique container ID: " + mDiagnostics.getBlackBerryAppContainerID()
                                        + ". Reference this container ID when working with BlackBerry Support.");
                                builder.setPositiveButton("Close", new DialogInterface.OnClickListener() {
                                    public void onClick(DialogInterface dialog, int id) {
                                        dialog.dismiss();
                                    }
                                });

                                //Allow access to the sample even if issues are found.
                                builder.setNeutralButton("Copy Container ID", new DialogInterface.OnClickListener() {
                                    public void onClick(DialogInterface dialog, int id) {
                                        ClipboardManager cbManager = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                                        ClipData cd = ClipData.newPlainText("Container ID", mDiagnostics.getBlackBerryAppContainerID());
                                        cbManager.setPrimaryClip(cd);
                                    }
                                });
                                builder.create().show();
                            } else {
                                //Log upload wasn't successful, display the result.
                                new AlertDialog.Builder(SettingsActivity.this)
                                        .setTitle("Logs Upload")
                                        .setMessage("Logs Upload Result: " + logsUploadFinishedStatus)
                                        .show();
                            }
                        }
                    }
                });
            }
        });
    }

    //Loads scan rules from a JSON file.
    public void onLoadRules(View view) {
        Rules sr = new Rules();
        sr.loadRules(this);
    }

    //Converts the currently set scan rules to JSON that could be saved or uploaded to a server.
    public void onSaveRules(View view) {
        Rules sr = new Rules();
        sr.saveRules();
    }
}