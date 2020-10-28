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

import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.Spinner;
import android.widget.TextView;

import com.blackberry.security.config.ManageRules;
import com.blackberry.security.config.rules.DeviceSoftwareRules;
import com.blackberry.security.identity.AppIdentity;
import com.blackberry.security.util.Diagnostics;

import org.w3c.dom.Text;

import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneId;
import java.util.Calendar;
import java.util.Date;

//SettingsActivity demonstrates:
// * Uploading of BlackBerry Spark SDK logs to a BlackBerry data center for troubleshooting.
// * Displays the BlackBerry Spark SDK app instance identifier. This ID is to uniquely identify an
//   app instance to your server.<br />Allows for manual display of DeviceChecksActivity.
// * Allows customization of the minimum Android patch level used in device software scans.
//   This is one of many rules that can be customized for each type of scan.

public class SettingsActivity extends AppCompatActivity implements AdapterView.OnItemSelectedListener {

    private Diagnostics mDiagnostics;
    ManageRules mRules;

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
        //app instance to your server.<br />Allows for manual display of DeviceChecksActivity.
        textViewUUID.setText(identity.getAppInstanceIdentifier());

        //Load the patch level configured for scans from DeviceSoftwareRules.
        //Default is Unix epoch.
        DeviceSoftwareRules dsRules = mRules.getDeviceSoftwareRules();
        Date patchDate = dsRules.getSecurityPatchMinimumDate();
        LocalDate patchLocalDate = patchDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        LocalDate now = LocalDate.now();

        Period timeBetween = Period.between(patchLocalDate, now);

        //Calculate the total number of months between now and the configured date.
        int totalMonths = timeBetween.getMonths() + (12 * timeBetween.getYears());

        Spinner spinnerPatchMonths = findViewById(R.id.spinnerPatchMonths);

        //The sample UI displays from 1-24 months.
        if (totalMonths >= 23 )
        {
            spinnerPatchMonths.setSelection(23);
        }
        else
        {
            spinnerPatchMonths.setSelection(totalMonths - 1);
        }

        spinnerPatchMonths.setOnItemSelectedListener(this);
    }

    public void onClickUploadLogs(View view)
    {
        scheduleLogUpload();
    }

    //Display the threat status level using DeviceChecksActivity.
    public void onDisplayThreatStatus(View view)
    {
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
                        new AlertDialog.Builder(SettingsActivity.this)
                                .setTitle("Logs Upload")
                                .setMessage("Logs Upload Result: " + logsUploadFinishedStatus)
                                .show();
                    }
                });
            }
        });
    }

    //Change the minimum Android patch level used in the device scan.  Patch levels lower than
    //the minimum will be considered a threat.
    @Override
    public void onItemSelected(AdapterView<?> adapterView, View view, int pos, long id) {
        //Set the DeviceSoftwareRules to use the new patch level value.
        String month = (String)adapterView.getItemAtPosition(pos);

        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MONTH, -(Integer.parseInt(month)));

        DeviceSoftwareRules dsRules = mRules.getDeviceSoftwareRules();
        dsRules.setSecurityPatchMinimumDate(cal.getTime());
        mRules.setDeviceSoftwareRules(dsRules);
    }

    @Override
    public void onNothingSelected(AdapterView<?> adapterView) {}
}