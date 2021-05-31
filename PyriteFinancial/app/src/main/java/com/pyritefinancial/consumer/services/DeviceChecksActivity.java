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
import androidx.core.content.ContextCompat;

import android.annotation.SuppressLint;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.blackberry.security.detect.DeviceChecker;
import com.blackberry.security.threat.ApkInfo;
import com.blackberry.security.threat.PlayProtectStatus;
import com.blackberry.security.threat.ThreatAppMalware;
import com.blackberry.security.threat.ThreatDeviceSecurity;
import com.blackberry.security.threat.ThreatDeviceSoftware;
import com.blackberry.security.threat.ThreatLevel;
import com.blackberry.security.threat.ThreatStatus;
import com.blackberry.security.threat.ThreatType;

//DeviceChecksActivity demonstrates:
//Checks the threat status of and warns the user of threats related to:
// * Device Security - A range of checks are performed to determine the security health of the users device.
//   For example, if the user has rooted the device, whether the disk is unencrypted, if the user has
//   set a screen lock or if the device is running in developer mode.
// * Device Software - Checks are made against the device OS version, security patch levels and the
//   manufacture/model of the device to confirm they meet the required security minimum standards.
// * Malware - Detects malicious applications or malware on an Android device using AI and machine learning to analyze the app package.

public class DeviceChecksActivity extends AppCompatActivity {

    private static final String TAG = DeviceChecksActivity.class.getSimpleName();

    //The following constants are used to track the level of threat for each scan type
    //used in this class.  This sample considers threat levels Critical, High and Medium to be
    //unsafe.  Threat levels Low or unknown are considered safe by this sample.
    private static final int HARDWARE_SCAN_STATUS_SAFE = 10;
    private static final int HARDWARE_SCAN_STATUS_UNSAFE = 20;
    private static final int HARDWARE_SCAN_STATUS_UNKNOWN = 30;

    private static final int OS_SCAN_STATUS_SAFE = 100;
    private static final int OS_SCAN_STATUS_UNSAFE = 120;
    private static final int OS_SCAN_STATUS_UNKNOWN = 130;

    private static final int MALWARE_SCAN_STATUS_SAFE = 200;
    private static final int MALWARE_SCAN_STATUS_UNSAFE = 220;
    private static final int MALWARE_SCAN_STATUS_UNKNOWN = 230;

    //Holds the last known status.
    private int hwScanStatus = HARDWARE_SCAN_STATUS_UNKNOWN;
    private int osScanStatus = OS_SCAN_STATUS_UNKNOWN;
    private int mwScanStatus = MALWARE_SCAN_STATUS_UNKNOWN;

    private String securityError;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_device_checks);

        PyriteApplication pa = (PyriteApplication)getApplication();
        pa.setDeviceChecksActivity(this);

        checkCurrentThreatStatus();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        PyriteApplication pa = (PyriteApplication)getApplication();
        pa.setDeviceChecksActivity(null);
    }

    public void refreshThreatStatus()
    {
        checkCurrentThreatStatus();
    }

    @Override
    public void onBackPressed() {
        //Disabling back
    }

    //Checks the current threat level for Device Security, Device Software and Malware.
    private void checkCurrentThreatStatus()
    {
        hwScanStatus = HARDWARE_SCAN_STATUS_UNKNOWN;
        osScanStatus = OS_SCAN_STATUS_UNKNOWN;
        mwScanStatus = MALWARE_SCAN_STATUS_UNKNOWN;

        securityError = "";

        ThreatStatus threatStatus = ThreatStatus.getInstance();

        StringBuilder sbSecurityErrors = new StringBuilder();

        //Check device security and display result to the user.
        ThreatDeviceSecurity deviceSecurity = (ThreatDeviceSecurity) threatStatus.getThreat(ThreatType.DeviceSecurity);

        //Ensure the initial check has completed.
        if (deviceSecurity != null && deviceSecurity.getEvaluatedTime() > 0) {
            ThreatLevel deviceSecurityThreatLevel = deviceSecurity.getRiskLevel();

            ProgressBar progressHW = findViewById(R.id.progressHW);
            ImageView imageViewHWStatus = findViewById(R.id.imageViewHWStatus);

            //Ensure this type of scan is enabled.  You can enable, disable and customize the capabilities of each scan type.
            if (!deviceSecurity.getDetectionEnabled()) {
                hwScanStatus = HARDWARE_SCAN_STATUS_UNKNOWN;
                progressHW.setVisibility(View.VISIBLE);
                imageViewHWStatus.setVisibility(View.INVISIBLE);
                sbSecurityErrors.append("Device Security checks are disabled.\n");

                //This sample considers low level threats safe. Adjust based on your own application's requirements.
            } else if (deviceSecurityThreatLevel == ThreatLevel.Null || deviceSecurityThreatLevel == ThreatLevel.Low) {
                hwScanStatus = HARDWARE_SCAN_STATUS_SAFE;
                progressHW.setVisibility(View.INVISIBLE);
                imageViewHWStatus.setImageDrawable(ContextCompat.getDrawable(DeviceChecksActivity.this, R.drawable.pass));
                imageViewHWStatus.setVisibility(View.VISIBLE);

            } else if (deviceSecurityThreatLevel == ThreatLevel.Critical ||
                    deviceSecurityThreatLevel == ThreatLevel.High ||
                    deviceSecurityThreatLevel == ThreatLevel.Medium) {
                hwScanStatus = HARDWARE_SCAN_STATUS_UNSAFE;
                progressHW.setVisibility(View.INVISIBLE);
                imageViewHWStatus.setImageDrawable(ContextCompat.getDrawable(DeviceChecksActivity.this, R.drawable.fail));
                imageViewHWStatus.setVisibility(View.VISIBLE);

                sbSecurityErrors.append(deviceSecurity.getInfo());
                sbSecurityErrors.append('\n');

                //Check threats and build an error message to show to the user.
                if (deviceSecurity.isDeviceCompromised()) {
                    sbSecurityErrors.append("Device is rooted or connected to a debugger.\n");
                }

                if (deviceSecurity.isDiskUnencrypted()) {
                    sbSecurityErrors.append("Device storage is not encrypted.\n");
                }

                if (deviceSecurity.isDeveloperModeEnabled()) {
                    sbSecurityErrors.append("Developer mode is enabled.\n");
                }

                if (deviceSecurity.isScreenLockDisabled()) {
                    sbSecurityErrors.append("Screen lock (device password) has not been enabled.\n");
                }

                if (deviceSecurity.isDeviceAttestationFailed()) {
                    sbSecurityErrors.append("Android Safetynet device attestation has failed or is not enabled.\n");
                }

                ThreatLevel emulationThreatLevel = deviceSecurity.getRunningOnEmulatorRisk();

                if (emulationThreatLevel == ThreatLevel.Medium || emulationThreatLevel == ThreatLevel.High
                        || emulationThreatLevel == ThreatLevel.Critical) {
                    sbSecurityErrors.append("Risk of app running in an emulator: ");
                    sbSecurityErrors.append(emulationThreatLevel.toString());
                    sbSecurityErrors.append(".\n");
                }

                PlayProtectStatus playProtectStatus = deviceSecurity.getPlayProtectStatus();
                switch (playProtectStatus) {
                    case UNSUPPORTED_DEVICE:
                        sbSecurityErrors.append("Play Protect is not supported on this device.\n");
                        break;
                    case DISABLED:
                        sbSecurityErrors.append(("Play Protect is disabled.\n"));
                        break;
                    case UNDEFINED:
                        sbSecurityErrors.append("The Play Protect DeviceSecurity check is either not enabled or has not completed.\n");
                        break;
                    case ENABLED:
                        //Play Protect is enabled and verifying that installed and updated applications are safe.  Nothing to report.
                        break;
                }
            }
        }

        //Check OS security and display the result to the user.
        ThreatDeviceSoftware deviceOS = (ThreatDeviceSoftware)threatStatus.getThreat(ThreatType.DeviceSoftware);

        //Ensure the initial check has completed.
        if (deviceOS != null && deviceOS.getEvaluatedTime() > 0) {
            ThreatLevel deviceOSThreatLevel = deviceOS.getRiskLevel();

            ProgressBar progressOS = findViewById(R.id.progressOS);
            ImageView imageViewOSStatus = findViewById(R.id.imageViewOSStatus);

            //Ensure this type of scan is enabled.  You can enable, disable and customize the capabilities of each scan type.
            if (!deviceOS.getDetectionEnabled()) {
                osScanStatus = OS_SCAN_STATUS_UNKNOWN;
                progressOS.setVisibility(View.VISIBLE);
                imageViewOSStatus.setVisibility(View.INVISIBLE);
                sbSecurityErrors.append("Operating system checks are disabled.\n");

                //This sample considers low level threats safe. Adjust based on your own application's requirements.
            } else if (deviceOSThreatLevel == ThreatLevel.Null || deviceOSThreatLevel == ThreatLevel.Low) {
                osScanStatus = OS_SCAN_STATUS_SAFE;
                progressOS.setVisibility(View.INVISIBLE);
                imageViewOSStatus.setImageDrawable(ContextCompat.getDrawable(DeviceChecksActivity.this, R.drawable.pass));
                imageViewOSStatus.setVisibility(View.VISIBLE);

            } else if (deviceOSThreatLevel == ThreatLevel.Critical || deviceOSThreatLevel == ThreatLevel.High ||
                    deviceOSThreatLevel == ThreatLevel.Medium) {
                osScanStatus = OS_SCAN_STATUS_UNSAFE;
                progressOS.setVisibility(View.INVISIBLE);
                imageViewOSStatus.setImageDrawable(ContextCompat.getDrawable(DeviceChecksActivity.this, R.drawable.fail));
                imageViewOSStatus.setVisibility(View.VISIBLE);

                sbSecurityErrors.append(deviceOS.getInfo());
                sbSecurityErrors.append('\n');

                //Check threats and build an error message to show to the user.
                if (deviceOS.isDeviceManufacturerRestricted()) {
                    sbSecurityErrors.append("This device manufacturer is restricted.\n");
                }

                if (deviceOS.isDeviceModelRestricted()) {
                    sbSecurityErrors.append("This device model is restricted.\n");
                }

                if (deviceOS.isDeviceOSRestricted()) {
                    sbSecurityErrors.append("This device OS version is restricted.\n");
                }

                if (deviceOS.isDeviceSecurityPatchRestricted()) {
                    sbSecurityErrors.append("This device security patch level is too old.\n");
                }

            }
        }

        //Check device for malware and display the result to the user.
        ThreatAppMalware malware = (ThreatAppMalware) threatStatus.getThreat(ThreatType.AppMalware);

        //Ensure the initial check has completed.
        if (malware != null && malware.getEvaluatedTime() > 0) {
            ApkInfo[] badApps = malware.getMaliciousApps();
            ThreatLevel threatLevel = malware.getRiskLevel();

            ProgressBar progressMalware = findViewById(R.id.progressMalware);
            ImageView imageViewMalware = findViewById(R.id.imageViewMalware);

            //Ensure this type of scan is enabled.  You can enable, disable and customize the capabilities of each scan type.
            if (!malware.getDetectionEnabled()) {
                mwScanStatus = MALWARE_SCAN_STATUS_UNKNOWN;
                progressMalware.setVisibility(View.VISIBLE);
                imageViewMalware.setVisibility(View.INVISIBLE);
                sbSecurityErrors.append("Malware checks are disabled.\n");

                //This sample considers low level threats safe. Adjust based on your own application's requirements.
            } else if (threatLevel == ThreatLevel.Null || threatLevel == ThreatLevel.Low) {
                mwScanStatus = MALWARE_SCAN_STATUS_SAFE;
                progressMalware.setVisibility(View.INVISIBLE);
                imageViewMalware.setImageDrawable(ContextCompat.getDrawable(DeviceChecksActivity.this, R.drawable.pass));
                imageViewMalware.setVisibility(View.VISIBLE);

            } else if (threatLevel == ThreatLevel.Critical || threatLevel == ThreatLevel.High || threatLevel == ThreatLevel.Medium) {
                mwScanStatus = MALWARE_SCAN_STATUS_UNSAFE;
                progressMalware.setVisibility(View.INVISIBLE);
                imageViewMalware.setImageDrawable(ContextCompat.getDrawable(DeviceChecksActivity.this, R.drawable.fail));
                imageViewMalware.setVisibility(View.VISIBLE);

                sbSecurityErrors.append(malware.getInfo());
                sbSecurityErrors.append('\n');

                if (badApps.length > 0) {
                    sbSecurityErrors.append("Malicious Apps Detected:\n");

                    for (int count = 0; count < badApps.length; count++) {
                        sbSecurityErrors.append(badApps[count].packageName);
                        sbSecurityErrors.append('\n');
                    }
                }
            }
        }


        securityError = sbSecurityErrors.toString();

        TextView textViewStatus = findViewById(R.id.textViewStatus);
        if (hwScanStatus == HARDWARE_SCAN_STATUS_UNSAFE || osScanStatus == OS_SCAN_STATUS_UNSAFE ||
                mwScanStatus == MALWARE_SCAN_STATUS_UNSAFE) {
            textViewStatus.setText("Security Warning \n Click for more information");
            textViewStatus.setTextColor(ContextCompat.getColor(getApplicationContext(), R.color.colorUNSAFE));
        }
        else {
            textViewStatus.setText("Device is Safe \n Click to continue");
            textViewStatus.setTextColor(ContextCompat.getColor(getApplicationContext(), R.color.colorSAFE));
        }

    }

    //Triggers new scans of device security and device software.
    //Malware scanning is continuous by default, so triggering a new malware scan isn't required.
    @SuppressLint("SetTextI18n")
    private void triggerRescan()
    {
        //On most devices this scan happens so quickly that the user won't see
        //the progress bars appear.  But we've added them for usability on constrained devices.
        ProgressBar progressHW = findViewById(R.id.progressHW);
        ImageView imageViewHWStatus = findViewById(R.id.imageViewHWStatus);
        ProgressBar progressOS = findViewById(R.id.progressOS);
        ImageView imageViewOSStatus = findViewById(R.id.imageViewOSStatus);

        imageViewHWStatus.setVisibility((View.INVISIBLE));
        progressHW.setVisibility((View.VISIBLE));

        imageViewOSStatus.setVisibility(View.INVISIBLE);
        progressOS.setVisibility(View.VISIBLE);

        TextView textViewStatus = findViewById(R.id.textViewStatus);
        textViewStatus.setTextColor(ContextCompat.getColor(DeviceChecksActivity.this, R.color.regularTextColor));
        textViewStatus.setText("Touch here for scan status.");

        DeviceChecker dc = new DeviceChecker();
        dc.checkDeviceSecurity();
        dc.checkDeviceSoftware();

        checkCurrentThreatStatus();
    }

    //Shows a dialog with detailed information about the threats detected.
    public void onClickForMore(View view)
    {
        if (hwScanStatus == HARDWARE_SCAN_STATUS_SAFE && osScanStatus == OS_SCAN_STATUS_SAFE &&
                mwScanStatus == MALWARE_SCAN_STATUS_SAFE) {

            DeviceChecksActivity.this.finish();
        }
        else
        {
            String title = "Some security checks are disabled or in progress.";

            if (hwScanStatus == HARDWARE_SCAN_STATUS_UNSAFE || osScanStatus == OS_SCAN_STATUS_UNSAFE ||
                    mwScanStatus == MALWARE_SCAN_STATUS_UNSAFE)
            {
                title = "Security Check Failed";
            }

            //Device is not safe or scans are in an unknown state.
            // //Scan could be disabled or in progress.  Display remediation information.
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle(title);
            builder.setMessage(securityError);
            builder.setPositiveButton("Refresh Threat Status", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int id) {
                    triggerRescan();
                    dialog.dismiss();
                }
            });

            //Allow access to the sample even if issues are found.
            builder.setNeutralButton("Continue Anyway", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int id) {
                    dialog.dismiss();
                    DeviceChecksActivity.this.finish();
                }
            });

            builder.create().show();
        }
    }
}