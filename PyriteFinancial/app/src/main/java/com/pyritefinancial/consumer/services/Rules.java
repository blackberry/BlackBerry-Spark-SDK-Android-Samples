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

import android.content.Context;
import android.util.Log;
import android.widget.Toast;

import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;
import com.blackberry.security.config.ManageFeatures;
import com.blackberry.security.config.ManageRules;
import com.blackberry.security.config.rules.ContentCheckerRules;
import com.blackberry.security.config.rules.DataCollectionRules;
import com.blackberry.security.config.rules.DeviceOfflineRules;
import com.blackberry.security.config.rules.DeviceSecurityRules;
import com.blackberry.security.config.rules.DeviceSoftwareRules;
import com.blackberry.security.config.rules.MalwareScanRules;
import com.blackberry.security.detect.DeviceChecker;
import com.blackberry.security.identity.AppIdentity;
import com.blackberry.security.threat.ThreatType;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

//Rules demonstrates:
// * Reading and writing BlackBerry Spark SDK rules and features to and from JSON.
// * Refer to rules.json in the root project directory for example JSON for setting rules.


public class Rules {

    private static final String TAG = Rules.class.getSimpleName();

    private Context mContext;

    public Rules()
    { }

    //Download a Rules JSON file.
    public void loadRules(Context context)
    {
        mContext = context;
        RequestQueue queue = Volley.newRequestQueue(context);

        //This URL points to an example rules.json on Github from this project.
        //TODO - Comment out the line below if you are testing with the Pyrite Financial Server.
        String url ="https://raw.githubusercontent.com/blackberry/BlackBerry-Spark-SDK-Android-Samples/master/PyriteFinancial/rules.json";

        //This URL points to an instance of the Pyrite Financial Server, which can be used to generate
        //the JSON used to configure this sample.
        //Clone the server from https://github.com/blackberry/BlackBerry-Spark-SDK-Android-Samples
        //This sample passed the authenticity ID to the server.  This ID is unique to this application,
        //but remains constant on all installations.  This ID is never shared with BlackBerry.
        //The application instance ID is a unique ID which is constant for a single activated instance of the application.
        //This identifier is never shared or known by BlackBerry.
        //TODO - Uncomment the lines below and enter your server address if you are testing with the Pyrite Financial Server.
/*
        AppIdentity aID = new AppIdentity();
        Map appIDs = aID.getApplicationAuthenticityIdentifiers();
        String url ="http://<YOUR_SERVER_ADDRESS>:3000/rules?appAuthenticityID=" + appIDs.get(AppIdentity.AUTHENTICITY_ID)
                + "&appInstanceID=" + aID.getAppInstanceIdentifier();
*/

        StringRequest stringRequest = new StringRequest(Request.Method.GET, url,
                new Response.Listener<String>() {
                    @Override
                    public void onResponse(String response) {
                        applyRules((response));
                    }
                }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                Log.e(TAG, "Failed to download JSON. " + error.toString());
            }
        });
        //Clear cache so the JSON is fetched every time (not taken from cache).
        queue.getCache().clear();
        queue.add(stringRequest);
    }

    //Parse the rules JSON and apply the specified rules.
    //This method supports parsing JSON that doesn't include entries for each rule.
    //Rules not listed in the JSON will not be changed.
    private void applyRules(String rulesJSON)
    {
        ManageRules manageRules = new ManageRules();

        try {
            JSONObject jsonRules = new JSONObject(rulesJSON);

            //Parse and apply Features. Features need to be applied first because enabling a feature will enable all checks within that feature.
            if (jsonRules.has("Features"))
            {
                ManageFeatures manageFeatures = new ManageFeatures();
                JSONObject jsonFeatures = jsonRules.getJSONObject("Features");

                if (jsonFeatures.has("AppMalware_Enabled"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonFeatures.getString("AppMalware_Enabled")))
                    {
                        manageFeatures.enableFeature(ThreatType.AppMalware);

                    } else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonFeatures.getString("AppMalware_Enabled")))
                    {
                        manageFeatures.disableFeature(ThreatType.AppMalware);
                    }
                }

                if (jsonFeatures.has("AppSideload_Enabled"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonFeatures.getString("AppSideload_Enabled")))
                    {
                        manageFeatures.enableFeature(ThreatType.AppSideload);

                    } else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonFeatures.getString("AppSideload_Enabled")))
                    {
                        manageFeatures.disableFeature(ThreatType.AppSideload);
                    }
                }

                if (jsonFeatures.has("DeviceSecurity_Enabled"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonFeatures.getString("DeviceSecurity_Enabled")))
                    {
                        manageFeatures.enableFeature(ThreatType.DeviceSecurity);

                    } else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonFeatures.getString("DeviceSecurity_Enabled")))
                    {
                        manageFeatures.disableFeature(ThreatType.DeviceSecurity);
                    }
                }

                if (jsonFeatures.has("DeviceSoftware_Enabled"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonFeatures.getString("DeviceSoftware_Enabled")))
                    {
                        manageFeatures.enableFeature(ThreatType.DeviceSoftware);

                    } else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonFeatures.getString("DeviceSoftware_Enabled")))
                    {
                        manageFeatures.disableFeature(ThreatType.DeviceSoftware);
                    }
                }

                if (jsonFeatures.has("SafeBrowsing_Enabled"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonFeatures.getString("SafeBrowsing_Enabled")))
                    {
                        manageFeatures.enableFeature(ThreatType.SafeBrowsing);

                    } else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonFeatures.getString("SafeBrowsing_Enabled")))
                    {
                        manageFeatures.disableFeature(ThreatType.SafeBrowsing);
                    }
                }

                if (jsonFeatures.has("SafeMessaging_Enabled"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonFeatures.getString("SafeMessaging_Enabled")))
                    {
                        manageFeatures.enableFeature(ThreatType.SafeMessaging);

                    } else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonFeatures.getString("SafeMessaging_Enabled")))
                    {
                        manageFeatures.disableFeature(ThreatType.SafeMessaging);
                    }
                }

            }

            //Parse and apply Malware Scan Rules.
            if (jsonRules.has("MalwareScanRules")) {
                JSONObject jsonMWScanRules = jsonRules.getJSONObject("MalwareScanRules");

                MalwareScanRules.Builder rulesBuilder = new MalwareScanRules.Builder();

                if (jsonMWScanRules.has("MalwareUploadType"))
                {
                    rulesBuilder.allowedUploadType(MalwareScanRules.UploadType.valueOf(jsonMWScanRules.getString("MalwareUploadType")));
                }

                if (jsonMWScanRules.has("MalwareScanTrigger"))
                {
                    rulesBuilder.scanTrigger(MalwareScanRules.MalwareScanTrigger.valueOf(jsonMWScanRules.getString("MalwareScanTrigger")));
                }

                //Set to 0 for unlimited upload size.
                if (jsonMWScanRules.has("MalwareUploadItemSizeLimit_Cellular") && jsonMWScanRules.has("MalwareUploadMonthlySizeLimit_Cellular"))
                {
                    rulesBuilder.setUploadSizeLimits(MalwareScanRules.UploadType.CELLULAR, jsonMWScanRules.getInt("MalwareUploadItemSizeLimit_Cellular"),
                            jsonMWScanRules.getInt("MalwareUploadMonthlySizeLimit_Cellular"));
                }

                //Set to 0 for unlimited upload size.
                if (jsonMWScanRules.has("MalwareUploadItemSizeLimit_WiFi") && jsonMWScanRules.has("MalwareUploadMonthlySizeLimit_WiFi"))
                {
                    rulesBuilder.setUploadSizeLimits(MalwareScanRules.UploadType.WIFI, jsonMWScanRules.getInt("MalwareUploadItemSizeLimit_WiFi"),
                            jsonMWScanRules.getInt("MalwareUploadMonthlySizeLimit_WiFi"));
                }

                // Build the rules object and set the new rules.
                MalwareScanRules malwareScanRules = rulesBuilder.build();
                manageRules.setMalwareScanRules(malwareScanRules);

                Log.d(TAG, "Malware Scan Rules Saved.");
            }

            //Parse and apply Content Checker Rules.
            if (jsonRules.has("ContentCheckerRules"))
            {
                ContentCheckerRules ccRules = manageRules.getContentCheckerRules();
                JSONObject jsonCCRules = jsonRules.getJSONObject("ContentCheckerRules");

                if (jsonCCRules.has("SafeBrowsing_CheckType"))
                {
                    ccRules.setCheckType(ThreatType.SafeBrowsing, ContentCheckerRules.CheckType.valueOf(jsonCCRules.getString("SafeBrowsing_CheckType")));
                }

                if (jsonCCRules.has("SafeMessaging_CheckType"))
                {
                    ccRules.setCheckType(ThreatType.SafeMessaging, ContentCheckerRules.CheckType.valueOf(jsonCCRules.getString("SafeMessaging_CheckType")));
                }

                if (jsonCCRules.has("AllowedDomainURLs"))
                {
                    ccRules.setCheckList(ContentCheckerRules.CheckListType.ALLOWLIST, ContentCheckerRules.CheckListCategory.DOMAIN_URLS,
                            convertJSONArrayToList(jsonCCRules.getJSONArray("AllowedDomainURLs")));
                }

                if (jsonCCRules.has("DisallowedDomainURLs"))
                {
                    ccRules.setCheckList(ContentCheckerRules.CheckListType.DENYLIST, ContentCheckerRules.CheckListCategory.DOMAIN_URLS,
                            convertJSONArrayToList(jsonCCRules.getJSONArray("DisallowedDomainURLs")));
                }

                if (jsonCCRules.has("AllowedIPs"))
                {
                    ccRules.setCheckList(ContentCheckerRules.CheckListType.ALLOWLIST, ContentCheckerRules.CheckListCategory.IP,
                            convertJSONArrayToList(jsonCCRules.getJSONArray("AllowedIPs")));
                }

                if (jsonCCRules.has("DisallowedIPs"))
                {
                    ccRules.setCheckList(ContentCheckerRules.CheckListType.DENYLIST, ContentCheckerRules.CheckListCategory.IP,
                            convertJSONArrayToList(jsonCCRules.getJSONArray("DisallowedIPs")));
                }

                boolean rulesSaved = manageRules.setContentCheckerRules(ccRules);
                Log.d(TAG, "Content Checker Rules Saved: " + rulesSaved);
            }

            //Parse and apply Device Security Rules.
            if (jsonRules.has("DeviceSecurityRules"))
            {
                DeviceSecurityRules deviceSecurityRules = manageRules.getDeviceSecurityRules();
                JSONObject jsonDeviceSecurityRules = jsonRules.getJSONObject("DeviceSecurityRules");

                if (jsonDeviceSecurityRules.has("DeviceLockScreen_Check"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("DeviceLockScreen_Check")))
                    {
                        deviceSecurityRules.enableCheck(DeviceSecurityRules.DeviceSecurityCheck.DEVICE_LOCK_SCREEN);
                    }
                    else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("DeviceLockScreen_Check")))
                    {
                        deviceSecurityRules.disableCheck(DeviceSecurityRules.DeviceSecurityCheck.DEVICE_LOCK_SCREEN);
                    }
                }

                if (jsonDeviceSecurityRules.has("DeveloperMode_Check"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("DeveloperMode_Check")))
                    {
                        deviceSecurityRules.enableCheck(DeviceSecurityRules.DeviceSecurityCheck.DEVELOPER_MODE);
                    }
                    else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("DeveloperMode_Check")))
                    {
                        deviceSecurityRules.disableCheck(DeviceSecurityRules.DeviceSecurityCheck.DEVELOPER_MODE);
                    }
                }

                if (jsonDeviceSecurityRules.has("EmulatorDetection_Check"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("EmulatorDetection_Check")))
                    {
                        deviceSecurityRules.enableCheck(DeviceSecurityRules.DeviceSecurityCheck.EMULATOR_DETECTION);
                    }
                    else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("EmulatorDetection_Check")))
                    {
                        deviceSecurityRules.disableCheck(DeviceSecurityRules.DeviceSecurityCheck.EMULATOR_DETECTION);
                    }
                }

                if (jsonDeviceSecurityRules.has("GooglePlayProtect_Check"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("GooglePlayProtect_Check")))
                    {
                        deviceSecurityRules.enableCheck(DeviceSecurityRules.DeviceSecurityCheck.PLAY_PROTECT_VERIFICATION);
                    }
                    else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("GooglePlayProtect_Check")))
                    {
                        deviceSecurityRules.disableCheck(DeviceSecurityRules.DeviceSecurityCheck.PLAY_PROTECT_VERIFICATION);
                    }
                }

                if (jsonDeviceSecurityRules.has("DeviceEncryption_Check"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("DeviceEncryption_Check")))
                    {
                        deviceSecurityRules.enableCheck(DeviceSecurityRules.DeviceSecurityCheck.DEVICE_ENCRYPTION);
                    }
                    else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("DeviceEncryption_Check")))
                    {
                        deviceSecurityRules.disableCheck(DeviceSecurityRules.DeviceSecurityCheck.DEVICE_ENCRYPTION);
                    }
                }

                if (jsonDeviceSecurityRules.has("JailbreakDetection_Check"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("JailbreakDetection_Check")))
                    {
                        deviceSecurityRules.enableCheck(DeviceSecurityRules.DeviceSecurityCheck.JAILBREAK_DETECTION);
                    }
                    else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("JailbreakDetection_Check")))
                    {
                        deviceSecurityRules.disableCheck(DeviceSecurityRules.DeviceSecurityCheck.JAILBREAK_DETECTION);
                    }
                }

                if (jsonDeviceSecurityRules.has("AndroidHWKeyVerifyBoot_Check"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("AndroidHWKeyVerifyBoot_Check")))
                    {
                        deviceSecurityRules.enableCheck(DeviceSecurityRules.DeviceSecurityCheck.ANDROID_HWKEY_VERIFY_BOOT);
                    }
                    else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("AndroidHWKeyVerifyBoot_Check")))
                    {
                        deviceSecurityRules.disableCheck(DeviceSecurityRules.DeviceSecurityCheck.ANDROID_HWKEY_VERIFY_BOOT);
                    }
                }

                if (jsonDeviceSecurityRules.has("DebugDetection_Check"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("DebugDetection_Check")))
                    {
                        deviceSecurityRules.enableCheck(DeviceSecurityRules.DeviceSecurityCheck.DEBUG_DETECTION);
                    }
                    else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("DebugDetection_Check")))
                    {
                        deviceSecurityRules.disableCheck(DeviceSecurityRules.DeviceSecurityCheck.DEBUG_DETECTION);
                    }
                }

                if (jsonDeviceSecurityRules.has("DebugDetection_EnforcementAction"))
                {
                    deviceSecurityRules.setEnforcementAction(DeviceSecurityRules.DeviceSecurityCheck.DEBUG_DETECTION,
                            DeviceSecurityRules.EnforcementAction.valueOf(jsonDeviceSecurityRules.getString("DebugDetection_EnforcementAction")));
                }

                if (jsonDeviceSecurityRules.has("HookDetection_Check"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("HookDetection_Check")))
                    {
                        deviceSecurityRules.enableCheck(DeviceSecurityRules.DeviceSecurityCheck.HOOK_DETECTION);
                    }
                    else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonDeviceSecurityRules.getString("HookDetection_Check")))
                    {
                        deviceSecurityRules.disableCheck(DeviceSecurityRules.DeviceSecurityCheck.HOOK_DETECTION);
                    }
                }

                boolean rulesSaved = manageRules.setDeviceSecurityRules(deviceSecurityRules);
                Log.d(TAG, "Device Security Rules Saved: " + rulesSaved);
            }

            //Parse and apply Device Software Rules.
            if (jsonRules.has("AndroidDeviceSoftwareRules"))
            {
                DeviceSoftwareRules deviceSoftwareRules = manageRules.getDeviceSoftwareRules();
                JSONObject jsonDeviceSoftwareRules = jsonRules.getJSONObject("AndroidDeviceSoftwareRules");

                if (jsonDeviceSoftwareRules.has("DeviceSecurityPatchSoftware_Check"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonDeviceSoftwareRules.getString("DeviceSecurityPatchSoftware_Check")))
                    {
                        deviceSoftwareRules.enableCheck(DeviceSoftwareRules.DeviceSoftwareCheck.DEVICE_SECURITY_PATCH_SOFTWARE);
                    }
                    else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonDeviceSoftwareRules.getString("DeviceSecurityPatchSoftware_Check")))
                    {
                        deviceSoftwareRules.disableCheck(DeviceSoftwareRules.DeviceSoftwareCheck.DEVICE_SECURITY_PATCH_SOFTWARE);
                    }
                }

                if (jsonDeviceSoftwareRules.has("DeviceOSSoftware_Check"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonDeviceSoftwareRules.getString("DeviceOSSoftware_Check")))
                    {
                        deviceSoftwareRules.enableCheck(DeviceSoftwareRules.DeviceSoftwareCheck.DEVICE_OS_SOFTWARE);
                    }
                    else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonDeviceSoftwareRules.getString("DeviceOSSoftware_Check")))
                    {
                        deviceSoftwareRules.disableCheck(DeviceSoftwareRules.DeviceSoftwareCheck.DEVICE_OS_SOFTWARE);
                    }
                }

                if (jsonDeviceSoftwareRules.has("DeviceManufacturer_Check"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonDeviceSoftwareRules.getString("DeviceManufacturer_Check")))
                    {
                        deviceSoftwareRules.enableCheck(DeviceSoftwareRules.DeviceSoftwareCheck.DEVICE_MANUFACTURER);
                    }
                    else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonDeviceSoftwareRules.getString("DeviceManufacturer_Check")))
                    {
                        deviceSoftwareRules.disableCheck(DeviceSoftwareRules.DeviceSoftwareCheck.DEVICE_MANUFACTURER);
                    }
                }

                if (jsonDeviceSoftwareRules.has("DeviceModel_Check"))
                {
                    if (ManageFeatures.FeatureStatus.ENABLED.toString().equalsIgnoreCase(jsonDeviceSoftwareRules.getString("DeviceModel_Check")))
                    {
                        deviceSoftwareRules.enableCheck(DeviceSoftwareRules.DeviceSoftwareCheck.DEVICE_MODEL);
                    }
                    else if (ManageFeatures.FeatureStatus.DISABLED.toString().equalsIgnoreCase(jsonDeviceSoftwareRules.getString("DeviceModel_Check")))
                    {
                        deviceSoftwareRules.disableCheck(DeviceSoftwareRules.DeviceSoftwareCheck.DEVICE_MODEL);
                    }
                }

                if (jsonDeviceSoftwareRules.has("ManufacturerDenyList"))
                {
                    deviceSoftwareRules.setManufacturerDenyList(convertJSONArrayToList(jsonDeviceSoftwareRules.getJSONArray("ManufacturerDenyList")));
                }

                if (jsonDeviceSoftwareRules.has("ModelDenyList"))
                {
                    deviceSoftwareRules.setModelDenyList(convertJSONArrayToList(jsonDeviceSoftwareRules.getJSONArray("ModelDenyList")));
                }

                if (jsonDeviceSoftwareRules.has("MinimumOSVersion"))
                {
                    deviceSoftwareRules.setMinimumOSVersion(jsonDeviceSoftwareRules.getString("MinimumOSVersion"));
                }

                if (jsonDeviceSoftwareRules.has("SecurityPatchMinimumDate"))
                {
                    deviceSoftwareRules.setSecurityPatchMinimumDate(new Date(jsonDeviceSoftwareRules.getLong("SecurityPatchMinimumDate")));
                }

                boolean rulesSaved = manageRules.setDeviceSoftwareRules(deviceSoftwareRules);
                Log.d(TAG, "Device Software Rules Saved: " + rulesSaved);
            }

            //Parse and apply Data Collection Rules.
            if (jsonRules.has("DataCollectionRules")) {
                DataCollectionRules  dcRules = manageRules.getDataCollectionRules();
                JSONObject jsonDataCollectionRules = jsonRules.getJSONObject("DataCollectionRules");

                if (jsonDataCollectionRules.has("DataCollectionEnabled"))
                {
                    if ("ENABLED".equalsIgnoreCase(jsonDataCollectionRules.getString("DataCollectionEnabled")))
                    {
                        dcRules.enableDataCollection();
                    }
                    else if ("DISABLED".equalsIgnoreCase(jsonDataCollectionRules.getString("DataCollectionEnabled")))
                    {
                        dcRules.disableDataCollection();
                    }
                }

                if (jsonDataCollectionRules.has("UploadType"))
                {
                    dcRules.setUploadType(DataCollectionRules.UploadType.valueOf(jsonDataCollectionRules.getString("UploadType")));
                }

                if (jsonDataCollectionRules.has("UploadMonthlyLimit"))
                {
                    dcRules.setUploadMonthlyLimit(DataCollectionRules.UploadMonthlyLimit.valueOf(jsonDataCollectionRules.getString("UploadMonthlyLimit")));
                }

                boolean rulesSaved = manageRules.setDataCollectionRules(dcRules);
                Log.d(TAG, "Data Collection Rules Saved: " + rulesSaved);
            }

            //Parse and apply Device Offline Rules.
            if (jsonRules.has("DeviceOfflineRules")) {
                DeviceOfflineRules doRules = manageRules.getDeviceOfflineRules();

                JSONObject jsonDeviceOfflineRules = jsonRules.getJSONObject("DeviceOfflineRules");

                if (jsonDeviceOfflineRules.has("MinutesToMedium"))
                {
                    doRules.setMinutesToMediumThreatLevel(jsonDeviceOfflineRules.getInt("MinutesToMedium"));
                }

                if (jsonDeviceOfflineRules.has("MinutesToHigh"))
                {
                    doRules.setMinutesToHighThreatLevel(jsonDeviceOfflineRules.getInt("MinutesToHigh"));
                }

                boolean rulesSaved = manageRules.setDeviceOfflineRules(doRules);
                Log.d(TAG, "Device Offline Rules Saved: " + rulesSaved);
            }

            Toast toast = Toast.makeText(mContext, "Rules were loaded.", Toast.LENGTH_LONG);
            toast.show();

        } catch (JSONException | IllegalArgumentException e) {
            Log.e(TAG, "Failed to parse JSON. " + Arrays.toString(e.getStackTrace()));

            Toast toast = Toast.makeText(mContext, "Failed to parse JSON.", Toast.LENGTH_LONG);
            toast.show();
        }

        //Trigger re-scans to pick up risks based on newly set rules.
        DeviceChecker dc = new DeviceChecker();
        dc.checkDeviceSecurity();
        dc.checkDeviceSoftware();
    }

    //Converts JSONArray to List<String>
    private List<String> convertJSONArrayToList(JSONArray jsonArray)
    {
        List<String> list = new ArrayList<>();

        for (int i=0; i < jsonArray.length(); i++) {
            list.add( jsonArray.optString(i) );
        }

        return list;
    }

    //Converts all of the scan rules to JSON, which could be saved, uploaded to a server, etc...
    public void saveRules()
    {
        ManageRules manageRules = new ManageRules();
        ManageFeatures manageFeatures = new ManageFeatures();

        //Read in the current active rules.
        MalwareScanRules mwRules = manageRules.getMalwareScanRules();
        ContentCheckerRules ccRules = manageRules.getContentCheckerRules();
        DeviceSecurityRules deviceSecurityRules = manageRules.getDeviceSecurityRules();
        DeviceSoftwareRules deviceSoftwareRules = manageRules.getDeviceSoftwareRules();
        DataCollectionRules dcRules = manageRules.getDataCollectionRules();
        DeviceOfflineRules doRules = manageRules.getDeviceOfflineRules();

        //Save the rules to JSON.
        try
        {
            //Convert MalwareScanRules to JSON.
            JSONObject jsonMWScanRules = new JSONObject();
            jsonMWScanRules.put("MalwareUploadType", mwRules.getUploadType());
            jsonMWScanRules.put("MalwareScanTrigger", mwRules.getScanTrigger());
            jsonMWScanRules.put("MalwareUploadItemSizeLimit_Cellular", mwRules.getUploadItemSizeLimit(MalwareScanRules.UploadType.CELLULAR));
            jsonMWScanRules.put("MalwareUploadItemSizeLimit_WiFi", mwRules.getUploadItemSizeLimit(MalwareScanRules.UploadType.WIFI));
            jsonMWScanRules.put("MalwareUploadMonthlySizeLimit_Cellular", mwRules.getUploadMonthlySizeLimit(MalwareScanRules.UploadType.CELLULAR));
            jsonMWScanRules.put("MalwareUploadMonthlySizeLimit_WiFi", mwRules.getUploadMonthlySizeLimit(MalwareScanRules.UploadType.WIFI));

            //Convert ContentCheckerRules to JSON.
            JSONObject jsonCCRules = new JSONObject();
            jsonCCRules.put("SafeBrowsing_CheckType", ccRules.getCheckType(ThreatType.SafeBrowsing));
            jsonCCRules.put("SafeMessaging_CheckType", ccRules.getCheckType(ThreatType.SafeMessaging));
            List<String>  allowedDomainURLs = ccRules.getCheckList(ContentCheckerRules.CheckListType.ALLOWLIST, ContentCheckerRules.CheckListCategory.DOMAIN_URLS);
            List<String>  disallowedDomainURLs = ccRules.getCheckList(ContentCheckerRules.CheckListType.DENYLIST, ContentCheckerRules.CheckListCategory.DOMAIN_URLS);
            List<String>  allowedIPs = ccRules.getCheckList(ContentCheckerRules.CheckListType.ALLOWLIST, ContentCheckerRules.CheckListCategory.IP);
            List<String>  disallowedIPs = ccRules.getCheckList(ContentCheckerRules.CheckListType.DENYLIST, ContentCheckerRules.CheckListCategory.IP);
            jsonCCRules.put("AllowedDomainURLs", new JSONArray(allowedDomainURLs));
            jsonCCRules.put("DisallowedDomainURLs", new JSONArray(disallowedDomainURLs));
            jsonCCRules.put("AllowedIPs", new JSONArray(allowedIPs));
            jsonCCRules.put("DisallowedIPs", new JSONArray(disallowedIPs));

            //Convert DeviceSecurityRules to JSON.
            JSONObject jsonDeviceSecurityRules = new JSONObject();
            jsonDeviceSecurityRules.put("DeviceLockScreen_Check", deviceSecurityRules.getCheck(DeviceSecurityRules.DeviceSecurityCheck.DEVICE_LOCK_SCREEN));
            jsonDeviceSecurityRules.put("DeveloperMode_Check", deviceSecurityRules.getCheck(DeviceSecurityRules.DeviceSecurityCheck.DEVELOPER_MODE));
            jsonDeviceSecurityRules.put("DeviceEncryption_Check", deviceSecurityRules.getCheck(DeviceSecurityRules.DeviceSecurityCheck.DEVICE_ENCRYPTION));
            jsonDeviceSecurityRules.put("JailbreakDetection_Check", deviceSecurityRules.getCheck(DeviceSecurityRules.DeviceSecurityCheck.JAILBREAK_DETECTION));
            jsonDeviceSecurityRules.put("AndroidHWKeyVerifyBoot_Check", deviceSecurityRules.getCheck(DeviceSecurityRules.DeviceSecurityCheck.ANDROID_HWKEY_VERIFY_BOOT));
            jsonDeviceSecurityRules.put("DebugDetection_Check", deviceSecurityRules.getCheck(DeviceSecurityRules.DeviceSecurityCheck.DEBUG_DETECTION));
            jsonDeviceSecurityRules.put("DebugDetection_EnforcementAction", deviceSecurityRules.getEnforcementAction(DeviceSecurityRules.DeviceSecurityCheck.DEBUG_DETECTION));
            jsonDeviceSecurityRules.put("HookDetection_Check", deviceSecurityRules.getCheck(DeviceSecurityRules.DeviceSecurityCheck.HOOK_DETECTION));
            jsonDeviceSecurityRules.put("EmulatorDetection_Check", deviceSecurityRules.getCheck(DeviceSecurityRules.DeviceSecurityCheck.EMULATOR_DETECTION));
            jsonDeviceSecurityRules.put("GooglePlayProtect_Check", deviceSecurityRules.getCheck(DeviceSecurityRules.DeviceSecurityCheck.PLAY_PROTECT_VERIFICATION));

            //Convert DeviceSoftwareRules to JSON.
            JSONObject jsonDeviceSoftwareRules = new JSONObject();
            jsonDeviceSoftwareRules.put("DeviceSecurityPatchSoftware_Check", deviceSoftwareRules.getCheck(DeviceSoftwareRules.DeviceSoftwareCheck.DEVICE_SECURITY_PATCH_SOFTWARE));
            jsonDeviceSoftwareRules.put("DeviceOSSoftware_Check", deviceSoftwareRules.getCheck(DeviceSoftwareRules.DeviceSoftwareCheck.DEVICE_OS_SOFTWARE));
            jsonDeviceSoftwareRules.put("DeviceManufacturer_Check", deviceSoftwareRules.getCheck(DeviceSoftwareRules.DeviceSoftwareCheck.DEVICE_MANUFACTURER));
            jsonDeviceSoftwareRules.put("DeviceModel_Check", deviceSoftwareRules.getCheck(DeviceSoftwareRules.DeviceSoftwareCheck.DEVICE_MODEL));
            jsonDeviceSoftwareRules.put("ManufacturerDenyList", new JSONArray(deviceSoftwareRules.getManufacturerDenyList()));
            jsonDeviceSoftwareRules.put("ModelDenyList", new JSONArray(deviceSoftwareRules.getModelDenyList()));
            jsonDeviceSoftwareRules.put("MinimumOSVersion", deviceSoftwareRules.getMinimumOSVersion());
            jsonDeviceSoftwareRules.put("SecurityPatchMinimumDate", deviceSoftwareRules.getSecurityPatchMinimumDate().getTime());

            //Convert DataCollectionRules to JSON.
            JSONObject jsonDataCollectionRules = new JSONObject();

            if (dcRules.dataCollectionIsEnabled())
            {
                jsonDataCollectionRules.put("DataCollectionEnabled","ENABLED");
            }
            else
            {
                jsonDataCollectionRules.put("DataCollectionEnabled", "DISABLED");
            }

            jsonDataCollectionRules.put("UploadType", dcRules.getUploadType());
            jsonDataCollectionRules.put("UploadMonthlyLimit", dcRules.getUploadMonthlyLimit());

            //Convert DeviceOfflineRules to JSON.
            JSONObject jsonDeviceOfflineRules = new JSONObject();
            jsonDeviceOfflineRules.put("MinutesToMedium", doRules.getMinutesToMediumThreatLevel());
            jsonDeviceOfflineRules.put("MinutesToHigh", doRules.getMinutesToHighThreatLevel());

            //Convert ManageFeatures to JSON.
            JSONObject jsonFeatures = new JSONObject();
            jsonFeatures.put("AppMalware_Enabled", manageFeatures.getFeature(ThreatType.AppMalware));
            jsonFeatures.put("AppSideload_Enabled", manageFeatures.getFeature(ThreatType.AppSideload));
            jsonFeatures.put("DeviceSecurity_Enabled", manageFeatures.getFeature(ThreatType.DeviceSecurity));
            jsonFeatures.put("DeviceSoftware_Enabled", manageFeatures.getFeature(ThreatType.DeviceSoftware));
            jsonFeatures.put("SafeBrowsing_Enabled", manageFeatures.getFeature(ThreatType.SafeBrowsing));
            jsonFeatures.put("SafeMessaging_Enabled", manageFeatures.getFeature(ThreatType.SafeMessaging));

            //Combine all JSON Objects into a single JSONObject.
            JSONObject allRules = new JSONObject();
            allRules.put("MalwareScanRules", jsonMWScanRules);
            allRules.put("ContentCheckerRules", jsonCCRules);
            allRules.put("DeviceSecurityRules", jsonDeviceSecurityRules);
            allRules.put("AndroidDeviceSoftwareRules", jsonDeviceSoftwareRules);
            allRules.put("DataCollectionRules", jsonDataCollectionRules);
            allRules.put("DeviceOfflineRules", jsonDeviceOfflineRules);
            allRules.put("Features", jsonFeatures);

            //Create compact JSON to send to a server.
            String compactJSONScanRules = allRules.toString();

            //Create human readable JSON for debugging.
            String humanJSONScanRules = allRules.toString(4);

            Log.d(TAG, "JSON Generation is complete");

        } catch (JSONException e) {
            Log.e(TAG, "Error creating JSON: " + Arrays.toString(e.getStackTrace()));
        }
    }
}

