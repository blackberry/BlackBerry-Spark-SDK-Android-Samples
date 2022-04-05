/*
 * Copyright (c) 2020 BlackBerry Limited. All Rights Reserved.
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
 */

var express = require('express');
const fs = require('fs');
const path = require('path');
var router = express.Router();
const storage = require('node-persist');

router.get('/', async(req, res) => {
    const appAuthicityID = req.query.appAuthenticityID
    const appInstanceID = req.query.appInstanceID
    if (appAuthicityID && appInstanceID) {
        const savedAppInstanceIds = await storage.getItem("appInstanceIds")
        const savedAppAuthicityIDs = await storage.getItem("appAuthicityIDs")

        if (savedAppInstanceIds && savedAppAuthicityIDs) {
            if (savedAppAuthicityIDs[appAuthicityID] === undefined) {
                savedAppAuthicityIDs[appAuthicityID] = {
                    count : 1,
                    appInstanceIds: [appInstanceID]
                }
            } else {
                if (!savedAppAuthicityIDs[appAuthicityID]["appInstanceIds"].includes(appInstanceID)) {
                    savedAppAuthicityIDs[appAuthicityID].count = savedAppAuthicityIDs[appAuthicityID].count + 1
                    savedAppAuthicityIDs[appAuthicityID]["appInstanceIds"] = [...savedAppAuthicityIDs[appAuthicityID]["appInstanceIds"], appInstanceID]
                }
            }

            if (savedAppInstanceIds[appInstanceID] === undefined) {    
                savedAppInstanceIds[appInstanceID] = {
                    count: 1
                }
            } else {
                savedAppInstanceIds[appInstanceID].count = savedAppInstanceIds[appInstanceID].count + 1
            }

            await storage.setItem("appInstanceIds", savedAppInstanceIds)
            await storage.setItem("appAuthicityIDs", savedAppAuthicityIDs)
        } else {
            const appAuthenticitydata = {}
            appAuthenticitydata[appAuthicityID] = {
                count : 1,
                appInstanceIds: [appInstanceID]
            }

            const appInstanceData = {}
            appInstanceData[appInstanceID] = {
                count: 1
            }

            await storage.setItem("appInstanceIds", appInstanceData)
            await storage.setItem("appAuthicityIDs", appAuthenticitydata)
        }
    }

    var filePath = path.join(__dirname, '../rules/rules.json');
    var stat = fs.statSync(filePath);

    res.writeHead(200, {
		"Content-Type": "application/json",
        'Content-Length': stat.size
    });

    var readStream = fs.createReadStream(filePath);
    readStream.pipe(res);
});

router.post('/save', function(req, res) {
    const incomingRules = req.body;
    const newRules = {
        "ContentCheckerRules": {
            "SafeBrowsing_CheckType": incomingRules.safeBrowsingCheckType,
            "SafeMessaging_CheckType": incomingRules.safeMessagingCheckType,
            "AllowedDomainURLs": incomingRules.allowedDomains.split(','),
            "DisallowedDomainURLs": incomingRules.disallowedDomains.split(','),
            "AllowedIPs": incomingRules.allowedIps.split(','),
            "DisallowedIPs": incomingRules.disallowedIps.split(',')
        },
        "DeviceSecurityRules": {
            "DeviceLockScreen_Check": incomingRules.deviceLockScreenCheck,
            "DebugDetection_Check": incomingRules.debugDetectionCheck,
            "DebugDetection_EnforcementAction": incomingRules.debugDetectionEnforcementAction,
            "JailbreakDetection_Check": incomingRules.jailbreakDetectionCheck,
            "HookDetection_Check": incomingRules.hookDetectionCheck,
            "DeviceEncryption_Check": incomingRules.deviceEncryptionCheck,
            "AndroidHWKeyVerifyBoot_Check": incomingRules.androidHWKeyVerifyBootCheck,
            "DeveloperMode_Check": incomingRules.developerModeCheck,
			"EmulatorDetection_Check": incomingRules.emulatorDetectionCheck,
			"GooglePlayProtect_Check": incomingRules.playProtectCheck
        },
        "iOSDeviceSoftwareRules": {
            "DeviceOSSoftware_Check": incomingRules.iOSDeviceOSSoftwareCheck,
            "MinimumOSVersion": incomingRules.iOSMinimumOsVersion
        },
        "AndroidDeviceSoftwareRules": {
            "DeviceSecurityPatchSoftware_Check": incomingRules.deviceSecurityPatchSoftwareCheck,
            "DeviceOSSoftware_Check": incomingRules.androidDeviceOSSoftwareCheck,
            "DeviceManufacturer_Check": incomingRules.deviceManufacturerCheck,
            "DeviceModel_Check": incomingRules.deviceModelCheck,
            "ManufacturerDenyList": incomingRules.manufacturerDenyList.split(','),
            "ModelDenyList": incomingRules.modelDenyList.split(','),
            "MinimumOSVersion": incomingRules.androidMinimumOsVersion,
            "SecurityPatchMinimumDate": incomingRules.securityPatchMinimumDate
        },
        "MalwareScanRules": {
            "MalwareUploadType": incomingRules.malwareUploadType,
            "MalwareScanTrigger": incomingRules.malwareScanTrigger,
            "MalwareUploadItemSizeLimit_Cellular": incomingRules.malwareUploadItemSizeLimit_Cellular,
			"MalwareUploadItemSizeLimit_WiFi": incomingRules.malwareUploadItemSizeLimit_WiFi,
			"MalwareUploadMonthlySizeLimit_Cellular": incomingRules.malwareUploadMonthlySizeLimit_Cellular,
			"MalwareUploadMonthlySizeLimit_WiFi": incomingRules.malwareUploadMonthlySizeLimit_WiFi
        },
        "DeviceOfflineRules": {
            "MinutesToMedium": incomingRules.minutesToMedium,
            "MinutesToHigh": incomingRules.minutesToHigh
        },
        "Features": {
            "AppMalware_Enabled": incomingRules.appMalwareEnabled,
            "AppSideload_Enabled": incomingRules.appSideloadEnabled,
            "DeviceSecurity_Enabled": incomingRules.deviceSecurityEnabled,
            "DeviceSoftware_Enabled": incomingRules.deviceSoftwareEnabled,
            "SafeBrowsing_Enabled": incomingRules.safeBrowsingEnabled,
            "SafeMessaging_Enabled": incomingRules.safeMessagingEnabled,
            "DeviceOffline_Enabled": incomingRules.deviceOfflineEnabled,
			"NetworkSecurity_Enabled": incomingRules.networkSecurityEnabled,
			"WiFiSecurity_Enabled": incomingRules.wiFiSecurityEnabled
        }
    }
	
    fs.writeFile('./rules/rules.json' , JSON.stringify(newRules), (err) => {
        if (err) {
            throw err;
        }
        res.redirect('/');
    });
});

module.exports = router;