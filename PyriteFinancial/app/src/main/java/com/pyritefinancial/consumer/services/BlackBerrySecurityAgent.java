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

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.util.Log;

import com.blackberry.security.ErrorType;
import com.blackberry.security.InitializationState;
import com.blackberry.security.SecurityControl;
import com.blackberry.security.threat.ThreatLevel;
import com.blackberry.security.threat.ThreatStatus;

//BlackBerrySecurityAgent demonstrates:
//Initialization of BlackBerry Spark SDK.
//Registration of broadcast receivers to receive notifications of the change of the device threat level.
//Triggers an alert using DeviceChecksActivity to warn the user if the threat level is medium, high or critical.

public class BlackBerrySecurityAgent {

    private static final String TAG = BlackBerrySecurityAgent.class.getSimpleName();

    SecurityControl mSecurity;
    PyriteApplication mApp;
    private InitializationState currentState = InitializationState.INITIAL;


    public BlackBerrySecurityAgent(PyriteApplication app)
    {
        mApp = app;
        // Initialize BlackBerry Security
        mSecurity = new SecurityControl(mApp);
        mSecurity.enableSecurity();

        // Register for updates from BlackBerry Security
        registerForThreatUpdates();
    }

    private void registerForThreatUpdates() {

        //Register broadcast receivers sent by the BlackBerry Spark SDK.

        //To receive notifications when the threat status changes.
        IntentFilter filter = new IntentFilter();
        filter.addAction(ThreatStatus.ACTION_THREAT_STATE_NOTIFICATION);

        mSecurity.registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {

                displayThreatStatusResults();

            }
        }, filter);
        Log.d(TAG, "Broadcast receiver has been registered for action " + ThreatStatus.ACTION_THREAT_STATE_NOTIFICATION);

        //To receive notifications when the library initialization status changes.
        filter = new IntentFilter();
        filter.addAction(SecurityControl.ACTION_INITIALIZATION_STATE_NOTIFICATION);

        mSecurity.registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {

                InitializationState state = (InitializationState) intent.getSerializableExtra(InitializationState.KEY_SERIALIZABLE);
                ErrorType error = (ErrorType)intent.getSerializableExtra(InitializationState.KEY_ERRORTYPE);
                int httpStatus = intent.getIntExtra(InitializationState.KEY_HTTPSTATUSCODE, 0);
                updateState(state, error, httpStatus);

            }
        }, filter);
        Log.d(TAG, "Broadcast receiver has been registered for action " + SecurityControl.ACTION_INITIALIZATION_STATE_NOTIFICATION);
    }

    //Handle the various initialization states.
    public void updateState(InitializationState state, ErrorType error, int httpStatus) {

        //The sample doesn't do anything with 'currentState' other than use it for logging.
        Log.d(TAG, "updateState: state " + currentState + " -> " + state);
        currentState = state;

        switch (state) {
            case INITIAL:
                Log.d(TAG, "onUpdateState INITIAL");
                break;

            case REGISTRATION:
                Log.d(TAG, "onUpdateState REGISTRATION");
                //The Firebase token used in this sample will be valid for 1 hour.
                requestLogin("");
                break;

            case TOKENVALIDATION:
                Log.d(TAG, "onUpdateState TOKENVALIDATION");
                break;

            case ACTIVE:
                // As soon as BlackBerry Spark SDK is in active state we can check current threat status.
                Log.d(TAG, "onUpdateState ACTIVE");
                //Log in was successful.  Display the icon screen.
                Intent iconIntent = new Intent(mApp, IconActivity.class);
                iconIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                mApp.startActivity(iconIntent);

                //Display threat status.
                displayThreatStatusResults();
                break;

            case TOKENEXPIRED:
                Log.d(TAG, "onUpdateState TOKENEXPIRED");
                requestLogin("BlackBerry Security log in expired. Please log in again.");
                //This will occur after 1 hour in this sample and is based on the token
                //expiry time for your IDP (Firebase for this sample).
                break;

            case ERROR:
                String errorMessage = "";

                if(ErrorType.ErrorTypeOtherHttpResponse == error) {
                    errorMessage = "BBDSecurity::onUpdateState ERROR: " + error.toString() + " : " + httpStatus;
                }
                else {
                    errorMessage = "BBDSecurity::onUpdateState ERROR: " + error.toString() + " (Domain: " + error.getDomain().toString() + ")";
                }

                Log.d(TAG, errorMessage);
                requestLogin("Failed to log into BlackBerry Security. Please try again.\n" + errorMessage);
                break;
        }
    }

    //Request the user log in.  Display the Login Activity.
    private void requestLogin(String message)
    {
        Intent loginIntent = new Intent(mApp, LoginActivity.class);
        loginIntent.putExtra("com.pyritefinancial.consumer.services.LoginActivity.message", message);
        loginIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        mApp.startActivity(loginIntent);
    }

    //Display the Device Checks Activity.
    private void displayThreatStatusResults()
    {
        //Refresh DeviceChecksActivity is in the foreground, otherwise display a new instance.
        if (!mApp.triggerRefreshDeviceChecksActivity()) {
            // First check overall threat state
            ThreatStatus threatStatus = ThreatStatus.getInstance();
            ThreatLevel overall = threatStatus.getOverallThreatLevel();

            //If it's high or medium warn the user.
            if (overall == ThreatLevel.High || overall == ThreatLevel.Medium) {
                Log.d(TAG, "High or medium threat level. Notifying user.");
                Intent loginIntent = new Intent(mApp, DeviceChecksActivity.class);
                loginIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                mApp.startActivity(loginIntent);
            } else {
                Log.d(TAG, "Low or null threat level.");
            }
        }
    }

    //Pass the authentication token into this class.
    public void doLogin(String token)
    {
        mSecurity.provideToken(token);
    }
}
