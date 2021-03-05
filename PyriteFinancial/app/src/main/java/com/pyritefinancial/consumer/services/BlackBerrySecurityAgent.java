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
import android.os.Bundle;
import android.util.Log;

import androidx.annotation.NonNull;

import com.blackberry.security.ErrorType;
import com.blackberry.security.InitializationState;
import com.blackberry.security.SecurityControl;
import com.blackberry.security.auth.AppAuthentication;
import com.blackberry.security.threat.ThreatLevel;
import com.blackberry.security.threat.ThreatStatus;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.auth.GetTokenResult;

//BlackBerrySecurityAgent demonstrates:
//Initialization of BlackBerry Spark SDK.
//Registration of broadcast receivers to receive notifications of the change of the device threat level.
//Triggers an alert using DeviceChecksActivity to warn the user if the threat level is medium, high or critical.

public class BlackBerrySecurityAgent extends BroadcastReceiver{

    public static final String PIN_REQUEST_TYPE_EXTRA_NAME = "com.pyritefinancial.consumer.services.PINEntryActivit.requestType";
    public static final String LOGIN_MESSAGE_EXTRA_NAME = "com.pyritefinancial.consumer.services.LoginActivity.message";

    public static final int PIN_REQUEST_TYPE_CREATE = 1000;
    public static final int PIN_REQUEST_TYPE_ENTER = 2000;
    public static final int PIN_REQUEST_TYPE_REENTER = 3000;

    public static final String SHARED_PREFS_NAME = "PyriteSharedPrefs";
    public static final String BIOMETRIC_AUTH_OPT_OUT = "BiometricAuthOptOut";

    private static final String TAG = BlackBerrySecurityAgent.class.getSimpleName();

    private int mPINEntryAttempts = 0;

    SecurityControl mSecurity;
    PyriteApplication mApp;
    private InitializationState currentState = InitializationState.INITIAL;


    public BlackBerrySecurityAgent(PyriteApplication app)
    {
        mApp = app;
        // Initialize BlackBerry Security
        mSecurity = new SecurityControl(mApp);
        Bundle configuration = new Bundle();
        //This example enables the BlackBerry Spark SDK's password feature.
        //This optional feature enables a user to set an application password or PIN during setup which
        //is then required to subsequently login to the application. Requiring an application password
        //further protects access to the runtime's Secure Storage and controls authorized access when the device is off-line.
        configuration.putBoolean(SecurityControl.CONFIGURATION_KEY_AUTHENTICATION_REQUIRED, true);
        mSecurity.enableSecurity(configuration);

        // Register for updates from BlackBerry Security
        registerForThreatUpdates();
    }

    private void registerForThreatUpdates() {

        //Register broadcast receivers sent by the BlackBerry Spark SDK.
        //Filters to receive notifications when the threat status and library initialization status changes.
        IntentFilter filter = new IntentFilter();
        filter.addAction(ThreatStatus.ACTION_THREAT_STATE_NOTIFICATION);
        filter.addAction(SecurityControl.ACTION_INITIALIZATION_STATE_NOTIFICATION);
        mSecurity.registerReceiver(this, filter);
        Log.d(TAG, "Broadcast receiver has been registered for actions.");

    }

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();

        if (ThreatStatus.ACTION_THREAT_STATE_NOTIFICATION.equals(action)) {
            displayThreatStatusResults();
        }
        else if (SecurityControl.ACTION_INITIALIZATION_STATE_NOTIFICATION.equals(action)) {
            InitializationState state = (InitializationState) intent.getSerializableExtra(InitializationState.KEY_SERIALIZABLE);
            ErrorType error = (ErrorType)intent.getSerializableExtra(InitializationState.KEY_ERRORTYPE);
            int httpStatus = intent.getIntExtra(InitializationState.KEY_HTTPSTATUSCODE, 0);
            boolean biometryCancelled = intent.getBooleanExtra(InitializationState.KEY_BIOMETRY_CANCELLED, false);
            updateState(state, error, httpStatus, biometryCancelled);
        }
        else {
            Log.e(TAG, "onReceive: unknown action " + action);
        }
    }

    //Handle the various initialization states.
    public void updateState(InitializationState state, ErrorType error, int httpStatus, boolean biometryCancelled) {

        //The sample doesn't do anything with 'currentState' other than use it for logging.
        Log.d(TAG, "updateState: state " + currentState + " -> " + state);
        currentState = state;

        switch (state) {
            case INITIAL:
                Log.d(TAG, "onUpdateState INITIAL");
                break;

            case AUTHENTICATION_SETUP_REQUIRED:
                Log.d(TAG, "onUpdateState AUTHENTICATION_SETUP_REQUIRED");
                requestOrCreatePIN(PIN_REQUEST_TYPE_CREATE);
                break;

            case AUTHENTICATION_REQUIRED:
                Log.d(TAG, "onUpdateState AUTHENTICATION_REQUIRED");

                if (mPINEntryAttempts == 0) {
                    AppAuthentication appAuth = new AppAuthentication();
                    //Initially prompt for biometric authentication if it has been set up.
                    //Otherwise, fall back to PIN.
                    if(appAuth.isBiometricsSetup() && !biometryCancelled) {
                        if(!appAuth.promptBiometrics()) {
                            requestOrCreatePIN(PIN_REQUEST_TYPE_ENTER);
                            mPINEntryAttempts++;
                        }
                    } else {
                        requestOrCreatePIN(PIN_REQUEST_TYPE_ENTER);
                        mPINEntryAttempts++;
                    }
                }
                else
                {
                    //This sample does not limit the number of attempts a user can use to try to
                    //enter their PIN.  For added security, you could limit this to a maximum
                    //amount and call SecurityControl.deactivate() to delete data stored
                    // in BlackBerry Spark storage when the user reaches that threshold.
                    requestOrCreatePIN(PIN_REQUEST_TYPE_REENTER);
                    mPINEntryAttempts++;
                }

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
                //Reset PIN entry counter after a successful login.
                mPINEntryAttempts = 0;

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

    //Request the user create or enter their PIN.
    private void requestOrCreatePIN(int pinRequestType)
    {
        Intent pinEntryIntent = new Intent(mApp, PINEntryActivity.class);
        pinEntryIntent.putExtra(BlackBerrySecurityAgent.PIN_REQUEST_TYPE_EXTRA_NAME, pinRequestType);
        pinEntryIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        mApp.startActivity(pinEntryIntent);
    }

    //Request the user log in.  Display the Login Activity.
    private void requestLogin(final String message)
    {
        FirebaseAuth fbAuth;
        FirebaseUser fbUser;

        // Initialize Firebase Auth
        fbAuth = FirebaseAuth.getInstance();
        fbUser = fbAuth.getCurrentUser();

        if (fbUser != null)
        {
            //User is already logged in.  Get the Firebase ID Token.
            fbUser.getIdToken(false)
                    .addOnCompleteListener(new OnCompleteListener<GetTokenResult>() {
                        public void onComplete(@NonNull Task<GetTokenResult> task) {
                            if (task.isSuccessful()) {
                                //Firebase Id Token was received.  This token will be valid for 1 hour.
                                String idToken = task.getResult().getToken();
                                doLogin(idToken);
                            } else {
                                // Failed to get Firebase Id token.
                                Log.w(TAG, "getIdToken:failure", task.getException());

                                //Their account could be invalid.  Get them to enter their credentials.
                                Intent loginIntent = new Intent(mApp, LoginActivity.class);
                                loginIntent.putExtra(LOGIN_MESSAGE_EXTRA_NAME, message);
                                loginIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                                mApp.startActivity(loginIntent);
                            }
                        }
                    });
        }
        else
        {
            Intent loginIntent = new Intent(mApp, LoginActivity.class);
            loginIntent.putExtra(LOGIN_MESSAGE_EXTRA_NAME, message);
            loginIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            mApp.startActivity(loginIntent);
        }
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
