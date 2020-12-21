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
import androidx.core.content.ContextCompat;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

import com.blackberry.security.SecurityControl;
import com.blackberry.security.auth.AppAuthentication;

//PINEntryActivity demonstrates:
//Allows creation and entry of a PIN defined by the user,  which is then required to subsequently
//login to the application. Requiring an application password is an optional feature that further
// protects access to the runtime's Secure Storage and helps control authorized access when the
// device is off-line.

public class PINEntryActivity extends AppCompatActivity {

    private int mPINRequestType;  //Stores whether this is creation of a new PIN or entry of an existing one.
    private String mPINBeingEntered = new String();  //The PIN the user is entering.

    private String mFirstNewPIN = "";  //When creating a PIN we have the user enter it twice. The first value is stored here.

    private TextView mTopMessageTextView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pin_entry);

        mTopMessageTextView = findViewById(R.id.topMessageTextView);

        //Receive any error message that may have occurred while logging in.
        mPINRequestType = (int)getIntent().getSerializableExtra(BlackBerrySecurityAgent.PIN_REQUEST_TYPE_EXTRA_NAME);

        if (BlackBerrySecurityAgent.PIN_REQUEST_TYPE_CREATE == mPINRequestType)
        {
            mTopMessageTextView.setText("Create a 5 Digit PIN");
        }
        else if (BlackBerrySecurityAgent.PIN_REQUEST_TYPE_ENTER == mPINRequestType)
        {
            mTopMessageTextView.setText("Enter Your 5 Digit PIN");
        }
        else if (BlackBerrySecurityAgent.PIN_REQUEST_TYPE_REENTER == mPINRequestType)
        {
            mTopMessageTextView.setText("Incorrect PIN. Try again.");
        }
    }

    @Override
    public void onBackPressed() {
        //Intentionally doing nothing to prevent dismissal of the login screen using the back button.
    }

    public void onClickNumber(View view)
    {
        switch (view.getId())
        {
            case R.id.oneImageView:
                mPINBeingEntered += '1';
                handlePINEntry();
            break;

            case R.id.twoImageView:
                mPINBeingEntered += '2';
                handlePINEntry();
            break;

            case R.id.threeImageView:
                mPINBeingEntered += '3';
                handlePINEntry();
            break;

            case R.id.fourImageView:
                mPINBeingEntered += '4';
                handlePINEntry();
                break;

            case R.id.fiveImageView:
                mPINBeingEntered += '5';
                handlePINEntry();
                break;

            case R.id.sixImageView:
                mPINBeingEntered += '6';
                handlePINEntry();
                break;

            case R.id.sevenImageView:
                mPINBeingEntered += '7';
                handlePINEntry();
                break;

            case R.id.eightImageView:
                mPINBeingEntered += '8';
                handlePINEntry();
                break;

            case R.id.nineImageView:
                mPINBeingEntered += '9';
                handlePINEntry();
                break;

            case R.id.zeroImageView:
                mPINBeingEntered += '0';
                handlePINEntry();
                break;

            case R.id.backImageView:
                if (mPINBeingEntered.length() > 0) {
                    mPINBeingEntered = mPINBeingEntered.substring(0, mPINBeingEntered.length() - 1);
                    handlePINEntry();
                }
                break;
        }
    }

    private void handlePINEntry()
    {
        int pinLength = mPINBeingEntered.length();
        ImageView circle1 = findViewById(R.id.pinCircle1ImageView);
        ImageView circle2 = findViewById(R.id.pinCircle2ImageView);
        ImageView circle3 = findViewById(R.id.pinCircle3ImageView);
        ImageView circle4 = findViewById(R.id.pinCircle4ImageView);
        ImageView circle5 = findViewById(R.id.pinCircle5ImageView);

        switch (pinLength)
        {
            case 0:
                circle1.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
            break;

            case 1:
                circle1.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_entered_circle));
                circle2.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
            break;

            case 2:
                circle2.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_entered_circle));
                circle3.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
            break;

            case 3:
                circle3.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_entered_circle));
                circle4.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
            break;

            case 4:
                circle4.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_entered_circle));
                circle5.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
            break;

            case 5:
                circle5.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_entered_circle));

                if (BlackBerrySecurityAgent.PIN_REQUEST_TYPE_CREATE == mPINRequestType)
                {
                    if (mFirstNewPIN.length() == 5 && mFirstNewPIN.equals(mPINBeingEntered)) {
                        //PIN was entered twice and both PINs match.  Set password and finish.
                        AppAuthentication appAuth = new AppAuthentication();
                        appAuth.setPassword(mPINBeingEntered);
                        this.finish();
                    }
                    else if (mFirstNewPIN.length() == 5 && !mFirstNewPIN.equals(mPINBeingEntered))
                    {
                        //PIN was entered twice but PINs don't match.  Reset and try again.
                        mTopMessageTextView.setText("PINs didn't match.  Try again.");
                        mPINBeingEntered = "";
                        mFirstNewPIN = "";
                        circle1.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
                        circle2.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
                        circle3.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
                        circle4.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
                        circle5.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
                    }
                    else if (mFirstNewPIN.length() < 5)
                    {
                        mFirstNewPIN = mPINBeingEntered;
                        mPINBeingEntered = "";
                        mTopMessageTextView.setText("Enter PIN a Second Time");
                        circle1.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
                        circle2.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
                        circle3.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
                        circle4.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
                        circle5.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.pin_not_entered_circle));
                    }
                }
                else if (BlackBerrySecurityAgent.PIN_REQUEST_TYPE_ENTER == mPINRequestType ||
                        BlackBerrySecurityAgent.PIN_REQUEST_TYPE_REENTER == mPINRequestType)
                {
                    //User entered their PIN.  Close and accept.
                    AppAuthentication appAuth = new AppAuthentication();
                    appAuth.enterPassword(mPINBeingEntered);
                    this.finish();
                }
            break;
        }
    }
}