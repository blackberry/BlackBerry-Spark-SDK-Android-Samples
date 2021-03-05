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

import android.os.Bundle;

import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.auth.AuthResult;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.auth.GetTokenResult;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import android.text.Editable;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

//LoginActivity demonstrates:
// Authenticates the user to Firebase, which is one of many identify providers that can be used with BlackBerry Spark SDK.

public class LoginActivity extends AppCompatActivity {

    private static final String TAG = LoginActivity.class.getSimpleName();

    private FirebaseAuth mAuth;
    private FirebaseUser user;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        //Receive any error message that may have occurred while logging in.
        String errorMessage = (String)getIntent().getSerializableExtra(BlackBerrySecurityAgent.LOGIN_MESSAGE_EXTRA_NAME);

        if (errorMessage != null) {
            TextView tvErrorMessage = findViewById(R.id.textViewMessage);
            tvErrorMessage.setText(errorMessage);
        }

        // Initialize Firebase Auth
        mAuth = FirebaseAuth.getInstance();
    }

    @Override
    public void onBackPressed() {
        //Intentionally doing nothing to prevent dismissal of the login screen using the back button.
    }

    //Attempt to log into Firebase and obtain an authorization token, which will be used during
    //initialization of the BlackBerry Spark SDK.
    public void onButtonLogin(View view)
    {
        EditText editTextUserName = findViewById(R.id.editTextUserName);
        EditText editTextPassword = findViewById(R.id.editTextTextPassword);
        Editable userName = editTextUserName.getText();
        Editable password = editTextPassword.getText();

        if (userName.length() > 0 && password.length() > 0) {

            mAuth.signInWithEmailAndPassword(userName.toString(), password.toString())
                    .addOnCompleteListener(this, new OnCompleteListener<AuthResult>() {
                        @Override
                        public void onComplete(@NonNull Task<AuthResult> task) {
                            if (task.isSuccessful()) {
                                // Sign in success, update UI with the signed-in user's information
                                Log.d(TAG, "signInWithEmail:success");
                                user = mAuth.getCurrentUser();

                                //Login was successful, now get the Firebase ID Token.
                                user.getIdToken(false)
                                        .addOnCompleteListener(new OnCompleteListener<GetTokenResult>() {
                                            public void onComplete(@NonNull Task<GetTokenResult> task) {
                                                if (task.isSuccessful()) {
                                                    //Firebase Id Token was received.  This token will be valid for 1 hour.
                                                    String idToken = task.getResult().getToken();

                                                    //Use the token to log into BlackBerry Spark.
                                                    PyriteApplication pa = (PyriteApplication)getApplication();
                                                    pa.getBlackBerrySecurityAgent().doLogin(idToken);
                                                    LoginActivity.this.finish();
                                                } else {
                                                    // Failed to get Firebase Id token.
                                                    Log.w(TAG, "getIdToken:failure", task.getException());
                                                    Toast.makeText(LoginActivity.this, "Failed to obtain Firebase Id Token.",
                                                            Toast.LENGTH_LONG).show();
                                                }
                                            }
                                        });


                            } else {
                                // If sign in fails, display a message to the user.
                                Log.w(TAG, "signInWithEmail:failure", task.getException());
                                Toast.makeText(LoginActivity.this, "Authentication failed.",
                                        Toast.LENGTH_LONG).show();
                            }
                        }
                    });
        }
        else {
            Toast.makeText(LoginActivity.this, "Enter a user name and password.",
                    Toast.LENGTH_SHORT).show();
        }
    }
}