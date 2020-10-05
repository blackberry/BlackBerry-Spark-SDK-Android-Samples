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

import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;

import com.blackberry.security.config.ManageRules;
import com.blackberry.security.config.rules.DataCollectionRules;
import com.blackberry.security.content.Preferences;

//IconActivity demonstrates:
// BlackBerry Spark SDK secure shared preference storage.
// Enabling of threat data collection.

public class IconActivity extends AppCompatActivity {

    private static final String SHARED_PREFS_NAME = "PyriteSharedPrefs";
    private static final String THREAT_COLLECTION_ENABLED = "ThreatCollectionEnabled";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_icon);
        Toolbar myToolbar = (Toolbar) findViewById(R.id.iconToolbar);
        setSupportActionBar(myToolbar);

        //Read the preference from a BlackBerry Spark SDK secure preference file.
        Preferences p = new Preferences();
        SharedPreferences prefs = p.getSharedPreferences(SHARED_PREFS_NAME, MODE_PRIVATE);

        //Check if the user has agreed to anonymous threat data collection.
        if (prefs.contains(THREAT_COLLECTION_ENABLED)) {

            if (prefs.getBoolean(THREAT_COLLECTION_ENABLED, false)) {
                //They have agreed, enable it.
                enableThreatCollection();
            }
        }
        else
        {
            //Ask user to enable anonymous threat data collection.
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle("Enable Anonymous Threat Data Collection?");
            builder.setMessage("The BlackBerry Spark SDK collects anonymous data that BlackBerry believes may assist in finding new, previously undetected, threats, and increasing confidence in the detection of threats. The information may bring benefits to future detection capabilities. The information collected does not allow identification of the individual user, device or organization.");
            builder.setPositiveButton("Enable", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int id) {
                    //Store the preference in a BlackBerry Spark SDK secure preference file.
                    Preferences p = new Preferences();
                    SharedPreferences prefs = p.getSharedPreferences(SHARED_PREFS_NAME, MODE_PRIVATE);
                    prefs.edit().putBoolean(THREAT_COLLECTION_ENABLED, true).commit();
                    enableThreatCollection();
                    dialog.dismiss();
                }
            });
            builder.setNeutralButton("Ask Me Later", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int id) {
                    dialog.dismiss();
                }
            });
            builder.setNegativeButton("Disable", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int id) {
                    //Store the preference in a BlackBerry Spark SDK secure preference file.
                    Preferences p = new Preferences();
                    SharedPreferences prefs = p.getSharedPreferences(SHARED_PREFS_NAME, MODE_PRIVATE);
                    prefs.edit().putBoolean(THREAT_COLLECTION_ENABLED, false).commit();
                    dialog.dismiss();
                }
            });

            builder.create().show();
        }
    }

    //Enables anonymous threat data collection to aid in discovering new threats.
    private void enableThreatCollection()
    {
        ManageRules manageRules = new ManageRules();
        DataCollectionRules dcRules = manageRules.getDataCollectionRules();
        dcRules.enableDataCollection();
        manageRules.setDataCollectionRules(dcRules);
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
        switch (item.getItemId()) {
            case R.id.action_settings:
                // User chose the "Settings" item, show the app settings UI...
                Intent settingsIntent = new Intent(this, SettingsActivity.class);
                startActivity(settingsIntent);
                return true;

            default:
                return super.onOptionsItemSelected(item);

        }
    }
}