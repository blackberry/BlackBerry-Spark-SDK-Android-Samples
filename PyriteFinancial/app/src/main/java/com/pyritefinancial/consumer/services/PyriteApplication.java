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

import android.app.Application;

public class PyriteApplication extends Application {

    static BlackBerrySecurityAgent mSa;
    private DeviceChecksActivity mDc = null;

    @Override
    public void onCreate() {
        super.onCreate();

        mSa = new BlackBerrySecurityAgent(this);
    }

    public BlackBerrySecurityAgent getBlackBerrySecurityAgent()
    {
        return mSa;
    }

    //Called by BlackBerrySecurityAgent, triggers DeviceChecksActivity to update the status if
    // it's on the top of the display stack.  If it isn't, BlackBerrySecurityAgent will display it.
    public void setDeviceChecksActivity(DeviceChecksActivity dc)
    {
        mDc = dc;
    }

    public boolean triggerRefreshDeviceChecksActivity()
    {
        if (mDc == null)
        {
            return false;
        }
        else
        {
            mDc.refreshThreatStatus();
            return true;
        }
    }
}
