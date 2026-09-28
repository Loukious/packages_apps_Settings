/* Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.settings.security.securespaces;
import android.app.ActivityManager;
import android.content.Context;
import android.os.UserHandle;
import android.os.UserManager;
import com.android.settings.core.BasePreferenceController;

/** The management entry is constant for the owner and never advertises stored configuration. */
public final class SecureAuthDuressPreferenceController extends BasePreferenceController {
    public SecureAuthDuressPreferenceController(Context context, String key) { super(context, key); }
    @Override public int getAvailabilityStatus() {
        UserManager users = mContext.getSystemService(UserManager.class);
        return users.getUserHandle() == UserHandle.USER_SYSTEM && users.isAdminUser()
                && ActivityManager.getCurrentUser() == UserHandle.USER_SYSTEM
                ? AVAILABLE : DISABLED_FOR_USER;
    }
}
