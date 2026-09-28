/*
 * Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.settings.security.securespaces;

import android.content.Context;
import android.os.UserHandle;
import android.os.UserManager;

import com.android.settings.core.BasePreferenceController;

public class SecureSpacesPreferenceController extends BasePreferenceController {
    public SecureSpacesPreferenceController(Context context, String key) {
        super(context, key);
    }

    @Override
    public int getAvailabilityStatus() {
        UserManager users = mContext.getSystemService(UserManager.class);
        return users.getUserHandle() == UserHandle.USER_SYSTEM && users.isAdminUser()
                && users.isUserTypeEnabled(UserManager.USER_TYPE_FULL_SECURE_SPACE)
                ? AVAILABLE : DISABLED_FOR_USER;
    }
}
