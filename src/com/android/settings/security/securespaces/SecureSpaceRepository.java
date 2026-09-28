/*
 * Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.settings.security.securespaces;

import android.app.ActivityManager;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.content.pm.UserInfo;
import android.os.UserHandle;
import android.os.UserManager;
import android.provider.Settings;

import com.android.internal.widget.LockPatternUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.function.IntSupplier;

/** Uses UserManager's persisted user type as the authoritative Secure Spaces registry. */
public final class SecureSpaceRepository {
    private final UserManager mUsers;
    private final LockPatternUtils mLockPatternUtils;
    private final IntSupplier mForegroundUser;
    private final ContentResolver mResolver;

    public SecureSpaceRepository(Context context) {
        this(context.getSystemService(UserManager.class), new LockPatternUtils(context),
                ActivityManager::getCurrentUser, context.getContentResolver());
    }

    SecureSpaceRepository(UserManager users, LockPatternUtils lockPatternUtils,
            IntSupplier foregroundUser) {
        this(users, lockPatternUtils, foregroundUser, null);
    }

    SecureSpaceRepository(UserManager users, LockPatternUtils lockPatternUtils,
            IntSupplier foregroundUser, ContentResolver resolver) {
        mUsers = users;
        mLockPatternUtils = lockPatternUtils;
        mForegroundUser = foregroundUser;
        mResolver = resolver;
    }

    public boolean isOwner() {
        return mUsers.getUserHandle() == UserHandle.USER_SYSTEM
                && mForegroundUser.getAsInt() == UserHandle.USER_SYSTEM
                && mUsers.isAdminUser();
    }

    public boolean hasOwnerCredential() {
        return mLockPatternUtils.isSecure(UserHandle.USER_SYSTEM);
    }

    public int getOwnerCredentialType() {
        return mLockPatternUtils.getCredentialTypeForUser(UserHandle.USER_SYSTEM);
    }

    public boolean hasOwnerRoutingCredential() {
        return hasRoutingCredential(UserHandle.USER_SYSTEM);
    }

    private boolean hasRoutingCredential(int userId) {
        int type = mLockPatternUtils.getCredentialTypeForUser(userId);
        return mLockPatternUtils.isSecure(userId)
                && (type == LockPatternUtils.CREDENTIAL_TYPE_PIN
                    || type == LockPatternUtils.CREDENTIAL_TYPE_PASSWORD);
    }

    public boolean canCreateSpace() {
        return isOwner() && hasOwnerRoutingCredential()
                && !mUsers.hasUserRestriction(UserManager.DISALLOW_ADD_USER)
                && mUsers.canAddMoreUsers(UserManager.USER_TYPE_FULL_SECURE_SPACE);
    }

    public List<UserInfo> getSpaces() {
        List<UserInfo> result = new ArrayList<>();
        for (UserInfo user : mUsers.getAliveUsers()) {
            if (isSpace(user)) {
                result.add(user);
            }
        }
        return result;
    }

    public boolean hasCredential(int userId) {
        return hasRoutingCredential(userId);
    }

    /** Eligible identities only; this method never verifies or stores a credential. */
    public List<UserInfo> getRoutingCandidates() {
        List<UserInfo> result = new ArrayList<>();
        for (UserInfo user : mUsers.getAliveUsers()) {
            if ((user.id == UserHandle.USER_SYSTEM || isSpace(user))
                    && !user.partial && !user.preCreated && user.isFull()
                    && user.isEnabled() && user.isInitialized()
                    && mLockPatternUtils.isSecure(user.id)) {
                result.add(user);
            }
        }
        return result;
    }

    public UserInfo createSpace(String name) {
        enforceOwner();
        if (!canCreateSpace()) {
            throw new IllegalStateException("Secure Space creation is unavailable");
        }
        UserInfo user = mUsers.createUser(validateName(name),
                UserManager.USER_TYPE_FULL_SECURE_SPACE, UserInfo.FLAG_INITIALIZED);
        if (user == null) {
            throw new IllegalStateException("UserManager could not create the Secure Space");
        }
        // Secure Spaces have their own guided credential/fingerprint setup. Do not launch the
        // generic secondary-user Setup Wizard when the space is first opened. Xiaomi's Second
        // Space initialization likewise marks the destination user setup-complete before entry.
        if (mResolver != null && !Settings.Secure.putIntForUser(mResolver,
                Settings.Secure.USER_SETUP_COMPLETE, 1, user.id)) {
            mUsers.removeUserWhenPossible(user.getUserHandle(), false);
            throw new IllegalStateException("Secure Space could not be initialized");
        }
        return user;
    }

    public void renameSpace(UserInfo identity, String name) {
        enforceOwner();
        requireSpace(identity);
        mUsers.setUserName(identity.id, validateName(name));
    }

    public void removeSpace(UserInfo identity) {
        enforceOwner();
        requireSpace(identity);
        if (mUsers.hasUserRestriction(UserManager.DISALLOW_REMOVE_USER)) {
            throw new SecurityException("User removal is restricted");
        }
        if (!UserManager.isRemoveResultSuccessful(
                mUsers.removeUserWhenPossible(UserHandle.of(identity.id), false))) {
            throw new IllegalStateException("UserManager could not remove the Secure Space");
        }
    }

    public void switchToSpace(UserInfo identity) {
        enforceOwner();
        UserInfo user = requireSpace(identity);
        if (!hasOwnerRoutingCredential() || !hasRoutingCredential(user.id)
                || !user.isEnabled() || !user.supportsSwitchTo()
                || mUsers.hasUserRestriction(UserManager.DISALLOW_USER_SWITCH)) {
            throw new SecurityException("User switching is unavailable");
        }
        try {
            if (!ActivityManager.getService().switchUser(user.id)) {
                throw new IllegalStateException("User switch failed");
            }
        } catch (android.os.RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }

    /** Enroll as the destination user, after its first primary unlock, never as owner UID. */
    public void switchToSpaceAndEnrollFingerprint(Context context, UserInfo identity) {
        enforceOwner();
        UserInfo target = requireSpace(identity);
        Context application = context.getApplicationContext();
        Handler main = new Handler(Looper.getMainLooper());
        long deadline = SystemClock.elapsedRealtime() + 120_000;
        switchToSpace(target);
        main.post(new Runnable() {
            private boolean sawDestination;
            @Override public void run() {
                if (SystemClock.elapsedRealtime() >= deadline) return;
                UserInfo current = mUsers.getUserInfo(target.id);
                if (!isSpace(current) || current.serialNumber != target.serialNumber
                        || !current.isEnabled()) return;
                int foreground = ActivityManager.getCurrentUser();
                if (foreground == target.id) sawDestination = true;
                else if (sawDestination || foreground != UserHandle.USER_SYSTEM) return;
                if (foreground == target.id
                        && mUsers.isUserUnlocked(UserHandle.of(target.id))) {
                    Intent enroll = new Intent(application,
                            com.android.settings.biometrics.fingerprint.
                                    FingerprintEnrollIntroduction.class);
                    enroll.putExtra(Intent.EXTRA_USER_ID, target.id);
                    enroll.putExtra(com.android.settings.biometrics.BiometricEnrollIntroduction
                            .EXTRA_DEFER_CONFIRM_UNTIL_UNLOCKED, true);
                    enroll.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                            | Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS);
                    try { application.startActivityAsUser(enroll, UserHandle.of(target.id)); }
                    catch (RuntimeException unavailable) {
                        // The space remains usable; enrollment can be opened in its Settings.
                        android.util.Log.w("SecureSpaceRepository",
                                "Fingerprint setup could not be opened");
                    }
                    return;
                }
                main.postDelayed(this, 250);
            }
        });
    }

    private void enforceOwner() {
        if (!isOwner() || !hasOwnerCredential()) {
            throw new SecurityException("A credential-protected foreground owner is required");
        }
    }

    private UserInfo requireSpace(UserInfo identity) {
        UserInfo user = mUsers.getUserInfo(identity.id);
        if (!isSpace(user) || user.serialNumber != identity.serialNumber) {
            throw new IllegalArgumentException("Secure Space identity is no longer valid");
        }
        return user;
    }

    private static boolean isSpace(UserInfo user) {
        return user != null && user.id != UserHandle.USER_SYSTEM && user.isFull()
                && !user.partial && !user.preCreated
                && UserManager.USER_TYPE_FULL_SECURE_SPACE.equals(user.userType);
    }

    private static String validateName(String name) {
        if (name == null || name.trim().isEmpty()
                || name.trim().length() > UserManager.MAX_USER_NAME_LENGTH) {
            throw new IllegalArgumentException("Invalid Secure Space name");
        }
        return name.trim();
    }
}
