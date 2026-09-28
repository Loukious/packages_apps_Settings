/* Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.settings.security.securespaces;

import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.app.settings.SettingsEnums;
import android.content.Intent;
import android.content.pm.UserInfo;
import android.os.Bundle;
import android.os.UserHandle;
import android.os.UserManager;
import android.view.View;
import android.view.WindowManager;
import android.widget.Toast;
import androidx.lifecycle.ViewModelProvider;
import androidx.preference.Preference;
import androidx.preference.PreferenceScreen;
import com.android.internal.widget.LockPatternUtils;
import com.android.internal.widget.LockscreenCredential;
import com.android.settings.R;
import com.android.settings.SettingsPreferenceFragment;
import com.android.settings.Utils;
import com.android.settings.password.ChooseLockPassword;
import com.android.settings.password.ChooseLockSettingsHelper;

/** Xiaomi-style lock-then-fingerprint setup using the ROM's native credential screens. */
public final class SecureSpaceLockSettings extends SettingsPreferenceFragment {
    public static final String ARG_USER_ID = "secure_space_user_id";
    public static final String ARG_SERIAL = "secure_space_serial";
    private static final int CONFIRM_OWNER = 321;
    private static final int CHOOSE_CREDENTIAL = 322;
    private static final int CONFIRM_FINGERPRINT = 323;
    private static final int CONFIRM_OPEN = 324;
    private SecureSpaceLockViewModel mModel;
    private LockscreenCredential mPendingCredential;
    private int mPendingOpen;
    private long mPendingOpenAt;
    private int mUserId;
    private int mSerial;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        mModel = new ViewModelProvider(this).get(SecureSpaceLockViewModel.class);
        Bundle args = getArguments();
        mUserId = args == null ? -1 : args.getInt(ARG_USER_ID, -1);
        mSerial = args == null ? -1 : args.getInt(ARG_SERIAL, -1);
        try { mModel.setIdentity(mUserId, mSerial); }
        catch (IllegalArgumentException invalid) { finish(); }
    }
    @Override public void onViewCreated(View view, Bundle state) {
        super.onViewCreated(view, state);
        getActivity().getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        mModel.getState().observe(getViewLifecycleOwner(), this::render);
    }
    @Override public void onResume() {
        super.onResume();
        getActivity().setTitle(getText(R.string.secure_spaces_lock_and_fingerprint));
        if (!mModel.isOwner()) { finish(); return; }
        mModel.onForeground();
        if (mPendingCredential != null) {
            LockscreenCredential credential = mPendingCredential;
            mPendingCredential = null;
            if (mModel.stage(credential)) launchConfirmation(CONFIRM_OWNER, true);
            else {
                credential.close();
                Toast.makeText(getContext(), R.string.secure_spaces_operation_failed,
                        Toast.LENGTH_SHORT).show();
            }
        }
        if (mPendingOpen != 0) {
            int action = mPendingOpen;
            mPendingOpen = 0;
            long age = android.os.SystemClock.elapsedRealtime() - mPendingOpenAt;
            if (age >= 0 && age < 30_000) openSpace(action == CONFIRM_FINGERPRINT);
        }
        render(mModel.getState().getValue());
    }
    @Override public void onStop() {
        mModel.onBackground();
        setPreferenceScreen(getPreferenceManager().createPreferenceScreen(getPrefContext()));
        super.onStop();
    }
    @Override public void onDestroy() {
        if (mPendingCredential != null) mPendingCredential.close();
        super.onDestroy();
    }
    @Override public int getMetricsCategory() { return SettingsEnums.SECURITY; }
    private void render(SecureSpaceLockViewModel.State state) {
        if (!isAdded()) return;
        PreferenceScreen screen = getPreferenceManager().createPreferenceScreen(getPrefContext());
        setPreferenceScreen(screen);
        Preference description = new Preference(getPrefContext());
        description.setSelectable(false);
        description.setSummary(mModel.isConfigured() ? R.string.secure_spaces_fingerprint_description
                : mModel.canConfigure() ? R.string.secure_spaces_initial_lock_description
                : R.string.secure_spaces_owner_lock_required);
        screen.addPreference(description);
        if (!mModel.canConfigure()) return;
        if (mModel.isConfigured()) {
            if (Utils.hasFingerprintHardware(getContext())) {
                addAction(screen, R.string.secure_spaces_set_fingerprint,
                        () -> launchConfirmation(CONFIRM_FINGERPRINT, false));
            }
            addAction(screen, R.string.secure_spaces_open,
                    () -> launchConfirmation(CONFIRM_OPEN, false));
        } else {
            boolean pin = mModel.getOwnerCredentialType() == LockPatternUtils.CREDENTIAL_TYPE_PIN;
            addAction(screen, pin ? R.string.secure_spaces_set_pin
                    : R.string.secure_spaces_set_password, () -> chooseCredential(pin));
        }
        if (state.failed) {
            Preference error = new Preference(getPrefContext());
            error.setSummary(R.string.secure_spaces_operation_failed);
            error.setSelectable(false);
            screen.addPreference(error);
        }
        screen.setEnabled(!state.busy);
    }
    private void addAction(PreferenceScreen screen, int title, Runnable action) {
        Preference choice = new Preference(getPrefContext());
        choice.setTitle(title);
        choice.setOnPreferenceClickListener(ignored -> { action.run(); return true; });
        screen.addPreference(choice);
    }
    private void chooseCredential(boolean pin) {
        if (!mModel.canConfigure() || mModel.getState().getValue().busy) return;
        Intent intent = new ChooseLockPassword.IntentBuilder(getContext())
                .setUserId(UserHandle.USER_SYSTEM)
                .setPasswordType(pin ? DevicePolicyManager.PASSWORD_QUALITY_NUMERIC
                        : DevicePolicyManager.PASSWORD_QUALITY_ALPHABETIC).build();
        intent.putExtra(ChooseLockPassword.EXTRA_COLLECT_CREDENTIAL, true);
        intent.putExtra(ChooseLockPassword.EXTRA_COLLECT_DESCRIPTION,
                getString(R.string.secure_spaces_initial_lock_description));
        startActivityForResult(intent, CHOOSE_CREDENTIAL);
    }
    private void launchConfirmation(int request, boolean returnCredential) {
        boolean launched = new ChooseLockSettingsHelper.Builder(getActivity(), this)
                .setRequestCode(request)
                .setTitle(getText(R.string.secure_spaces_initial_lock_title))
                .setUserId(UserHandle.USER_SYSTEM).setForceVerifyPath(false)
                .setForegroundOnly(true).setReturnCredentials(returnCredential).show();
        if (!launched) mModel.cancel();
    }
    private void openSpace(boolean fingerprint) {
        try {
            UserInfo target = getContext().getSystemService(UserManager.class).getUserInfo(mUserId);
            if (target == null || target.serialNumber != mSerial) {
                throw new IllegalStateException("Space identity changed");
            }
            SecureSpaceRepository repository = new SecureSpaceRepository(getContext());
            if (fingerprint) {
                Toast.makeText(getContext(), R.string.secure_spaces_fingerprint_unlock,
                        Toast.LENGTH_LONG).show();
                repository.switchToSpaceAndEnrollFingerprint(getContext(), target);
            } else repository.switchToSpace(target);
        } catch (RuntimeException failure) {
            Toast.makeText(getContext(), R.string.secure_spaces_operation_failed,
                    Toast.LENGTH_SHORT).show();
        }
    }
    @Override public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == CONFIRM_FINGERPRINT || requestCode == CONFIRM_OPEN) {
            if (resultCode == Activity.RESULT_OK) {
                mPendingOpen = requestCode;
                mPendingOpenAt = android.os.SystemClock.elapsedRealtime();
            }
            return;
        }
        if (requestCode != CONFIRM_OWNER && requestCode != CHOOSE_CREDENTIAL) return;
        LockscreenCredential credential = data == null ? null : data.getParcelableExtra(
                ChooseLockSettingsHelper.EXTRA_KEY_PASSWORD, LockscreenCredential.class);
        if (data != null) data.removeExtra(ChooseLockSettingsHelper.EXTRA_KEY_PASSWORD);
        if (resultCode != Activity.RESULT_OK || credential == null) {
            if (credential != null) credential.close();
            mModel.cancel();
            return;
        }
        if (requestCode == CHOOSE_CREDENTIAL) {
            if (mPendingCredential != null) mPendingCredential.close();
            mPendingCredential = credential;
        } else mModel.onOwnerConfirmation(credential);
    }
}
