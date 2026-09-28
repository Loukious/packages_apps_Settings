/* Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.settings.security.securespaces;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.settings.SettingsEnums;
import android.content.Intent;
import android.os.Bundle;
import android.os.UserHandle;
import android.view.View;
import android.view.WindowManager;

import androidx.lifecycle.ViewModelProvider;
import androidx.preference.Preference;
import androidx.preference.PreferenceScreen;

import com.android.internal.widget.LockscreenCredential;
import com.android.settings.R;
import com.android.settings.SettingsPreferenceFragment;
import com.android.settings.password.ChooseLockSettingsHelper;

/** Owner-authenticated duress enrollment; this screen has no test-wipe action. */
public final class SecureAuthDuressSettings extends SettingsPreferenceFragment {
    private static final int CONFIRM_OWNER = 311;
    private static final int CHOOSE_PIN = 312;
    private static final int CHOOSE_PASSWORD = 313;
    private LockscreenCredential mDraftPin;
    private LockscreenCredential mDraftPassword;
    private boolean mChoosePassword;
    private boolean mCollecting;
    private SecureAuthDuressViewModel mModel;
    private AlertDialog mDialog;

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        mModel = new ViewModelProvider(this).get(SecureAuthDuressViewModel.class);
    }

    @Override
    public void onViewCreated(View view, Bundle state) {
        super.onViewCreated(view, state);
        getActivity().getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        mModel.getState().observe(getViewLifecycleOwner(), this::render);
    }

    @Override
    public void onResume() {
        super.onResume();
        if (!mModel.isOwner()) { finish(); return; }
        mModel.onForeground();
        if (mChoosePassword && mDraftPin != null) {
            mChoosePassword = false;
            chooseDuressCredential(false);
            return;
        }
        if (mDraftPin != null && mDraftPassword != null) {
            // Disclosure is revoked while the pickers run. Reauthorize at commit using a fresh
            // native owner credential; do not restore any earlier disclosure proof.
            if (mModel.stageEnrollment(mDraftPin, mDraftPassword)) {
                mDraftPin = null;
                mDraftPassword = null;
                mCollecting = false;
                launchConfirmation();
            } else clearDrafts();
            return;
        }
        if (mCollecting) return;
        SecureAuthDuressViewModel.State state = mModel.getState().getValue();
        render(state);
        if (!state.busy && !state.authorized && !state.failed
                && mModel.hasOwnerCredential() && mModel.stageRead()) {
            launchConfirmation();
        }
    }

    @Override
    public void onStop() {
        if (mDialog != null) mDialog.dismiss();
        mModel.onBackground();
        setPreferenceScreen(getPreferenceManager().createPreferenceScreen(getPrefContext()));
        super.onStop();
    }

    @Override
    public int getMetricsCategory() { return SettingsEnums.SECURITY; }

    private void render(SecureAuthDuressViewModel.State state) {
        if (!isAdded()) return;
        PreferenceScreen screen = getPreferenceManager().createPreferenceScreen(getPrefContext());
        setPreferenceScreen(screen);
        Preference description = new Preference(getPrefContext());
        description.setSummary(R.string.secure_auth_duress_description);
        description.setSelectable(false);
        screen.addPreference(description);
        if (!mModel.hasOwnerCredential()) {
            description.setSummary(R.string.secure_spaces_owner_lock_required);
            return;
        }
        if (!mModel.canDisclose()) {
            if (!state.busy) {
                Preference verify = new Preference(getPrefContext());
                verify.setTitle(R.string.secure_auth_duress_verify);
                if (state.failed) verify.setSummary(R.string.secure_auth_duress_failed);
                verify.setOnPreferenceClickListener(item -> {
                    if (mModel.stageRead()) launchConfirmation();
                    return true;
                });
                screen.addPreference(verify);
            }
            return;
        }
        Preference status = new Preference(getPrefContext());
        status.setTitle(R.string.secure_auth_duress_title);
        status.setSummary(state.configured ? R.string.secure_auth_duress_enabled
                : R.string.secure_auth_duress_disabled);
        status.setSelectable(false);
        screen.addPreference(status);
        Preference configure = new Preference(getPrefContext());
        configure.setTitle(R.string.secure_auth_duress_configure);
        configure.setEnabled(mModel.hasOwnerRoutingCredential());
        if (!mModel.hasOwnerRoutingCredential()) {
            configure.setSummary(R.string.secure_spaces_owner_lock_required);
        }
        configure.setOnPreferenceClickListener(item -> { showEnrollment(); return true; });
        screen.addPreference(configure);
        if (state.configured) {
            Preference remove = new Preference(getPrefContext());
            remove.setTitle(R.string.secure_auth_duress_remove);
            remove.setOnPreferenceClickListener(item -> {
                if (mModel.stageDelete()) launchConfirmation();
                return true;
            });
            screen.addPreference(remove);
        }
        screen.setEnabled(!state.busy);
    }

    private void showEnrollment() {
        if (!mModel.canDisclose()) return;
        AlertDialog dialog = new AlertDialog.Builder(getContext())
                .setTitle(R.string.secure_auth_duress_configure)
                .setMessage(R.string.secure_auth_duress_enrollment_warning)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(android.R.string.ok,
                        (ignored, button) -> {
                            if (mModel.beginEnrollment()) chooseDuressCredential(true);
                        }).create();
        mDialog = dialog;
        dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        dialog.setOnDismissListener(ignored -> { if (mDialog == dialog) mDialog = null; });
        dialog.show();
    }

    private void chooseDuressCredential(boolean pin) {
        Intent intent = new com.android.settings.password.ChooseLockPassword.IntentBuilder(
                getContext()).setUserId(UserHandle.USER_SYSTEM)
                .setPasswordType(pin ? android.app.admin.DevicePolicyManager.PASSWORD_QUALITY_NUMERIC
                        : android.app.admin.DevicePolicyManager.PASSWORD_QUALITY_ALPHABETIC)
                .build();
        intent.putExtra(com.android.settings.password.ChooseLockPassword.EXTRA_COLLECT_CREDENTIAL,
                true);
        intent.putExtra(com.android.settings.password.ChooseLockPassword.EXTRA_COLLECT_DESCRIPTION,
                getString(pin ? R.string.secure_auth_duress_pin
                        : R.string.secure_auth_duress_password));
        mCollecting = true;
        startActivityForResult(intent, pin ? CHOOSE_PIN : CHOOSE_PASSWORD);
    }

    private void clearDrafts() {
        if (mDraftPin != null) mDraftPin.close();
        if (mDraftPassword != null) mDraftPassword.close();
        mDraftPin = null;
        mDraftPassword = null;
        mChoosePassword = false;
        mCollecting = false;
    }

    @Override public void onDestroy() {
        clearDrafts();
        super.onDestroy();
    }

    private void launchConfirmation() {
        boolean launched = new ChooseLockSettingsHelper.Builder(getActivity(), this)
                .setRequestCode(CONFIRM_OWNER)
                .setTitle(getText(R.string.secure_auth_duress_title))
                .setUserId(UserHandle.USER_SYSTEM)
                .setForceVerifyPath(false)
                .setForegroundOnly(true)
                .setReturnCredentials(true)
                .show();
        if (!launched) mModel.cancelPendingAction();
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == CHOOSE_PIN || requestCode == CHOOSE_PASSWORD) {
            LockscreenCredential chosen = data == null ? null : data.getParcelableExtra(
                    ChooseLockSettingsHelper.EXTRA_KEY_PASSWORD, LockscreenCredential.class);
            if (data != null) data.removeExtra(ChooseLockSettingsHelper.EXTRA_KEY_PASSWORD);
            if (resultCode != Activity.RESULT_OK || chosen == null
                    || (requestCode == CHOOSE_PIN ? !chosen.isPin() : !chosen.isPassword())) {
                if (chosen != null) chosen.close();
                clearDrafts();
                return;
            }
            if (requestCode == CHOOSE_PIN) {
                if (mDraftPin != null) mDraftPin.close();
                mDraftPin = chosen;
                mChoosePassword = true;
            } else {
                if (mDraftPassword != null) mDraftPassword.close();
                mDraftPassword = chosen;
            }
            return;
        }
        if (requestCode != CONFIRM_OWNER) return;
        LockscreenCredential credential = data == null ? null : data.getParcelableExtra(
                ChooseLockSettingsHelper.EXTRA_KEY_PASSWORD, LockscreenCredential.class);
        if (data != null) data.removeExtra(ChooseLockSettingsHelper.EXTRA_KEY_PASSWORD);
        if (resultCode != Activity.RESULT_OK || credential == null) {
            if (credential != null) credential.close();
            mModel.cancelPendingAction();
            finish();
            return;
        }
        mModel.onOwnerConfirmation(credential);
    }
}
