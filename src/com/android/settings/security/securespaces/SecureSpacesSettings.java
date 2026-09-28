/*
 * Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.settings.security.securespaces;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.settings.SettingsEnums;
import android.content.Intent;
import android.content.pm.UserInfo;
import android.os.Bundle;
import android.os.UserHandle;
import android.os.UserManager;
import android.text.InputFilter;
import android.text.InputType;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import androidx.lifecycle.ViewModelProvider;
import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;
import androidx.preference.PreferenceScreen;

import com.android.settings.R;
import com.android.settings.core.SubSettingLauncher;
import com.android.settings.SettingsPreferenceFragment;
import com.android.settings.password.ChooseLockGeneric;
import com.android.settings.password.ChooseLockSettingsHelper;

/** Owner-only management of full Android Secure Space users. */
public class SecureSpacesSettings extends SettingsPreferenceFragment {
    private static final int CONFIRM_OWNER = 301;
    private static final int CONFIRM_DISCLOSURE = 302;
    private SecureSpacesViewModel mModel;
    private AlertDialog mPrivateDialog;

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        mModel = new ViewModelProvider(this).get(SecureSpacesViewModel.class);
    }

    @Override
    public void onViewCreated(android.view.View view, Bundle state) {
        super.onViewCreated(view, state);
        // This SubSettings page contains private user names after confirmation.
        getActivity().getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE);
        mModel.getState().observe(getViewLifecycleOwner(), this::render);
    }

    @Override
    public void onResume() {
        super.onResume();
        getActivity().setTitle(getText(R.string.secure_spaces_title));
        mModel.onForeground();
        render(mModel.getState().getValue());
        SecureSpacesViewModel.State state = mModel.getState().getValue();
        SecureSpaceRepository repository = mModel.getRepository();
        if (!getActivity().isFinishing() && !state.ownerConfirmed && !state.busy
                && repository.isOwner()
                && repository.hasOwnerCredential() && mModel.stageDisclosureConfirmation()) {
            if (!launchOwnerConfirmation(CONFIRM_DISCLOSURE)) {
                mModel.onDisclosureConfirmationResult(false);
                finish();
            }
        }
    }

    @Override
    public void onStop() {
        if (mPrivateDialog != null) {
            mPrivateDialog.dismiss();
        }
        if (!getActivity().isChangingConfigurations()) {
            mModel.revokeDisclosure();
            // LiveData observers are inactive on stop; clear rendered names synchronously too.
            setPreferenceScreen(getPreferenceManager().createPreferenceScreen(getPrefContext()));
        }
        super.onStop();
    }

    @Override
    public int getMetricsCategory() {
        return SettingsEnums.SECURITY;
    }

    private void render(SecureSpacesViewModel.State state) {
        if (!isAdded()) {
            return;
        }
        SecureSpaceRepository repository = mModel.getRepository();
        if (!repository.isOwner()) {
            finish();
            return;
        }
        PreferenceScreen screen = getPreferenceManager().createPreferenceScreen(getPrefContext());
        setPreferenceScreen(screen);

        Preference description = new Preference(getPrefContext());
        description.setSummary(R.string.secure_spaces_description);
        description.setSelectable(false);
        screen.addPreference(description);

        Preference owner = new Preference(getPrefContext());
        owner.setKey("secure_spaces_owner");
        owner.setTitle(R.string.secure_spaces_owner);
        owner.setSummary(repository.hasOwnerRoutingCredential()
                ? R.string.secure_spaces_owner_lock : R.string.secure_spaces_owner_lock_required);
        owner.setOnPreferenceClickListener(preference -> {
            startActivity(new Intent(getContext(), ChooseLockGeneric.class));
            return true;
        });
        screen.addPreference(owner);

        if (!mModel.canDisclose() || !repository.hasOwnerCredential()) {
            return; // Never enumerate spaces, counts, or capacity before fresh owner confirmation.
        }

        PreferenceCategory spaces = new PreferenceCategory(getPrefContext());
        spaces.setTitle(R.string.secure_spaces_title);
        screen.addPreference(spaces);
        for (UserInfo user : repository.getSpaces()) {
            Preference entry = new Preference(getPrefContext());
            entry.setKey("secure_space_" + user.serialNumber);
            entry.setTitle(user.name);
            entry.setSummary(repository.hasCredential(user.id)
                    ? R.string.secure_spaces_lock_set : R.string.secure_spaces_setup_required);
            entry.setOnPreferenceClickListener(preference -> {
                showSpaceActions(user);
                return true;
            });
            spaces.addPreference(entry);
        }

        Preference add = new Preference(getPrefContext());
        add.setKey("secure_spaces_add");
        add.setTitle(R.string.secure_spaces_add);
        add.setEnabled(repository.canCreateSpace());
        add.setOnPreferenceClickListener(preference -> {
            showNameDialog(null);
            return true;
        });
        screen.addPreference(add);
        if (state.failed) {
            Preference error = new Preference(getPrefContext());
            error.setSummary(R.string.secure_spaces_operation_failed);
            error.setSelectable(false);
            screen.addPreference(error);
        }
        screen.setEnabled(!state.busy);
    }

    private void showSpaceActions(UserInfo user) {
        if (!mModel.canDisclose()) return;
        final boolean configured = mModel.getRepository().hasCredential(user.id);
        final CharSequence[] actions = configured
                ? new CharSequence[] {getText(R.string.secure_spaces_open),
                        getText(R.string.secure_spaces_set_fingerprint),
                        getText(R.string.secure_spaces_rename),
                        getText(R.string.secure_spaces_remove)}
                : new CharSequence[] {getText(R.string.secure_spaces_initial_lock_title),
                        getText(R.string.secure_spaces_rename),
                        getText(R.string.secure_spaces_remove)};
        showPrivateDialog(new AlertDialog.Builder(getContext())
                .setTitle(user.name)
                .setItems(actions, (dialog, which) -> {
                            if (which == 0) {
                                if (configured) {
                                    confirm(() -> mModel.getRepository().switchToSpace(user));
                                } else {
                                    launchSpaceSecurity(user,
                                            R.string.secure_spaces_initial_lock_title);
                                }
                            } else if (configured && which == 1) {
                                launchSpaceSecurity(user,
                                        R.string.secure_spaces_set_fingerprint);
                            } else if (which == (configured ? 2 : 1)) {
                                showNameDialog(user);
                            } else {
                                showPrivateDialog(new AlertDialog.Builder(getContext())
                                        .setTitle(R.string.secure_spaces_remove)
                                        .setMessage(getString(
                                                R.string.secure_spaces_remove_confirmation,
                                                user.name))
                                        .setNegativeButton(android.R.string.cancel, null)
                                        .setPositiveButton(R.string.secure_spaces_remove,
                                                (confirmation, button) -> confirm(
                                                        () -> mModel.getRepository()
                                                                .removeSpace(user)))
                                        .create());
                            }
                        }).create());
    }

    private void launchSpaceSecurity(UserInfo user, int title) {
        Bundle args = new Bundle();
        args.putInt(SecureSpaceLockSettings.ARG_USER_ID, user.id);
        args.putInt(SecureSpaceLockSettings.ARG_SERIAL, user.serialNumber);
        new SubSettingLauncher(getContext())
                .setDestination(SecureSpaceLockSettings.class.getName())
                .setArguments(args)
                .setSourceMetricsCategory(getMetricsCategory())
                .setTitleText(getText(title))
                .launch();
    }

    private void showNameDialog(UserInfo user) {
        if (!mModel.canDisclose()) return;
        View content = LayoutInflater.from(getContext()).inflate(R.layout.dialog_edittext, null);
        EditText input = content.findViewById(R.id.edittext);
        input.setSingleLine(true);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);
        input.setFilters(new InputFilter[] {
                new InputFilter.LengthFilter(UserManager.MAX_USER_NAME_LENGTH)});
        input.setHint(R.string.secure_spaces_name_hint);
        if (user != null) {
            input.setText(user.name);
            input.selectAll();
        }
        showPrivateDialog(new AlertDialog.Builder(getContext())
                .setTitle(user == null ? R.string.secure_spaces_add : R.string.secure_spaces_rename)
                .setView(content)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(android.R.string.ok, (dialog, which) -> {
                    String name = input.getText().toString().trim();
                    if (name.isEmpty()) {
                        Toast.makeText(getContext(), R.string.secure_spaces_name_required,
                                Toast.LENGTH_SHORT).show();
                        return;
                    }
                    confirm(() -> {
                        if (user == null) {
                            mModel.getRepository().createSpace(name);
                        } else {
                            mModel.getRepository().renameSpace(user, name);
                        }
                    });
                }).create());
    }

    private void showPrivateDialog(AlertDialog dialog) {
        if (mPrivateDialog != null) mPrivateDialog.dismiss();
        mPrivateDialog = dialog;
        dialog.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE);
        dialog.setOnDismissListener(dismissed -> {
            if (mPrivateDialog == dialog) mPrivateDialog = null;
        });
        dialog.show();
    }

    private void confirm(Runnable action) {
        if (!mModel.stageAction(action)) {
            return;
        }
        boolean launched = launchOwnerConfirmation(CONFIRM_OWNER);
        // An absent credential or unavailable confirmation UI must never approve a mutation.
        if (!launched) {
            mModel.onConfirmationResult(false);
        }
    }

    private boolean launchOwnerConfirmation(int requestCode) {
        return new ChooseLockSettingsHelper.Builder(getActivity(), this)
                .setRequestCode(requestCode)
                .setTitle(getText(R.string.secure_spaces_title))
                .setUserId(UserHandle.USER_SYSTEM)
                .setForceVerifyPath(true)
                .setForegroundOnly(true)
                .setReturnCredentials(false)
                .show();
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == CONFIRM_DISCLOSURE) {
            mModel.onDisclosureConfirmationResult(resultCode == Activity.RESULT_OK);
            if (resultCode != Activity.RESULT_OK) finish();
        } else if (requestCode == CONFIRM_OWNER) {
            mModel.onConfirmationResult(resultCode == Activity.RESULT_OK);
            if (resultCode != Activity.RESULT_OK) finish();
        }
    }
}
