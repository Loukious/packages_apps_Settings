/*
 * Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.settings.security.securespaces;

import android.app.Application;
import android.util.Log;
import android.os.SystemClock;

import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.android.settingslib.utils.ThreadUtils;

import java.util.function.Consumer;
import java.util.function.LongSupplier;

/** Keeps a pending confirmation and background operation across screen rotation. */
public class SecureSpacesViewModel extends AndroidViewModel {
    public static final class State {
        public final boolean busy;
        public final boolean failed;
        public final boolean ownerConfirmed;

        State(boolean busy, boolean failed, boolean ownerConfirmed) {
            this.busy = busy;
            this.failed = failed;
            this.ownerConfirmed = ownerConfirmed;
        }
    }

    private final SecureSpaceRepository mRepository;
    private final Consumer<Runnable> mBackgroundExecutor;
    private final Consumer<Runnable> mMainExecutor;
    private final LongSupplier mClock;
    private boolean mConfirmationAwaitingForeground;
    private long mConfirmedAt;
    private final MutableLiveData<State> mState =
            new MutableLiveData<>(new State(false, false, false));
    private Runnable mPendingAction;
    private boolean mDisclosureConfirmationPending;
    // In-memory foreground-page permission, never saved to a Bundle or disk.
    private boolean mOwnerConfirmed;

    public SecureSpacesViewModel(Application application) {
        this(application, new SecureSpaceRepository(application));
    }

    SecureSpacesViewModel(Application application, SecureSpaceRepository repository) {
        this(application, repository, ThreadUtils::postOnBackgroundThread,
                ThreadUtils::postOnMainThread);
    }

    SecureSpacesViewModel(Application application, SecureSpaceRepository repository,
            Consumer<Runnable> backgroundExecutor, Consumer<Runnable> mainExecutor) {
        this(application, repository, backgroundExecutor, mainExecutor, SystemClock::elapsedRealtime);
    }

    SecureSpacesViewModel(Application application, SecureSpaceRepository repository,
            Consumer<Runnable> backgroundExecutor, Consumer<Runnable> mainExecutor,
            LongSupplier clock) {
        super(application);
        mRepository = repository;
        mBackgroundExecutor = backgroundExecutor;
        mMainExecutor = mainExecutor;
        mClock = clock;
    }

    public SecureSpaceRepository getRepository() {
        return mRepository;
    }

    public LiveData<State> getState() {
        return mState;
    }

    public boolean stageDisclosureConfirmation() {
        if (mState.getValue().busy || mOwnerConfirmed) {
            return false;
        }
        mDisclosureConfirmationPending = true;
        mState.setValue(new State(true, false, false));
        return true;
    }

    public void onDisclosureConfirmationResult(boolean confirmed) {
        if (!mDisclosureConfirmationPending) {
            return;
        }
        mDisclosureConfirmationPending = false;
        mOwnerConfirmed = confirmed;
        mConfirmationAwaitingForeground = confirmed;
        mConfirmedAt = confirmed ? mClock.getAsLong() : 0;
        mState.setValue(new State(false, false, mOwnerConfirmed));
    }

    public boolean canDisclose() {
        if (!mOwnerConfirmed) return false;
        if (!mConfirmationAwaitingForeground) return true;
        long now = mClock.getAsLong();
        return now >= mConfirmedAt && now - mConfirmedAt < 30_000;
    }

    public void onForeground() {
        // Activity results can arrive while stopped. A delayed return must request fresh proof.
        if (mConfirmationAwaitingForeground) {
            if (!canDisclose()) {
                revokeDisclosure();
            }
            mConfirmationAwaitingForeground = false;
        }
    }

    public void revokeDisclosure() {
        mOwnerConfirmed = false;
        mConfirmationAwaitingForeground = false;
        mConfirmedAt = 0;
        State previous = mState.getValue();
        mState.setValue(new State(previous.busy, previous.failed, false));
    }

    public boolean stageAction(Runnable action) {
        if (mState.getValue().busy || !canDisclose()) {
            return false;
        }
        mPendingAction = action;
        mState.setValue(new State(true, false, mOwnerConfirmed));
        return true;
    }

    public void onConfirmationResult(boolean confirmed) {
        Runnable action = mPendingAction;
        mPendingAction = null;
        if (action == null) {
            return;
        }
        if (!confirmed) {
            mState.setValue(new State(false, false, mOwnerConfirmed));
            return;
        }
        // This is a fresh owner confirmation too, so it can reopen the foreground list.
        mOwnerConfirmed = true;
        mConfirmationAwaitingForeground = true;
        mConfirmedAt = mClock.getAsLong();
        mState.setValue(new State(true, false, true));
        mBackgroundExecutor.accept(() -> {
            boolean failed = false;
            try {
                action.run();
            } catch (RuntimeException e) {
                Log.e("SecureSpaces", "Secure Space operation failed", e);
                failed = true;
            }
            final boolean operationFailed = failed;
            // Read the permission on the main thread: a queued completion must not undo onStop.
            mMainExecutor.accept(() -> mState.setValue(
                    new State(false, operationFailed, mOwnerConfirmed)));
        });
    }
}
