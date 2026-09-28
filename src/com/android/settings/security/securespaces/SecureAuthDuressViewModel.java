/* Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.settings.security.securespaces;

import android.app.Application;
import android.os.SystemClock;

import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.android.internal.widget.LockPatternUtils;
import com.android.internal.widget.LockscreenCredential;
import com.android.settingslib.utils.ThreadUtils;

import java.util.concurrent.Executor;
import java.util.function.LongSupplier;

/** In-memory configuration transaction. Credentials never enter saved state or preferences. */
public final class SecureAuthDuressViewModel extends AndroidViewModel {
    static final int READ = 1;
    static final int SET = 2;
    static final int DELETE = 3;
    private static final long CONFIRMATION_LIFETIME = 30_000;

    public static final class State {
        final boolean busy;
        final boolean authorized;
        final boolean configured;
        final boolean failed;

        State(boolean busy, boolean authorized, boolean configured, boolean failed) {
            this.busy = busy;
            this.authorized = authorized;
            this.configured = configured;
            this.failed = failed;
        }
    }

    private final SecureSpaceRepository mRepository;
    interface Backend {
        boolean hasCredentials(LockscreenCredential owner);
        void setCredentials(LockscreenCredential owner, LockscreenCredential pin,
                LockscreenCredential password);
    }

    private final Backend mBackend;
    private final Executor mBackground;
    private final Executor mMain;
    private final LongSupplier mClock;
    private final MutableLiveData<State> mState =
            new MutableLiveData<>(new State(false, false, false, false));
    private boolean mForeground;
    private boolean mWaitingForConfirmation;
    private int mPurpose;
    private long mGeneration;
    private long mRunningGeneration;
    private long mConfirmedAt;
    private boolean mEnrollmentStarted;
    private long mEnrollmentStartedAt;
    private LockscreenCredential mOwnerCredential;
    private LockscreenCredential mPin;
    private LockscreenCredential mPassword;

    public SecureAuthDuressViewModel(Application application) {
        this(application, new SecureSpaceRepository(application), nativeBackend(application),
                ThreadUtils::postOnBackgroundThread, ThreadUtils::postOnMainThread,
                SystemClock::elapsedRealtime);
    }

    SecureAuthDuressViewModel(Application application, SecureSpaceRepository repository,
            Backend backend, Executor background, Executor main, LongSupplier clock) {
        super(application);
        mRepository = repository;
        mBackend = backend;
        mBackground = background;
        mMain = main;
        mClock = clock;
    }

    private static Backend nativeBackend(Application application) {
        LockPatternUtils locks = new LockPatternUtils(application);
        return new Backend() {
            public boolean hasCredentials(LockscreenCredential owner) {
                return locks.hasSecureAuthDuressCredentials(owner);
            }
            public void setCredentials(LockscreenCredential owner, LockscreenCredential pin,
                    LockscreenCredential password) {
                locks.setSecureAuthDuressCredentials(owner, pin, password);
            }
        };
    }

    LiveData<State> getState() { return mState; }
    boolean isOwner() { return mRepository.isOwner(); }
    boolean hasOwnerCredential() { return mRepository.hasOwnerCredential(); }
    boolean hasOwnerRoutingCredential() { return mRepository.hasOwnerRoutingCredential(); }
    boolean canDisclose() { return mForeground && mState.getValue().authorized; }

    void onForeground() {
        mForeground = true;
        dispatchConfirmedAction();
    }

    void onBackground() {
        mForeground = false;
        ++mGeneration;
        State state = mState.getValue();
        mState.setValue(new State(state.busy, false, false, state.failed));
        // A returned proof cannot be carried through another background transition.
        if (mOwnerCredential != null) cancelPendingAction();
    }

    boolean stageRead() { return stage(READ, null, null); }

    /** Takes ownership of the two credentials only on success. */
    boolean stageSet(LockscreenCredential pin, LockscreenCredential password) {
        return stage(SET, pin, password);
    }

    boolean beginEnrollment() {
        if (!canDisclose() || mState.getValue().busy) return false;
        mEnrollmentStarted = true;
        mEnrollmentStartedAt = mClock.getAsLong();
        return true;
    }

    /** Collecting new secrets is not authentication; commit still needs fresh native owner proof. */
    boolean stageEnrollment(LockscreenCredential pin, LockscreenCredential password) {
        long now = mClock.getAsLong();
        if (!mEnrollmentStarted || now < mEnrollmentStartedAt
                || now - mEnrollmentStartedAt >= 300_000 || pin == null || !pin.isPin()
                || password == null || !password.isPassword()) return false;
        boolean staged = stage(SET, pin, password, true);
        if (staged) mEnrollmentStarted = false;
        return staged;
    }

    boolean stageDelete() { return stage(DELETE, null, null); }

    private boolean stage(int purpose, LockscreenCredential pin, LockscreenCredential password) {
        return stage(purpose, pin, password, false);
    }

    private boolean stage(int purpose, LockscreenCredential pin, LockscreenCredential password,
            boolean enrollment) {
        if (!mForeground || mState.getValue().busy || !isOwner() || !hasOwnerCredential()
                || (purpose != READ && !canDisclose() && !enrollment)) return false;
        mPurpose = purpose;
        mPin = pin;
        mPassword = password;
        mWaitingForConfirmation = true;
        State state = mState.getValue();
        mState.setValue(new State(true, state.authorized, state.configured, false));
        return true;
    }

    void onOwnerConfirmation(LockscreenCredential credential) {
        if (!mWaitingForConfirmation || credential == null || credential.isNone()) {
            close(credential);
            if (mWaitingForConfirmation) cancelPendingAction();
            return;
        }
        mWaitingForConfirmation = false;
        mOwnerCredential = credential;
        mConfirmedAt = mClock.getAsLong();
        dispatchConfirmedAction();
    }

    private void dispatchConfirmedAction() {
        if (!mForeground || mOwnerCredential == null) return;
        long now = mClock.getAsLong();
        if (now < mConfirmedAt || now - mConfirmedAt >= CONFIRMATION_LIFETIME
                || !isOwner()) {
            cancelPendingAction();
            return;
        }
        final int purpose = mPurpose;
        final LockscreenCredential owner = mOwnerCredential;
        final LockscreenCredential pin = mPin;
        final LockscreenCredential password = mPassword;
        mOwnerCredential = null;
        mPin = null;
        mPassword = null;
        mPurpose = 0;
        final long generation = ++mGeneration;
        mRunningGeneration = generation;
        mBackground.execute(() -> {
            boolean configured = false;
            boolean failed = false;
            try {
                if (purpose == READ) {
                    configured = mBackend.hasCredentials(owner);
                } else if (purpose == SET) {
                    mBackend.setCredentials(owner, pin, password);
                    configured = true;
                } else if (purpose == DELETE) {
                    try (LockscreenCredential nonePin = LockscreenCredential.createNone();
                            LockscreenCredential nonePassword = LockscreenCredential.createNone()) {
                        mBackend.setCredentials(owner, nonePin, nonePassword);
                    }
                } else {
                    throw new IllegalStateException("Missing configuration action");
                }
            } catch (RuntimeException error) {
                failed = true;
            } finally {
                close(owner);
                close(pin);
                close(password);
            }
            final boolean result = configured;
            final boolean error = failed;
            mMain.execute(() -> {
                if (mRunningGeneration != generation) return;
                mRunningGeneration = 0;
                boolean current = mForeground && generation == mGeneration && isOwner();
                // Never restore protected status from a completion queued before onStop.
                mState.setValue(new State(false, current && !error,
                        current && !error && result, current && error));
            });
        });
    }

    void cancelPendingAction() {
        mEnrollmentStarted = false;
        close(mOwnerCredential);
        close(mPin);
        close(mPassword);
        mOwnerCredential = null;
        mPin = null;
        mPassword = null;
        mPurpose = 0;
        mWaitingForConfirmation = false;
        ++mGeneration;
        mState.setValue(new State(mRunningGeneration != 0, false, false, false));
    }

    private static void close(LockscreenCredential credential) {
        if (credential != null) credential.close();
    }

    @Override
    protected void onCleared() {
        mForeground = false;
        cancelPendingAction();
    }
}
