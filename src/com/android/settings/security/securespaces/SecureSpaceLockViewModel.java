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

/** One owner-confirmed initial credential transaction, held only in memory. */
public final class SecureSpaceLockViewModel extends AndroidViewModel {
    static final class State {
        final boolean busy;
        final boolean finished;
        final boolean failed;
        State(boolean busy, boolean finished, boolean failed) {
            this.busy = busy;
            this.finished = finished;
            this.failed = failed;
        }
    }
    interface Backend {
        boolean setInitial(LockscreenCredential owner, LockscreenCredential credential,
                int userId, int serial);
    }
    private final SecureSpaceRepository mRepository;
    private final Backend mBackend;
    private final Executor mBackground;
    private final Executor mMain;
    private final LongSupplier mClock;
    private final MutableLiveData<State> mState =
            new MutableLiveData<>(new State(false, false, false));
    private int mUserId = -1;
    private int mSerial = -1;
    private boolean mForeground;
    private boolean mWaiting;
    private long mGeneration;
    private long mRunning;
    private long mConfirmedAt;
    private LockscreenCredential mCredential;
    private LockscreenCredential mOwner;

    public SecureSpaceLockViewModel(Application application) {
        this(application, new SecureSpaceRepository(application),
                new LockPatternUtils(application)::setInitialSecureSpaceCredential,
                ThreadUtils::postOnBackgroundThread, ThreadUtils::postOnMainThread,
                SystemClock::elapsedRealtime);
    }
    SecureSpaceLockViewModel(Application app, SecureSpaceRepository repository,
            Backend backend, Executor background, Executor main, LongSupplier clock) {
        super(app);
        mRepository = repository;
        mBackend = backend;
        mBackground = background;
        mMain = main;
        mClock = clock;
    }
    void setIdentity(int userId, int serial) {
        if (userId <= 0 || serial < 0
                || (mUserId != -1 && (mUserId != userId || mSerial != serial))) {
            throw new IllegalArgumentException("Invalid initial Space identity");
        }
        mUserId = userId;
        mSerial = serial;
    }
    LiveData<State> getState() { return mState; }
    boolean isOwner() { return mRepository.isOwner(); }
    int getOwnerCredentialType() { return mRepository.getOwnerCredentialType(); }
    boolean isConfigured() { return mUserId > 0 && mRepository.hasCredential(mUserId); }
    boolean canConfigure() { return isOwner() && mRepository.hasOwnerRoutingCredential(); }
    void onForeground() { mForeground = true; dispatch(); }
    void onBackground() {
        mForeground = false;
        ++mGeneration;
        if (mOwner != null) cancel();
        State state = mState.getValue();
        mState.setValue(new State(state.busy, false, false));
    }
    /** Takes ownership only if the action can be staged. */
    boolean stage(LockscreenCredential credential) {
        if (!mForeground || !canConfigure() || mUserId <= 0 || mState.getValue().busy
                || credential == null || (!credential.isPin() && !credential.isPassword())
                || credential.getType() != getOwnerCredentialType()) {
            return false;
        }
        mCredential = credential;
        mWaiting = true;
        mState.setValue(new State(true, false, false));
        return true;
    }
    void onOwnerConfirmation(LockscreenCredential owner) {
        if (!mWaiting || owner == null || owner.isNone()) {
            close(owner);
            if (mWaiting) cancel();
            return;
        }
        mWaiting = false;
        mOwner = owner;
        mConfirmedAt = mClock.getAsLong();
        dispatch();
    }
    private void dispatch() {
        if (!mForeground || mOwner == null) return;
        long now = mClock.getAsLong();
        if (!canConfigure() || now < mConfirmedAt || now - mConfirmedAt >= 30_000) {
            cancel();
            return;
        }
        LockscreenCredential owner = mOwner;
        LockscreenCredential credential = mCredential;
        mOwner = null;
        mCredential = null;
        int userId = mUserId;
        int serial = mSerial;
        long generation = ++mGeneration;
        mRunning = generation;
        mBackground.execute(() -> {
            boolean success = false;
            try { success = mBackend.setInitial(owner, credential, userId, serial); }
            catch (RuntimeException rejected) { /* Return generic failure, never private details. */ }
            finally { close(owner); close(credential); }
            final boolean result = success;
            mMain.execute(() -> {
                if (mRunning != generation) return;
                mRunning = 0;
                boolean current = mForeground && mGeneration == generation && isOwner();
                mState.setValue(new State(false, current && result, current && !result));
            });
        });
    }
    void cancel() {
        close(mOwner);
        close(mCredential);
        mOwner = null;
        mCredential = null;
        mWaiting = false;
        ++mGeneration;
        mState.setValue(new State(mRunning != 0, false, false));
    }
    private static void close(LockscreenCredential credential) {
        if (credential != null) credential.close();
    }
    @Override protected void onCleared() { mForeground = false; cancel(); }
}
