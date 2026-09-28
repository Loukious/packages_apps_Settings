/* Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.settings.security.securespaces;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import com.android.internal.widget.LockscreenCredential;
import com.android.internal.widget.LockPatternUtils;
import android.os.UserManager;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import java.util.ArrayDeque;
import java.util.concurrent.atomic.AtomicLong;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 35, manifest = Config.NONE, application = android.app.Application.class)
public class SecureSpaceLockViewModelTest {
    private final ArrayDeque<Runnable> mBackground = new ArrayDeque<>();
    private final ArrayDeque<Runnable> mMain = new ArrayDeque<>();
    private final AtomicLong mClock = new AtomicLong(1);
    private SecureSpaceRepository mRepository;
    private UserManager mUsers;
    private LockPatternUtils mLocks;
    private SecureSpaceLockViewModel.Backend mBackend;
    private SecureSpaceLockViewModel mModel;
    @Before public void setUp() {
        mUsers = mock(UserManager.class);
        when(mUsers.getUserHandle()).thenReturn(0);
        when(mUsers.isAdminUser()).thenReturn(true);
        mLocks = mock(LockPatternUtils.class);
        when(mLocks.isSecure(0)).thenReturn(true);
        when(mLocks.getCredentialTypeForUser(0)).thenReturn(LockPatternUtils.CREDENTIAL_TYPE_PIN);
        mRepository = new SecureSpaceRepository(mUsers, mLocks, () -> 0);
        mBackend = mock(SecureSpaceLockViewModel.Backend.class);
        when(mBackend.setInitial(any(), any(), eq(10), eq(7))).thenReturn(true);
        mModel = new SecureSpaceLockViewModel(RuntimeEnvironment.getApplication(), mRepository,
                mBackend, mBackground::add, mMain::add, mClock::get);
        mModel.setIdentity(10, 7);
        mModel.onForeground();
    }
    private LockscreenCredential stage() {
        LockscreenCredential credential = LockscreenCredential.createPin("5678");
        assertThat(mModel.stage(credential)).isTrue();
        return credential;
    }
    private static void closed(LockscreenCredential credential) {
        assertThrows(IllegalStateException.class, credential::getCredential);
    }
    @Test public void identityCannotBeRetargetedAfterFragmentRecreation() {
        mModel.setIdentity(10, 7);
        assertThrows(IllegalArgumentException.class, () -> mModel.setIdentity(10, 8));
        assertThrows(IllegalArgumentException.class, () -> mModel.setIdentity(11, 7));
    }
    @Test public void stagingDoesNotSetCredentialWithoutOwnerProof() {
        LockscreenCredential credential = stage();
        assertThat(mBackground).isEmpty();
        verifyNoInteractions(mBackend);
        mModel.cancel();
        closed(credential);
    }
    @Test public void nativeSetterReceivesExactSerialAndClosesBothCredentials() {
        LockscreenCredential credential = stage();
        LockscreenCredential owner = LockscreenCredential.createPin("1234");
        mModel.onOwnerConfirmation(owner);
        mBackground.remove().run();
        verify(mBackend).setInitial(owner, credential, 10, 7);
        closed(owner);
        closed(credential);
        assertThat(mModel.getState().getValue().finished).isFalse();
        mMain.remove().run();
        assertThat(mModel.getState().getValue().finished).isTrue();
    }
    @Test public void unsolicitedProofIsClosedWithoutCallingBackend() {
        LockscreenCredential owner = LockscreenCredential.createPin("1234");
        mModel.onOwnerConfirmation(owner);
        closed(owner);
        verifyNoInteractions(mBackend);
    }
    @Test public void ownerChangeBeforeDispatchCancelsAndClosesStagedSecrets() {
        LockscreenCredential credential = stage();
        when(mUsers.isAdminUser()).thenReturn(false);
        LockscreenCredential owner = LockscreenCredential.createPin("1234");
        mModel.onOwnerConfirmation(owner);
        closed(owner);
        closed(credential);
        assertThat(mBackground).isEmpty();
    }
    @Test public void expiredReturnedProofCannotBeCarriedBackToForeground() {
        LockscreenCredential credential = stage();
        mModel.onBackground();
        LockscreenCredential owner = LockscreenCredential.createPin("1234");
        mModel.onOwnerConfirmation(owner);
        mClock.addAndGet(30_000);
        mModel.onForeground();
        closed(owner);
        closed(credential);
        verifyNoInteractions(mBackend);
    }
    @Test public void backgroundCompletionDoesNotRestorePrivateResult() {
        stage();
        mModel.onOwnerConfirmation(LockscreenCredential.createPin("1234"));
        mBackground.remove().run();
        mModel.onBackground();
        mModel.onForeground();
        mMain.remove().run();
        assertThat(mModel.getState().getValue().finished).isFalse();
        assertThat(mModel.getState().getValue().failed).isFalse();
        assertThat(mModel.getState().getValue().busy).isFalse();
    }
    @Test public void nativeRejectionDoesNotOpenSpaceAndClosesCredentials() {
        when(mBackend.setInitial(any(), any(), eq(10), eq(7))).thenReturn(false);
        LockscreenCredential credential = stage();
        LockscreenCredential owner = LockscreenCredential.createPin("1234");
        mModel.onOwnerConfirmation(owner);
        mBackground.remove().run();
        mMain.remove().run();
        closed(owner);
        closed(credential);
        assertThat(mModel.getState().getValue().failed).isTrue();
        assertThat(mModel.getState().getValue().finished).isFalse();
    }
    @Test public void patternOwnerCannotStageInitialSpaceCredential() {
        when(mLocks.getCredentialTypeForUser(0)).thenReturn(LockPatternUtils.CREDENTIAL_TYPE_PATTERN);
        try (LockscreenCredential credential = LockscreenCredential.createPin("5678")) {
            assertThat(mModel.stage(credential)).isFalse();
            assertThat(credential.getCredential()).isNotEmpty();
        }
        verifyNoInteractions(mBackend);
    }
    @Test public void pinOwnerCannotCreatePasswordSpace() {
        try (LockscreenCredential credential = LockscreenCredential.createPassword("new secret")) {
            assertThat(mModel.stage(credential)).isFalse();
            assertThat(credential.getCredential()).isNotEmpty();
        }
        verifyNoInteractions(mBackend);
    }
    @Test public void passwordOwnerCannotCreatePinSpace() {
        when(mLocks.getCredentialTypeForUser(0)).thenReturn(LockPatternUtils.CREDENTIAL_TYPE_PASSWORD);
        try (LockscreenCredential credential = LockscreenCredential.createPin("5678")) {
            assertThat(mModel.stage(credential)).isFalse();
        }
        verifyNoInteractions(mBackend);
    }
    @Test public void passwordOwnerCanCreatePasswordSpaceAfterFreshProof() {
        when(mLocks.getCredentialTypeForUser(0)).thenReturn(LockPatternUtils.CREDENTIAL_TYPE_PASSWORD);
        LockscreenCredential credential = LockscreenCredential.createPassword("space secret");
        assertThat(mModel.stage(credential)).isTrue();
        mModel.onOwnerConfirmation(LockscreenCredential.createPassword("owner secret"));
        mBackground.remove().run();
        mMain.remove().run();
        assertThat(mModel.getState().getValue().finished).isTrue();
        closed(credential);
    }

}
