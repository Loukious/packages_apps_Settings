/* Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.settings.security.securespaces;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import android.os.UserManager;

import com.android.internal.widget.LockPatternUtils;
import com.android.internal.widget.LockscreenCredential;

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
public class SecureAuthDuressViewModelTest {
    private final ArrayDeque<Runnable> mBackground = new ArrayDeque<>();
    private final ArrayDeque<Runnable> mMain = new ArrayDeque<>();
    private final AtomicLong mClock = new AtomicLong(1);
    private final java.util.concurrent.atomic.AtomicInteger mUser =
            new java.util.concurrent.atomic.AtomicInteger();
    private SecureSpaceRepository mRepository;
    private SecureAuthDuressViewModel.Backend mBackend;
    private SecureAuthDuressViewModel mModel;

    @Before
    public void setUp() {
        UserManager users = mock(UserManager.class);
        when(users.getUserHandle()).thenReturn(0);
        when(users.isAdminUser()).thenReturn(true);
        LockPatternUtils locks = mock(LockPatternUtils.class);
        when(locks.isSecure(0)).thenReturn(true);
        mRepository = new SecureSpaceRepository(users, locks, mUser::get);
        mBackend = mock(SecureAuthDuressViewModel.Backend.class);
        when(mBackend.hasCredentials(any())).thenReturn(true);
        mModel = new SecureAuthDuressViewModel(RuntimeEnvironment.getApplication(),
                mRepository, mBackend, mBackground::add, mMain::add, mClock::get);
        mModel.onForeground();
    }

    @Test
    public void unsolicitedOwnerProof_isClosedAndDoesNotAuthorize() {
        LockscreenCredential owner = LockscreenCredential.createPin("1234");
        mModel.onOwnerConfirmation(owner);
        assertClosed(owner);
        assertThat(mModel.canDisclose()).isFalse();
        assertThat(mBackground).isEmpty();
        verifyNoInteractions(mBackend);
    }

    @Test
    public void nativeRead_isRequiredBeforeDisclosureAndProofIsClosed() {
        LockscreenCredential owner = queueRead();
        assertThat(mModel.canDisclose()).isFalse();
        mBackground.remove().run();
        verify(mBackend).hasCredentials(owner);
        assertClosed(owner);
        assertThat(mModel.canDisclose()).isFalse();
        mMain.remove().run();
        assertThat(mModel.canDisclose()).isTrue();
        assertThat(mModel.getState().getValue().configured).isTrue();
    }

    @Test
    public void backgroundBeforeCompletion_neverRestoresProtectedStatus() {
        queueRead();
        mBackground.remove().run();
        mModel.onBackground();
        mModel.onForeground();
        mMain.remove().run();
        assertThat(mModel.canDisclose()).isFalse();
        assertThat(mModel.getState().getValue().configured).isFalse();
    }

    @Test
    public void changedOwnerBeforeCompletion_neverDiscloses() {
        queueRead();
        mBackground.remove().run();
        mUser.set(10);
        mMain.remove().run();
        assertThat(mModel.canDisclose()).isFalse();
    }

    @Test
    public void cancellationDuringNativeWork_keepsBusyUntilOwnedCompletion() {
        queueRead();
        mModel.cancelPendingAction();
        assertThat(mModel.stageRead()).isFalse();
        mBackground.remove().run();
        mMain.remove().run();
        assertThat(mModel.canDisclose()).isFalse();
        assertThat(mModel.stageRead()).isTrue();
    }

    @Test
    public void expiredProofReturnedWhileBackgrounded_isClosedWithoutNativeCall() {
        assertThat(mModel.stageRead()).isTrue();
        mModel.onBackground();
        LockscreenCredential owner = LockscreenCredential.createPin("1234");
        mModel.onOwnerConfirmation(owner);
        mClock.addAndGet(30_000);
        mModel.onForeground();
        assertClosed(owner);
        verifyNoInteractions(mBackend);
        assertThat(mBackground).isEmpty();
    }

    @Test
    public void cancelledEnrollment_closesBothSecretsWithoutSaving() {
        authorize();
        LockscreenCredential pin = LockscreenCredential.createPin("6789");
        LockscreenCredential password = LockscreenCredential.createPassword("duress secret");
        assertThat(mModel.stageSet(pin, password)).isTrue();
        mModel.cancelPendingAction();
        assertClosed(pin);
        assertClosed(password);
        assertThat(mBackground).isEmpty();
    }

    @Test
    public void enrollment_requiresFreshProofAndClosesEveryCredential() {
        authorize();
        LockscreenCredential pin = LockscreenCredential.createPin("6789");
        LockscreenCredential password = LockscreenCredential.createPassword("duress secret");
        assertThat(mModel.stageSet(pin, password)).isTrue();
        assertThat(mBackground).isEmpty();
        LockscreenCredential owner = LockscreenCredential.createPin("1234");
        mModel.onOwnerConfirmation(owner);
        mBackground.remove().run();
        verify(mBackend).setCredentials(owner, pin, password);
        assertClosed(owner);
        assertClosed(pin);
        assertClosed(password);
        mMain.remove().run();
        assertThat(mModel.getState().getValue().configured).isTrue();
    }

    @Test public void collectedSecretsRequireAuthorizedStartAndFreshCommitProof() {
        assertThat(mModel.beginEnrollment()).isFalse();
        authorize();
        assertThat(mModel.beginEnrollment()).isTrue();
        mModel.onBackground();
        mModel.onForeground();
        assertThat(mModel.canDisclose()).isFalse();
        LockscreenCredential pin = LockscreenCredential.createPin("6789");
        LockscreenCredential password = LockscreenCredential.createPassword("duress secret");
        assertThat(mModel.stageEnrollment(pin, password)).isTrue();
        assertThat(mBackground).isEmpty();
        LockscreenCredential owner = LockscreenCredential.createPin("1234");
        mModel.onOwnerConfirmation(owner);
        mBackground.remove().run();
        verify(mBackend).setCredentials(owner, pin, password);
        assertClosed(owner);
        assertClosed(pin);
        assertClosed(password);
        mMain.remove().run();
        assertThat(mModel.getState().getValue().configured).isTrue();
    }
    @Test public void enrollmentWithoutAuthorizedStartCannotStage() {
        try (LockscreenCredential pin = LockscreenCredential.createPin("6789");
                LockscreenCredential password = LockscreenCredential.createPassword("duress secret")) {
            assertThat(mModel.stageEnrollment(pin, password)).isFalse();
        }
        verifyNoInteractions(mBackend);
    }
    @Test public void expiredCollectionDoesNotRetainSecretsOrCallBackend() {
        authorize();
        assertThat(mModel.beginEnrollment()).isTrue();
        mClock.addAndGet(300_000);
        try (LockscreenCredential pin = LockscreenCredential.createPin("6789");
                LockscreenCredential password = LockscreenCredential.createPassword("duress secret")) {
            assertThat(mModel.stageEnrollment(pin, password)).isFalse();
            assertThat(pin.getCredential()).isNotEmpty();
        }
        verify(mBackend, never()).setCredentials(any(), any(), any());
    }
    @Test public void cancellingCollectionRevokesPermissionToStage() {
        authorize();
        assertThat(mModel.beginEnrollment()).isTrue();
        mModel.cancelPendingAction();
        try (LockscreenCredential pin = LockscreenCredential.createPin("6789");
                LockscreenCredential password = LockscreenCredential.createPassword("duress secret")) {
            assertThat(mModel.stageEnrollment(pin, password)).isFalse();
        }
        verify(mBackend, never()).setCredentials(any(), any(), any());
    }

    private LockscreenCredential queueRead() {
        assertThat(mModel.stageRead()).isTrue();
        LockscreenCredential owner = LockscreenCredential.createPin("1234");
        mModel.onOwnerConfirmation(owner);
        return owner;
    }

    private void authorize() {
        queueRead();
        mBackground.remove().run();
        mMain.remove().run();
    }

    private static void assertClosed(LockscreenCredential credential) {
        try {
            credential.getCredential();
            throw new AssertionError("Credential was not cleared");
        } catch (IllegalStateException expected) {
            // Native credential buffers must be unusable after ownership ends.
        }
    }
}
