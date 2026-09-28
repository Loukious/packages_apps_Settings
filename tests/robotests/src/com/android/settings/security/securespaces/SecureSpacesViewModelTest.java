/*
 * Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.settings.security.securespaces;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import android.os.UserManager;

import com.android.internal.widget.LockPatternUtils;

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
public class SecureSpacesViewModelTest {
    private SecureSpacesViewModel mModel;
    private Runnable mAction;

    @Before
    public void setUp() {
        mModel = new SecureSpacesViewModel(RuntimeEnvironment.getApplication(),
                new SecureSpaceRepository(mock(UserManager.class), mock(LockPatternUtils.class),
                        () -> 0));
        mAction = mock(Runnable.class);
    }

    @Test
    public void cancelledConfirmation_neverRunsPendingMutation() {
        confirmOwnerForDisclosure();
        assertThat(mModel.stageAction(mAction)).isTrue();
        assertThat(mModel.getState().getValue().busy).isTrue();

        mModel.onConfirmationResult(false);

        verify(mAction, never()).run();
        assertThat(mModel.getState().getValue().busy).isFalse();
    }

    @Test
    public void noPendingOperation_confirmationDoesNotAuthorizeNewAction() {
        mModel.onConfirmationResult(true);

        verify(mAction, never()).run();
        assertThat(mModel.getState().getValue().busy).isFalse();
    }

    @Test
    public void whileWaitingForConfirmation_cannotReplacePendingAction() {
        confirmOwnerForDisclosure();
        Runnable replacement = mock(Runnable.class);
        assertThat(mModel.stageAction(mAction)).isTrue();

        assertThat(mModel.stageAction(replacement)).isFalse();
        mModel.onConfirmationResult(false);

        verify(mAction, never()).run();
        verify(replacement, never()).run();
    }

    private void confirmOwnerForDisclosure() {
        assertThat(mModel.stageDisclosureConfirmation()).isTrue();
        mModel.onDisclosureConfirmationResult(true);
    }

    @Test
    public void beforeConfirmation_disclosureAndMutationsDenied() {
        assertThat(mModel.getState().getValue().ownerConfirmed).isFalse();
        assertThat(mModel.stageAction(mAction)).isFalse();
        verify(mAction, never()).run();
    }

    @Test
    public void confirmedDisclosure_doesNotExecuteMutation() {
        confirmOwnerForDisclosure();
        assertThat(mModel.getState().getValue().ownerConfirmed).isTrue();
        assertThat(mModel.getState().getValue().busy).isFalse();
        verify(mAction, never()).run();
    }

    @Test
    public void cancelledDisclosure_keepsListPrivate() {
        assertThat(mModel.stageDisclosureConfirmation()).isTrue();
        mModel.onDisclosureConfirmationResult(false);
        assertThat(mModel.getState().getValue().ownerConfirmed).isFalse();
        assertThat(mModel.stageAction(mAction)).isFalse();
    }

    @Test
    public void unsolicitedSuccessfulResult_cannotRevealList() {
        mModel.onDisclosureConfirmationResult(true);
        mModel.onConfirmationResult(true);
        assertThat(mModel.getState().getValue().ownerConfirmed).isFalse();
        assertThat(mModel.stageAction(mAction)).isFalse();
    }

    @Test
    public void leavingForeground_revokesReadAndMutationPermission() {
        confirmOwnerForDisclosure();
        mModel.revokeDisclosure();
        assertThat(mModel.getState().getValue().ownerConfirmed).isFalse();
        assertThat(mModel.stageAction(mAction)).isFalse();
        confirmOwnerForDisclosure();
        assertThat(mModel.getState().getValue().ownerConfirmed).isTrue();
    }

    @Test
    public void disclosureConfirmationCannotBeReplacedByMutation() {
        assertThat(mModel.stageDisclosureConfirmation()).isTrue();
        assertThat(mModel.stageDisclosureConfirmation()).isFalse();
        assertThat(mModel.stageAction(mAction)).isFalse();
        mModel.onConfirmationResult(true);
        assertThat(mModel.getState().getValue().ownerConfirmed).isFalse();
        assertThat(mModel.getState().getValue().busy).isTrue();
    }

    @Test
    public void queuedMutationCompletion_cannotRestoreBackgroundDisclosure() {
        ArrayDeque<Runnable> background = new ArrayDeque<>();
        ArrayDeque<Runnable> main = new ArrayDeque<>();
        mModel = new SecureSpacesViewModel(RuntimeEnvironment.getApplication(),
                new SecureSpaceRepository(mock(UserManager.class), mock(LockPatternUtils.class),
                        () -> 0), background::add, main::add);
        confirmOwnerForDisclosure();
        assertThat(mModel.stageAction(mAction)).isTrue();
        mModel.onConfirmationResult(true);
        background.remove().run(); // Operation completed; UI completion is still queued.
        mModel.revokeDisclosure();
        main.remove().run();
        verify(mAction).run();
        assertThat(mModel.getState().getValue().busy).isFalse();
        assertThat(mModel.getState().getValue().ownerConfirmed).isFalse();
    }

    @Test
    public void delayedConfirmationReturn_requiresNewOwnerProof() {
        AtomicLong clock = new AtomicLong(100);
        mModel = new SecureSpacesViewModel(RuntimeEnvironment.getApplication(),
                new SecureSpaceRepository(mock(UserManager.class), mock(LockPatternUtils.class),
                        () -> 0), Runnable::run, Runnable::run, clock::get);
        confirmOwnerForDisclosure();
        clock.set(30_100);
        assertThat(mModel.canDisclose()).isFalse();
        assertThat(mModel.stageAction(mAction)).isFalse();
        mModel.onForeground();
        assertThat(mModel.getState().getValue().ownerConfirmed).isFalse();
        assertThat(mModel.stageAction(mAction)).isFalse();
    }
}
