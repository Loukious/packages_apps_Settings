/*
 * Copyright (C) 2026 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.settings.security.securespaces;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.pm.UserInfo;
import android.os.UserHandle;
import android.os.UserManager;

import com.android.internal.widget.LockPatternUtils;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.List;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 35, manifest = Config.NONE, application = android.app.Application.class)
public class SecureSpaceRepositoryTest {
    @Mock private UserManager mUsers;
    @Mock private LockPatternUtils mLocks;
    private SecureSpaceRepository mRepository;
    private int mForegroundUser;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        when(mUsers.getUserHandle()).thenReturn(UserHandle.USER_SYSTEM);
        when(mUsers.isAdminUser()).thenReturn(true);
        when(mLocks.isSecure(anyInt())).thenReturn(true);
        when(mLocks.getCredentialTypeForUser(anyInt())).thenReturn(LockPatternUtils.CREDENTIAL_TYPE_PIN);
        when(mUsers.canAddMoreUsers(UserManager.USER_TYPE_FULL_SECURE_SPACE)).thenReturn(true);
        mRepository = new SecureSpaceRepository(mUsers, mLocks, () -> mForegroundUser);
    }

    @Test
    public void listSpaces_excludesOtherUserTypesAndIncompleteUsers() {
        UserInfo owner = user(0, UserManager.USER_TYPE_FULL_SYSTEM);
        UserInfo ordinary = user(10, UserManager.USER_TYPE_FULL_SECONDARY);
        UserInfo space = user(11, UserManager.USER_TYPE_FULL_SECURE_SPACE);
        UserInfo partial = user(12, UserManager.USER_TYPE_FULL_SECURE_SPACE);
        partial.partial = true;
        UserInfo preCreated = user(13, UserManager.USER_TYPE_FULL_SECURE_SPACE);
        preCreated.preCreated = true;
        when(mUsers.getAliveUsers()).thenReturn(
                List.of(owner, ordinary, space, partial, preCreated));

        assertThat(mRepository.getSpaces()).containsExactly(space);
    }

    @Test
    public void routingCandidates_requireInitializedEnabledCredentialProtectedFullUsers() {
        UserInfo owner = user(0, UserManager.USER_TYPE_FULL_SYSTEM);
        UserInfo secured = user(10, UserManager.USER_TYPE_FULL_SECURE_SPACE);
        UserInfo unsecured = user(11, UserManager.USER_TYPE_FULL_SECURE_SPACE);
        UserInfo disabled = user(12, UserManager.USER_TYPE_FULL_SECURE_SPACE);
        disabled.flags |= UserInfo.FLAG_DISABLED;
        UserInfo unfinished = user(13, UserManager.USER_TYPE_FULL_SECURE_SPACE);
        unfinished.flags &= ~UserInfo.FLAG_INITIALIZED;
        UserInfo ordinary = user(14, UserManager.USER_TYPE_FULL_SECONDARY);
        when(mLocks.isSecure(11)).thenReturn(false);
        when(mUsers.getAliveUsers()).thenReturn(
                List.of(owner, secured, unsecured, disabled, unfinished, ordinary));

        assertThat(mRepository.getRoutingCandidates()).containsExactly(owner, secured);
    }

    @Test
    public void patternOwnerCannotCreateConcealedSpace() {
        when(mLocks.getCredentialTypeForUser(0)).thenReturn(LockPatternUtils.CREDENTIAL_TYPE_PATTERN);
        assertThat(mRepository.canCreateSpace()).isFalse();
        assertThrows(IllegalStateException.class, () -> mRepository.createSpace("Private"));
        verify(mUsers, never()).createUser(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(), anyInt());
    }

    @Test
    public void unconfiguredSpaceCannotBeOpenedBeforeNativeCredentialSetup() {
        UserInfo space = user(10, UserManager.USER_TYPE_FULL_SECURE_SPACE);
        when(mUsers.getUserInfo(10)).thenReturn(space);
        when(mLocks.getCredentialTypeForUser(10)).thenReturn(LockPatternUtils.CREDENTIAL_TYPE_NONE);
        assertThrows(SecurityException.class, () -> mRepository.switchToSpace(space));
    }

    @Test
    public void createSpace_usesDedicatedFullUserType() {
        UserInfo space = user(10, UserManager.USER_TYPE_FULL_SECURE_SPACE);
        when(mUsers.createUser("Private", UserManager.USER_TYPE_FULL_SECURE_SPACE,
                UserInfo.FLAG_INITIALIZED))
                .thenReturn(space);

        assertThat(mRepository.createSpace(" Private ")).isSameInstanceAs(space);
        verify(mUsers).createUser("Private", UserManager.USER_TYPE_FULL_SECURE_SPACE,
                UserInfo.FLAG_INITIALIZED);
    }

    @Test
    public void createSpace_rejectsNonOwnerAndForegroundUserChange() {
        mForegroundUser = 10;
        assertThrows(SecurityException.class, () -> mRepository.createSpace("Private"));
        mForegroundUser = 0;
        when(mUsers.getUserHandle()).thenReturn(10);
        assertThrows(SecurityException.class, () -> mRepository.createSpace("Private"));
    }

    @Test
    public void createSpace_requiresOwnerCredentialAndRespectsCreationRestrictions() {
        when(mLocks.isSecure(0)).thenReturn(false);
        assertThrows(SecurityException.class, () -> mRepository.createSpace("Private"));
        when(mLocks.isSecure(0)).thenReturn(true);
        when(mUsers.hasUserRestriction(UserManager.DISALLOW_ADD_USER)).thenReturn(true);
        assertThrows(IllegalStateException.class, () -> mRepository.createSpace("Private"));
        assertThat(mRepository.canCreateSpace()).isFalse();
    }

    @Test
    public void renameSpace_rejectsRecycledUserId() {
        UserInfo original = user(10, UserManager.USER_TYPE_FULL_SECURE_SPACE);
        UserInfo replacement = user(10, UserManager.USER_TYPE_FULL_SECURE_SPACE);
        replacement.serialNumber = original.serialNumber + 1;
        when(mUsers.getUserInfo(10)).thenReturn(replacement);

        assertThrows(IllegalArgumentException.class,
                () -> mRepository.renameSpace(original, "Renamed"));
        verify(mUsers, never()).setUserName(10, "Renamed");
    }

    @Test
    public void removeSpace_cannotRemoveOwnerOrOrdinaryUser() {
        UserInfo owner = user(0, UserManager.USER_TYPE_FULL_SYSTEM);
        UserInfo ordinary = user(10, UserManager.USER_TYPE_FULL_SECONDARY);
        when(mUsers.getUserInfo(0)).thenReturn(owner);
        when(mUsers.getUserInfo(10)).thenReturn(ordinary);

        assertThrows(IllegalArgumentException.class, () -> mRepository.removeSpace(owner));
        assertThrows(IllegalArgumentException.class, () -> mRepository.removeSpace(ordinary));
    }

    @Test
    public void removeSpace_respectsDevicePolicyWithoutOverride() {
        UserInfo space = user(10, UserManager.USER_TYPE_FULL_SECURE_SPACE);
        when(mUsers.getUserInfo(10)).thenReturn(space);
        when(mUsers.hasUserRestriction(UserManager.DISALLOW_REMOVE_USER)).thenReturn(true);
        assertThrows(SecurityException.class, () -> mRepository.removeSpace(space));

        when(mUsers.hasUserRestriction(UserManager.DISALLOW_REMOVE_USER)).thenReturn(false);
        when(mUsers.removeUserWhenPossible(UserHandle.of(10), false))
                .thenReturn(UserManager.REMOVE_RESULT_REMOVED);
        mRepository.removeSpace(space);
        verify(mUsers).removeUserWhenPossible(UserHandle.of(10), false);
    }

    private static UserInfo user(int id, String type) {
        UserInfo user = new UserInfo(id, "User " + id, null,
                UserInfo.FLAG_FULL | UserInfo.FLAG_INITIALIZED, type);
        user.serialNumber = 100 + id;
        return user;
    }
}
