/*
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.android.nearby.presence.rust;

import static java.lang.annotation.RetentionPolicy.SOURCE;

import androidx.annotation.IntDef;
import java.lang.annotation.Retention;

/** Base class for V0 data element types. */
public abstract class V0DataElement {

  /**
   * A visitor interface that can be used while iterating data elements in an advertisement to avoid
   * checking {@code instanceof} on every one.
   */
  public interface Visitor {
    default void visitTxPower(TxPower txPower) {}

    default void visitV0Actions(V0Actions v0Actions) {}
  }

  // All subclasses should be in this file
  private V0DataElement() {}

  /** Visit this advertisement with the given visitor. */
  public abstract void visit(Visitor v);

  /** Contains the TxPower information. See the spec for more information. */
  public static final class TxPower extends V0DataElement {
    private final int txPower;

    public TxPower(int txPower) {
      this.txPower = txPower;
    }

    public int getTxPower() {
      return txPower;
    }

    public void visit(Visitor v) {
      v.visitTxPower(this);
    }
  }

  /** Marker annotation/enum for V0 action values. */
  @IntDef({
    V0ActionType.CROSS_DEV_SDK,
    V0ActionType.CALL_TRANSFER,
    V0ActionType.ACTIVE_UNLOCK,
    V0ActionType.NEARBY_SHARE,
    V0ActionType.INSTANT_TETHERING,
    V0ActionType.PHONE_HUB,
  })
  @Retention(SOURCE)
  public @interface V0ActionType {
    // NOTE: Copied from `np_ffi_core::v0::BooleanActionType`.
    public static final int CROSS_DEV_SDK = 1;
    public static final int CALL_TRANSFER = 4;
    public static final int ACTIVE_UNLOCK = 8;
    public static final int NEARBY_SHARE = 9;
    public static final int INSTANT_TETHERING = 10;
    public static final int PHONE_HUB = 11;
  }

  /** The Actions data element. See the spec for more information. */
  public static final class V0Actions extends V0DataElement {
    static {
      System.loadLibrary(NpAdv.LIBRARY_NAME);
    }

    private final @IdentityKind int identityKind;
    private final int actionBits;

    public V0Actions(@IdentityKind int identityKind, int actionBits) {
      this.identityKind = identityKind;
      this.actionBits = actionBits;
    }

    @IdentityKind
    public int getIdentityKind() {
      return identityKind;
    }

    public int getActionBits() {
      return actionBits;
    }

    /** Checks if this Actions DE contains the given action. */
    public boolean hasAction(@V0ActionType int action) {
      return nativeHasAction(identityKind, actionBits, action);
    }

    public void visit(Visitor v) {
      v.visitV0Actions(this);
    }

    private static native boolean nativeHasAction(int identityKind, int actionBits, int action);
  }
}
