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

import androidx.annotation.Nullable;
import java.lang.ref.Cleaner;

/**
 * Internal handle type for deserialized V0 advertisements. It provides access to the native data
 * and allows that data to be deallocated.
 */
public final class V0Payload extends OwnedHandle {

  static {
    System.loadLibrary(NpAdv.LIBRARY_NAME);
  }

  /**
   * Create a V0Payload handle from the raw handle id. This will use the default cleaner form {@code
   * NpAdv#getCleaner()}. This is expected to be called from native code.
   */
  /* package-visible */ V0Payload(long handleId) {
    this(handleId, NpAdv.getCleaner());
  }

  /** Create a V0Payload handle from the raw handle id. */
  /* package-visible */ V0Payload(long handleId, Cleaner cleaner) {
    super(handleId, cleaner, V0Payload::deallocate);
  }

  /**
   * Get the data element at the given index.
   *
   * @param index The data element's index in the advertisement
   * @throws IndexOutOfBoundsException if the given index is out of range for this advertisement
   * @return The data element at that index
   */
  public V0DataElement getDataElement(int index) {
    V0DataElement de = nativeGetDataElement(this.handleId, index);
    if (de == null) {
      throw new IndexOutOfBoundsException();
    }
    return de;
  }

  @Nullable
  private static native V0DataElement nativeGetDataElement(long handleId, int index);

  private static native void deallocate(long handleId);
}
