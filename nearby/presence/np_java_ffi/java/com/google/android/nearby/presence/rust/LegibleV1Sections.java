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

/** Internal handle for a V1 deserialized advertisement. */
public final class LegibleV1Sections extends OwnedHandle {

  static {
    System.loadLibrary(NpAdv.LIBRARY_NAME);
  }

  /**
   * Create a LegibleV1Sections handle from the raw handle id. This will use the default cleaner
   * form {@code NpAdv#getCleaner()}. This is expected to be called from native code.
   */
  /* package-visible */ LegibleV1Sections(long handleId) {
    this(handleId, NpAdv.getCleaner());
  }

  /** Create a LegibleV1Sections handle from the raw handle id. */
  /* package-visible */ LegibleV1Sections(long handleId, Cleaner cleaner) {
    super(handleId, cleaner, LegibleV1Sections::deallocate);
  }

  /**
   * Get the section at the given index.
   *
   * @param index The section's index in the advertisement
   * @throws IndexOutOfBoundsException if the given index is out of range for this advertisement
   * @return The section at that index
   */
  public DeserializedV1Section getSection(int index) {
    DeserializedV1Section section = nativeGetSection(index);
    if (section == null) {
      throw new IndexOutOfBoundsException();
    }
    return section;
  }

  /**
   * Get the data element from a specific section.
   *
   * @param sectionIndex The section's index in the advertisement. This only counts legible sections
   * @param deIndex The data element's index in the section
   * @throws IndexOutOfBoundsException if either index is out of range for this advertisement
   * @return The data element found at {@code deIndex} in the section at {@code sectionIndex}
   */
  public V1DataElement getSectionDataElement(int sectionIndex, int deIndex) {
    V1DataElement de = nativeGetSectionDataElement(sectionIndex, deIndex);
    if (de == null) {
      throw new IndexOutOfBoundsException();
    }
    return de;
  }

  @Nullable
  private native DeserializedV1Section nativeGetSection(int index);

  @Nullable
  private native V1DataElement nativeGetSectionDataElement(int sectionIndex, int deIndex);

  private static native void deallocate(long handleId);
}
