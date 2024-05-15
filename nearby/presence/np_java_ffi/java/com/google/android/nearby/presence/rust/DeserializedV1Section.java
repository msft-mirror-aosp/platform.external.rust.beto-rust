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

import java.util.Iterator;

public final class DeserializedV1Section {
  private final LegibleV1Sections legibleSections;
  private final int legibleSectionsIndex;
  private final int numDataElements;
  private final @IdentityKind int identityTag;

  /* package */ DeserializedV1Section(
      LegibleV1Sections legibleSections,
      int legibleSectionsIndex,
      int numDataElements,
      @IdentityKind int identityTag) {
    this.legibleSections = legibleSections;
    this.legibleSectionsIndex = legibleSectionsIndex;
    this.numDataElements = numDataElements;
    this.identityTag = identityTag;
  }

  /** Gets the identity kind for this section. */
  @IdentityKind
  public int getIdentityKind() {
    return this.identityTag;
  }

  /** Gets the number of data elements in this section. */
  public int getDataElementCount() {
    return this.numDataElements;
  }

  /**
   * Gets the data element at the given {@code index} in this advertisement.
   *
   * @throws IllegalStateException if the advertisement is not legible ({@link #isLegible()}).
   * @throws IndexOutOfBoundsException if the index is invalid
   */
  public V1DataElement getDataElement(int index) {
    return legibleSections.getSectionDataElement(this.legibleSectionsIndex, index);
  }

  /** Gets all the data elements for iteration. */
  public Iterable<V1DataElement> getDataElements() {
    return () -> new DataElementIterator(legibleSections, legibleSectionsIndex, numDataElements);
  }

  /** Visits all the data elements with the given visitor. */
  public void visitDataElements(V1DataElement.Visitor v) {
    for (V1DataElement de : getDataElements()) {
      de.visit(v);
    }
  }

  private static final class DataElementIterator implements Iterator<V1DataElement> {
    private final LegibleV1Sections legibleSections;
    private final int legibleSectionsIndex;
    private final int numDataElements;

    private int position = 0;

    public DataElementIterator(
        LegibleV1Sections legibleSections, int legibleSectionsIndex, int numDataElements) {
      this.legibleSections = legibleSections;
      this.legibleSectionsIndex = legibleSectionsIndex;
      this.numDataElements = numDataElements;
    }

    @Override
    public boolean hasNext() {
      return position < (numDataElements - 1);
    }

    @Override
    public V1DataElement next() {
      return legibleSections.getSectionDataElement(legibleSectionsIndex, position++);
    }
  }
}
