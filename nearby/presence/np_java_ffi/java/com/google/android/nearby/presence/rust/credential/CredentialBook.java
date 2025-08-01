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

package com.google.android.nearby.presence.rust.credential;

import com.google.android.nearby.presence.rust.NpAdv;
import com.google.android.nearby.presence.rust.OwnedHandle;
import java.lang.ref.Cleaner;
import java.util.ArrayList;

public final class CredentialBook<M extends CredentialBook.MatchedMetadata> extends OwnedHandle {

  static {
    System.loadLibrary(NpAdv.LIBRARY_NAME);
  }

  /** Metadata that is associated with a Credential. */
  public interface MatchedMetadata {
    /**
     * Get the bytes for encrypted metadata. This byte array may be empty if there is no encrypted
     * metadata.
     */
    byte[] getEncryptedMetadataBytes();
  }

  /** {@link MatchedMetadata} implementation for cases where there is no associated metadata. */
  public static class NoMetadata implements MatchedMetadata {

    /** An instance to avoid needing additional instances of this class. */
    public static final NoMetadata INSTANCE = new NoMetadata();

    @Override
    public byte[] getEncryptedMetadataBytes() {
      return new byte[0];
    }
  }

  /** Thrown when a cryptographic key is given and those key bytes are not valid. */
  public static final class InvalidPublicKeyException extends RuntimeException {
    public InvalidPublicKeyException() {
      super(
          "The provided public key bytes do not actually represent a valid \"edwards y\" format or"
              + " that said compressed point is not actually a point on the curve.");
    }
  }

  /** Builder for {@code CredentialBook} */
  public static final class Builder<M extends MatchedMetadata> {
    private Cleaner cleaner;
    private CredentialSlab slab;

    // Each credential should be given an id of its metadata index so that this array is an
    // id-to-metadata map.
    private ArrayList<M> matchDataList;

    /**
     * Create a builder instance. The {@link CredentialBook#builder()} factory method can be used to
     * create a {@code Builder} with the default {@link Cleaner}. This can fail if there isn't room
     * to create a new {@code CredentialSlab} handle.
     *
     * @param cleaner The cleaner instance to use for the {@link CredentialSlab} and {@code
     *     CredentialBook}.
     */
    public Builder(Cleaner cleaner) {
      this.cleaner = cleaner;
      this.slab = new CredentialSlab(cleaner);
      this.matchDataList = new ArrayList<>();
    }

    /** Add a {@link V0DiscoveryCredential} to the book. */
    public Builder<M> addDiscoveryCredential(V0DiscoveryCredential credential, M matchData) {
      int credIdx = matchDataList.size();
      matchDataList.add(matchData);
      slab.addDiscoveryCredential(credential, credIdx, matchData.getEncryptedMetadataBytes());
      return this;
    }

    /**
     * Add a {@link V1DiscoveryCredential} to the book. May throw {@link
     * CredentialBook.InvalidPublicKeyException} if the key inside {@code credential} is improperly
     * formatted.
     */
    public Builder<M> addDiscoveryCredential(V1DiscoveryCredential credential, M matchData) {
      int credIdx = matchDataList.size();
      matchDataList.add(matchData);
      slab.addDiscoveryCredential(credential, credIdx, matchData.getEncryptedMetadataBytes());
      return this;
    }

    /**
     * Create the {@code CredentialBook}. This can fail if there isn't room to create a new {@code
     * CredentialBook} handle.
     */
    public CredentialBook<M> build() {
      return new CredentialBook(slab, matchDataList, cleaner);
    }
  }

  /** Create a credential book builder with the default cleaner from {@link NpAdv#getCleaner()}. */
  public static <M extends MatchedMetadata> Builder<M> builder() {
    return new Builder<M>(NpAdv.getCleaner());
  }

  /**
   * Create an empty credential book. This is useful for when only plaintext advertisements are
   * being deserialized.
   */
  public static CredentialBook<NoMetadata> empty() {
    return new Builder<NoMetadata>(NpAdv.getCleaner()).build();
  }

  private final ArrayList<M> matchData;

  /**
   * Create a new credential book. This always consumes the slab handle. This should only be called
   * from {@code Builder}. {@code matchData} is formatted so that each credential is given an id of
   * the index of its metadata in {@code matchData}.
   */
  private CredentialBook(CredentialSlab slab, ArrayList<M> matchData, Cleaner cleaner) {
    super(allocate(slab.move()), cleaner, CredentialBook::deallocate);
    this.matchData = matchData;
  }

  private static native long allocate(long slabHandleId);

  private static native void deallocate(long handleId);
}
