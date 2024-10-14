# Rust image

The point of this image is to verify the MSRV in CI so we can catch if a code or dependency change bumped the MSRV.
If this is acceptable then update the version in the Dockerfile.Rust FROM line then build the new image see below.

# Build and publish rust image

Make sure you have valid `quay.io/libpod` credentials in order to push the image there.
Then run the script `build_and_publish_rust_image.sh` to build and push it.
