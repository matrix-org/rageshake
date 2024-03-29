1. Set a variable to the version number for convenience:
   ```sh
   ver=x.y.z
   ```
1. Update the changelog:
   ```sh
   pip3 install --pre 'towncrier~=21.9'
   towncrier build --version=$ver
   ```
1. Push your changes:
   ```sh
   git add -u && git commit -m $ver && git push
   ```
1. Sanity-check the
   [changelog](https://github.com/matrix-org/rageshake/blob/master/CHANGES.md)
   and update if need be.
1. Create release on GH project page:
   ```sh
   xdg-open https://github.com/matrix-org/rageshake/releases/new?tag=v$ver&title=v$ver
   ```
   Describe the release based on the changelog.

   This will trigger a docker image to be built as well as a binary to be uploaded to the release
1. Check that the docker image has been created and tagged (a few mins)
   ```
   xdg-open https://github.com/matrix-org/rageshake/pkgs/container/rageshake/versions?filters%5Bversion_type%5D=tagged
   ```
1. Check that the rageshake binary has been built and added to the release (a few mins)
   ```
   xdg-open https://github.com/matrix-org/rageshake/releases
   ```
