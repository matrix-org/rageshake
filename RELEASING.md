1. Set a variable to the version number for convenience:
   ```sh
   ver=x.y.z
   ```
1. Update the changelog:
   ```sh
   # we need 19.9 to read config from towncrier.toml
   pip3 install --pre 'towncrier>19.2'
   towncrier --version=$ver
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
   xdg-open https://github.com/matrix-org/rageshake/releases/new
   ```
   Set the tag to be the new version (eg v2.2.1).
    Ensure you selected "create tag" if it doesn't already exist.
    Release name will be autocompleted to the tag name
   Describe the release based on the changelog
1. Check that the docker image has been created and tagged (a few mins)
   ```
   xdg-open https://github.com/matrix-org/rageshake/pkgs/container/rageshake/versions?filters%5Bversion_type%5D=tagged
   ```
1. Check that the rageshake binary has been built and added to the release (a few mins)
   ```
   xdg-open https://github.com/matrix-org/rageshake/releases
   ```
