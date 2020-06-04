1. Set a variable to the version number for convenience:
   ```sh
   ver=x.y
   ```
1. Update the changelog:
   ```sh
   pip3 install --pre 'towncrier>=19.2'
   towncrier --version=$ver
   ```
1. Push your changes:
   ```sh
   git add -u && git commit -m $ver && git push
   ```
1. Sanity-check the
   [changelog](https://github.com/matrix-org/rageshake/blob/master/CHANGES.md)
   and update if need be.
1. Create a signed tag for the release:
   ```sh
   git tag -s v$ver
   ```
   Base the tag message on the changelog.
1. Push the tag:
   ```sh
   git push origin tag v$ver
   ```
1. Create release on GH project page:
   ```sh
   xdg-open https://github.com/matrix-org/rageshake/releases/edit/v$ver
   ```
