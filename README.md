# Navicat Linux Crack

This tool currently supports the Linux x86_64 **Navicat Premium 17.3.10** and **Navicat Premium 18.0.2** build. It verifies `usr/lib/libcc.so` before making any changes and rejects other builds.

1. Download `navicat17-premium-en-x86_64.AppImage` from the [official Navicat website](https://www.navicat.com/en/download/navicat-premium). Make sure it is the supported 17.3.10 or 18.0.2 build.

2. In the directory containing the AppImage, make it executable and extract it. The files will appear in `squashfs-root`.

   ```sh
   chmod +x navicat17-premium-en-x86_64.AppImage
   ./navicat17-premium-en-x86_64.AppImage --appimage-extract .
   ```

3. From this project's directory, start the interactive tool with the path to the extracted directory:

   ```sh
   go run . /path/to/squashfs-root
   ```

   Follow the necessary menu steps in order: generate a private key, patch `libcc.so`, generate a license key, and complete manual activation.

4. Return to the directory containing `squashfs-root`, download `appimagetool`, and repack the modified directory:

   ```sh
   wget https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
   chmod +x appimagetool-x86_64.AppImage
   ./appimagetool-x86_64.AppImage squashfs-root navicat17-premium-en-x86_64-repack.AppImage
   ```

5. Make the repacked AppImage executable and run it:

   ```sh
   chmod +x navicat17-premium-en-x86_64-repack.AppImage
   ./navicat17-premium-en-x86_64-repack.AppImage
   ```

The source code in this repository is licensed under the [MIT License](LICENSE).
