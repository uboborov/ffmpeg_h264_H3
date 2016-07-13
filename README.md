# ffmpeg_h264_H3
h264 encoder support for Allwinner H3 CPU

These are modified sources of the port of **FFmpeg** for Cedrus originally located here: https://github.com/stulluk/FFmpeg-Cedrus
To use these sources checkout original sources and replace file **FFmpeg-root-dir/libavcodec/cedrus264.c** with one from this repository,
replace folder **FFmpeg-root-dir/libavcodec/arm/sunxi** with folder from this repository.

    ./configure --prefix=/usr --enable-nonfree --enable-gpl --enable-version3 --enable-vdpau --enable-libx264 --enable-libmp3lame --enable-libpulse --enable-libv4l2
and then, 
    make && sudo make install
