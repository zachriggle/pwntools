############################################################
# Dockerfile to build Pwntools container
# Based on Ubuntu
############################################################

FROM pwntools/pwntools:docker
MAINTAINER Maintainer Gallopsled et al.

USER root

#==============================================================================
#                               ANDROID EMULATOR
#==============================================================================
# Android emulator from travis/install.sh
WORKDIR /usr/local
RUN wget -nv https://dl.google.com/android/android-sdk_r24.4.1-linux.tgz; \
    tar xf android-sdk_r24.4.1-linux.tgz; \
    rm -f android-sdk_r24.4.1-linux.tgz;
RUN ln -s android-sdk-linux android-sdk
ENV PATH="/usr/local/android-sdk/tools:$PATH"
ENV PATH="/usr/local/android-sdk/platform-tools:$PATH"

RUN wget -nv https://dl.google.com/android/repository/android-ndk-r13b-linux-x86_64.zip ; \
    unzip android-ndk-r13b-linux-x86_64.zip ; \
    rm -f android-ndk-r13b-linux-x86_64.zip ;
RUN ln -s android-ndk-r13b android-ndk

# Ensure that all executables can be run by other users e.g. travis
RUN find android-sdk/ -perm 744 -type f -executable | xargs chmod +x

ENV NDK="/usr/local/android-ndk"
ENV PATH="$NDK:$PATH"

RUN echo y | android update sdk --no-ui --all --filter platform-tools,extra-android-support
RUN echo y | android update sdk --no-ui --all --filter android-21
RUN echo y | android update sdk --no-ui --all --filter sys-img-armeabi-v7a-android-21

#==============================================================================
#                            ANDROID EMULATOR SETUP
#==============================================================================
RUN echo no | android --silent create avd --name android-armeabi-v7a   --target android-21 --force --snapshot --abi armeabi-v7a
RUN emulator64-arm -avd android-armeabi-v7a -no-window -no-boot-anim -no-skin -no-audio -no-window -no-snapshot & \
    adb wait-for-device; \
    adb shell id; \
    adb shell getprop; \
    adb emu kill

USER travis
