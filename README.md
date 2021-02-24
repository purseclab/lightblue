# LightBlue

This is the code repository for our USENIX'21 paper ([LIGHTBLUE : Automatic Profile-Aware Debloating of Bluetooth Stacks](http://a_link)).

## 0. Directory Explanation

The *llvmpass* folder contains the code for our LLVM pass.

The *bitcodes* folder contains the bitcode files that are used in LightBlue and this documentation.

The *scripts* folder contains all the scripts used in LightBlue and this documentation.

The *firmware* folder contains all the dumped firmware used in LightBlue.

The *firmware_analysis* folder contains the code for firmware analysis.

## 1. Host Code Debloating

We debloat the host Bluetooth stack based on LLVM framework, therefore, there are 3 general steps to debloat the host stack.

1. Generate the host stack LLVM bitcode.

2. Run the LLVM pass to debloat the LLVM bitcode (and generate a list of HCI commands, the command list is in the generated 'hcicmds.txt' file).

3. Compile LLVM bitcode to object code and generate the executable file.

We tested on Ubuntu 18.04 with LLVM 9.

Since BlueZ user space communicate with the kernel code via sockets and the kernel code sends HCI commands to the controller, we also need to analyze the kernel code to generate a list of needed HCI commands.
We leveraged the Kconfig in kernel to do kernel debloating.


### 1. Linux (BlueZ 5.52) Host Debloating

The link for BlueZ 5.52 can be found at [download (http://www.bluez.org/release-of-bluez-5-52/)](http://www.bluez.org/release-of-bluez-5-52/).

We used *wllvm* to compile and generate the LLVM bitcode.

How to install and configure wllvm can be found at [wllvm (https://github.com/SRI-CSL/whole-program-llvm)](https://github.com/SRI-CSL/whole-program-llvm).

Since BlueZ has well written configure file, we leveraged the configure file together with the LLVM pass.

#### 1.1 Host User Space Bitcode generation

The general steps to get the BlueZ user space bitcode is as following:

1. Configure accordingly (enable and disable profiles through the *configure* script).

2. Generate the object file.

3. Extract the bitcode from object file.

The detailed commands and procedures are described as following.

* Decompress the downloaded BlueZ code into folder *bluez*.

* Run the following commands to configure and compile BlueZ.

```
  $ cd bluez
  $ ./configure --enable-health --enable-a2dp --enable-avrcp --enable-mesh \
  --enable-hid --enable-network --enable-sap --enable-obex --enable-hog \
  --disable-optimization CC=wllvm
  $ make
```

* Run the following commands to extract the bitcode of baseline, i.e., no debloating (*bluetoothd.bc*).

```
  $ cd src
  $ extract-bc bluetoothd
```

* Run the *configure* script to generate different object file with only the wanted profile.
For example, run the following command if only A2DP(AVRCP) is needed.

```
  $ cd bluez
  $ ./configure --disable-health --enable-a2dp --enable-avrcp --disable-mesh \
  --disable-hid --disable-network --disable-sap --disable-obex --disable-hog \
  --disable-optimization CC=wllvm
  $ make
  $ cd src
  $ extract-bc bluetoothd
  $ mv bluetoothd.bc bluetoothd_a2dp.bc
```

#### 1.2. Compile and Run the LLVM Pass

A *makefile* is provided to compile the LLVM pass module.

The *LLVM_DIR* in makefile should be correctly set to the root folder of LLVM tool-chain to correctly compile the pass.
For instance, the *LLVM_DIR* should be set to '/home/user/llvm' if the whole LLVM tool-chain is download from ([LLVM download (https://releases.llvm.org/download.html#9.0.0)](https://releases.llvm.org/download.html#9.0.0)) and extract to that folder.
In this case, the path of 'clang' is '/home/user/llvm/bin/clang'.

After setting the root directory, run *make* command to compile and generate the LLVM pass executable.
Run the following command to run the pass against a bitcode file and generate the debloated bitcode:

```
  //-btstack specifies the stack and -profile specifies the profile to keep
  $ opt bluetoothd.bc -load ./BTanalysis.so -btanalysis -btstack bluez -profile a2dp -o bt_a2dp.bc
```

At last, compile the bitcode to object file and link to an executable file (which is similar to the original *bluetoothd*).

```
  //compile bitcode to object code
  $ llc -filetype=obj bt_a2dp.bc -o bt_a2dp.o
  //link object to generate executable
  $ clang bt_a2dp.o -lglib-2.0 -ldbus-1 -ldl -o bt_a2dp
  //run the code
  $ sudo ./bt_a2dp
```

#### 1.3. Kernel Bitcode Generation and HCI Commands Extraction

We also used *wllvm* to generate the kernel bitcode.
We tested with Linux 5.0.0 kernel version, and it should be similar for other versions.
Run the following commands to compile the kernel module with wllvm and extract the bitcode:

```
  $ cd linux
  $ make HOSTCC=wllvm CC=wllvm SUBDIRS=net/bluetooth
  $ cd net/bluetooth
  $ extract-bc bluetooth.ko
```

At last, run the pass with the generated bitcode to get the HCI command list:

```
  $ opt bluetooth.ko.bc -load ./BTanalysis.so -btanalysis -btstack kernel -profile a2dp -o tmp.bc
```

The list of HCI commands can be used in the firmware debloating.

### 2. BlueKitchen Host Debloating

Similar to BlueZ, we also need to generate the bitcode for BlueKitchen.
We also used the same tool, *wllvm*.
We tested LightBlue on BlueKitchen commit 30a3afbae836935d0d86cc4798f3c5e8419ce018.
The baseline is similar to BlueZ, enabling all profiles.
Therefore, we modified the makefile under directory 'path/to/bluekitchen/example/Makefile.inc' by adding the following to the file:

```
  // in EXAMPLES_GENERAL
  baseline    \
  // the compiliation rule for baseline
  baseline: ${CORE_OBJ} ${COMMON_OBJ} ${CLASSIC_OBJ} ${SDP_CLIENT} ${ATT_OBJ}
  ${GATT_SERVER_OBJ} ${GATT_CLIENT_OBJ} ${PAN_OBJ} ${SBC_DECODER_OBJ} ${SBC_ENCODER_OBJ}
  ${CVSD_PLC_OBJ} ${AVDTP_OBJ} baseline.o
	${CC} $^ ${CFLAGS} ${LDFLAGS} -o $@
```

Run the following command to compile BlueKitchen and extract the bitcode.
Note that, to run BlueKitchen on Linux, the files under 'path/to/bluekitchen/port/libusb' need to be compiled.
These files are the Linux port to support running BlueKitchen on Linux.

```
  $ cd port/libusb
  $ CC=wllvm make
```

Then the executable files are generated under port/libusb folder.
Here we take the *a2dp_sink_demo* as an example to show how to debloate it and recompile it to an executable file.

```
  // extract bitcode
  $ extract-bc a2dp_sink_demo
  // run the pass to debloate
  $ opt a2dp_sink_demo.bc -load ./BTanalysis.so -btanalysis -btstack bluekitchen -profile a2dp -o bk_a2dp.bc
  // recompile to object file
  $ llc llc -filetype=obj bk_a2dp.bc -o kitchen.a2dp.sink.o
  // link and generate executable file
  $ clang kitchen.a2dp.sink.o -lusb-1.0 -o kitchen.a2dp.sink
  // at last, the executable can be executed
  $ sudo ./kitchen.a2dp.sink
```

While running the pass, the needed HCI command list will be printed out, which can be used in the firmware debloating.

### 3. BlueDroid Host Debloating

Similar steps are needed to debloat the BlueDroid host stack, i.e., generating bitcode, running the LLVM pass, and recompile the bitcode to object file.

#### 3.1 Bitcode Generation

To generate the bitcode of BlueDroid stack, we need to download and compile the Android source code.
How to download the source code can be found [here (https://source.android.com/setup/build/downloading)](https://source.android.com/setup/build/downloading).
Note that the Android version we tested for Nexus 5 is android-6.0.1_r77.
The following command can be used to check that branch out:

```
  $ repo init -u https://android.googlesource.com/platform/manifest -b android-6.0.1_r77
```

The building tutorial is similar to [Sony's tutorial (https://developer.sony.com/develop/open-devices/guides/aosp-build-instructions/build-aosp-nougat-marshmallow-6-0-1/#tutorial-step-1)](https://developer.sony.com/develop/open-devices/guides/aosp-build-instructions/build-aosp-nougat-marshmallow-6-0-1/#tutorial-step-1).
But we don't need to build the whole system, we only need to compile the Bluetooth stack.
Therefore, once the preparation is done, run the following command to compile the Bluetooth stack only:

```
  // assume the source code is under 'andrsource' folder
  $ cd andrsource
  $ source build/envsetup.sh
  $ lunch aosp_hammerhead-userdebug
  $ cd system/bt
  $ mma
```

Once compiling is finished, the BlueDroid stack is generated and the intermediate object files are generated.
Because some of the Android source file cannot be compiled with clang (due to gcc specific features), we need to compile these files with gcc to generate the object file.
Then we compile other file with clang and generate the bitcode.
After running the LLVM pass and recompile to object code, we link all the object files together to generate the BlueDroid stack.
Therefore, the next step is to modify the *Android.mk* files so that we can generate the bitcode.

Add *LOCAL_CLANG_CFLAGS += -flto* to the following files and comment out the 24 Line (i.e., *LOCAL_CLANG := false*) in 'andrsource/system/bt/device/Android.mk' file:

```
  andrsource/system/bt/audio_a2dp_hw/Android.mk
  andrsource/system/bt/bta/Android.mk
  andrsource/system/bt/embdrv/sbc/decoder/Android.mk
  andrsource/system/bt/hci/Android.mk
  andrsource/system/bt/main/Android.mk
  andrsource/system/bt/profile/Android.mk
  andrsource/system/bt/stack/Android.mk
  andrsource/system/bt/tools/hci/Android.mk
  andrsource/system/bt/utils/Android.mk
```

After the modification, running *mma* again under 'andrsource/system/bt/' folder to generate the bitcode file.
There will be link errors, but it's OK.
Run the 'link_bluedroid.sh' script (you should change the *OBJ* variable accordingly) to link the bitcode and generate the whole program bitcode:

```
  $ sh link_bluedroid.sh bluedroid.bc
```

To test if the generate bitcode is correct or not, you can recompile to object code and link with the pre-generated object file to generate the BlueDroid library object file.

```
  $ sh bluedroid_ir2obj.sh bluedroid.bc bluedroid.so
```

And push the library file to the Nexus 5 phone.

```
  $ sh nexus5_change_lib.sh bluedroid.so
```

#### 3.2 Run LLVM Pass against The Bitcode

We take A2DP as an example.

```
  $ opt bluedroid.bc -load ./BTanalysis.so -btanalysis -btstack bluedroid -profile a2dp -o a2dp.bc 
  $ bluedroid_ir2obj.sh a2dp.bc a2dp.so
  $ sh nexus5_change_lib.sh a2dp.so
```

### 4. Fluoride Host Debloating

Fluoride is similar with BlueDroid in general.
Since Fluoride uses soong as the building system, the modification is slightly different.

#### 4.1 Bitcode Generation

We also need to download the Fluoride stack source code.
The repo we used for Pixel 3 is :

```
  repo init -u https://android.googlesource.com/platform/manifest -b android-9.0.0_r16
```

To successfully compile the code, the 'andrsource/build/soong/cc/sanitize.go' needs to be changed.
The 229 -- 232 need to be commented out and add the following to disable the CFI.

```
  // It looks like the following after modification.
  229     //s.Cfi = boolPtr(true)
  230     //if inList("cfi", ctx.Config().SanitizeDeviceDiag()) {
  231     //    s.Diag.Cfi = boolPtr(true)
  232     //}
  233         s.Cfi = nil
  234         s.Diag.Cfi = nil
```

The following two files need to be changed to help extract the HCI command.

The the *make_command* function at 34 Line in file:
```
  andrsource/system/bt/hci/src/hci_packet_factory.cc

  // append '__attribute__((noinline))' to the function, it looks like the following
  // after modification
  34  static BT_HDR* make_command(uint16_t opcode, size_t parameter_size,
  35                             uint8_t** stream_out) __attribute__((noinline));
```

And the *btu_hcif_send_cmd* function at 377 Line in file:
```
  andrsource/system/bt/stack/btu/btu_hcif.cc

  // append '__attribute__((noinline))' to the function, it looks like the following
  // after modification
  377  void btu_hcif_send_cmd(UNUSED_ATTR uint8_t controller_id, BT_HDR* p_buf) __attribute__((noinline)) {
```

Similar to BlueDroid compiliation, run the following command to compile the Fluoride stack.

```
  // assume the source code is under 'andrsource' folder
  $ cd andrsource
  $ source build/envsetup.sh
  $ lunch aosp_blueline-userdebug
  $ cd system/bt
  $ mma
```
Then change the following files by adding the *cflags: ["-flto"]* to the cflags:

```
  andrsource/system/bt/bta/Android.bp
  andrsource/system/bt/btif/Android.bp
  andrsource/system/bt/device/Android.bp
  andrsource/system/bt/hci/Android.bp
  andrsource/system/bt/main/Android.bp
  andrsource/system/bt/profile/avrcp/Android.bp
  andrsource/system/bt/stack/Android.bp
  andrsource/system/bt/utils/Android.bp
```

We take the first file as an example, the modification is shown as following:

```
  diff --git a/bta/Android.bp b/bta/Android.bp
  index d6919defe..e251a70a0 100644
  --- a/bta/Android.bp
  +++ b/bta/Android.bp
  @@ -118,26 +118,27 @@ cc_library_static {
       whole_static_libs: [
           "libaudio-hearing-aid-hw-utils",
       ],
  +    cflags: ["-flto"]
   }
```

After the modification, running *mma* again under 'andrsource/system/bt/' folder to generate the bitcode file.
There will be link errors, but it's OK.
Run the 'link_fluoride.sh' script (you should change the *OBJ* variable accordingly) to link the bitcode and generate the whole program bitcode:

```
  $ sh link_fluoride.sh fluoride.bc
```

To test if the generate bitcode is correct or not, you can recompile to object code and link with the pre-generated object file to generate the Fluoride library object file.

```
  $ sh fluoride_ir2obj.sh fluoride.bc fluoride.so
```

And push the library file to the Nexus 5 phone.

```
  $ sh pixel_change_lib.sh fluoride.so
```

#### 4.2 Run LLVM Pass against The Bitcode

We take A2DP as an example.

```
  $ opt fluoride.bc -load ./BTanalysis.so -btanalysis -btstack fluoride -profile a2dp -o a2dp.bc 
  $ fluoride_ir2obj.sh a2dp.bc a2dp.so
  $ sh pixel_change_lib.sh a2dp.so
```

## 2. Firmware Debloating

1. Dump firmware.

2. Firmware analysis.

With analysis.py, we identify the instruction address and resgister which relates to HCI opcode and command handler. 

3. HCI command handler extraction.

With the information from Firmware analysis, we extract the address for each HCI command handler. 

4. Firmware rewriting.

After identifying HCI command handler, we set the unneeded handler as dummy code. rewriting.py is a demo of keeping A2DP on CYPRESS920735Q60EVB. 
