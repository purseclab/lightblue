OBJ=/home/wu/andrsource/out/target/product/hammerhead/obj
llvm-link $OBJ/SHARED_LIBRARIES/bluetooth.default_intermediates/*.o\
    $OBJ/SHARED_LIBRARIES/bluetooth.default_intermediates/dotdot/btif/co/*.o\
    $OBJ/SHARED_LIBRARIES/bluetooth.default_intermediates/dotdot/btif/src/*.o\
    $OBJ/SHARED_LIBRARIES/bluetooth.default_intermediates/dotdot/embdrv/sbc/encoder/srce/*.o\
    $OBJ/SHARED_LIBRARIES/bluetooth.default_intermediates/dotdot/udrv/ulinux/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_bta_intermediates/ag/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_bta_intermediates/ar/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_bta_intermediates/av/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_bta_intermediates/dm/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_bta_intermediates/gatt/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_bta_intermediates/hf_client/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_bta_intermediates/hh/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_bta_intermediates/hl/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_bta_intermediates/jv/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_bta_intermediates/pan/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_bta_intermediates/sdp/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_bta_intermediates/sys/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/a2dp/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/avct/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/avdt/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/avrc/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/bnep/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/btm/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/btu/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/gap/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/gatt/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/hcic/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/hid/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/l2cap/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/mcap/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/pan/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/rfcomm/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/sdp/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/smp/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-brcm_stack_intermediates/srvc/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-hci_intermediates/src/*.o\
    $OBJ/STATIC_LIBRARIES/libbtprofile_intermediates/src/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-qcom_sbc_decoder_intermediates/srce/*.o\
    $OBJ/STATIC_LIBRARIES/libbt-utils_intermediates/src/*.o\
    $OBJ/STATIC_LIBRARIES/libbtdevice_intermediates/src/*.o\
    $OBJ/STATIC_LIBRARIES/libbtdevice_intermediates/src/classic/*.o -o $1
