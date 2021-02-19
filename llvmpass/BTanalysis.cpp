//===- Hello.cpp - Example code from "Writing an LLVM Pass" ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements two versions of the LLVM "Hello World" pass described
// in docs/WritingAnLLVMPass.html
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedUser.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"

#include "llvm/Analysis/MemorySSA.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Analysis/CallGraph.h"
#include <algorithm>
#include <iostream>
#include <list>
#include <queue>
#include <typeinfo>

#include <cxxabi.h>
#include <fstream>

#include "BTanalysis.h"

using namespace llvm;

static cl::list<std::string> btstack("btstack", cl::ZeroOrMore);
static cl::list<std::string> profile("profile", cl::ZeroOrMore);

namespace {

struct BTanalysis : public ModulePass {
  static char ID; // Pass identification, replacement for typeid

  std::list<Function *> interface_funcs;

  std::list<Function *> func_to_keep;
  std::list<Function *> func_to_remove;

  std::list<Function *> to_keep_worklist;
  std::list<Function *> to_remove_worklist;

  StringRef btu_init_name = StringRef("btu_init_core");
  StringRef bte_init_name = StringRef("BTE_InitStack");
  StringRef get_profile_name = StringRef("get_profile_interface");

  std::list<Function *> btu_init_rm_list;
  std::list<Function *> bte_init_rm_list;
  std::list<Function *> profile_int_rm_list;
  std::list<Function *> evt_rm_list;

  std::map<StringRef, Function *> name_function_map;
  std::map<Function *, StringRef> function_name_map;

  std::map<GlobalVariable *, std::set<int> *> global_value_map;
  std::map<Argument *, std::set<int> *> func_args_map;
  std::map<Value *, std::set<int> *> var_val_map;

  std::map<StringRef, std::list<Function *>> kitchen_profile_interface_map;

  BTanalysis() : ModulePass(ID) {}

  ~BTanalysis() {}

  enum code_type { BLUE, FLUO, BLUEZ, KERNEL, KITCHEN };
  enum profile_type {
    A2DP,
    HFP,
    PAN,
    HID,
    HSP,
    SPP,
    PBAP,
    GATT,
    SAP,
    MAP,
    HDP
  };

  std::list<int> acl_link = {0x0405, 0x0406, 0x0408, 0x0409, 0x040A};
  std::list<int> sco_link = {0x0428, 0x0429, 0x042A, 0x043d, 0x043e};
  std::list<int> le_link = {0x200d, 0x200e, 0x2043, 0x200a, 0x200c, 0x2039,
                            0x2042, 0x2040, 0x2044, 0x2045, 0x2046, 0x2064,
                            0x2066, 0x2067, 0x2068, 0x206a};

  code_type c_code = BLUE;
  profile_type profile_code = A2DP;

  void
  getKitchenProfileInterface(Module &M, profile_type profile,
                             std::list<Function *> &kitchen_profile_interface) {
    kitchen_profile_interface.push_back(M.getFunction("l2cap_init"));
    kitchen_profile_interface.push_back(M.getFunction("sdp_init"));
    switch (profile) {
    case A2DP:
      for (auto p : a2dp_interface) {
        auto f = M.getFunction(p);
        if (f == nullptr) {
          errs() << p << "\n";
          errs() << "error in find a2dp interface func\n";
        } else {
          kitchen_profile_interface.push_back(f);
        }
      }
      break;
    case HFP:
      for (auto p : hfp_interface) {
        auto f = M.getFunction(p);
        if (f == nullptr) {
          errs() << p << "\n";
          errs() << "error in find hfp interface func\n";
        } else {
          kitchen_profile_interface.push_back(f);
        }
      }
      break;
    case PAN:
      for (auto p : pan_interface) {
        auto f = M.getFunction(p);
        if (f == nullptr) {
          errs() << p << "\n";
          errs() << "error in find pan interface func\n";
        } else {
          kitchen_profile_interface.push_back(f);
        }
      }
      break;
    case HID:
      for (auto p : hid_inpterface) {
        auto f = M.getFunction(p);
        if (f == nullptr) {
          errs() << p << "\n";
          errs() << "error in find hid interface func\n";
        } else {
          kitchen_profile_interface.push_back(f);
        }
      }
      break;
    case HSP:
      for (auto p : hsp_interface) {
        auto f = M.getFunction(p);
        if (f == nullptr) {
          errs() << p << "\n";
          errs() << "error in find hsp interface func\n";
        } else {
          kitchen_profile_interface.push_back(f);
        }
      }
      break;
    case SPP:
      for (auto p : spp_interface) {
        auto f = M.getFunction(p);
        if (f == nullptr) {
          errs() << p << "\n";
          errs() << "error in find spp interface func\n";
        } else {
          kitchen_profile_interface.push_back(f);
        }
      }
      break;
    case PBAP:
      for (auto p : pbap_interface) {
        auto f = M.getFunction(p);
        if (f == nullptr) {
          errs() << p << "\n";
          errs() << "error in find pbap interface func\n";
        } else {
          kitchen_profile_interface.push_back(f);
        }
      }

      for (auto p : goep_interface) {
        auto f = M.getFunction(p);
        if (f == nullptr) {
          errs() << p << "\n";
          errs() << "error in find goep interface func\n";
        } else {
          kitchen_profile_interface.push_back(f);
        }
      }
      break;
    case GATT:
      for (auto p : gatt_interface) {
        auto f = M.getFunction(p);
        if (f == nullptr) {
          errs() << p << "\n";
          errs() << "error in find gatt interface func\n";
        } else {
          kitchen_profile_interface.push_back(f);
        }
      }
      break;
    default:
      errs() << "Incorrect profile for BlueKitchen\n";
      break;
    }
  }

  // generate original name-function map for c++
  void createNameFunctionMap(Module &M) {
    int s;
    for (Function &F : M) {
      if (F.hasName() && !F.empty()) {
        StringRef ori_name =
            abi::__cxa_demangle(F.getName().data(), NULL, NULL, &s);
        if (ori_name != "") {
          name_function_map.insert(
              std::pair<StringRef, Function *>(ori_name.split('(').first, &F));
          function_name_map.insert(
              std::pair<Function *, StringRef>(&F, ori_name.split('(').first));
        }
      }
    }
  }

  GlobalVariable *getInterfaceClass(Module &M, Function *F) { return nullptr; }

  void emptyHandsfreeInterface(Module &M) {
    auto *gv =
        M.getGlobalVariable("_ZTVN9bluetooth7headset16HeadsetInterfaceE");
    std::list<Constant *> clist;
    if (gv->hasInitializer()) {
      flatenStruct(gv->getInitializer(), clist);
      for (auto c : clist) {
        if (auto F = dyn_cast<Function>(c)) {
          replaceFunctionBodyWithReturn(F);
        }
      }
    }
  }

  void emptyAvrcpInterface(Module &M) {
    auto *gv = M.getGlobalVariable(
        "_ZTVN9bluetooth5avrcp12AvrcpService20ServiceInterfaceImplE");
    std::list<Constant *> clist;
    if (gv->hasInitializer()) {
      flatenStruct(gv->getInitializer(), clist);
      for (auto c : clist) {
        if (auto F = dyn_cast<Function>(c)) {
          replaceFunctionBodyWithReturn(F);
        }
      }
    }
  }

  void initRmList(Module &M) {

    int depth = 0;

    switch (c_code) {
    case BLUE:
      errs() << "bluedroid.\n";
      switch (profile_code) {
      case A2DP:
        profile_int_rm_list.push_back(M.getFunction("btif_hh_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_hl_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_gatt_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_hf_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_hf_client_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_pan_get_interface"));

        // a2dp interfaces
        depth = 0;
        constPropergate(M.getFunction("init_src"), depth);
        depth = 0;
        constPropergate(M.getFunction("src_connect_sink"), depth);
        depth = 0;
        constPropergate(M.getFunction("disconnect"), depth);
        depth = 0;
        constPropergate(M.getFunction("init_sink"), depth);
        depth = 0;
        constPropergate(M.getFunction("sink_connect_src"), depth);
        depth = 0;
        constPropergate(M.getFunction("disconnect"), depth);

        // sdp interfaces
        depth = 0;
        constPropergate(M.getFunction("init.1653"), depth);
        depth = 0;
        constPropergate(M.getFunction("deinit"), depth);
        depth = 0;
        constPropergate(M.getFunction("search"), depth);

        removeCallInst(M.getFunction("btif_pan_init"),
                       M.getFunction("BTA_PanEnable"));
        removeCallInst(M.getFunction("btif_pan_init"),
                       M.getFunction("btpan_enable"));
        break;
      case HFP:
        profile_int_rm_list.push_back(M.getFunction("btif_pan_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_av_get_src_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_av_get_sink_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_hh_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_hl_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_gatt_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_rc_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_rc_ctrl_get_interface"));

        // hfp
        depth = 0;
        constPropergate(M.getFunction("init.868"), depth);
        depth = 0;
        constPropergate(M.getFunction("connect"), depth);
        depth = 0;
        constPropergate(M.getFunction("disconnect.869"), depth);
        // sdp
        depth = 0;
        constPropergate(M.getFunction("init.1653"), depth);
        depth = 0;
        constPropergate(M.getFunction("deinit"), depth);
        depth = 0;
        constPropergate(M.getFunction("search"), depth);

        removeCallInst(M.getFunction("btif_pan_init"),
                       M.getFunction("BTA_PanEnable"));
        removeCallInst(M.getFunction("btif_pan_init"),
                       M.getFunction("btpan_enable"));
        break;
      case PAN:
        profile_int_rm_list.push_back(M.getFunction("btif_hf_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_hf_client_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_av_get_src_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_av_get_sink_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_hh_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_hl_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_gatt_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_rc_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_rc_ctrl_get_interface"));

        // pan
        depth = 0;
        constPropergate(M.getFunction("btpan_enable"), depth);
        depth = 0;
        constPropergate(M.getFunction("btpan_connect"), depth);
        depth = 0;
        constPropergate(M.getFunction("btpan_disconnect"), depth);
        // sdp
        depth = 0;
        constPropergate(M.getFunction("init.1653"), depth);
        depth = 0;
        constPropergate(M.getFunction("deinit"), depth);
        depth = 0;
        constPropergate(M.getFunction("search"), depth);

        break;
      case HID:
        profile_int_rm_list.push_back(M.getFunction("btif_pan_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_hf_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_hf_client_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_av_get_src_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_av_get_sink_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_gatt_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_rc_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_hl_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_rc_ctrl_get_interface"));

        // hid
        depth = 0;
        constPropergate(M.getFunction("init.1084"), depth);
        depth = 0;
        constPropergate(M.getFunction("connect.1085"), depth);
        depth = 0;
        constPropergate(M.getFunction("disconnect.1086"), depth);
        // sdp
        depth = 0;
        constPropergate(M.getFunction("init.1653"), depth);
        depth = 0;
        constPropergate(M.getFunction("deinit"), depth);
        depth = 0;
        constPropergate(M.getFunction("search"), depth);

        removeCallInst(M.getFunction("btif_pan_init"),
                       M.getFunction("BTA_PanEnable"));
        removeCallInst(M.getFunction("btif_pan_init"),
                       M.getFunction("btpan_enable"));
        break;
      case HDP:
        profile_int_rm_list.push_back(M.getFunction("btif_pan_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_hf_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_hf_client_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_av_get_src_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_av_get_sink_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_gatt_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_rc_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_rc_ctrl_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_hh_get_interface"));

        // hdp
        depth = 0;
        constPropergate(M.getFunction("init.1255"), depth);
        depth = 0;
        constPropergate(M.getFunction("connect_channel"), depth);
        depth = 0;
        constPropergate(M.getFunction("destroy_channel"), depth);
        // sdp
        depth = 0;
        constPropergate(M.getFunction("init.1653"), depth);
        depth = 0;
        constPropergate(M.getFunction("deinit"), depth);
        depth = 0;
        constPropergate(M.getFunction("search"), depth);

        removeCallInst(M.getFunction("btif_pan_init"),
                       M.getFunction("BTA_PanEnable"));
        removeCallInst(M.getFunction("btif_pan_init"),
                       M.getFunction("btpan_enable"));
        break;
      case GATT:
        profile_int_rm_list.push_back(M.getFunction("btif_pan_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_hf_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_hf_client_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_av_get_src_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_av_get_sink_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_rc_get_interface"));
        profile_int_rm_list.push_back(
            M.getFunction("btif_rc_ctrl_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_hh_get_interface"));
        profile_int_rm_list.push_back(M.getFunction("btif_hl_get_interface"));

        // gatt
        depth = 0;
        constPropergate(M.getFunction("btif_gatt_init"), depth);
        depth = 0;
        constPropergate(M.getFunction("btif_gatt_cleanup"), depth);
        // sdp
        depth = 0;
        constPropergate(M.getFunction("init.1653"), depth);
        depth = 0;
        constPropergate(M.getFunction("deinit"), depth);
        depth = 0;
        constPropergate(M.getFunction("search"), depth);

        removeCallInst(M.getFunction("btif_pan_init"),
                       M.getFunction("BTA_PanEnable"));
        removeCallInst(M.getFunction("btif_pan_init"),
                       M.getFunction("btpan_enable"));
        break;
      default:
        errs() << "Invalid profile for BlueDroid\n";
        break;
      }
      break;
    case FLUO:
      errs() << "fluoride.\n";
      switch (profile_code) {
      case A2DP:
        profile_int_rm_list.push_back(
            name_function_map["btif_pan_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hf_client_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hh_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hd_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hl_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["stack_mcap_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hearing_aid_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_gatt_get_interface"]);

        // a2dp
        depth = 0;
        constPropergate(name_function_map["BtifAvSource::Init"], depth);
        depth = 0;
        constPropergate(name_function_map["BtifAvSource::Cleanup"], depth);
        depth = 0;
        constPropergate(name_function_map["BtifAvSink::Init"], depth);
        depth = 0;
        constPropergate(name_function_map["BtifAvSink::Cleanup"], depth);
        // sdp
        depth = 0;
        constPropergate(M.getFunction("_ZL4initP17btsdp_callbacks_t"), depth);
        depth = 0;
        constPropergate(M.getFunction("_ZL6deinitv"), depth);
        depth = 0;
        constPropergate(
            M.getFunction("_ZL6searchP10RawAddressRKN9bluetooth4UuidE"), depth);

        removeCallInst(name_function_map["btif_pan_init"],
                       name_function_map["BTA_PanEnable"]);
        removeCallInst(name_function_map["btif_pan_init"],
                       name_function_map["btpan_enable"]);
        break;
      case HFP:
        profile_int_rm_list.push_back(
            name_function_map["btif_pan_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_av_get_sink_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_av_get_src_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hh_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hd_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hl_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_rc_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_rc_ctrl_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["stack_mcap_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hearing_aid_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_gatt_get_interface"]);

        // hfp
        depth = 0;
        constPropergate(
            name_function_map["bluetooth::headset::HeadsetInterface::Init"],
            depth);
        depth = 0;
        constPropergate(
            name_function_map["bluetooth::headset::HeadsetInterface::Connect"],
            depth);
        depth = 0;
        constPropergate(
            name_function_map
                ["bluetooth::headset::HeadsetInterface::Disconnect"],
            depth);
        // sdp
        depth = 0;
        constPropergate(M.getFunction("_ZL4initP17btsdp_callbacks_t"), depth);
        depth = 0;
        constPropergate(M.getFunction("_ZL6deinitv"), depth);
        depth = 0;
        constPropergate(
            M.getFunction("_ZL6searchP10RawAddressRKN9bluetooth4UuidE"), depth);

        removeCallInst(name_function_map["btif_pan_init"],
                       name_function_map["BTA_PanEnable"]);
        removeCallInst(name_function_map["btif_pan_init"],
                       name_function_map["btpan_enable"]);
        break;
      case PAN:
        profile_int_rm_list.push_back(
            name_function_map["btif_hf_client_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_av_get_sink_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_av_get_src_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hh_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hd_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hl_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_rc_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_rc_ctrl_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["stack_mcap_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hearing_aid_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_gatt_get_interface"]);

        // pan
        depth = 0;
        constPropergate(M.getFunction("btpan_enable"), depth);
        depth = 0;
        constPropergate(M.getFunction("btpan_connect"), depth);
        depth = 0;
        constPropergate(M.getFunction("btpan_disconnect"), depth);
        // sdp
        depth = 0;
        constPropergate(M.getFunction("init.1653"), depth);
        depth = 0;
        constPropergate(M.getFunction("deinit"), depth);
        depth = 0;
        constPropergate(M.getFunction("search"), depth);
        break;
      case HID:
        profile_int_rm_list.push_back(
            name_function_map["btif_pan_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hf_client_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_av_get_sink_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_av_get_src_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hl_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_rc_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_rc_ctrl_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["stack_mcap_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hearing_aid_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_gatt_get_interface"]);

        // hid
        depth = 0;
        constPropergate(M.getFunction("_ZL4initP16bthh_callbacks_t"), depth);
        depth = 0;
        constPropergate(M.getFunction("_ZL7connectP10RawAddress.4114"), depth);
        depth = 0;
        constPropergate(M.getFunction("_ZL10disconnectP10RawAddress"), depth);

        depth = 0;
        constPropergate(M.getFunction("_ZL4initP16bthd_callbacks_t"), depth);
        depth = 0;
        constPropergate(M.getFunction("_ZL7connectP10RawAddress"), depth);
        depth = 0;
        constPropergate(M.getFunction("_ZL10disconnectv"), depth);

        // sdp
        depth = 0;
        constPropergate(M.getFunction("_ZL4initP17btsdp_callbacks_t"), depth);
        depth = 0;
        constPropergate(M.getFunction("_ZL6deinitv"), depth);
        depth = 0;
        constPropergate(
            M.getFunction("_ZL6searchP10RawAddressRKN9bluetooth4UuidE"), depth);

        removeCallInst(name_function_map["btif_pan_init"],
                       name_function_map["BTA_PanEnable"]);
        removeCallInst(name_function_map["btif_pan_init"],
                       name_function_map["btpan_enable"]);
        break;
      case HDP:
        profile_int_rm_list.push_back(
            name_function_map["btif_pan_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hf_client_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_av_get_sink_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_av_get_src_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hh_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hd_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_rc_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_rc_ctrl_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["stack_mcap_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hearing_aid_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_gatt_get_interface"]);

        // hdp
        depth = 0;
        constPropergate(M.getFunction("_ZL4initP16bthl_callbacks_t"), depth);
        depth = 0;
        constPropergate(M.getFunction("_ZL15connect_channeliP10RawAddressiPi"), depth);
        depth = 0;
        constPropergate(M.getFunction("_ZL15destroy_channeli"), depth);
        // sdp
        depth = 0;
        constPropergate(M.getFunction("_ZL4initP17btsdp_callbacks_t"), depth);
        depth = 0;
        constPropergate(M.getFunction("_ZL6deinitv"), depth);
        depth = 0;
        constPropergate(
            M.getFunction("_ZL6searchP10RawAddressRKN9bluetooth4UuidE"), depth);

        removeCallInst(name_function_map["btif_pan_init"],
                       name_function_map["BTA_PanEnable"]);
        removeCallInst(name_function_map["btif_pan_init"],
                       name_function_map["btpan_enable"]);
        break;
      case MAP:
        profile_int_rm_list.push_back(
            name_function_map["btif_pan_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hf_client_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_av_get_sink_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_av_get_src_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hh_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hd_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hl_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_rc_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_rc_ctrl_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hearing_aid_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_gatt_get_interface"]);

        // map
        depth = 0;
        constPropergate(M.getFunction("_ZL4initP17btmce_callbacks_t"), depth);
        // sdp
        depth = 0;
        constPropergate(M.getFunction("_ZL4initP17btsdp_callbacks_t"), depth);
        depth = 0;
        constPropergate(M.getFunction("_ZL6deinitv"), depth);
        depth = 0;
        constPropergate(
            M.getFunction("_ZL6searchP10RawAddressRKN9bluetooth4UuidE"), depth);

        removeCallInst(name_function_map["btif_pan_init"],
                       name_function_map["BTA_PanEnable"]);
        removeCallInst(name_function_map["btif_pan_init"],
                       name_function_map["btpan_enable"]);
        break;
      case GATT:
        profile_int_rm_list.push_back(
            name_function_map["btif_pan_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hf_client_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_av_get_sink_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_av_get_src_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hh_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hd_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hl_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_rc_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_rc_ctrl_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["stack_mcap_get_interface"]);
        profile_int_rm_list.push_back(
            name_function_map["btif_hearing_aid_get_interface"]);

        // gatt
        depth = 0;
        constPropergate(M.getFunction("_ZL14btif_gatt_initPK18btgatt_callbacks_t"), depth);
        depth = 0;
        constPropergate(M.getFunction("_ZL17btif_gatt_cleanupv"), depth);
        // sdp
        depth = 0;
        constPropergate(M.getFunction("_ZL4initP17btsdp_callbacks_t"), depth);
        depth = 0;
        constPropergate(M.getFunction("_ZL6deinitv"), depth);
        depth = 0;
        constPropergate(
            M.getFunction("_ZL6searchP10RawAddressRKN9bluetooth4UuidE"), depth);

        removeCallInst(name_function_map["btif_pan_init"],
                       name_function_map["BTA_PanEnable"]);
        removeCallInst(name_function_map["btif_pan_init"],
                       name_function_map["btpan_enable"]);
        break;
      default:
        errs() << "Invalid profile for Fluoride\n";
      }

      break;
    case BLUEZ:
      errs() << "No need to remove for bluez.\n";
      break;
    case KERNEL:
      errs() << "No need to remove for kernel.\n";
      break;
    case KITCHEN:
      errs() << "No need to remove for bluekitchen.\n";
      break;
    default:
      errs() << "Invalid c_code type. exit.\n";
      exit(0);
    }
  }

  // if a function is not in list
  bool notInList(std::list<Function *> &fList, Function *f) {
    if (std::find(fList.begin(), fList.end(), f) == fList.end()) {
      return true;
    }
    return false;
  }

  // remove call instruction from a basic block
  void removeCallInst(Function *caller, Function *callee) {
    Instruction *i = nullptr;
    for (BasicBlock &B : *caller) {
      for (auto I = B.begin(); I != B.end(); ++I) {
        if (auto *ci = dyn_cast<CallInst>(I)) {
          if (auto *removed = dyn_cast<Function>(
                  ci->getCalledValue()->stripPointerCasts())) {
            if (removed == callee) {
              i = ci;
            }
          }
        }
      }
    }
    std::list<Instruction *> ilist;
    if (i != nullptr) {
      for (auto U : i->users()) {
        if (auto *I = dyn_cast<Instruction>(U)) {
          if (!isa<SwitchInst>(I)) {
            ilist.push_back(I);
          }
        }
      }
      for (auto I : ilist) {
        I->replaceAllUsesWith(UndefValue::get(I->getType()));
        I->eraseFromParent();
      }
      i->eraseFromParent();
    }
    for (BasicBlock &B : *caller) {
      for (Instruction &I : B) {
        if (auto *phi = dyn_cast<PHINode>(&I)) {
          for (auto b = 0; b < phi->getNumIncomingValues(); ++b) {
            if (UndefValue::get(I.getType()) == phi->getIncomingValue(b)) {
              phi->setIncomingValue(b, Constant::getNullValue(I.getType()));
            }
          }
        }
      }
    }
  }

  // handle nested structure with function pointers
  void flatenStruct(Constant *c, std::list<Constant *> &clist) {
    int index = 0;
    while (1) {
      Constant *element = c->getAggregateElement(index);
      if (element != nullptr) {
        element = element->stripPointerCasts();
        if (element->hasName()) {
          if (element->getName() == "hci_dev_list" ||
              element->getName() == "hci_cb_list" ||
              element->getName() == "mgmt_chan_list" ||
              element->getName() == "chan_list" ||
              element->getName() == "amp_mgr_list") {
            break;
          }
        }
        if (auto *gv = dyn_cast<GlobalVariable>(element)) {
          if (gv->hasInitializer()) {
            if (auto *cs = dyn_cast<ConstantAggregate>(gv->getInitializer())) {
              flatenStruct(cs, clist);
              ++index;
              continue;
            }
          }
        } else if (auto *ca = dyn_cast<ConstantAggregate>(element)) {
          flatenStruct(ca, clist);
          ++index;
          continue;
        } else if (auto *gep = dyn_cast<GEPOperator>(element)) {
          if (auto *gepgv = dyn_cast<GlobalVariable>(
                  gep->getOperand(0)->stripPointerCasts())) {
            if (gepgv->hasInitializer()) {
              if (gepgv->hasName()) {
                // hack to avoid infinate loop
                if (gepgv->getName() != "mgmt_chan_list_lock" &&
                    gepgv->getName() != "hci_cb_list_lock" &&
                    gepgv->getName() != "amp_mgr_list_lock") {
                  flatenStruct(gepgv->getInitializer(), clist);
                  ++index;
                }
              }
            }
          }
        }
        clist.push_back(element->stripPointerCasts());
        ++index;
        continue;
      } else {
        break;
      }
    }
  }

  void constructCallGraph(CallGraph &cg, Module &M) {
    for (Function &F : M) {
      handleIndirectCall(F, cg);
    }
  }

  // if callee is not called by caller
  bool notCalled(CallGraph &cg, Function *caller, Function *callee) {
    for (auto f : *(cg[caller])) {
      if (callee == f.second->getFunction()) {
        return false;
      }
    }
    return true;
  }

  void addEdgeFromList(Function &F, CallGraph &cg,
                       std::list<Constant *> clist) {
    for (auto *c : clist) {
      if (auto *f = dyn_cast<Function>(c)) {
        if (notCalled(cg, &F, f)) {
          if (F.hasName() && f->hasName()) {
          }
          cg[&F]->addCalledFunction(nullptr, cg.getOrInsertFunction(f));
        }
      }
      if (auto *o = dyn_cast<Operator>(c)) {
        for (auto opd : o->operand_values()) {
          if (auto *f = dyn_cast<Function>(opd)) {
            if (F.hasName() && f->hasName()) {
            }
            cg[&F]->addCalledFunction(nullptr, cg.getOrInsertFunction(f));
          }
        }
      }
    }
  }

  StringRef getBTModuleName(Instruction *I) {
    for (auto operand : I->operand_values()) {
      if (auto *i = dyn_cast<ConstantExpr>(operand)) {
        auto module_name = i->getOperand(0);
        if (auto *gv = dyn_cast<GlobalVariable>(module_name)) {
          if (auto *s =
                  dyn_cast<ConstantDataSequential>(gv->getInitializer())) {
            if (s->isString()) {
              return s->getAsString();
            }
          }
        }
      }
    }
    return StringRef();
  }

  ConstantStruct *findBTModuleStructWithName(StringRef module_name, Module *M) {
    for (auto &gv : M->globals()) {
      if (gv.hasInitializer()) {
        auto v = gv.getInitializer();
        if (auto *cs = dyn_cast<ConstantStruct>(v)) {
          int index = 0;
          while (1) {
            auto *e = cs->getAggregateElement(index);
            if (e != NULL) {
              if (auto *c = dyn_cast<ConstantExpr>(e)) {
                if (auto *gv = dyn_cast<GlobalVariable>(c->getOperand(0))) {
                  if (gv->hasInitializer()) {
                    if (auto *s = dyn_cast<ConstantDataSequential>(
                            gv->getInitializer())) {
                      if (s->isString() && module_name == s->getAsString()) {
                        return cs;
                      }
                    }
                  }
                }
              }
              index++;
            } else {
              break;
            }
          }
        }
      }
    }
    return nullptr;
  }

  void handleIndirectCall(Function &F, CallGraph &cg) {
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        // handle load module function
        if (auto *ci = dyn_cast<CallInst>(&I)) {
          Function *f = ci->getCalledFunction();

          if (f != nullptr && f->hasName()) {
            if (f->getName() == "get_module" ||
                f->getName() == "_Z10get_modulePKc") {
              StringRef m_name = getBTModuleName(ci);
              if (m_name != StringRef()) {
                ConstantStruct *cs =
                    findBTModuleStructWithName(m_name, F.getParent());
                if (cs != nullptr) {
                  std::list<Constant *> l;
                  flatenStruct(cs, l);
                  addEdgeFromList(F, cg, l);
                }
              }
            }
          }
        }
        // handle returned structure with function pointers
        // handle all other function pointers
        for (auto operand : I.operand_values()) {
          if (operand != nullptr) {
            // function pointer as an argument like callbacks
            if (auto *f = dyn_cast<Function>(operand)) {
              cg[&F]->addCalledFunction(nullptr, cg.getOrInsertFunction(f));
            }
            if (auto *gv =
                    dyn_cast<GlobalVariable>(operand->stripPointerCasts())) {
              if (gv->hasInitializer()) {
                if (auto *ca =
                        dyn_cast<ConstantAggregate>(gv->getInitializer())) {
                  std::list<Constant *> l;
                  if (ca->hasName()) {
                    errs() << ca->getName() << "\n";
                  }
                  flatenStruct(ca, l);
                  addEdgeFromList(F, cg, l);
                }
              }
            }
            // handle ptrtoint
            if (auto *opt = dyn_cast<Operator>(operand)) {
              for (auto opd : opt->operand_values()) {
                if (auto *ff = dyn_cast<Function>(opd)) {
                  cg[&F]->addCalledFunction(nullptr,
                                            cg.getOrInsertFunction(ff));
                }
              }
            }
            // handle constant aggregate but not global variable
            if (auto *ca = dyn_cast<ConstantAggregate>(operand)) {
              std::list<Constant *> l;
              flatenStruct(ca, l);
              addEdgeFromList(F, cg, l);
            }
          }
        }
        // handle statemachine function table
        if (auto *ci = dyn_cast<CallInst>(&I)) {
          for (auto operand : ci->operand_values()) {
            if (auto *li = dyn_cast<LoadInst>(operand)) {
              if (auto *i = dyn_cast<Instruction>(li->getPointerOperand())) {
                if (auto *gv = dyn_cast<GlobalVariable>(i->getOperand(0))) {
                  if (gv->hasInitializer()) {
                    if (auto *ca =
                            dyn_cast<ConstantArray>(gv->getInitializer())) {
                      std::list<Constant *> l;
                      flatenStruct(ca, l);
                      addEdgeFromList(F, cg, l);
                    }
                  }
                }
              }
            }
          }
        }
        // handle vtable
        if (auto *si = dyn_cast<StoreInst>(&I)) {
          for (auto operand : si->operand_values()) {
            if (auto *op = dyn_cast<Operator>(operand)) {
              if (auto *p = dyn_cast<Operator>(op->getOperand(0))) {
                if (auto *gv = dyn_cast<GlobalVariable>(p->getOperand(0))) {
                  if (gv->hasInitializer()) {
                    if (auto *a =
                            dyn_cast<ConstantAggregate>(gv->getInitializer())) {
                      std::list<Constant *> l;
                      flatenStruct(a, l);
                      addEdgeFromList(F, cg, l);
                    }
                  }
                }
              }
            }
            if (auto *ca = dyn_cast<ConstantAggregate>(operand)) {
              std::list<Constant *> clist;
              flatenStruct(ca, clist);
              for (auto c : clist) {
                if (auto o = dyn_cast<Operator>(c)) {
                  if (auto gv = dyn_cast<GlobalVariable>(o->getOperand(0))) {
                    if (gv->hasInitializer()) {
                      if (auto *a = dyn_cast<ConstantAggregate>(
                              gv->getInitializer())) {
                        std::list<Constant *> l;
                        flatenStruct(a, l);
                        addEdgeFromList(F, cg, l);
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  void getRelevantFunctions(CallGraph &cg, std::list<Function *> &flist,
                            std::list<Function *> &visited) {
    while (!flist.empty()) {
      Function *f = flist.front();
      flist.pop_front();
      visited.push_back(f);
      for (auto CFN : *(cg[f])) {
        Function *callee = CFN.second->getFunction();
        if (callee != nullptr && notInList(flist, callee) &&
            notInList(visited, callee)) {
          flist.push_back(callee);
        }
      }
    }
  }

  void getInitFunc(Module &M, std::map<StringRef, Function *> &fmap) {
    // get init_func in c code (bluedroid)
    switch (c_code) {
    case BLUE:
      fmap.insert(std::pair<StringRef, Function *>(
          btu_init_name, M.getFunction(btu_init_name)));
      fmap.insert(std::pair<StringRef, Function *>(
          bte_init_name, M.getFunction(bte_init_name)));
      fmap.insert(std::pair<StringRef, Function *>(
          get_profile_name, M.getFunction(get_profile_name)));
      break;
    // get init_func in c++ code (fluoride)
    case FLUO:
      fmap.insert(std::pair<StringRef, Function *>(
          btu_init_name, name_function_map[btu_init_name]));
      fmap.insert(std::pair<StringRef, Function *>(
          bte_init_name, name_function_map[bte_init_name]));
      fmap.insert(std::pair<StringRef, Function *>(
          get_profile_name, name_function_map[get_profile_name]));
      break;
    case BLUEZ:
    case KERNEL:
    case KITCHEN:
      break;
    }
  }

  void replaceInterfaceFunctions(Function *F) {
    for (auto &BB : *F) {
      for (auto &II : BB) {
        if (auto *ret = dyn_cast<ReturnInst>(&II)) {
          if (auto *gv = dyn_cast<GlobalVariable>(ret->getReturnValue())) {
            if (gv->hasInitializer()) {
              if (auto *ca =
                      dyn_cast<ConstantAggregate>(gv->getInitializer())) {
                std::list<Constant *> l;
                flatenStruct(ca, l);
                for (auto c : l) {
                  if (auto ff = dyn_cast<Function>(c)) {
                    interface_funcs.push_back(ff);
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  void removeInit(Module &M) {
    // remove unneeded registeration from init
    // c version (bluedroid)
    std::map<StringRef, Function *> init_func_map;
    getInitFunc(M, init_func_map);

    Function *evt;
    if (c_code == BLUE) {
      evt = M.getFunction("btif_in_execute_service_request");
    } else if (c_code == FLUO) {
      evt = name_function_map["btif_in_execute_service_request"];
    }
    for (Function *n : evt_rm_list) {
      removeCallInst(evt, n);
    }

    Function *get_prof_int = init_func_map[get_profile_name];
    switch (c_code) {
    case BLUE:
      for (Function *n : profile_int_rm_list) {
        removeCallInst(get_prof_int, n);
      }
      break;
    case FLUO:
      // replace avrcp interface functions to avoid app crash because
      // of the lacking of null pointer check
      if (profile_code != A2DP) {
        emptyAvrcpInterface(M);
      }

      if (profile_code != HFP) {
        emptyHandsfreeInterface(M);
      }

      for (Function *n : profile_int_rm_list) {
        removeCallInst(get_prof_int, n);
        replaceInterfaceFunctions(n);
      }
      break;
    case BLUEZ:
    case KERNEL:
    case KITCHEN:
      break;
    }
  }

  void removeCallInstFromInterfaceFunc() {
    // remove interface functions from all callers
    for (Function *n : profile_int_rm_list) {
      for (BasicBlock &BB : *n) {
        for (Instruction &II : BB) {
          if (auto reti = dyn_cast<ReturnInst>(&II)) {
            if (auto gv = dyn_cast<GlobalVariable>(
                    reti->getReturnValue()->stripPointerCasts())) {
              if (gv->hasInitializer()) {
                if (auto ca =
                        dyn_cast<ConstantAggregate>(gv->getInitializer())) {
                  std::list<Constant *> l;
                  flatenStruct(ca, l);
                  for (auto c : l) {
                    if (Function *f = dyn_cast<Function>(c)) {
                      // errs() << f->getName() << "\n";
                      for (auto U : f->users()) {
                        if (auto i = dyn_cast<Instruction>(U)) {
                          // i->print(errs());
                          removeCallInst(i->getParent()->getParent(), f);
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  void getDependenceFuncsBluedroid(Module &M, CallGraph &cg) {
    Function *entry = M.getFunction("open_bluetooth_stack");
    Function *entry2 = M.getFunction("close_bluetooth_stack");
    to_keep_worklist.push_back(entry);
    getRelevantFunctions(cg, to_keep_worklist, func_to_keep);
    to_keep_worklist.push_back(entry2);
    getRelevantFunctions(cg, to_keep_worklist, func_to_keep);
  }

  void getDependenceFuncsFluoride(Module &M, CallGraph &cg) {
    GlobalVariable *gv = M.getGlobalVariable("llvm.global_ctors");
    auto *ca = dyn_cast<ConstantArray>(gv->getInitializer());
    for (auto &cc : ca->operands()) {
      if (auto *cs = dyn_cast<ConstantStruct>(cc)) {
        if (auto *f = dyn_cast<Function>(cs->getOperand(1))) {
          to_keep_worklist.push_back(f);
          getRelevantFunctions(cg, to_keep_worklist, func_to_keep);
        }
      }
    }

    auto entry_struct = M.getGlobalVariable("bluetoothInterface");
    if (entry_struct != NULL) {
      if (entry_struct->hasInitializer()) {
        if (auto *cs =
                dyn_cast<ConstantStruct>(entry_struct->getInitializer())) {
          std::list<Constant *> l;
          flatenStruct(cs, l);
          for (Value *v : l) {
            if (auto *f = dyn_cast<Function>(v)) {
              to_keep_worklist.push_back(f);
              getRelevantFunctions(cg, to_keep_worklist, func_to_keep);
            }
          }
        }
      }
    }

    // device needed
    Function *parser = M.getFunction("_Z31hci_packet_parser_get_interfacev");
    to_keep_worklist.push_back(parser);
    getRelevantFunctions(cg, to_keep_worklist, func_to_keep);
  }

  void getKernelInterface(Module &M, std::list<Function *> &flist) {
    Function *f = M.getFunction("l2cap_init_sockets");
    flist.push_back(f);
    f = M.getFunction("l2cap_cleanup_sockets");
    flist.push_back(f);
  }

  void getDependenceFuncsBluez(Module &M, CallGraph &cg) {
    std::list<Function *> flist;
    flist.push_back(M.getFunction("main"));
    for (Function *f : flist) {
      to_keep_worklist.push_back(f);
      getRelevantFunctions(cg, to_keep_worklist, func_to_keep);
    }
  }

  void getDependenceFuncsKernel(Module &M, CallGraph &cg) {
    std::list<Function *> flist;
    flist.push_back(M.getFunction("init_module"));
    flist.push_back(M.getFunction("cleanup_module"));
    // exported symbals
    flist.push_back(M.getFunction("__hci_cmd_sync"));
    flist.push_back(M.getFunction("l2cap_chan_set_defaults"));
    flist.push_back(M.getFunction("hci_cmd_sync"));
    flist.push_back(M.getFunction("__hci_cmd_sync_ev"));
    flist.push_back(M.getFunction("bt_info"));
    flist.push_back(M.getFunction("hci_register_dev"));
    flist.push_back(M.getFunction("l2cap_register_user"));
    flist.push_back(M.getFunction("bt_procfs_init"));
    flist.push_back(M.getFunction("hci_free_dev"));
    flist.push_back(M.getFunction("bt_accept_dequeue"));
    flist.push_back(M.getFunction("l2cap_unregister_user"));
    flist.push_back(M.getFunction("l2cap_chan_del"));
    flist.push_back(M.getFunction("bt_err"));
    flist.push_back(M.getFunction("bt_to_errno"));
    flist.push_back(M.getFunction("baswap"));
    flist.push_back(M.getFunction("hci_reset_dev"));
    flist.push_back(M.getFunction("l2cap_conn_get"));
    flist.push_back(M.getFunction("l2cap_chan_close"));
    flist.push_back(M.getFunction("bt_sock_unregister"));
    flist.push_back(M.getFunction("hci_register_cb"));
    flist.push_back(M.getFunction("bt_err_ratelimited"));
    flist.push_back(M.getFunction("hci_suspend_dev"));
    flist.push_back(M.getFunction("hci_set_fw_info"));
    flist.push_back(M.getFunction("hci_set_hw_info"));
    flist.push_back(M.getFunction("bt_sock_unlink"));
    flist.push_back(M.getFunction("hci_conn_security"));
    flist.push_back(M.getFunction("bt_debugfs"));
    flist.push_back(M.getFunction("bt_accept_unlink"));
    flist.push_back(M.getFunction("l2cap_add_psm"));
    flist.push_back(M.getFunction("bt_sock_reclassify_lock"));
    flist.push_back(M.getFunction("bt_sock_poll"));
    flist.push_back(M.getFunction("__hci_cmd_send"));
    flist.push_back(M.getFunction("hidp_hid_driver"));
    flist.push_back(M.getFunction("hci_conn_switch_role"));
    flist.push_back(M.getFunction("bt_sock_wait_ready"));
    flist.push_back(M.getFunction("bt_sock_wait_state"));
    flist.push_back(M.getFunction("bt_sock_stream_recvmsg"));
    flist.push_back(M.getFunction("bt_sock_recvmsg"));
    flist.push_back(M.getFunction("hci_mgmt_chan_register"));
    flist.push_back(M.getFunction("l2cap_chan_connect"));
    flist.push_back(M.getFunction("l2cap_chan_create"));
    flist.push_back(M.getFunction("hci_conn_check_secure"));
    flist.push_back(M.getFunction("l2cap_is_socket"));
    flist.push_back(M.getFunction("hci_recv_frame"));
    flist.push_back(M.getFunction("l2cap_conn_put"));
    flist.push_back(M.getFunction("l2cap_chan_put"));
    flist.push_back(M.getFunction("hci_get_route"));
    flist.push_back(M.getFunction("bt_sock_register"));
    flist.push_back(M.getFunction("bt_procfs_cleanup"));
    flist.push_back(M.getFunction("hci_unregister_cb"));
    flist.push_back(M.getFunction("bt_sock_ioctl"));
    flist.push_back(M.getFunction("l2cap_chan_send"));
    flist.push_back(M.getFunction("hci_resume_dev"));
    flist.push_back(M.getFunction("hci_mgmt_chan_unregister"));
    flist.push_back(M.getFunction("hci_recv_diag"));
    flist.push_back(M.getFunction("bt_warn"));
    flist.push_back(M.getFunction("hci_unregister_dev"));
    flist.push_back(M.getFunction("hci_alloc_dev"));
    flist.push_back(M.getFunction("bt_accept_enqueue"));
    flist.push_back(M.getFunction("bt_sock_link"));

    for (Function *f : flist) {
      to_keep_worklist.push_back(f);
      getRelevantFunctions(cg, to_keep_worklist, func_to_keep);
    }
  }

  void getDependenceFuncsKitchen(Module &M, CallGraph &cg) {
    std::list<Function *> flist;
    getKitchenProfileInterface(M, profile_code, flist);
    for (Function *f : flist) {
      to_keep_worklist.push_back(f);
      getRelevantFunctions(cg, to_keep_worklist, func_to_keep);
    }
    Function *main = M.getFunction("main");
    to_keep_worklist.push_back(main);
    getRelevantFunctions(cg, to_keep_worklist, func_to_keep);
  }

  void removeGlobalVariableAlias(Module &M, std::list<Function *> flist) {
    std::list<GlobalAlias *> galist;
    for (GlobalAlias &ga : M.getAliasList()) {
      if (auto *f = dyn_cast<Function>(ga.getAliasee())) {
        if (!notInList(flist, f)) {
          galist.push_back(&ga);
          errs() << "Remove alias: " << ga.getName() << "\n";
        }
      }
    }
    for (auto ga : galist) {
      ga->eraseFromParent();
    }
  }

  void replaceFunctionBodyWithReturn(Function *F) {
    F->deleteBody();
    BasicBlock *b = BasicBlock::Create(F->getContext());
    F->getBasicBlockList().push_front(b);
    IRBuilder<> builder(b);
    Type *ret_type = F->getReturnType();
    if (Type::getVoidTy(F->getContext()) == ret_type) {
      builder.CreateRetVoid();
    } else {
      Value *v = UndefValue::get(ret_type);
      builder.CreateRet(v);
    }
  }

  Function *getAppHciInterface(Module &M) {
    switch (c_code) {
    case BLUE:
      return M.getFunction("btu_hcif_send_cmd");
      break;
    case FLUO:
      return M.getFunction("_Z17btu_hcif_send_cmdhP6BT_HDR");
      break;
    case BLUEZ:
      break;
    case KERNEL:
      return M.getFunction("hci_prepare_cmd");
      break;
    case KITCHEN:
      return M.getFunction("hci_send_cmd");
      break;
    default:
      errs() << "Invalid c_code type. exit.\n";
      exit(0);
    }
    return nullptr;
  }

  Function *getDeviceHciInterface(Module &M) {
    switch (c_code) {
    case BLUE:
      return M.getFunction("make_command");
      break;
    case FLUO:
      return M.getFunction("_ZL12make_commandtmPPh");
      break;
    case BLUEZ:
    case KERNEL:
      break;
    default:
      errs() << "Invalid c_code type. exit.\n";
      exit(0);
    }
    return nullptr;
  }

  int getAppHciOpCode(Function *interface, Function *caller, int param) {
    int OCF = 0;
    int OGF = 0;
    CallInst *ci = nullptr;
    // find call instruction
    for (auto &BB : *caller) {
      for (auto &II : BB) {
        if (auto callinst = dyn_cast<CallInst>(&II)) {
          if (callinst->getCalledFunction() == interface) {
            ci = callinst;
            break;
          }
        }
      }
    }
    // get OGF and OCF from buffer position 9 and 8
    if (auto c = dyn_cast<Instruction>(ci->getOperand(param))) {
      for (auto UU : c->getOperand(0)->users()) {
        if (auto OP = dyn_cast<GetElementPtrInst>(UU)) {
          if (auto V = dyn_cast<ConstantInt>(OP->getOperand(1))) {
            int value = V->getZExtValue();
            if (value == 8) {
              for (auto S : OP->users()) {
                if (auto st = dyn_cast<StoreInst>(S)) {
                  if (auto c = dyn_cast<ConstantInt>(st->getOperand(0))) {
                    OCF = c->getZExtValue();
                  }
                  if (auto sel = dyn_cast<SelectInst>(st->getOperand(0))) {
                    if (auto c = dyn_cast<ConstantInt>(sel->getTrueValue())) {
                      OCF = c->getZExtValue();
                    }
                    if (auto c = dyn_cast<ConstantInt>(sel->getFalseValue())) {
                      OCF = c->getZExtValue();
                    }
                  }
                }
              }
            }
            if (value == 9) {
              for (auto S : OP->users()) {
                if (auto st = dyn_cast<StoreInst>(S)) {
                  if (auto c = dyn_cast<ConstantInt>(st->getOperand(0))) {
                    OGF = c->getZExtValue();
                  }
                  if (auto sel = dyn_cast<SelectInst>(st->getOperand(0))) {
                    if (auto c = dyn_cast<ConstantInt>(sel->getTrueValue())) {
                      OGF = c->getZExtValue();
                    }
                    if (auto c = dyn_cast<ConstantInt>(sel->getFalseValue())) {
                      OGF = c->getZExtValue();
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    // buffer is an argument of a outer function which calls btu_hcif_send_cmd
    if (auto a = dyn_cast<Argument>(ci->getOperand(param))) {
      for (auto U : a->getParent()->users()) {
        if (auto I = dyn_cast<Instruction>(U)) {
          return getAppHciOpCode(a->getParent(), I->getParent()->getParent(),
                                 0);
        }
      }
    }
    return (OGF << 8) | OCF;
  }

  // application layer hci cmds
  void getHciAppCmdsInModule(Function *F, std::set<int> &cmd_list) {
    for (auto U : F->users()) {
      if (auto I = dyn_cast<CallInst>(U)) {
        int opcode = getAppHciOpCode(F, I->getCaller(), 1);
        if (opcode != 0) {
          cmd_list.insert(opcode);
        }
      }
    }
  }

  // device level hci cmds
  void getHciDeviceCmdsInModule(Function *F, std::set<int> &cmd_list) {
    for (auto U : F->users()) {
      if (auto I = dyn_cast<CallInst>(U)) {
        if (auto C = dyn_cast<ConstantInt>(I->getOperand(0))) {
          cmd_list.insert(C->getZExtValue());
        }
      }
    }
  }

  // get hci cmds in kernel
  void getHciCmdsInKernel(Function *F, std::set<int> &cmd_list) {
    std::list<Function *> worklist;
    std::list<int> argNumList;

    worklist.push_back(F);
    argNumList.push_back(1);

    while (!worklist.empty()) {
      Function *f = worklist.front();
      worklist.pop_front();
      int arg = argNumList.front();
      argNumList.pop_front();

      for (auto U : f->users()) {
        if (auto I = dyn_cast<CallInst>(U)) {
          if (auto a = dyn_cast<Argument>(I->getArgOperand(arg))) {
            worklist.push_back(I->getParent()->getParent());
            argNumList.push_back(a->getArgNo());
          } else if (auto C = dyn_cast<ConstantInt>(I->getOperand(arg))) {
            cmd_list.insert(C->getZExtValue());
          }
        }
      }
    }
  }

  void extractHCICmdFromFunction(Function *F, std::set<int> &cmd_list) {
    for (auto &B : *F) {
      for (auto &I : B) {
        if (auto li = dyn_cast<LoadInst>(&I)) {
          if (auto gi = dyn_cast<GEPOperator>(li->getOperand(0))) {
            if (auto gv = dyn_cast<GlobalVariable>(gi->getOperand(0))) {
              if (gv->hasInitializer()) {
                if (auto ca =
                        dyn_cast<ConstantAggregate>(gv->getInitializer())) {
                  if (auto ci = dyn_cast<ConstantInt>(
                          ca->getAggregateElement(int(0)))) {
                    cmd_list.insert(ci->getSExtValue());
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  void getHCICmdsInBluekitchen(Function *F, std::set<int> &cmd_list) {
    for (auto u : F->users()) {
      if (auto ci = dyn_cast<CallInst>(u)) {
        if (auto gv = dyn_cast<GlobalVariable>(ci->getArgOperand(0))) {
          if (gv->hasInitializer()) {
            if (auto ca = dyn_cast<ConstantAggregate>(gv->getInitializer())) {
              auto opcode =
                  dyn_cast<ConstantInt>(ca->getAggregateElement(int(0)));
              cmd_list.insert(opcode->getSExtValue());
            }
          }
        }
      }
    }
  }

  void getUserSet(Value *v, std::set<Value *> &u_set) {
    std::list<Value *> work_list;
    work_list.push_back(v);
    u_set.insert(v);
    while (!work_list.empty()) {
      Value *va = work_list.front();
      work_list.pop_front();
      for (auto us : va->users()) {
        if (u_set.find(us) == u_set.end()) {
          work_list.push_back(us);
          u_set.insert(us);
        }
      }
    }
  }

  bool dataAffectCtrlFlow(Function *F) {
    std::list<Value *> cond_list;
    for (BasicBlock &B : *F) {
      for (Instruction &I : B) {
        if (auto swi = dyn_cast<SwitchInst>(&I)) {
          cond_list.push_back(swi->getCondition());
        }
      }
    }

    std::set<Value *> u_set;
    for (auto &arg : F->args()) {
      getUserSet(&arg, u_set);
    }

    for (auto v1 : u_set) {
      for (auto v2 : cond_list) {
        if (v1 == v2) {
          return true;
        }
      }
    }
    return false;
  }

  bool argIsCondition(Function *F, Argument *A) {
    std::list<Value *> cond_list;
    for (BasicBlock &B : *F) {
      for (Instruction &I : B) {
        if (auto swi = dyn_cast<SwitchInst>(&I)) {
          cond_list.push_back(swi->getCondition());
        }
      }
    }

    for (auto v : cond_list) {
      Value *val = traceBackConstant(v);
      if (val != nullptr) {
        if (auto a = dyn_cast<Argument>(val)) {
          if (a == A) {
            return true;
          }
        }
      }
    }
    return false;
  }

  bool initCallConstant(CallInst *ci) {
    for (auto &arg : ci->arg_operands()) {
      if (!isa<ConstantInt>(arg)) {
        return false;
      }
    }
    return true;
  }

  // not for callback register, therefore the order of arguments are the same
  void copyConstArgs(iterator_range<User::op_iterator> args, Function *callee) {
    for (auto &a : args) {
      auto arg_it = callee->arg_begin();

      if (auto ar = dyn_cast<Argument>(&a)) {
        if (!func_args_map[ar]->empty()) {
          for (int i : *(func_args_map[ar])) {
            func_args_map[arg_it + a.getOperandNo()]->insert(i);
          }
        }
      }

      if (auto consti = dyn_cast<ConstantInt>(&a)) {
        func_args_map[arg_it + a.getOperandNo()]->insert(
            consti->getSExtValue());
      }

      if (auto i = dyn_cast<LoadInst>(&a)) {
        Value *v = traceBackConstant(i);
        if (v != nullptr) {
          if (auto ar = dyn_cast<Argument>(v)) {
            for (auto i : *(func_args_map[ar])) {
              func_args_map[arg_it + a.getOperandNo()]->insert(i);
            }
          }
          if (auto c = dyn_cast<ConstantInt>(i)) {
            func_args_map[arg_it + a.getOperandNo()]->insert(c->getSExtValue());
          }
        }
      }
    }
  }

  Value *traceBackConstant(Value *I) {
    if (auto ai = dyn_cast<AllocaInst>(I)) {
      for (auto U : ai->users()) {
        if (auto si = dyn_cast<StoreInst>(U)) {
          return traceBackConstant(si->getOperand(0));
        }
      }
    }

    if (auto si = dyn_cast<StoreInst>(I)) {
      return traceBackConstant(si->getOperand(0)->stripPointerCasts());
    }

    if (auto li = dyn_cast<LoadInst>(I)) {
      return traceBackConstant(li->getOperand(0)->stripPointerCasts());
    }

    if (auto arg = dyn_cast<Argument>(I)) {
      return arg;
    }

    if (auto ci = dyn_cast<ConstantInt>(I)) {
      return ci;
    }

    if (auto zt = dyn_cast<ZExtInst>(I)) {
      return traceBackConstant(zt->getOperand(0));
    }
    return nullptr;
  }

  // copy args for callback register callinst
  void copyConstForCallbacks(iterator_range<User::op_iterator> args,
                             Function *callee, std::list<int> &arg_order) {
    int callee_arg_index = 0;
    for (auto i : arg_order) {
      auto arg_it = callee->arg_begin();
      if (auto ci = dyn_cast<ConstantInt>(args.begin() + i)) {
        func_args_map[arg_it + callee_arg_index]->insert(ci->getSExtValue());
      }

      if (auto ar = dyn_cast<Argument>(args.begin() + i)) {
        for (int j : *(func_args_map[ar])) {
          func_args_map[arg_it + callee_arg_index]->insert(j);
        }
      }

      if (auto ai = dyn_cast<Instruction>(args.begin() + i)) {
        Value *v = traceBackConstant(ai);
        if (v != nullptr) {
          if (auto ar = dyn_cast<Argument>(v)) {
            for (int j : *(func_args_map[ar])) {
              func_args_map[arg_it + callee_arg_index]->insert(j);
            }
          }
          if (auto ci = dyn_cast<ConstantInt>(v)) {
            func_args_map[arg_it + callee_arg_index]->insert(
                ci->getSExtValue());
          }
        }
      }
      callee_arg_index++;
    }
  }

  bool funcPtrInCall(CallInst *ci) {
    if (ci->getCalledFunction() != nullptr &&
        isa<Function>(ci->getOperand(0)) &&
        ci->getOperand(0) != ci->getCalledFunction()) {
      return true;
    }
    return false;
  }

  bool isArgPassedToOtherFunc(Function *F) {
    for (auto &B : *F) {
      for (auto &I : B) {
        if (auto ci = dyn_cast<CallInst>(&I)) {
          if (ci->getNumArgOperands() != 0 &&
              ci->getCalledFunction() != nullptr) {
            Function *callee = ci->getCalledFunction();
            for (auto &BB : *callee) {
              for (auto &II : BB) {
                if (auto cali = dyn_cast<CallInst>(&II)) {
                  for (auto &a : cali->arg_operands()) {
                    if (isa<Argument>(&a)) {
                      return true;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    return false;
  }

  bool matchParam(Function *caller, Function *callback,
                  std::list<int> &arg_index) {
    bool matched = false;

    if (callback->arg_size() == 0) {
      return false;
    }

    if (callback->arg_size() >= caller->arg_size()) {
      return false;
    }

    for (auto &a : caller->args()) {
      for (auto &b : callback->args()) {
        if (a.getType() == b.getType()) {
          matched = true;
          arg_index.push_back(a.getArgNo());
        }
      }
    }

    return matched;
  }

  void copyCallbackArgs(iterator_range<User::op_iterator> args,
                        Function *caller, Function *callee) {
    std::list<int> arg;
    if (matchParam(caller, callee, arg)) {
      copyConstForCallbacks(args, callee, arg);
    }
  }

  void constPropergate(Function *F, int &depth) {
    if (depth >= 20) {
      return;
    }

    depth++;

    if (F->empty()) {
      return;
    }

    if (function_name_map[F].startswith("std::") ||
        function_name_map[F].startswith("base::") ||
        function_name_map[F].startswith("void std::")) {
      return;
    }

    for (auto &B : *F) {
      for (auto &I : B) {
        if (auto ci = dyn_cast<CallInst>(&I)) {
          Function *f = ci->getCalledFunction();
          if (f != nullptr && !f->empty() && !f->getName().startswith("llvm") &&
              !f->getName().startswith("__") && !f->isVarArg() &&
              // hack to bypass dead loop
              !f->getName().startswith("controller_get_interface")) {
            // no argument
            if (ci->getNumArgOperands() == 0) {
              constPropergate(f, depth);
            }
            // function pointer in argument, register callbacks
            else if (funcPtrInCall(ci)) {
              if (auto callback = dyn_cast<Function>(ci->getOperand(0))) {
                copyCallbackArgs(ci->arg_operands(), f, callback);
                constPropergate(callback, depth);
              }
            }
            // call with arguments, but no function pointers
            else {
              copyConstArgs(ci->arg_operands(), ci->getCalledFunction());
              constPropergate(f, depth);
            }
          }
        }
      }
    }
  }

  void pruneFunctions(Module &M) {
    for (auto &F : M) {
      if (dataAffectCtrlFlow(&F)) {
        for (auto &a : F.args()) {
          if (!func_args_map[&a]->empty() && argIsCondition(&F, &a)) {
            pruneConditions(&F);
          }
        }
      }
    }
  }

  bool callInBlock(BasicBlock *B) {
    for (auto &I : *B) {
      if (auto ci = dyn_cast<CallInst>(&I)) {
        if (ci->getCalledFunction() != nullptr &&
            !ci->getCalledFunction()->getName().startswith("llvm")) {
          return true;
        }
      }
    }
    return false;
  }

  void pruneConditions(Function *F) {
    std::set<BasicBlock *> bl;
    std::list<ConstantInt *> l;
    SwitchInst *s;
    for (auto &B : *F) {
      for (auto &I : B) {
        if (auto si = dyn_cast<SwitchInst>(&I)) {
          Value *cond = si->getCondition();
          if (isa<Instruction>(cond)) {
            cond = traceBackConstant(cond);
          }
          if (auto ar = dyn_cast<Argument>(cond)) {
            s = si;
            for (auto ca : si->cases()) {
              // handle the consective 'case' without break
              if (F->getName().equals("btif_in_execute_service_request") ||
                  F->getName().equals(
                      "_Z31btif_in_execute_service_requesthb")) {
                if (func_args_map[ar]->count(6)) {
                  func_args_map[ar]->insert(5);
                }
              }

              if (!func_args_map[ar]->count(
                      ca.getCaseValue()->getSExtValue())) {
                if (callInBlock(ca.getCaseSuccessor())) {
                  bl.insert(ca.getCaseSuccessor());
                  l.push_back(ca.getCaseValue());
                }
              }
            }
          }
        }
        if (auto phi = dyn_cast<PHINode>(&I)) {
          for (auto b : bl) {
            phi->removeIncomingValue(b);
          }
        }
      }
    }
    for (auto b : bl) {
      b->eraseFromParent();
    }
    for (auto i : l) {
      s->removeCase(s->findCaseValue(i));
    }
  }

  int getInstNum(Module &M) {
    int sz = 0;
    for (auto &F : M) {
      for (auto &B : F) {
        sz += B.size();
      }
    }
    return sz;
  }

  void removeFunc(std::list<Function *> remove_list) {
    for (Function *F : remove_list) {
      F->replaceAllUsesWith(UndefValue::get(F->getType()));
      F->eraseFromParent();
    }
  }

  void mapInit(Module &M) {
    for (auto &gv : M.globals()) {
      global_value_map[&gv] = new std::set<int>();
    }

    for (auto &F : M) {
      for (Argument &A : F.args()) {
        func_args_map[&A] = new std::set<int>();
      }
    }
  }

  void cleanupMap() {
    for (auto g : global_value_map) {
      free(g.second);
    }

    for (auto a : func_args_map) {
      free(a.second);
    }
  }

  void replaceAliases(Module &M) {
    std::list<GlobalAlias *> alias_list;
    for (auto &ga : M.aliases()) {
      alias_list.push_back(&ga);
      ga.replaceAllUsesWith(ga.getAliasee());
    }

    for (auto ga : alias_list) {
      ga->eraseFromParent();
    }
  }

  int countFunc(Module &M) {
    int func_num = 0;
    for (auto &F : M) {
      if (!(F.size() >= 2)) {
        func_num++;
      }
    }
    return func_num;
  }

  void removeUnusedLink(std::set<int> &cmd_set, std::list<int> unneeded_link) {
    std::set<int>::iterator i;
    for (int opcode : unneeded_link) {
      i = cmd_set.find(opcode);
      if (i != cmd_set.end()) {
        cmd_set.erase(i);
      }
    }
  }

  void writeHciToFile(std::set<int> &cmd_set) {
    std::ofstream hcifile;
    hcifile.open("hcicmds.txt");
    for (int i : cmd_set) {
      hcifile << std::hex << i << "\n";
    }
    hcifile.close();
  }

  void saveHCI(std::set<int> &cmd_set) {
    switch (profile_code) {
    case A2DP:
    case PAN:
    case HID:
    case SPP:
    case PBAP:
    case SAP:
    case MAP:
    case HDP:
      removeUnusedLink(cmd_set, sco_link);
      removeUnusedLink(cmd_set, le_link);
      break;
    case HFP:
    case HSP:
      removeUnusedLink(cmd_set, le_link);
      break;
    case GATT:
      removeUnusedLink(cmd_set, sco_link);
      break;
    }
    writeHciToFile(cmd_set);
  }

  void setStack() {

    if (btstack.front() == "bluez") {
      errs() << "bluez stack\n";
      c_code = BLUEZ;
    }

    if (btstack.front() == "bluedroid") {
      errs() << "bluedroid stack\n";
      c_code = BLUE;
    }

    if (btstack.front() == "fluoride") {
      errs() << "fluoride stack\n";
      c_code = FLUO;
    }

    if (btstack.front() == "bluekitchen") {
      errs() << "bluekitchen stack\n";
      c_code = KITCHEN;
    }

    if (btstack.front() == "kernel") {
      errs() << "kernel analysis\n";
      c_code = KERNEL;
    }
  }

  void setProfile() {
    if (profile.front() == "a2dp") {
      errs() << "a2dp profile to keep\n";
      profile_code = A2DP;
    }

    if (profile.front() == "hsp") {
      errs() << "headset profile to keep\n";
      profile_code = HSP;
    }

    if (profile.front() == "hfp") {
      errs() << "handsfree profile to keep\n";
      profile_code = HFP;
    }

    if (profile.front() == "gatt") {
      errs() << "gatt profile to keep\n";
      profile_code = GATT;
    }

    if (profile.front() == "pan") {
      errs() << "pan profile to keep\n";
      profile_code = PAN;
    }

    if (profile.front() == "hid") {
      errs() << "hid profile to keep\n";
      profile_code = HID;
    }

    if (profile.front() == "sap") {
      errs() << "sap profile to keep\n";
      profile_code = SAP;
    }

    if (profile.front() == "spp") {
      errs() << "spp profile to keep\n";
      profile_code = SPP;
    }

    if (profile.front() == "pbap") {
      errs() << "pbap profile to keep\n";
      profile_code = PBAP;
    }

    if (profile.front() == "hdp") {
      errs() << "hdp profile to keep\n";
      profile_code = HDP;
    }

    if (profile.front() == "map") {
      errs() << "map profile to keep\n";
      profile_code = MAP;
    }
  }

  bool runOnModule(Module &M) override {

    if (btstack.size() != 1 || profile.size() != 1) {
      errs() << "Only 1 stack and 1 profile is allowed\n";
      return false;
    }

    setStack();

    setProfile();

    mapInit(M);

    if (c_code == FLUO) {
      replaceAliases(M);
      createNameFunctionMap(M);
    }

    initRmList(M);

    errs() << "Run pass on: ";
    errs() << M.getName() << "\n";

    removeInit(M);

    CallGraph *cg;

    errs() << "CFG construction done\n";

    std::list<GlobalAlias *> alist;

    switch (c_code) {
    case BLUE:
      pruneFunctions(M);
      cg = new CallGraph(M);
      constructCallGraph(*cg, M);
      getDependenceFuncsBluedroid(M, *cg);
      break;
    case FLUO:
      pruneFunctions(M);
      cg = new CallGraph(M);
      constructCallGraph(*cg, M);
      getDependenceFuncsFluoride(M, *cg);
      break;
    case BLUEZ:
      cg = new CallGraph(M);
      constructCallGraph(*cg, M);
      getDependenceFuncsBluez(M, *cg);
      break;
    case KERNEL:
      cg = new CallGraph(M);
      constructCallGraph(*cg, M);
      getDependenceFuncsKernel(M, *cg);
      break;
    case KITCHEN:
      cg = new CallGraph(M);
      constructCallGraph(*cg, M);
      getDependenceFuncsKitchen(M, *cg);
      break;
    default:
      errs() << "Invalid c_code type. exit.\n";
      return false;
    }

    std::set<int> clist;

    if (c_code == BLUE || c_code == FLUO) {

      for (Function &F : M) {
        if (!F.empty() && notInList(func_to_keep, &F) &&
            notInList(interface_funcs, &F)) {
          to_remove_worklist.push_back(&F);
        }
      }

      errs() << "Remove func num: " << to_remove_worklist.size() << "\n";

      removeFunc(to_remove_worklist);

      getHciAppCmdsInModule(getAppHciInterface(M), clist);
      getHciDeviceCmdsInModule(getDeviceHciInterface(M), clist);
    }

    if (c_code == BLUEZ) {
      for (Function &F : M) {
        if (!F.empty() && notInList(func_to_keep, &F)) {
          func_to_remove.push_back(&F);
        }
      }

      removeFunc(func_to_remove);
    }

    if (c_code == KERNEL) {
      getHciCmdsInKernel(getAppHciInterface(M), clist);

      for (Function &F : M) {
        if (!F.empty() && notInList(func_to_keep, &F)) {
          func_to_remove.push_back(&F);
        }
      }
    }

    if (c_code == KITCHEN) {

      for (Function &F : M) {
        if (!F.empty() && notInList(func_to_keep, &F)) {
          func_to_remove.push_back(&F);
        }
      }

      removeFunc(func_to_remove);
      getHCICmdsInBluekitchen(getAppHciInterface(M), clist);
      Function *f = M.getFunction("hci_send_cmd_packet");
      if (f != nullptr) {
        extractHCICmdFromFunction(f, clist);
      }
    }

    saveHCI(clist);

    errs() << "Write needed HCI cmds to 'hcicmds.txt'\n";

    errs() << "Num of functions in total: " << M.size() << "\n";

    errs() << "Keep functions: " << countFunc(M) << "\n";

    errs() << "Instructions: " << getInstNum(M) << "\n";

    errs() << "Done\n";

    errs() << "-------------------------------------------------------------\n";

    cleanupMap();
    delete (cg);
    return true;
  }
};
} // namespace

char BTanalysis::ID = 0;
static RegisterPass<BTanalysis> X("btanalysis", "Android BT analysis Pass");
