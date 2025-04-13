/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 University of Pennsylvania
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef PENN_CHORD_H
#define PENN_CHORD_H

#include "ns3/penn-application.h"
#include "penn-chord-message.h"
#include "ns3/ping-request.h"
#include <openssl/sha.h>

#include "ns3/penn-key-helper.h"
#include "ns3/ipv4-address.h"
#include <map>
#include <set>
#include <vector>
#include <string>
#include "ns3/socket.h"
#include "ns3/nstime.h"
#include "ns3/timer.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"

//-------------new----------------
#include <sstream>
#define DEBUG 1
//--------------------------------
using namespace ns3;
// class chord_use
// {
// public:
 
// // default function to initialize the class

// chord_use()
//   {
//     this->id = 0;
//     this->ipAddr = Ipv4Address::GetAny();
//     this->hash_key = 0;
//     this->successor = "0.0.0.0";
//     this->predecessor = "0.0.0.0";
//   }

//   chord_use(uint32_t id, Ipv4Address ipAddr)
//   {
//     this->id = id;
//     this->ipAddr = ipAddr;
//     this->hash_key = PennKeyHelper::CreateShaKey(ipAddr);
//     this->successor = "0.0.0.0";
//     this->predecessor = "0.0.0.0";
//   }

//   ~chord_use()
//   {
//     // Destructor
//   }
  
//   // chord_use(uint32_t id, Ipv4Address ipAddr, uint32_t successor, uint32_t predecessor)
//   // {
//   //   this->id = id;
//   //   this->ipAddr = ipAddr;
//   //   this->hash_key = PennKeyHelper::CreateShaKey(ipAddr);
//   //   this->successor = successor;
//   //   this->predecessor = predecessor;
//   // }
//   // set and get function provid to access the private variable
//   uint32_t getId() const { return id; }
//   void setId(uint32_t id) { this->id = id; }
//   Ipv4Address getIpAddr() const { return ipAddr; }
//   void setIpAddr(Ipv4Address ipAddr) { this->ipAddr = ipAddr; }
//   std::uint32_t getHashKey() const { return hash_key; }
//   void setHashKey(std::uint32_t hash_key) { this->hash_key = hash_key; }
//   void setHashKey(Ipv4Address ipAddr) { this->hash_key = PennKeyHelper::CreateShaKey(ipAddr); }
//   Ipv4Address getSuccessor() const { return successor; }
//   void setSuccessor(Ipv4Address successor) { this->successor = successor; }
//   Ipv4Address getPredecessor() const { return predecessor; }
//   void setPredecessor(Ipv4Address predecessor) { this->predecessor = predecessor; }
  
//   //------------tool function----------------

// public:
//   // successor and predecessor use id
//   uint32_t id;
//   Ipv4Address ipAddr;
//   uint32_t hash_key;
//   // uint32_t successor;
//   // uint32_t predecessor;
//   Ipv4Address successor;
//   Ipv4Address predecessor;
// };

class PennChord : public PennApplication
{
public:
  static TypeId GetTypeId(void);
  PennChord();
  virtual ~PennChord();

  // Basic operations
  void SendPing(Ipv4Address destAddress, std::string pingMessage);
  void RecvMessage(Ptr<Socket> socket);
  void AuditPings();
  uint32_t GetNextTransactionId();
  void StopChord();
  Ipv4Address GetIpFromId(uint32_t id);
  int GetIdFromIp(Ipv4Address ipAddr);

  void transmitRequest(PennChordMessage chordMsg, Ipv4Address targetAddr);

  // Callbacks
  void SetPingSuccessCallback(Callback<void, Ipv4Address, std::string> pingSuccessFn);
  void SetPingFailureCallback(Callback<void, Ipv4Address, std::string> pingFailureFn);
  void SetPingRecvCallback(Callback<void, Ipv4Address, std::string> pingRecvFn);

  // Process handlers
  void ProcessPingReq(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
  void ProcessPingRsp(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
  void ProcessLookUp(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
  void ProcessFingerTableLookUp(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
  Ipv4Address GetFinerTableTargetId(uint32_t use_key);

  // void ProcessUpdateNeighbors(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
  void ProcessRingState(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
  void ProcessPeenSearchResponse(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
  void ProcessSearch(uint32_t send_id, std::vector<std::string> findterms);
  // PennSearch message handlers
  void ProcessPennSearch(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
  void HandlePublish(PennChordMessage message);
  void HandleSearch(PennChordMessage message);

  // Request handlers
  virtual void ProcessCommand(std::vector<std::string> tokens);
  void  processInvertedRsp(Ipv4Address resultNode,std::string key);
  //---------------------------very important------------------------------------
  virtual void SetNodeAddressMap (std::map<uint32_t, Ipv4Address> nodeAddressMap);
  virtual void SetAddressNodeMap (std::map<Ipv4Address, uint32_t> addressNodeMap);
  //------------------------------------------------------------------------------

  void HandleJoinRequest(uint32_t node_id, Ipv4Address target_addr, Ipv4Address though_addr);
  void ProcessFind(PennChordMessage message);

  // void HandleLeaveRequest();
  // void HandleRingStateRequest();
  uint32_t Landmark;
  void ProcessUpdateIdIpMap(PennChordMessage message, Ipv4Address sourceAddress);
  void SyncNodeMap(bool isAdd, Ipv4Address targetAddr);
  // ChordNode* GetSuccessorNode();  // 获取后继节点信息
  // void LookOther(Ipv4Address resultNode,Ipv4Address orinNode,uint32_t key,std::string lookupMessage);
  uint32_t GetAbsDiffHash(Ipv4Address addr1, Ipv4Address addr2); 
  bool CheckIsInCircle(Ipv4Address MyNode,Ipv4Address preNode, Ipv4Address succNode);
  void outcontrol();
  void  ProcessCommandSelfUse(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
  void ProcessPublish(std::string terms, std::vector<std::string> filenames);
  void Notify(Ipv4Address node);
  void stabilize(Ipv4Address node);
  void fix_fingers();
  void stabilize_use();
  // 用于存储平均跳数  只在搜索层  不在chord层
  uint32_t lookupCount = 0; // 表示发起的查找请求总数，在Lookup函数中被更新，每次发起新的查找请求时增加计数:
  uint32_t lookupHopCount = 0; // 表示在Chord环中完成所有查找请求所经过的总跳数

protected:
  virtual void DoDispose();

private:
  virtual void StartApplication(void);
  virtual void StopApplication(void);

  uint32_t m_currentTransactionId;
  Ptr<Socket> m_socket;
  Time m_pingTimeout;
  Timer m_StabilizeTimer;
  Time m_StabilizeTimeout;

  uint16_t m_appPort;
  // Timers
  Timer m_auditPingsTimer;
  // Ping tracker
  std::map<uint32_t, Ptr<PingRequest>> m_pingTracker;
  // Callbacks
  Callback<void, Ipv4Address, std::string> m_pingSuccessFn;
  Callback<void, Ipv4Address, std::string> m_pingFailureFn;
  Callback<void, Ipv4Address, std::string> m_pingRecvFn;

  uint32_t JoinNodeId;
  Ipv4Address ipAddr;
  uint32_t nodeNumber;

  struct ChordNode {
    uint32_t id;                 // 节点ID
    uint32_t hash_key;          // 哈希值
    Ipv4Address ip_address;     // IP地址
    Ipv4Address predecessor;    // 前驱节点
    Ipv4Address successor;      // 后继节点
    bool preset;
    ChordNode(uint32_t node_id, Ipv4Address addr) 
        : id(node_id)
        , ip_address(addr)
        , predecessor(addr)    // 初始时指向自己
        , successor(addr) {    // 初始时指向自己
        hash_key = PennKeyHelper::CreateShaKey(addr);
    }

    ChordNode()
        : id(0)
        , hash_key(0)
        , ip_address(Ipv4Address::GetAny())
        , predecessor(Ipv4Address::GetAny())
        , successor(Ipv4Address::GetAny()),
        preset(false)
    { }
  };


  std::map<Ipv4Address, uint32_t> m_addressNodeMap; // 类型：从Ipv4Address映射到uint32_t的map
  std::map<uint32_t, Ipv4Address> m_nodeAddressMap; // 从uint32_t映射到Ipv4Address的map

  ChordNode m_selfNode; // 当前节点的信息
  /*---------------------------------------*/

  /*--------- add: tool function ------------*/
  template <typename T>
  bool parseStringTo(const std::string &str, T &outValue)
  {
    std::istringstream sin(str);
    sin >> outValue;
    return !sin.fail();
  }
  /*---------------------------------------*/
  std::map<std::string, std::string > hashedValueToOrin;
  std::map<std::string, bool > keyMonitorMap;
  std::map<Ipv4Address, std::map<std::string, std::vector<std::string> > > shipMap;
  std::map<std::string, std::vector<std::string> > invertedList;
  std::string CreateShaKey(const Ipv4Address& ip);
  int first_node_id=-5;


  enum Send_Command
  {
    SET_ALL = 0,
    SET_PRE,
    SET_SUCC,
    SET_FINER_FIRST
  };
  static const std::map<Send_Command, std::string> commandStrings;
  // void SendCommand(Ipv4Address ControledIp,std::string command);
  // void SendCommand(Ipv4Address ControledIp,Send_Command command);
  void  SendCommand(Ipv4Address ControledIp, Send_Command command,Ipv4Address ip_pre="",Ipv4Address ip_succ="");

  // std::pair<Ipv4Address, Ipv4Address> GetPreAndSucc(Ipv4Address MyNode ,Ipv4Address Node1,Ipv4Address Node2);
  std::pair<Ipv4Address, Ipv4Address> GetPreAndSucc(Ipv4Address MyNode ,Ipv4Address Node1,Ipv4Address Node2);
  bool InInterval(uint32_t A, uint32_t B, uint32_t C); // C是B的Succ  使用的时候记得注意一下

  // bool CheckInsidePre(uint32_t A, uint32_t B, uint32_t C);

  void SendFingerTableProgress(uint32_t send_index);
  
  void UpdateFingerTableProgress(uint32_t send_index);
  Ipv4Address GetClosest(uint32_t keyA);

  // finger table 的succ表示这个节点的下一个 但是我们在检查的时候只会检查上一个
  // 所以实际应该保存的是这个节点的predecessor
  struct FingerTableUse
  {
      Ipv4Address node; // 起始节点
      Ipv4Address pre; // 起始节点

      uint32_t key;
      FingerTableUse() : node("0.0.0.0"),pre("0.0.0.0"), key(0) {}
      FingerTableUse(Ipv4Address node,Ipv4Address pre) : node(node),pre(pre) {
        key = PennKeyHelper::CreateShaKey(node);
      }
      void SetKey() {
        key = PennKeyHelper::CreateShaKey(node);
      }
      // 编写一个函数 参数是一个a 一个k  返回 a+2^k 在uint32_t范围内的值 可能会溢出
      uint32_t GetFingerStart(uint32_t a, uint32_t k) {
        if (k >= 32) {
            throw std::out_of_range("k must be less than 32");
        }
        return a + (1u << k);
    }

 
    // 编写排序重定义< 按照
  };
  FingerTableUse fingerTable[32]; // 2^160
  //  1 2 3 4 5 6 7 8 9 
  //  2 2 2 2 3 3 3 3 0 0 0 1 1 1
  // fingerTable是一个递增的数组，可以使用二分查找
  // void updata_use(PennChordMessage chordMsg);
};

inline uint32_t GetHashFromIp(Ipv4Address ipAddr)
{ return PennKeyHelper::CreateShaKey(ipAddr); }

// 每次更新一个节点的successor 和successor的时候都会将其放入我们最新的map_table中
std::string CreateShaKey_(const Ipv4Address& ip);
inline uint32_t GetUpdateStart(uint32_t n,int i) {
  uint32_t m_bits = 32; // 你用了 32-bit 的 key
  uint32_t pow = 1u << (i - 1); // 相当于 2^(i-1)
  uint32_t need_find = (n + (1u << m_bits) - pow) % (1u << m_bits);
  return need_find;
}

inline uint32_t RingSubPowerOfTwo(uint32_t n, uint32_t i) {
  // 计算 2^i
  uint32_t pow2 = 1U << i;
  // 使用环形减法，利用无符号数自动取模
  return n - pow2;
}

#endif


// Ipv4Address predecessor;    // 前驱节点
// Ipv4Address successor;      // 后继节点
