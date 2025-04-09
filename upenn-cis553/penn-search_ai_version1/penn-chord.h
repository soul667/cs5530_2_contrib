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
// #include "ns3/penn-chord-message.h"
#include "penn-chord-message.h"

#include "ns3/ping-request.h"
#include <openssl/sha.h>

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

using namespace ns3;

class PennChord : public PennApplication
{
public:
  static TypeId GetTypeId(void);
  PennChord();
  virtual ~PennChord();

  void SendPing(Ipv4Address destAddress, std::string pingMessage);
  void RecvMessage(Ptr<Socket> socket);
  void ProcessPingReq(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
  void ProcessPingRsp(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort);
  void AuditPings();
  uint32_t GetNextTransactionId();
  void StopChord();

  // Callback with Application Layer (add more when required)
  void SetPingSuccessCallback(Callback<void, Ipv4Address, std::string> pingSuccessFn);
  void SetPingFailureCallback(Callback<void, Ipv4Address, std::string> pingFailureFn);
  void SetPingRecvCallback(Callback<void, Ipv4Address, std::string> pingRecvFn);

  // From PennApplication
  virtual void ProcessCommand(std::vector<std::string> tokens);

  // ---------------------------------------

protected:
  virtual void DoDispose();

private:
  virtual void StartApplication(void);
  virtual void StopApplication(void);

  uint32_t m_currentTransactionId;
  Ptr<Socket> m_socket;
  Time m_pingTimeout;
  uint16_t m_appPort;
  // Timers
  Timer m_auditPingsTimer;
  // Ping tracker
  std::map<uint32_t, Ptr<PingRequest>> m_pingTracker;
  // Callbacks
  Callback<void, Ipv4Address, std::string> m_pingSuccessFn;
  Callback<void, Ipv4Address, std::string> m_pingFailureFn;
  Callback<void, Ipv4Address, std::string> m_pingRecvFn;

  
  // chord use
  struct ChordNode
  {
    uint32_t id;      // 32位节点ID(SHA1哈希)
    Ipv4Address addr; // 节点IP地址
  };

  // DHT状态变量
  std::string successor;        // 后继节点hash
  std::string predecessor;      // 前驱节点hash 
  Ipv4Address successorIp;     // 后继IP
  Ipv4Address predecessorIp;   // 前驱IP
  Timer m_stabilizeTimer;      // 稳定定时器
  Time m_stabilizeTimeout;     // 稳定超时时间
  
  // 路由表相关
  std::vector<ChordNode> fingerTable;  // 路由表
  uint32_t m_numFingerEntries;        // 路由表条目数
  Timer m_fixFingersTimer;            // 修复路由表定时器

  // Node add and remove
  void Join(Ipv4Address bootstrapAddress);
  void Stabilize();
  void FixFingers();
  void CheckPredecessor();

  // Node Find
  ChordNode FindSuccessor(uint32_t id);
  ChordNode GetClosestPrecedingNode(uint32_t id);

  // Message processing
  void ProcessJoinReq();
  void ProcessStabilizeReq();
  void ProcessNotifyReq();
  void ProcessLookupReq();


  std::string GetHash(Ipv4Address ip);  // get ip's hash

  // DHT基础操作
  void CreateRing(const std::string& key);  // 创建/初始化环
  void ForwardLookup(PennChordMessage& msg, Ipv4Address nextHop);  // 转发查找请求
  void UpdateNodeInfo(const std::string& nodeId, Ipv4Address nodeIp);  // 更新节点信息
  
  // 辅助函数
  bool IsInRange(const std::string& key, const std::string& start, const std::string& end);  // 检查key是否在范围内
  void InitFingerTable();  // 初始化路由表
  std::string GetFingerStart(int index);  // 获取路由表索引对应的起始值


  Ipv4Address m_mainAddress;
  Timer m_StabilizeTimer;

};

#endif
