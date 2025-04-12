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

// #include "ns3/penn-chord.h"
#include "penn-chord.h"

#include "ns3/inet-socket-address.h"
#include "ns3/random-variable-stream.h"
#include "ns3/penn-key-helper.h"
#include "ns3/grader-logs.h"
#include <openssl/sha.h>

using namespace ns3;
const std::map<PennChord::Send_Command, std::string> PennChord::commandStrings = {
    {SET_ALL, "SET_ALL"},
    {SET_PRE, "SET_PRE"},
    {SET_SUCC, "SET_SUCC"},
    {SET_FINER_FIRST, "SET_FINER_FIRST"}};
// 节点信息结构体
struct ChordNode
{
  uint32_t id;             // 节点ID
  uint32_t hash_key;       // 哈希值
  Ipv4Address ip_address;  // IP地址
  Ipv4Address predecessor; // 前驱节点
  Ipv4Address successor;   // 后继节点

  // 构造函数
  ChordNode(uint32_t ByNodeId, Ipv4Address addr)
      : id(ByNodeId), ip_address(addr), predecessor(addr) // 初始时指向自己
        ,
        successor(addr)
  { // 初始时指向自己
    hash_key = PennKeyHelper::CreateShaKey(addr);
  }
};

TypeId
PennChord::GetTypeId()
{
  static TypeId tid = TypeId("PennChord")
                          .SetParent<PennApplication>()
                          .AddConstructor<PennChord>()
                          .AddAttribute("AppPort", "Listening port for Application", UintegerValue(10001),
                                        MakeUintegerAccessor(&PennChord::m_appPort), MakeUintegerChecker<uint16_t>())
                          .AddAttribute("PingTimeout", "Timeout value for PING_REQ in milliseconds", TimeValue(MilliSeconds(2000)),
                                        MakeTimeAccessor(&PennChord::m_pingTimeout), MakeTimeChecker());
  return tid;
}

PennChord::PennChord()
    : m_auditPingsTimer(Timer::CANCEL_ON_DESTROY)
{
  Ptr<UniformRandomVariable> m_uniformRandomVariable = CreateObject<UniformRandomVariable>();
  m_currentTransactionId = m_uniformRandomVariable->GetValue(0x00000000, 0xFFFFFFFF);
}

PennChord::~PennChord()
{
  uint32_t curr_id = GetIdFromIp(ipAddr);
  GraderLogs::AverageHopCount(std::to_string(curr_id), lookupCount, lookupHopCount);
}

void PennChord::DoDispose()
{
  StopApplication();
  PennApplication::DoDispose();
}

void PennChord::StartApplication(void)
{
  if (m_socket == 0)
  {
    TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    m_socket = Socket::CreateSocket(GetNode(), tid);
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_appPort);
    m_socket->Bind(local);
    m_socket->SetRecvCallback(MakeCallback(&PennChord::RecvMessage, this));
  }
  // 2 1 0
  // Configure timers
  m_auditPingsTimer.SetFunction(&PennChord::AuditPings, this);
  // Start timers
  m_auditPingsTimer.Schedule(m_pingTimeout);

  // Initialize node information when the application starts
  // JoinNodeId = GetNode()->GetId();
  ipAddr = GetLocalAddress(); // GET 0.0.0.0????
  // JoinNodeId = GetNode()->GetId();
  JoinNodeId = GetIdFromIp(ipAddr);
  // ipAddr= GetIpFromId(JoinNodeId);

  // GET NODE IP
  // std::cout << "Node ID: " << JoinNodeId << " IP Address: " << ipAddr << std::endl;
}

void PennChord::StopApplication(void)
{
  // Close socket
  if (m_socket)
  {
    m_socket->Close();
    m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket>>());
    m_socket = 0;
  }

  // Cancel timers
  m_auditPingsTimer.Cancel();
  m_pingTracker.clear();
}

// 处理节点加入请求
void PennChord::HandleJoinRequest(uint32_t JoinNodeId, Ipv4Address target_addr, Ipv4Address though_addr)
{
  // std::cout << "in orocess command," << "  now ip:" << ipAddr << " " << " want to add to chord through  " << though_addr << "  " << "target_addr: " << "(else debug:" << target_addr << ")" << std::endl;
  PennChordMessage message(PennChordMessage::LOOK_UP, GetNextTransactionId());
  // std::cout<<though_addr<<"  "<<target_addr<<std::endl;
  message.SetLookUpThoughNode(though_addr); // now ip address
  message.SetLookUpJoinNode(target_addr);
  message.SetLookUpFromNode(ipAddr); // 当前节点是发起的节点
  message.SetLookUpMessage("join");
  message.SetLookUpMessageType("LookupReq_Join");
  // message.SetNodenumber(JoinNodeId); // 发送请求的节点ID
  // std::cout << though_addr << "  " << message.GetLookUp().ThroughNode<< std::endl;
  // std::cout << "Prepare to send join request to: " << message.GetLookUp().JoinNode << "  from " << message.GetLookUp().ThoughNode << std::endl;
  // if(DEBUG) std::cout << "发送出的消息: " << "JoinNode: " << message.GetLookUp().JoinNode << "ThoughNode: " << message.GetLookUp().ThoughNode << std::endl;
  transmitRequest(message, though_addr);
  // 此处为发出请求
  uint32_t send_hsh = PennKeyHelper::CreateShaKey(though_addr);
  uint32_t curr_hsh = PennKeyHelper::CreateShaKey(ipAddr);
  CHORD_LOG(GraderLogs::GetLookupIssueLogStr(curr_hsh, send_hsh));
  // lookupCount++; //Update total lookups
}

void PennChord::ProcessCommand(std::vector<std::string> tokens)
{
  if (tokens.empty())
  {
    ERROR_LOG("Empty command received");
    return;
  }

  std::string command = tokens[0];
  // std::cout << "----------------------------COMMAND:" << command[0] << "----------------------------" << std::endl;
  try
  {
    if (command[0] == 'J')
    {
      if (tokens.size() < 2)
      {
        ERROR_LOG("Invalid JOIN command format");
        return;
      }
      uint32_t nodeNumber_;
      if (!parseStringTo<uint32_t>(tokens[1], nodeNumber_))
      {
        ERROR_LOG("Invalid node number format");
        return;
      }
      std::cout << "JOIN" << " " << nodeNumber_ << std::endl;
      // std::cout << "Join request received from node: " << nodeNumber_ << std::endl;
      uint32_t ByNodeId = static_cast<uint32_t>(nodeNumber_);
      // Ipv4Address ipAddr = GetLocalAddress();
      // std::cout << "Node ID: " << ByNodeId << " " << JoinNodeId << "  " << "IP Address: " << ipAddr << std::endl;
      // if (DEBUG)
      // std::cout << "NowIp: " << ipAddr << "  " << "JoinNodeId: " << ipAddr << " ThroughId" << GetIpFromId(ByNodeId) << std::endl;
      if (JoinNodeId != ByNodeId)
      {
        // m_nodeAddressMap[JoinNodeId] = ipAddr;
        // SyncNodeMap(true, m_selfNode.successor);
        HandleJoinRequest(JoinNodeId, ipAddr, GetIpFromId(ByNodeId));
      }
      else
      {
        // 作为第一个节点加入
        ChordNode new_node(JoinNodeId, ipAddr);
        new_node.successor = ipAddr;
        new_node.predecessor = ipAddr;
        m_selfNode = new_node;
        first_node_id = JoinNodeId;
        // 初始化finger table为它
        for (int i = 0; i <= 31; i++)
        {
          fingerTable[i].node = ipAddr;
          fingerTable[i].pre = ipAddr;
          fingerTable[i].SetKey();
        }
        // std::cout << " DEBUG【" << 0 << "】 INFO " << m_selfNode.successor << "(" << GetIdFromIp(m_selfNode.successor) << ")   " << m_selfNode.predecessor << " " << "(" << GetIdFromIp(m_selfNode.predecessor) << ")" << ipAddr << std::endl;

        // std::cout << "First node joined: First node joined: " << JoinNodeId << " IP Address: " << ipAddr << std::endl;
      }
    }
    else if (command[0] == 'L')
    {
      SendCommand(m_selfNode.successor, Send_Command::SET_PRE, m_selfNode.predecessor, m_selfNode.predecessor);
      SendCommand(m_selfNode.predecessor, Send_Command::SET_SUCC, m_selfNode.successor, m_selfNode.successor);
    }
    else if (command[0] == 'R')
    {
      // std::cout << "RingStateStart111" << std::endl;
      //  uint32_t currKey = PennKeyHelper::CreateShaKey(ipAddr);

      outcontrol();
      if (ipAddr != m_selfNode.successor)
      {
        // Ipv4Address orinNode = ipAddr;

        uint32_t transactionId = GetNextTransactionId();
        PennChordMessage message = PennChordMessage(PennChordMessage::LOOK_UP, transactionId);
        message.SetLookUpJoinNode(ipAddr);
        message.SetLookUpThoughNode(ipAddr);
        message.SetLookUpMessageType("Ringstate");
        // std::cout << "输出测试："<<message.GetRingState().originatorNode << "  " << message.GetRingState().targetNode << std::endl;
        transmitRequest(message, m_selfNode.successor);
      }
      else
      {
        // EndOfRingState
        GraderLogs::EndOfRingState();
      }
    }
    else
    {
      ERROR_LOG("Unknown command: " << command);
    }
  }
  catch (const std::exception &e)
  {
    ERROR_LOG("Exception in ProcessCommand: " << e.what());
  }
}

void PennChord::SendPing(Ipv4Address destAddress, std::string pingMessage)
{
  if (destAddress != Ipv4Address::GetAny())
  {
    uint32_t transactionId = GetNextTransactionId();
    CHORD_LOG("Sending PING_REQ to Node: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << pingMessage << " transactionId: " << transactionId);
    Ptr<PingRequest> pingRequest = Create<PingRequest>(transactionId, Simulator::Now(), destAddress, pingMessage);
    m_pingTracker.insert(std::make_pair(transactionId, pingRequest));
    Ptr<Packet> packet = Create<Packet>();
    PennChordMessage message = PennChordMessage(PennChordMessage::PING_REQ, transactionId);
    message.SetPingReq(pingMessage);
    packet->AddHeader(message);
    m_socket->SendTo(packet, 0, InetSocketAddress(destAddress, m_appPort));
  }
  else
  {
    m_pingFailureFn(destAddress, pingMessage);
  }
}

void PennChord::RecvMessage(Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom(sourceAddr);
  InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom(sourceAddr);
  Ipv4Address sourceAddress = inetSocketAddr.GetIpv4();
  uint16_t sourcePort = inetSocketAddr.GetPort();
  PennChordMessage message;
  packet->RemoveHeader(message);
  // std::cout <<"Received message from: " << sourceAddress << " Type: "<<message.GetMessageType()<< std::endl;
  switch (message.GetMessageType())
  {
  case PennChordMessage::PING_REQ:
    ProcessPingReq(message, sourceAddress, sourcePort);
    break;
  case PennChordMessage::PING_RSP:
    ProcessPingRsp(message, sourceAddress, sourcePort);
    break;
  case PennChordMessage::LOOK_UP:
    ProcessLookUp(message, sourceAddress, sourcePort);
    ProcessCommandSelfUse(message, sourceAddress, sourcePort);
    ProcessRingState(message, sourceAddress, sourcePort);
    ProcessFingerTableLookUp(message, sourceAddress, sourcePort);
    // std::cout <<"NODE【"<<GetIdFromIp(ipAddr)<<"】:  "<< "NowIp: " << ipAddr << " Hash: " <<PennKeyHelper::CreateShaKey( m_selfNode.successor)- PennKeyHelper::CreateShaKey(ipAddr)<< " Pree: " << m_selfNode.predecessor <<"  Suss"<< m_selfNode.successor << std::endl;
    //  std::cout << " DEBUG【" << JoinNodeId << "】 INFO " << m_selfNode.successor << "(" << GetIdFromIp(m_selfNode.successor) << ")   " << m_selfNode.predecessor << " " << "(" << GetIdFromIp(m_selfNode.predecessor) << ")" << ipAddr << "   Hash: " <<PennKeyHelper::CreateShaKey(ipAddr)<<std::endl;
    break;
  case PennChordMessage::PENNSEARCH:
    ProcessPeenSearchResponse(message, sourceAddress, sourcePort);
    break;

  default:
    ERROR_LOG("Unknown Message Type!");
    break;
  }
  // std::cout << " DEBUG【" << JoinNodeId << "】 INFO " << m_selfNode.successor << "(" << GetIdFromIp(m_selfNode.successor) << ")   " << m_selfNode.predecessor << " " << "(" << GetIdFromIp(m_selfNode.predecessor) << ")" << ipAddr << std::endl;
}

void PennChord::ProcessLookUp(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  std::string lookupMessage = message.GetLookUp().lookupMessage;

  if (lookupMessage == "LookupReq_Join")
  {
    ProcessFind(message);
    // std::cout << "Received LookupReq from: " << fromNode << ", Message: 【" << message.GetLookUp().lookupMessage << "】" << std::endl;
  }
}
void PennChord::ProcessPingReq(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  std::string fromNode = ReverseLookup(sourceAddress);
  // CHORD_LOG("Received PING_REQ, From Node: " << fromNode << ", Message: " << message.GetPingReq().pingMessage);

  PennChordMessage resp = PennChordMessage(PennChordMessage::PING_RSP, message.GetTransactionId());
  resp.SetPingRsp(message.GetPingReq().pingMessage);
  Ptr<Packet> packet = Create<Packet>();
  packet->AddHeader(resp);
  m_socket->SendTo(packet, 0, InetSocketAddress(sourceAddress, sourcePort));

  m_pingRecvFn(sourceAddress, message.GetPingReq().pingMessage);
}

void PennChord::ProcessPingRsp(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  std::map<uint32_t, Ptr<PingRequest>>::iterator iter;
  iter = m_pingTracker.find(message.GetTransactionId());
  if (iter != m_pingTracker.end())
  {
    std::string fromNode = ReverseLookup(sourceAddress);
    PRINT_LOG("Received PING_RSP, From Node: " << fromNode << ", Message: " << message.GetPingRsp().pingMessage);
    m_pingTracker.erase(iter);
    m_pingSuccessFn(sourceAddress, message.GetPingRsp().pingMessage);
  }
  else
  {
    DEBUG_LOG("Received invalid PING_RSP!");
  }
}

void PennChord::AuditPings()
{
  std::map<uint32_t, Ptr<PingRequest>>::iterator iter;
  for (iter = m_pingTracker.begin(); iter != m_pingTracker.end();)
  {
    Ptr<PingRequest> pingRequest = iter->second;
    if (pingRequest->GetTimestamp().GetMilliSeconds() + m_pingTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
    {
      DEBUG_LOG("Ping expired. Message: " << pingRequest->GetPingMessage() << " Timestamp: " << pingRequest->GetTimestamp().GetMilliSeconds() << " CurrentTime: " << Simulator::Now().GetMilliSeconds());
      m_pingTracker.erase(iter++);
      m_pingFailureFn(pingRequest->GetDestinationAddress(), pingRequest->GetPingMessage());
    }
    else
    {
      ++iter;
    }
  }
  m_auditPingsTimer.Schedule(m_pingTimeout);
}

void PennChord::StopChord()
{
  StopApplication();
}

uint32_t PennChord::GetNextTransactionId()
{
  return m_currentTransactionId++;
}

void PennChord::SetPingSuccessCallback(Callback<void, Ipv4Address, std::string> pingSuccessFn)
{
  m_pingSuccessFn = pingSuccessFn;
}

void PennChord::SetPingFailureCallback(Callback<void, Ipv4Address, std::string> pingFailureFn)
{
  m_pingFailureFn = pingFailureFn;
}

void PennChord::SetPingRecvCallback(Callback<void, Ipv4Address, std::string> pingRecvFn)
{
  m_pingRecvFn = pingRecvFn;
}

Ipv4Address PennChord::GetIpFromId(uint32_t id)
{
  auto it = m_nodeAddressMap.find(id);
  return (it != m_nodeAddressMap.end()) ? it->second : Ipv4Address::GetAny();
}

int PennChord::GetIdFromIp(Ipv4Address ipAddr)
{
  for (const auto &pair : m_nodeAddressMap)
  {
    if (pair.second == ipAddr)
    {
      return pair.first;
    }
  }
  return -1;
}
void PennChord::transmitRequest(PennChordMessage chordMsg, Ipv4Address targetAddr)
{
  Ptr<Packet> dataPacket = Create<Packet>();
  dataPacket->AddHeader(chordMsg);
  m_socket->SendTo(dataPacket, 0, InetSocketAddress(targetAddr, m_appPort));
  // std::cout<<"Send to: " << targetAddr << " port: " << m_appPort << std::endl;
  auto msgContent = chordMsg.GetLookUp();
  auto requestType = msgContent.lookupMessage;
}

void PennChord::SetNodeAddressMap(std::map<uint32_t, Ipv4Address> nodeAddressMap)
{
  m_nodeAddressMap = nodeAddressMap;
}

void PennChord::SetAddressNodeMap(std::map<Ipv4Address, uint32_t> addressNodeMap)
{
  m_addressNodeMap = addressNodeMap;
}

void PennChord::ProcessFind(PennChordMessage message)
{
  std::string lookupMessage = message.GetLookUp().lookupMessage;
  Ipv4Address JoinTargetNode = message.GetLookUp().JoinNode;

  Ipv4Address A = JoinTargetNode;
  Ipv4Address B = ipAddr;
  Ipv4Address C = m_selfNode.successor;
  uint32_t keyA = PennKeyHelper::CreateShaKey(A);
  uint32_t keyB = PennKeyHelper::CreateShaKey(B);
  uint32_t keyC = PennKeyHelper::CreateShaKey(C);

  uint32_t currHash = PennKeyHelper::CreateShaKey(ipAddr);
  uint32_t NextNodeKey = PennKeyHelper::CreateShaKey(m_selfNode.successor);
  std::string closestFingerString = std::to_string(GetIdFromIp(m_selfNode.successor));
  uint32_t target_key = PennKeyHelper::CreateShaKey(A);
  // TODO:  JoinNode可能不对 检查一下
  if (m_selfNode.successor == m_selfNode.predecessor && (first_node_id >= 0))
  {
    // 向只有一个节点的里面添加
    m_selfNode.successor = JoinTargetNode;
    m_selfNode.predecessor = JoinTargetNode;
    SendCommand(message.GetLookUp().JoinNode, Send_Command::SET_ALL, ipAddr, ipAddr);
    // 这里初始化更新一下FingerTable 都是它自己
    // 1. 初始化自己的fingerTable
    // fingerTable[0].node=m_selfNode.successor;
    // fingerTable[0].pre=ipAddr;

    // 这个好求
    fingerTable[0].node = JoinTargetNode;
    fingerTable[0].pre = ipAddr;
    fingerTable[0].SetKey();
    for (int i = 1; i <= 31; i++)
    {
      SendFingerTableProgress(i);
    }
    // message.SetLookUpMessageType("FingerTableInitFirst");
    
    // 2. 更新其他人的fingerTable
    // SendCommand(message.GetLookUp().JoinNode, Send_Command::SET_FINER_FIRST, ipAddr, ipAddr);
    first_node_id = -1;
    // 每次节点向发起初始查找请求的节点返回查找结果时 也就是找到的时候

    // 有一个fromNode 最初发起请求的Ip编号
    Ipv4Address FromNode = message.GetLookUp().FromNode;
    uint32_t FromNodeKey = PennKeyHelper::CreateShaKey(FromNode);
    uint32_t FromNodeId = GetIdFromIp(FromNode);
    CHORD_LOG(GraderLogs::GetLookupResultLogStr(
        currHash,
        target_key,
        std::to_string(FromNodeId),
        FromNodeKey));
  }
  else
  {
    bool isInCircle = InInterval(keyA, keyB, keyC);
    if (isInCircle)
    {
      SendCommand(A, Send_Command::SET_PRE, B, B);
      SendCommand(A, Send_Command::SET_SUCC, C, C);
      SendCommand(B, Send_Command::SET_SUCC, A, A);
      SendCommand(C, Send_Command::SET_PRE, A, A);
      // 这里顺便初始化它的FingetTable

      // 初始化自己的fingerTable
      // TODO: 这里更新的时候好像不太全
      fingerTable[0].node = JoinTargetNode;
      fingerTable[0].pre = ipAddr;
      fingerTable[0].SetKey();
      for (int i = 1; i <= 31; i++)
      {
        SendFingerTableProgress(i);
      }
      //uint32_t n = PennKeyHelper::CreateShaKey(JoinTargetNode);
      for(int i=1;i<=32;i++){

        UpdateFingerTableProgress(i);
      }
      // 更新其他人的fingerTable
    }
    else
    {
      Ipv4Address send_target_addr = m_selfNode.successor;
      // 先检查一下finger table里面 有没有合适的send_target_addr
      int now_max = 0;
      int now_key = PennKeyHelper::CreateShaKey(ipAddr);
      for (int i = 0; i <= 31; i++)
      {
        FingerTableUse fingerTable_ = fingerTable[i];
        if (fingerTable_.node != "0")
        {
          uint32_t key_start = fingerTable_.GetFingerStart(now_key, i);
          if (now_key > key_start)
          {
            if (now_max < key_start)
            {
              now_max = key_start;
              if (fingerTable_.pre != "0")
                send_target_addr = fingerTable_.pre;
            }
          }
        }
        // if()
      }
      message.SetLookUpThoughNode(send_target_addr);
      transmitRequest(message, send_target_addr);
      // 转发请求

      CHORD_LOG(GraderLogs::GetLookupForwardingLogStr(
          currHash,
          closestFingerString,
          NextNodeKey,
          target_key));
    }
  }
}

void PennChord::processInvertedRsp(Ipv4Address JoinNode, std::string key)
{
  // when it receives the response, modify shipMap, keyMonitorMap, delete entry of invertedList if necessary
  std::string keyword = hashedValueToOrin[key];
  keyMonitorMap[keyword] = true;

  std::map<Ipv4Address, std::map<std::string, std::vector<std::string>>>::const_iterator it = shipMap.find(JoinNode);

  std::map<std::string, std::vector<std::string>> temp;
  if (it != shipMap.end())
  {
    temp = it->second;
  }
  temp[keyword] = invertedList[keyword];
  shipMap[JoinNode] = temp;

  if (JoinNode != ipAddr)
  {
    invertedList.erase(keyword);
  }
  else
  {
    std::vector<std::string> docIDsTemp = invertedList[keyword];
    for (uint16_t i = 0; i < docIDsTemp.size(); i++)
    {
      CHORD_LOG("Store <" << keyword << " , " << docIDsTemp[i] << ">");
    }
  }
}

std::string CreateShaKey_(const Ipv4Address &ip)
{
  uint32_t ip_uint32 = ip.Get(); // 固定输入
  std::ostringstream oss;
  oss << std::hex << std::setw(8) << std::setfill('0') << ip_uint32;
  return oss.str(); // 示例输出："c0a80101"
}

void PennChord::SendCommand(Ipv4Address ControledIp, Send_Command command, Ipv4Address ip_pre, Ipv4Address ip_succ)
{
  // if(DEBUG) std::cout<<"SEND_COMMAND_SET_TRUE:  "<< ControledIp<<"  "<<command<<"   "<<ip_pre<<"    MY_IP: "<<ipAddr<< std::endl;
  std::string msg = "SendCommand Not init success";
  // Use an enum-to-string mapping for cleaner code

  auto it = commandStrings.find(command);
  msg = (it != commandStrings.end()) ? it->second : "SendCommand ERROR";
  PennChordMessage message = PennChordMessage(PennChordMessage::LOOK_UP, GetNextTransactionId());
  message.SetLookUpMessageType(msg);
  message.SetLookUpPreIp(ip_pre);
  message.SetLookUpSuccIp(ip_succ);
  // std::cout<<"pre="<<ip_pre<<"  succ="<<ip_succ<<std::endl;
  // std::cout<<"controlledIp="<<ControledIp<<"  "<<ipAddr<<std::endl;
  transmitRequest(message, ControledIp);
}

void PennChord::ProcessCommandSelfUse(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{

  std::string command = message.GetLookUp().lookupMessage;
  bool foundCommand = false;
  for (const auto &pair : commandStrings)
  {
    if (pair.second == command)
    {
      foundCommand = true;
      break;
    }
  }
  if (!foundCommand)
    return;

  Ipv4Address ip_pre = message.GetLookUpPreIp();
  Ipv4Address ip_succ = message.GetLookUpSuccIp();

  // if (DEBUG) std::cout << "Processing command: " << command << " from " << sourceAddress << "NowIp"<<ipAddr<<std::endl;
  // if (DEBUG) std::cout<< ip_pre << "  " << ip_succ << std::endl;
  if (command == "SET_ALL")
  {
    // if (DEBUG) std::cout << "Setting both successor and predecessor - Succ: " << ip_succ << ", Pred: " << ip_pre << std::endl;
    m_selfNode.successor = ip_succ;
    m_selfNode.predecessor = ip_pre;

    fingerTable[0].node = ip_succ;
    fingerTable[0].pre = ip_succ;
    fingerTable[0].SetKey();
    for (int i = 1; i <= 31; i++)
    {
      SendFingerTableProgress(i);
    }
  }
  else if (command == "SET_PRE")
  {
    // if (DEBUG) std::cout << "Setting predecessor to: " << ip_pre << std::endl;
    m_selfNode.predecessor = ip_pre;
  }
  else if (command == "SET_SUCC")
  {
    // if (DEBUG) std::cout << "Setting successor to: " << ip_succ << std::endl;
    m_selfNode.successor = ip_succ;
  }
  // TODO: 新增一个SET_FINGER_TABLE模式  用于查找到FingerTable的值后更新
  else if (command == "SET_FINGER_TABLE")
  {
  }
  else if (command == "SET_FINER_FIRST")
  {
    // std::cout << "Setting finger table to: " << ip_succ << std::endl;

    for (int i = 0; i <= 31; i++)
    {
      fingerTable[i].node = ip_succ;
      fingerTable[i].pre = ipAddr;
      fingerTable[i].SetKey();
    }
  }
  else if (command == "Ringstate")
  {
    // if (DEBUG) std::cout << "Setting RingState to: " << ip_succ << std::endl;
    outcontrol();
  }

  else
  {
    // if (DEBUG) std::cout << "Received unknown command: " << command << std::endl;
    ERROR_LOG("Unknown command: " << command);
  }

  // if (DEBUG) std::cout << "After command execution - Node " << JoinNodeId
  //                       << " Succ: " << m_selfNode.successor << " (" << GetIdFromIp(m_selfNode.successor) << ")"
  //                       << " Pred: " << m_selfNode.predecessor << " (" << GetIdFromIp(m_selfNode.predecessor) << ")" << std::endl;
}

void PennChord::ProcessRingState(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  std::string Type = message.GetLookUp().lookupMessage;
  // std::cout << "Ringstate  " <<Type<< std::endl;
  if (Type != "Ringstate")
    return;
  Ipv4Address fromNode = message.GetLookUp().JoinNode;
  if (fromNode == ipAddr)
  {
    GraderLogs::EndOfRingState();
    return;
  }
  else
  {
    // Forward the ring state message to the next node
    outcontrol();
    //  std::cout<<"【"<<JoinNodeId<<"】"<<"Forwarding RingState message to: " << targetNode << std::endl;
    message.SetLookUpThoughNode(ipAddr);
    transmitRequest(message, m_selfNode.successor);
  }
}

void PennChord::outcontrol()
{
  //   void GraderLogs::RingState(Ipv4Address currNodeIP,
  //     std::string currNodeId,
  //     uint32_t currNodeKey,
  //     Ipv4Address predNodeIP,
  //     std::string predNodeId,
  //     uint32_t predNodeKey,
  //     Ipv4Address succNodeIP,
  //     std::string succNodeId,
  //     uint32_t succNodeKey)
  // {
  // std::cout << "Ring State" << std::endl;
  // std::cout << "Curr<Node " << JoinNodeId << ", " << ipAddr << ", "
  //           << CreateShaKey_(ipAddr) << ">" << std::endl;
  // std::cout << "Pred<Node " << GetIdFromIp(m_selfNode.predecessor) << ", "
  //           << m_selfNode.predecessor << ", "
  //           << CreateShaKey_(m_selfNode.predecessor) << ">" << std::endl;
  // std::cout << "Succ<Node " << GetIdFromIp(m_selfNode.successor) << ", "
  //           << m_selfNode.successor << ", "
  //           << CreateShaKey_(m_selfNode.successor) << ">" << std::endl;
  // std::cout << std::endl;

  GraderLogs::RingState(ipAddr,
                        std::to_string(JoinNodeId),
                        PennKeyHelper::CreateShaKey(ipAddr),
                        m_selfNode.predecessor,
                        std::to_string(GetIdFromIp(m_selfNode.predecessor)),
                        PennKeyHelper::CreateShaKey(m_selfNode.predecessor),
                        m_selfNode.successor,
                        std::to_string(GetIdFromIp(m_selfNode.successor)),
                        PennKeyHelper::CreateShaKey(m_selfNode.successor));
}

void PennChord::ProcessPeenSearchResponse(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  // 接受到倒排索引的响应
  // 先调试 依次输出 m_message.pennSearch.operation ...
  // std::cout << "------------------------接受到倒排索引的响应------------------------" << std::endl;
  // std::cout << "Operation: " << message.GetPennSearch().operation << std::endl;
  // std::cout << "Origin Node: " << message.GetPennSearch().originNode << std::endl;
  // std::cout << "Current Results: " << std::endl;
  // for (const auto &result : message.GetPennSearch().currentResults)
  // {
  //   std::cout << result << std::endl;
  // }
  // // std::cout << "Remaining Queries: " << std::endl;
  // for (const auto &query : message.GetPennSearch().remainingQueries)
  // {
  //   std::cout << query << std::endl;
  // }
  // std::cout << "------------------------接受到倒排索引的响应------------------------" << std::endl;

  std::string mode_ = message.GetPennSearch().operation;
  std::vector<std::string> current_results = message.GetPennSearch().currentResults;
  if (mode_ == "publish")
  {
    std::string term = message.GetPennSearch().remainingQueries[0];
    uint32_t hash_use = PennKeyHelper::CreateShaKey(term);
    //     std::string lookupMessage = message.GetLookUp().lookupMessage;
    // Ipv4Address A = ;
    Ipv4Address B = ipAddr;
    Ipv4Address C = m_selfNode.successor;
    uint32_t keyA = hash_use;
    uint32_t keyB = PennKeyHelper::CreateShaKey(B);
    uint32_t keyC = PennKeyHelper::CreateShaKey(C);
    Ipv4Address target_addr = m_selfNode.successor;
    bool find_status = 0;
    find_status = InInterval(keyA, keyB, keyC);
    // 如果找到了
    if (find_status)
    {
      message.SetPennSearchOperation("publish_set");
      transmitRequest(message, target_addr);
    }
    else
    {
      transmitRequest(message, target_addr);
    }
  }
  else if (mode_ == "publish_set")
  {
    std::string term = message.GetPennSearch().remainingQueries[0];
    // NOTE: 测试正常
    // 添加到invertedList中
    // std::cout << "------------------------publish_set------------------------" << std::endl;
    //   std::cout << "term: " << term << "  HASH: " << PennKeyHelper::CreateShaKey(term) << std::endl;
    //   // 输出现在节点的Id
    //   std::cout << "Node ID: " << JoinNodeId << "  IP Address: " << ipAddr << std::endl;
    for (const auto &current_result : current_results)
    {
      invertedList[term].push_back(current_result);
      SEARCH_LOG(GraderLogs::GetStoreLogStr(term, current_result));
      // std::cout << "Store <" << term << " , " << current_result << ">" << std::endl;
    }
    // std::cout << "------------------------publish_set------------------------" << std::endl;
  }
  else if (mode_ == "search_set_use" || mode_ == "search_set_use_first")
  {
    // 更新result 和
    // 更新result
    std::vector<std::string> results = message.GetPennSearch().currentResults;
    std::vector<std::string> remainingQueries = message.GetPennSearch().remainingQueries;
    Ipv4Address target_addr = message.GetPennSearch().originNode;
    Ipv4Address next_addr = m_selfNode.successor;
    std::string term = "";
    if (message.GetPennSearch().remainingQueries.size() != 0)
      term = message.GetPennSearch().remainingQueries[0];
    else
    {
      message.SetPennSearchOperation("search_set"); // 只剩下一个了 直接发送就行
      transmitRequest(message, target_addr);
      return;
    }
    // 这个里面是找到了 当然term也可能是" " 如果这样直接输出

    std::vector<std::string> current_id_result = invertedList[term];

    if (mode_ == "search_set_use_first")
    {
      results = current_id_result;
    }
    else
    {
      std::set<std::string> results_set(results.begin(), results.end());
      std::vector<std::string> intersection;
      for (const auto &id : current_id_result)
      {
        if (results_set.count(id))
        {
          intersection.push_back(id);
        }
      }
      results = std::move(intersection);
    }
    message.SetPennSearchCurrentResults(results);
    if (remainingQueries.size() == 1)
    {
      message.SetPennSearchOperation("search_set"); // 只剩下一个了 直接发送就行
      transmitRequest(message, target_addr);
    }
    else
    {
      // vector remove掉第一个
      remainingQueries.erase(remainingQueries.begin());
      message.SetPennSearchRemainingQueries(remainingQueries);
      message.SetPennSearchOperation("search");
      message.SetPennSearchNowHops(message.GetPennSearch().NowHops + 1);
      transmitRequest(message, next_addr);
    }
  }
  else if (mode_ == "search" || mode_ == "search_first")
  {
    // TODO5: 补充完整，输出一些调试信息
    // TODO6: 处理查找的结果
    std::string term = "";
    if (message.GetPennSearch().remainingQueries.size() != 0)
      term = message.GetPennSearch().remainingQueries[0];
    else
    {
      message.SetPennSearchOperation("search_set"); // 只剩下一个了 直接发送就行
      transmitRequest(message, message.GetPennSearch().originNode);
      return;
    }

    // std::cout << "------------------------search------------------------" << std::endl;
    // std::cout << "term: " << term << "  HASH: " << PennKeyHelper::CreateShaKey(term) << std::endl;
    // // 输出现在节点的Id
    // std::cout << "Node ID: " << JoinNodeId << "  IP Address: " << ipAddr << std::endl;
    // std::cout << "Current Results: " << std::endl;
    // for (const auto &current_result : current_results)
    // {
    //   std::cout << current_result << std::endl;
    // }
    // std::cout << "------------------------search------------------------" << std::endl;
    // 从这个IP开始找
    std::vector<std::string> results = message.GetPennSearch().currentResults;
    std::vector<std::string> remainingQueries = message.GetPennSearch().remainingQueries;
    Ipv4Address target_addr = message.GetPennSearch().originNode;
    Ipv4Address next_addr = m_selfNode.successor;

    if (remainingQueries.size() == 0)
    {
      // 发送到输出请求
      message.SetPennSearchOperation("search_set");
      transmitRequest(message, target_addr); // 准备输出
      return;
    }
    else
    {
      // 还是先做lookup 找到存储这个节点的 应该都能找到
      uint32_t hash_use = PennKeyHelper::CreateShaKey(term);
      //     std::string lookupMessage = message.GetLookUp().lookupMessage;
      // Ipv4Address A = ;
      Ipv4Address B = ipAddr;
      Ipv4Address C = m_selfNode.successor;
      uint32_t keyA = hash_use;
      uint32_t keyB = PennKeyHelper::CreateShaKey(B);
      uint32_t keyC = PennKeyHelper::CreateShaKey(C);
      // Ipv4Address target_addr = m_selfNode.successor;
      // Ipv4Address next_addr = m_selfNode.successor;

      bool find_status = 0;
      find_status = InInterval(keyA, keyB, keyC);

      // 如果找到了
      if (find_status)
      {
        if (mode_ == "search_first")
          message.SetPennSearchOperation("search_set_use_first");
        else
          message.SetPennSearchOperation("search_set_use");
        message.SetPennSearchNowHops(message.GetPennSearch().NowHops + 1);
        transmitRequest(message, next_addr); // 找到了，但是这个key的信息存储在下一个节点，所以需要从下一个节点设置
      }
      else
      {
        message.SetPennSearchNowHops(message.GetPennSearch().NowHops + 1);
        transmitRequest(message, next_addr);
      }
    }
  }
  else if (mode_ == "search_set")
  {
    // 输出查找信息
    std::string term = "";
    if (message.GetPennSearch().remainingQueries.size() != 0)
      term = message.GetPennSearch().remainingQueries[0];
    // 这里term应该一直是空的-
    SEARCH_LOG(GraderLogs::GetSearchResultsLogStr(
        ipAddr,
        current_results));
    // 这里顺便更新该节点的totalHops
    // std::cout << "之前的hopcount: " << lookupHopCount << std::endl;
    // std::cout << "现在的hopcount: " << message.GetPennSearch().NowHops << std::endl;
    lookupHopCount = lookupHopCount + message.GetPennSearch().NowHops;
    // std::cout << "------------------------search_set------------------------" << std::endl;
    // std::cout << "term: " << term << "  HASH: " << PennKeyHelper::CreateShaKey(term) << std::endl;
    // 输出现在节点的Id
    // std::cout << "Node ID: " << JoinNodeId << "  IP Address: " << ipAddr << std::endl;
    // std::cout << "Current Results: " << std::endl;
    // for (const auto &current_result : current_results)
    // {
    //   std::cout << current_result << std::endl;
    // }
    // std::cout << "------------------------search_set------------------------" << std::endl;
  }
  else
  {
    std::cout << "Unknown operation" << std::endl;
  }
}
void PennChord::ProcessPublish(std::string terms, std::vector<std::string> current_results)
{
  // 将倒序列表发布到正确的节点
  PennChordMessage message = PennChordMessage(PennChordMessage::PENNSEARCH, GetNextTransactionId());
  message.SetPennSearchOperation("publish");
  message.SetPennSearchCurrentResults(current_results);

  std::vector<std::string> results;
  results.push_back(terms);
  message.SetPennSearchRemainingQueries(results);
  // std::cout<<"发送的原来的IP"<<ipAddr<<std::endl;
  // std::cout<<"11111111111111111111111111111111111111111111111111"<<std::endl;
  message.SetPennSearchOriginNode(ipAddr); // 从哪个节点发过来

  Ipv4Address target_addr = m_selfNode.successor;
  transmitRequest(message, target_addr);
}
void PennChord::ProcessSearch(uint32_t send_id, std::vector<std::string> findterms)
{
  // 输出
  // std::cout << "------------------------ProcessSearch------------------------" << std::endl;
  // std::cout << "Node ID: " << JoinNodeId << "  IP Address: " << ipAddr << std::endl;
  // for (const auto &term : findterms)
  // {
  //   std::cout << "Searching for term: " << term << std::endl;
  // }
  // std::cout << "------------------------ProcessSearch------------------------" << std::endl;

  // TODO3: 补充完整，输出一些调试信息
  // TODO4: 查找的结果
  PennChordMessage message = PennChordMessage(PennChordMessage::PENNSEARCH, GetNextTransactionId());
  message.SetPennSearchOperation("search_first");
  message.SetPennSearchOriginNode(ipAddr); // 从哪个节点发过来 最后要将搜索结果发到这个节点 注意不要修改

  message.SetPennSearchRemainingQueries(findterms); // 待查找的列表 如果全没有就发送到最初的节点
  std::vector<std::string> current_result;
  message.SetPennSearchCurrentResults(current_result); // 当前查找的结果 现在什么都没有
  message.SetPennSearchNowHops(0);                     // 现在的跳数
  // 从send_id获取它的IP
  Ipv4Address target_addr = GetIpFromId(send_id);
  transmitRequest(message, target_addr);
  lookupCount++; // 统计查找次数
  // 处理搜索请求
}

// TODO: 添加函数 作用是判断 A 是否在B C中间
bool PennChord::InInterval(uint32_t keyA, uint32_t keyB, uint32_t keyC)
{
  if (keyB == keyC)
    return false; // 区间为空
  if (keyA == keyB || keyA == keyC)
    return false; // 排除边界

  if (keyC > keyB)
  {
    return keyA > keyB && keyA < keyC;
  }
  else
  {
    return keyA > keyB || keyA < keyC;
  }
}

// void PennChord::ProcessFingerFind()
// NEED FIX:
// leave之后在join一堆空的，需要测试这种工况

// TODO: 添加维护finger table的函数
//  我们将环挨个走一遍即可
void PennChord::SendFingerTableProgress(uint32_t send_index)
{
  PennChordMessage message = PennChordMessage(PennChordMessage::LOOK_UP, GetNextTransactionId());
  // 设置index
  // message.GetLookUp().finger_query_index=send_index;
  message.SetFingerQueryIndex(send_index);
  message.SetFromNode(ipAddr);
  message.SetLookUpMessageType("finger_find_successor");

  Ipv4Address target_ip = m_selfNode.successor;
  transmitRequest(message, target_ip); // 因为自己的FingerTable还没有初始化所以直接发送到下一个
}

void PennChord::UpdateFingerTableProgress(uint32_t send_index)
{
  PennChordMessage message = PennChordMessage(PennChordMessage::LOOK_UP, GetNextTransactionId());
  // 设置index
  // message.GetLookUp().finger_query_index=send_index;
  message.SetFingerQueryIndex(send_index);
  message.SetFromNode(ipAddr);
  message.SetLookUpMessageType("finger_find_pre");
  message.SetLookUpId(send_index);

  Ipv4Address target_ip = m_selfNode.successor;
  transmitRequest(message, target_ip); // 因为自己的FingerTable还没有初始化所以直接发送到下一个
}

void PennChord::ProcessFingerTableLookUp(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  std::string lookupMessage = message.GetLookUp().lookupMessage;
  if (lookupMessage != "finger_find_successor" && lookupMessage != "finger_find_successor_return" && lookupMessage != "finger_find_pre"
  && lookupMessage != "finger_find_pre_return" &&lookupMessage != "update_finger_table"
  )
    return;
  // 剩下的就是处理FingerTable  跟正常的lookup一样 只是处理的时候多处理一下
  if (lookupMessage == "finger_find_successor")
  {
    // Ipv4Address A =JoinTargetNode;
    Ipv4Address B = ipAddr;
    Ipv4Address C = m_selfNode.successor;
    uint32_t keyA = message.GetLookUp().GetQueryKey(); // 要查找的 key（start = n + 2^i）
    uint32_t keyB = PennKeyHelper::CreateShaKey(B);    // 当前节点的 hash
    uint32_t keyC = PennKeyHelper::CreateShaKey(C);    // 当前 successor 的 hash
    bool isInCircle = InInterval(keyA, keyB, keyC);
    if (keyA == keyC) // 这里是因为反正succ(k)=该节点的下一个 使用1是没问题的
      isInCircle = 1;
    if (isInCircle)
    {
      message.SetFingerTableNode(m_selfNode.successor);
      message.SetFingerTablePredecessor(ipAddr);
      message.SetLookUpMessageType("finger_find_successor_return");
      Ipv4Address target_ip = message.GetFromNode();
      transmitRequest(message, target_ip);
      // message里面是自带index的
    }
    else
    {
      Ipv4Address send_target_addr = m_selfNode.successor;
      uint32_t now_key = PennKeyHelper::CreateShaKey(ipAddr);
      uint32_t target_key = keyA;
      for (int i = 0; i <= 31; i++)
      {
        FingerTableUse fingerTable_ = fingerTable[i];
        if (fingerTable_.node != "0")
        {
          uint32_t finger_key = PennKeyHelper::CreateShaKey(fingerTable_.node);
          if (InInterval(finger_key, now_key, target_key))
          {
            send_target_addr = fingerTable_.node; // 或 fingerTable_.pre，如果你想跳 predecessor
          }
        }
        //   // if()
      }
      // message.SetLookUpThoughNode(send_target_addr);
      transmitRequest(message, send_target_addr);
      // // 转发请求

      // CHORD_LOG(GraderLogs::GetLookupForwardingLogStr(
      //     currHash,
      //     closestFingerString,
      //     NextNodeKey,
      //     target_key));
    }
  }
  else if (lookupMessage == "finger_find_pre"){
    // 反向的环 寻找前面的
    Ipv4Address B = m_selfNode.predecessor;
    Ipv4Address C = ipAddr;
    uint32_t keyA = message.GetLookUp().GetQueryKey(); // 要查找的 key
    uint32_t keyB = PennKeyHelper::CreateShaKey(B);    // 当前 predecessor 的 hash
    uint32_t keyC = PennKeyHelper::CreateShaKey(C);    //  当前节点的 hash

    bool isInCircle = InInterval(keyA, keyB, keyC);
    if (keyA == keyB) // 这里是因为反正succ(k)=该节点的下一个 使用1是没问题的
      isInCircle = 1;
    if(isInCircle){
      message.SetFingerTableNode(ipAddr);
      message.SetFingerTablePredecessor(m_selfNode.predecessor);
      message.SetLookUpMessageType("finger_find_pre_return");
      Ipv4Address target_ip = message.GetFromNode();
      transmitRequest(message, target_ip);
    }
    else{
      // 反向查找（find_predecessor(key)）只能通过 successor/链表式递归完成
      Ipv4Address send_target_addr = m_selfNode.predecessor;
      transmitRequest(message, send_target_addr);
    }
  }
  // 设置某个index的finger table
  else if (lookupMessage == "finger_find_successor_return")
  {
    // 设置FingerTable
    uint32_t index = message.GetFingerQueryIndex();
    Ipv4Address node = message.GetFingerTableNode();
    Ipv4Address pre = message.GetFingerTablePredecessor();
    fingerTable[index].node = node;
    fingerTable[index].pre = pre;
    fingerTable[index].SetKey();
    if (DEBUG)
      std::cout << "设置FingerTable" << std::endl;
    if (DEBUG)
      std::cout << "index: " << index << "  node: " << node << "  pre: " << pre << std::endl;
  }
  
  else if (lookupMessage == "finger_find_pre_return")
  {
    // 这时候就找到了节点P
    Ipv4Address p=message.GetFingerTablePredecessor();
    message.SetLookUpMessageType("update_finger_table");
    message.SetFromNode(ipAddr);
  }
  else if (lookupMessage == "update_finger_table")
  {
    Ipv4Address s=message.GetLookUp().FromNode;
    Ipv4Address n=ipAddr;
    uint32_t s_=PennKeyHelper::CreateShaKey(s);
    uint32_t n_=PennKeyHelper::CreateShaKey(n);
    int i=message.GetLookUpId();

    // uint32_t key_a=s_key;
    // uint32_t key_b=n_key;

    uint32_t finger_i_node=PennKeyHelper::CreateShaKey(fingerTable[i].node);
    bool need_update=0;
    if(s_==n_ ||(InInterval(s_, n_,finger_i_node)))
    {
      need_update=1;
    }
    if(need_update){
      // 更新FingerTable
      fingerTable[i].node=s;
      Ipv4Address p=m_selfNode.predecessor;
      // p.update_finger_table(s, i);
      // 递归更新
      transmitRequest(message, p);
    }
  }
}
// 查找在fingerkey中
Ipv4Address PennChord::GetFinerTableTargetId(uint32_t use_key)
{
  Ipv4Address send_target_addr = m_selfNode.successor;
  // 先检查一下finger table里面 有没有合适的send_target_addr
  int now_max = 0;
  int now_key = use_key;
  for (int i = 0; i <= 31; i++)
  {
    FingerTableUse fingerTable_ = fingerTable[i];
    if (fingerTable_.node != "0")
    {
      uint32_t key_start = fingerTable_.GetFingerStart(now_key, i);
      if (now_key > key_start)
      {
        if (now_max < key_start)
        {
          now_max = key_start;
          if (fingerTable_.pre != "0")
            send_target_addr = fingerTable_.pre;
        }
      }
    }
    // if()
  }
}
// 我们要找的是：有哪些节点的第 i 个 finger 应该指向新加入的节点 n？
// 也就是：
// n ∈ (p + 2^{i-1}, finger[i])      ← 新节点 n 落在这段 finger 范围内

// 判断新加入的节点 n 是否更适合被当前节点的第 i 个 finger 所指向 —— 如果是，就更新它；并递归传播给它的前驱。
// if n ∈ [finger[i].start, finger[i].node):
//     finger[i].node = n
//     p.predecessor.finger_find_pre(n, i)

// TODO: 在LookUp的时候，有对相等的特殊情况做处理吗？

// TODO: 优化查找
// for i = 1 to m - 1                                  // 初始化剩余 finger 表项
//     if (start 属于 [n, finger[i].node)) {
//         finger[i+1].node = finger[i].node
//     } else {
//         finger[i+1].node = find_successor(start)
//     }

// TODO: update_others
// TODO: 实现find_predecessor的功能
// for i = 1 to m
//     p = find_predecessor(n - 2^{i-1})               // 找到可能受影响的节点
//     p.finger_find_pre(n, i)                    // 通知它更新第 i 个 finger

// TODO: finger_find_pre(n, i)：如果 n 更合适，更新第 i 个 finger

// if (n 属于 [finger[i].node)) {
//   finger[i].node = n
//   p = predecessor
//   p.finger_find_pre(n, i)                    // 向前传播
// }

// TODO: closest_preceding_finger