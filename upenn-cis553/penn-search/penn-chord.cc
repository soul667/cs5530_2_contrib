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
    {SET_SUCC, "SET_SUCC"}};
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
  if (lookupMessage != "LookupReq_Join")
    return;

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
  Ipv4Address A = message.GetLookUp().JoinNode;
  Ipv4Address B = message.GetLookUp().ThoughNode;
  Ipv4Address C = m_selfNode.successor;

  uint32_t currHash = PennKeyHelper::CreateShaKey(ipAddr);
  uint32_t NextNodeKey = PennKeyHelper::CreateShaKey(m_selfNode.successor);
  std::string closestFingerString = std::to_string(GetIdFromIp(m_selfNode.successor));
  uint32_t target_key = PennKeyHelper::CreateShaKey(A);
  // TODO:  JoinNode可能不对 检查一下
  if (m_selfNode.successor == m_selfNode.predecessor && (first_node_id >= 0))
  {
    m_selfNode.successor = message.GetLookUp().JoinNode;
    m_selfNode.predecessor = message.GetLookUp().JoinNode;
    SendCommand(message.GetLookUp().JoinNode, Send_Command::SET_ALL, ipAddr, ipAddr);
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
  else{
    uint32_t keyA = PennKeyHelper::CreateShaKey(A);
    uint32_t keyB = PennKeyHelper::CreateShaKey(B);
    uint32_t keyC = PennKeyHelper::CreateShaKey(C);
    bool isInCircle = CheckInside(keyA, keyB, keyC);
    if(isInCircle){
      SendCommand(A, Send_Command::SET_PRE, B, B);
      SendCommand(A, Send_Command::SET_SUCC, C, C);
      SendCommand(B, Send_Command::SET_SUCC, A, A);
      SendCommand(C, Send_Command::SET_PRE, A, A);
    }
    else{
      message.SetLookUpThoughNode(m_selfNode.successor);
      transmitRequest(message, m_selfNode.successor);
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
    find_status = CheckInside(keyA, keyB, keyC);
    // if (keyC > keyB)
    // {
    //   if (keyA > keyB && keyA < keyC)
    //   {
    //     find_status = 1;
    //   }
    //   else
    //   {
    //     // 发送到下一个节点请求
    //     transmitRequest(message, target_addr);
    //   }
    // }
    // else if (keyC < keyB && ((keyA < keyC) || keyA > keyB))
    // {
    //   find_status = 1;
    // }
    // else
    // {
    //   // 发送到下一个节点请求
    //   transmitRequest(message, target_addr);
    // }

    // 如果找到了
    if (find_status)
    {
      message.SetPennSearchOperation("publish_set");
      transmitRequest(message, target_addr);
    }
    else{
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
      find_status = CheckInside(keyA, keyB, keyC);

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
bool PennChord::CheckInside(uint32_t keyA, uint32_t keyB, uint32_t keyC)
{
  bool find_status = 0;
  if (keyC > keyB)
  {
    if (keyA > keyB && keyA < keyC)
    {
      find_status = 1;
    }
  }
  else if (keyC < keyB && ((keyA < keyC) || keyA > keyB))
  {
    find_status = 1;
  }
  return find_status;
}

// NEED FIX: 
// leave之后在join一堆空的，需要测试这种工况