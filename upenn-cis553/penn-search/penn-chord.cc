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
  message.SetLookUpMessage("join");
  message.SetLookUpMessageType("LookupReq_Join");
  // message.SetNodenumber(JoinNodeId); // 发送请求的节点ID
  // std::cout << though_addr << "  " << message.GetLookUp().ThroughNode<< std::endl;
  // std::cout << "Prepare to send join request to: " << message.GetLookUp().JoinNode << "  from " << message.GetLookUp().ThoughNode << std::endl;
  // if(DEBUG) std::cout << "发送出的消息: " << "JoinNode: " << message.GetLookUp().JoinNode << "ThoughNode: " << message.GetLookUp().ThoughNode << std::endl;
  transmitRequest(message, though_addr);
}

void PennChord::ProcessCommand(std::vector<std::string> tokens)
{
  if (tokens.empty())
  {
    ERROR_LOG("Empty command received");
    return;
  }

  std::string command = tokens[0];
  std::cout << "----------------------------COMMAND:" << command[0] << "----------------------------" << std::endl;
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
  // case PennChordMessage::RING_STATE:
  //   ProcessRingState(message, sourceAddress, sourcePort);
  //   break;
  default:
    ERROR_LOG("Unknown Message Type!");
    break;
  }
  // std::cout << " DEBUG【" << JoinNodeId << "】 INFO " << m_selfNode.successor << "(" << GetIdFromIp(m_selfNode.successor) << ")   " << m_selfNode.predecessor << " " << "(" << GetIdFromIp(m_selfNode.predecessor) << ")" << ipAddr << std::endl;
}

void PennChord::ProcessLookUp(PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  // Ipv4Address fromNode = message.GetLookUp().JoinNode;
  // Ipv4Address orinNode = message.GetLookUp().ThoughNode;
  std::string lookupMessage = message.GetLookUp().lookupMessage;

  if (lookupMessage != "LookupReq_Join")
    return;
  // if(DEBUG) std::cout << "接受到的消息: " << "JoinNode: " << message.GetLookUp().JoinNode << "ThoughNode: " << message.GetLookUp().ThoughNode << std::endl;
  // std::cout << "Received Lookup message from: " << message.GetLookUp().JoinNode << ", Message: " << message.GetLookUp().lookupMessage << "   from  " << orinNode << std::endl;
  //  if (lookupMessage == "LookupReq_Join" || lookupMessage == "LookupReq_Search" || lookupMessage == "LookupReq_InvertedList")

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
  if (m_selfNode.successor == m_selfNode.predecessor && (first_node_id >= 0))
  {
    m_selfNode.successor = message.GetLookUp().JoinNode;
    m_selfNode.predecessor = message.GetLookUp().JoinNode;
    SendCommand(message.GetLookUp().JoinNode, Send_Command::SET_ALL, ipAddr, ipAddr);
    first_node_id = -1;
  }
  else if (PennKeyHelper::CreateShaKey(C) > PennKeyHelper::CreateShaKey(B))
  {
    uint32_t keyA = PennKeyHelper::CreateShaKey(A);
    uint32_t keyB = PennKeyHelper::CreateShaKey(B);
    uint32_t keyC = PennKeyHelper::CreateShaKey(C);
    if (keyA > keyB && keyA < keyC)
    {
      SendCommand(A, Send_Command::SET_PRE, B, B);
      SendCommand(A, Send_Command::SET_SUCC, C, C);
      SendCommand(B, Send_Command::SET_SUCC, A, A);
      SendCommand(C, Send_Command::SET_PRE, A, A);
    }
    else if (keyA > keyC && keyA < keyB)
    {
      SendCommand(A, Send_Command::SET_PRE, C, C);
      SendCommand(A, Send_Command::SET_SUCC, B, B);
      SendCommand(C, Send_Command::SET_SUCC, A, A);
      SendCommand(B, Send_Command::SET_PRE, A, A);
    }
    else
    {
      message.SetLookUpThoughNode(m_selfNode.successor);
      transmitRequest(message, m_selfNode.successor);
    }
  }
  else if (PennKeyHelper::CreateShaKey(C) < PennKeyHelper::CreateShaKey(B) && ((PennKeyHelper::CreateShaKey(A) < PennKeyHelper::CreateShaKey(C)) || (PennKeyHelper::CreateShaKey(A) > PennKeyHelper::CreateShaKey(B))))
  {
    SendCommand(C, Send_Command::SET_PRE, message.GetLookUp().JoinNode, A);
    SendCommand(B, Send_Command::SET_SUCC, message.GetLookUp().JoinNode, A);

    SendCommand(A, Send_Command::SET_PRE, B, B);
    SendCommand(A, Send_Command::SET_SUCC, C, C);
  }
  else
  {
    // std::cout<<"FUCK3"<<std::endl;
    message.SetLookUpThoughNode(m_selfNode.successor);
    transmitRequest(message, m_selfNode.successor);
  }
  // sign_1=CheckIsInCircle
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
  std::cout << "Ring State" << std::endl;
  std::cout << "Curr<Node " << JoinNodeId << ", " << ipAddr << ", " 
            << CreateShaKey_(ipAddr) << ">" << std::endl;
  std::cout << "Pred<Node " << GetIdFromIp(m_selfNode.predecessor) << ", " 
            << m_selfNode.predecessor << ", " 
            << CreateShaKey_(m_selfNode.predecessor) << ">" << std::endl;
  std::cout << "Succ<Node " << GetIdFromIp(m_selfNode.successor) << ", " 
            << m_selfNode.successor << ", " 
            << CreateShaKey_(m_selfNode.successor) << ">" << std::endl;
  std::cout<< std::endl;
}
