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


#include "ns3/penn-chord.h"
#include "ns3/inet-socket-address.h"
#include "ns3/random-variable-stream.h"
#include "ns3/penn-key-helper.h"
#include "ns3/grader-logs.h"
#include <openssl/sha.h>

using namespace ns3;

TypeId
PennChord::GetTypeId ()
{
  static TypeId tid
      = TypeId ("PennChord")
            .SetParent<PennApplication> ()
            .AddConstructor<PennChord> ()
            .AddAttribute ("AppPort", "Listening port for Application", UintegerValue (10001),
                           MakeUintegerAccessor (&PennChord::m_appPort), MakeUintegerChecker<uint16_t> ())
            .AddAttribute ("PingTimeout", "Timeout value for PING_REQ in milliseconds", TimeValue (MilliSeconds (2000)),
                           MakeTimeAccessor (&PennChord::m_pingTimeout), MakeTimeChecker ())
  ;
  return tid;
}

PennChord::PennChord ()
    : m_auditPingsTimer (Timer::CANCEL_ON_DESTROY)
{
  Ptr<UniformRandomVariable> m_uniformRandomVariable = CreateObject<UniformRandomVariable> ();
  m_currentTransactionId = m_uniformRandomVariable->GetValue (0x00000000, 0xFFFFFFFF);
}

PennChord::~PennChord ()
{

}

void
PennChord::DoDispose ()
{
  StopApplication ();
  PennApplication::DoDispose ();
}


void
PennChord::StartApplication (void)
{
  // UDP socket to receive incoming messages
  std::cout << "PennChord::StartApplication()!!!!!" << std::endl;
  if (m_socket == 0)
    { 
      TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
      m_socket = Socket::CreateSocket (GetNode (), tid);
      InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny(), m_appPort);
      m_socket->Bind (local);
      m_socket->SetRecvCallback (MakeCallback (&PennChord::RecvMessage, this));
      // std::cout << "reset m_socekt to not null, now is " << m_socket << std::endl;
    }  
  
  // Configure timers
  m_auditPingsTimer.SetFunction (&PennChord::AuditPings, this);
  // Start timers
  m_auditPingsTimer.Schedule (m_pingTimeout);

  // need fix copy from open source
  m_mainAddress = ResolveNodeIpAddress(GetNode()->GetId());
  m_StabilizeTimer.SetFunction (&PennChord::SendStabReq, this);
}

void
PennChord::ProcessCommand (std::vector<std::string> tokens)
{
  std::vector<std::string>::iterator iterator = tokens.begin();
  std::string command = *iterator;
  // command type
  // Start landmark node   eg:0 PENNSEARCH CHORD JOIN 0
  // Nodes join  E.g., 1 PENNSEARCH CHORD JOIN 0
  // Voluntary node departure  E.g., 1 PENNSEARCH CHORD LEAVE
  switch (command[0])
  {
    case 'j':
    case 'J':
      {
        // 提取参数
        iterator++;
        std::istringstream sin(*iterator);
        uint32_t nodeNumber;
        sin >> nodeNumber;
        
        // 生成当前节点的哈希值
        std::string key = GetHash(GetLocalAddress());
        
        // 检查是否是自己(创建新环) 
        if(m_addressNodeMap[GetLocalAddress()] != nodeNumber)
        {
          // 作为一个新节点加入现有环
          Ipv4Address originNode = GetLocalAddress();
          uint32_t transactionId = GetNextTransactionId();
          PennChordMessage message = PennChordMessage(PennChordMessage::LOOKUP_MSG, transactionId);
          message.SetLookupMsg(key, originNode, "LookupReq_Join");
          
          // FIX: ERROR
          // ForwardLookup(message, ResolveNodeIpAddress(nodeNumber));
        }
        else
        {
          // 作为第一个节点创建环
          CreateRing(key);
        }
        
        // 启动稳定化定时器
        m_stabilizeTimer.Schedule(m_stabilizeTimeout);
        break;
      }
      
    case 'l':
    case 'L':
      {
        // 处理离开请求
        if(successorIp != Ipv4Address::GetAny() && GetLocalAddress() != successorIp)
        {
          // 通知后继节点
          uint32_t transactionId = GetNextTransactionId();
          PennChordMessage message = PennChordMessage(PennChordMessage::LOOKUP_MSG, transactionId);
          // FIX THIS
          // message.SetLookupMsg(predecessorIp, "leave_UpdatePred");
          ForwardLookup(message, successorIp);
        }
        
        if(predecessorIp != Ipv4Address::GetAny() && GetLocalAddress() != predecessorIp)
        {
          // 通知前驱节点
          uint32_t transactionId = GetNextTransactionId();
          PennChordMessage message = PennChordMessage(PennChordMessage::LOOKUP_MSG, transactionId);
          // FIX: ERROR
          // message.SetLookupMsg(successorIp, "leave_UpdateSucc");
          ForwardLookup(message, predecessorIp);
        }
        
        // 清理本节点状态
        predecessor = "0";
        successor = "0";
        predecessorIp = Ipv4Address::GetAny();
        successorIp = Ipv4Address::GetAny();
        break;
      }
      
    case 'r':
    case 'R':
      {
        // 处理环状态请求
        if(successor == "0")
        {
          ERROR_LOG("The node " << ReverseLookup(GetLocalAddress()) << " is not in any ring!");
        }
        else
        {
          std::string currKey = GetHash(GetLocalAddress());
          // 使用GraderLogs记录环状态
          GraderLogs::RingState(GetLocalAddress(), ReverseLookup(GetLocalAddress()), 
                             PennKeyHelper::CreateShaKey(GetLocalAddress()),
                             predecessorIp, ReverseLookup(predecessorIp),
                             PennKeyHelper::CreateShaKey(predecessorIp),
                             successorIp, ReverseLookup(successorIp),
                             PennKeyHelper::CreateShaKey(successorIp));
          
          if(GetLocalAddress() != successorIp)
          {
            // 转发到后继节点继续遍历
            uint32_t transactionId = GetNextTransactionId();
            PennChordMessage message = PennChordMessage(PennChordMessage::LOOKUP_MSG, transactionId);
            message.SetLookupMsg(GetHash(GetLocalAddress()), GetLocalAddress(), "Ringstate");
            ForwardLookup(message, successorIp);
          }
          else
          {
            // 完成环的遍历
            GraderLogs::EndOfRingState();
          }
        }
        break;
      }
      
    default:
      ERROR_LOG("Unknown command: " << command);
      break;
  }
}

//   // Cancel timers
//   m_auditPingsTimer.Cancel ();

//   m_pingTracker.clear ();
// }

// void
// PennChord::ProcessCommand (std::vector<std::string> tokens)
// {
//   std::vector<std::string>::iterator iterator = tokens.begin();
//   std::string command = *iterator;
//   // <new> 
//   // TODO: DELL WITH COMMAND
//   // start at there


// }

void
PennChord::SendPing (Ipv4Address destAddress, std::string pingMessage)
{
  if (destAddress != Ipv4Address::GetAny ())
    {
      uint32_t transactionId = GetNextTransactionId ();
      CHORD_LOG ("Sending PING_REQ to Node: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << pingMessage << " transactionId: " << transactionId);
      Ptr<PingRequest> pingRequest = Create<PingRequest> (transactionId, Simulator::Now(), destAddress, pingMessage);
      // Add to ping-tracker
      m_pingTracker.insert (std::make_pair (transactionId, pingRequest));
      Ptr<Packet> packet = Create<Packet> ();
      PennChordMessage message = PennChordMessage (PennChordMessage::PING_REQ, transactionId);
      message.SetPingReq (pingMessage);
      packet->AddHeader (message);
      m_socket->SendTo (packet, 0 , InetSocketAddress (destAddress, m_appPort));
      
    }
  else
    {
      // Report failure   
      m_pingFailureFn (destAddress, pingMessage);
    }
}

void
PennChord::RecvMessage (Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddr);
  InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom (sourceAddr);
  Ipv4Address sourceAddress = inetSocketAddr.GetIpv4 ();
  uint16_t sourcePort = inetSocketAddr.GetPort ();
  PennChordMessage message;
  packet->RemoveHeader (message);

  switch (message.GetMessageType ())
    {
      case PennChordMessage::PING_REQ:
        ProcessPingReq (message, sourceAddress, sourcePort);
        break;
      case PennChordMessage::PING_RSP:
        ProcessPingRsp (message, sourceAddress, sourcePort);
        break;
        // -------new---------
      
        //--------------------
      default:
        ERROR_LOG ("Unknown Message Type!");
        break;
    }
}

void
PennChord::ProcessPingReq (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{

    // Use reverse lookup for ease of debug
    std::string fromNode = ReverseLookup (sourceAddress);
    CHORD_LOG ("Received PING_REQ, From Node: " << fromNode << ", Message: " << message.GetPingReq().pingMessage);
    // Send Ping Response
    PennChordMessage resp = PennChordMessage (PennChordMessage::PING_RSP, message.GetTransactionId());
    resp.SetPingRsp (message.GetPingReq().pingMessage);
    Ptr<Packet> packet = Create<Packet> ();
    packet->AddHeader (resp);
    m_socket->SendTo (packet, 0 , InetSocketAddress (sourceAddress, sourcePort));
    // Send indication to application layer
    m_pingRecvFn (sourceAddress, message.GetPingReq().pingMessage);
}

void
PennChord::ProcessPingRsp (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  // Remove from pingTracker
  std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
  iter = m_pingTracker.find (message.GetTransactionId ());
  if (iter != m_pingTracker.end ())
    {
      std::string fromNode = ReverseLookup (sourceAddress);
      CHORD_LOG ("Received PING_RSP, From Node: " << fromNode << ", Message: " << message.GetPingRsp().pingMessage);
      m_pingTracker.erase (iter);
      // Send indication to application layer
      m_pingSuccessFn (sourceAddress, message.GetPingRsp().pingMessage);
    }
  else
    {
      DEBUG_LOG ("Received invalid PING_RSP!");
    }
}

void
PennChord::ProcessCommand (std::vector<std::string> tokens)
{
  std::vector<std::string>::iterator iterator = tokens.begin();
  std::string command = *iterator;

  switch (command[0])
  {
    case 'j':
    case 'J':
      {
        if (tokens.size() < 2)  // xx join n
        {
          ERROR_LOG ("Insufficient join params...");
          return;
        }
        iterator++;
        std::istringstream sin(*iterator);
        uint32_t nodeNumber;
        sin >> nodeNumber;
        
        // 生成当前节点的哈希值
        std::string key = GetHash(m_mainAddress);
        
        // 检查是否是自己(创建新环) 
        if(m_addressNodeMap[m_mainAddress] != nodeNumber)
        {
          // 作为一个新节点加入现有环
          Ipv4Address originNode = m_mainAddress;
          uint32_t transactionId = GetNextTransactionId();
          PennChordMessage message = PennChordMessage(PennChordMessage::LOOKUP_MSG, transactionId);
          message.SetLookupMsg(key, originNode, "LookupReq_Join");
          message.SetLookupMsg(ResolveNodeIpAddress(nodeNumber), "LookupReq_Join");
          
          ForwardLookup(message, ResolveNodeIpAddress(nodeNumber));
        }
        else
        {
          // 作为第一个节点创建环
          CreateRing(key);
        }
        
        // 启动稳定化定时器
        m_stabilizeTimer.Schedule(m_stabilizeTimeout);
        break;
      }
      
    case 'l':
    case 'L':
      {
        // 处理离开请求
        if(successorIp != Ipv4Address::GetAny() && m_mainAddress != successorIp)
        {
          // 通知后继节点
          uint32_t transactionId = GetNextTransactionId();
          PennChordMessage message = PennChordMessage(PennChordMessage::LOOKUP_MSG, transactionId);
          message.SetLookupMsg(predecessorIp, "leave_UpdatePred");
          ForwardLookup(message, successorIp);
        }
        
        if(predecessorIp != Ipv4Address::GetAny() && m_mainAddress != predecessorIp)
        {
          // 通知前驱节点
          uint32_t transactionId = GetNextTransactionId();
          PennChordMessage message = PennChordMessage(PennChordMessage::LOOKUP_MSG, transactionId);
          message.SetLookupMsg(successorIp, "leave_UpdateSucc");
          ForwardLookup(message, predecessorIp);
        }
        
        // 清理本节点状态
        predecessor = "0";
        successor = "0";
        predecessorIp = Ipv4Address::GetAny();
        successorIp = Ipv4Address::GetAny();
        break;
      }
      
    case 'r':
    case 'R':
      {
        // 处理环状态请求
        if(successor == "0")
        {
          ERROR_LOG("The node " << ReverseLookup(m_mainAddress) << " is not in any ring!");
        }
        else
        {
          std::string currKey = GetHash(m_mainAddress);
          // 使用GraderLogs记录环状态
          GraderLogs::RingState(m_mainAddress, ReverseLookup(m_mainAddress), 
                             PennKeyHelper::CreateShaKey(m_mainAddress),
                             predecessorIp, ReverseLookup(predecessorIp),
                             PennKeyHelper::CreateShaKey(predecessorIp),
                             successorIp, ReverseLookup(successorIp),
                             PennKeyHelper::CreateShaKey(successorIp));
          
          if(m_mainAddress != successorIp)
          {
            // 转发到后继节点继续遍历
            uint32_t transactionId = GetNextTransactionId();
            PennChordMessage message = PennChordMessage(PennChordMessage::LOOKUP_MSG, transactionId);
            message.SetLookupMsg(GetHash(m_mainAddress), m_mainAddress, "Ringstate");
            ForwardLookup(message, successorIp);
          }
          else
          {
            // 完成环的遍历
            GraderLogs::EndOfRingState();
          }
        }
        break;
      }
      
    default:
      ERROR_LOG("Unknown command: " << command);
      break;
  }
}
      else
        {
          ++iter;
        }
    }
  // Rechedule timer
  m_auditPingsTimer.Schedule (m_pingTimeout); 
}

uint32_t
PennChord::GetNextTransactionId ()
{
  return m_currentTransactionId++;
}

void
PennChord::StopChord ()
{
  StopApplication ();
}

void
PennChord::SetPingSuccessCallback (Callback <void, Ipv4Address, std::string> pingSuccessFn)
{
  m_pingSuccessFn = pingSuccessFn;
}


void
PennChord::SetPingFailureCallback (Callback <void, Ipv4Address, std::string> pingFailureFn)
{
  m_pingFailureFn = pingFailureFn;
}

void
PennChord::SetPingRecvCallback (Callback <void, Ipv4Address, std::string> pingRecvFn)
{
  m_pingRecvFn = pingRecvFn;
}

std::string
PennChord::GetHash(Ipv4Address ip)
{
  // 使用PennKeyHelper创建哈希值
  uint32_t hashValue = PennKeyHelper::CreateShaKey(ip);
  return PennKeyHelper::KeyToHexString(hashValue);
}

void
PennChord::CreateRing(const std::string& key)
{
  // 初始化节点作为环中的第一个节点
  successor = key;
  predecessor = key;
  successorIp = m_mainAddress;
  predecessorIp = m_mainAddress;

  // 初始化路由表
  InitFingerTable();
}

void
PennChord::ForwardLookup(PennChordMessage& msg, Ipv4Address nextHop)
{
  uint32_t transactionId = GetNextTransactionId();
  Ptr<Packet> packet = Create<Packet>();
  packet->AddHeader(msg);
  m_socket->SendTo(packet, 0, InetSocketAddress(nextHop, m_appPort));
}

void
PennChord::InitFingerTable()
{
  m_numFingerEntries = 32; // 使用32位哈希
  fingerTable.clear();
  
  // 初始化所有表项指向自己
  ChordNode self;
  self.id = PennKeyHelper::CreateShaKey(m_mainAddress);
  self.addr = m_mainAddress;
  
  for(uint32_t i = 0; i < m_numFingerEntries; i++) {
    fingerTable.push_back(self);
  }
}

std::string
PennChord::GetFingerStart(int index)
{
  uint32_t nodeId = PennKeyHelper::CreateShaKey(m_mainAddress);
  uint32_t start = nodeId + (1 << index);
  return PennKeyHelper::KeyToHexString(start);
}

bool 
PennChord::IsInRange(const std::string& key, const std::string& start, const std::string& end)
{
  uint32_t keyInt = std::stoul(key, nullptr, 16);
  uint32_t startInt = std::stoul(start, nullptr, 16);
  uint32_t endInt = std::stoul(end, nullptr, 16);

  if(startInt < endInt) {
    return (keyInt > startInt && keyInt <= endInt);
  } else {
    // 处理环绕情况
    return (keyInt > startInt || keyInt <= endInt);
  }
}
