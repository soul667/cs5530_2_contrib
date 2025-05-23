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

#include "penn-search.h"
#include "ns3/grader-logs.h"

#include "ns3/random-variable-stream.h"
#include "ns3/inet-socket-address.h"

using namespace ns3;

TypeId
PennSearch::GetTypeId()
{
  static TypeId tid = TypeId("PennSearch")
                          .SetParent<PennApplication>()
                          .AddConstructor<PennSearch>()
                          .AddAttribute("AppPort",
                                        "Listening port for Application",
                                        UintegerValue(10000),
                                        MakeUintegerAccessor(&PennSearch::m_appPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("ChordPort",
                                        "Listening port for Application",
                                        UintegerValue(10001),
                                        MakeUintegerAccessor(&PennSearch::m_chordPort),
                                        MakeUintegerChecker<uint16_t>())
                          .AddAttribute("PingTimeout",
                                        "Timeout value for PING_REQ in milliseconds",
                                        TimeValue(MilliSeconds(2000)),
                                        MakeTimeAccessor(&PennSearch::m_pingTimeout),
                                        MakeTimeChecker());
  return tid;
}

PennSearch::PennSearch()
    : m_auditPingsTimer(Timer::CANCEL_ON_DESTROY)
{
  m_chord = NULL;

  Ptr<UniformRandomVariable> m_uniformRandomVariable = CreateObject<UniformRandomVariable>();
  m_currentTransactionId = m_uniformRandomVariable->GetValue(0x00000000, 0xFFFFFFFF);
}

PennSearch::~PennSearch()
{
}

void PennSearch::DoDispose()
{
  StopApplication();
  PennApplication::DoDispose();

  // FOR TESTING
  GraderLogs::HelloGrader(ReverseLookup(GetLocalAddress()), GetLocalAddress());
}

void PennSearch::StartApplication(void)
{
  std::cout << "PennSearch::StartApplication()!!!!!" << std::endl;  // remove: to avoid printing
  // Create and Configure PennChord
  ObjectFactory factory;

  factory.SetTypeId(PennChord::GetTypeId());
  factory.Set("AppPort", UintegerValue(m_chordPort));
  m_chord = factory.Create<PennChord>();
  m_chord->SetNode(GetNode());
  m_chord->SetNodeAddressMap(m_nodeAddressMap);
  m_chord->SetAddressNodeMap(m_addressNodeMap);
  m_chord->SetModuleName("CHORD");
  std::string nodeId = GetNodeId();
  m_chord->SetNodeId(nodeId);
  m_chord->SetLocalAddress(m_local);

  // Configure Callbacks with Chord
  m_chord->SetPingSuccessCallback(MakeCallback(&PennSearch::HandleChordPingSuccess, this));
  m_chord->SetPingFailureCallback(MakeCallback(&PennSearch::HandleChordPingFailure, this));
  m_chord->SetPingRecvCallback(MakeCallback(&PennSearch::HandleChordPingRecv, this));
  // Start Chord
  m_chord->SetStartTime(Simulator::Now());
  m_chord->Initialize();

  if (m_socket == 0)
  {
    TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    m_socket = Socket::CreateSocket(GetNode(), tid);
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_appPort);
    m_socket->Bind(local);
    m_socket->SetRecvCallback(MakeCallback(&PennSearch::RecvMessage, this));
  }

  // Configure timers
  m_auditPingsTimer.SetFunction(&PennSearch::AuditPings, this);
  // Start timers
  m_auditPingsTimer.Schedule(m_pingTimeout);
}

void PennSearch::StopApplication(void)
{
  // Stop chord
  m_chord->StopChord();
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

void PennSearch::ProcessCommand(std::vector<std::string> tokens)
{
  std::vector<std::string>::iterator iterator = tokens.begin();
  std::string command = *iterator;
  if (command == "CHORD")
  {
    // Send to Chord Sub-Layer
    tokens.erase(iterator);
    m_chord->ProcessCommand(tokens);
  }
  if (command == "PING")
  {
    if (tokens.size() < 3)
    {
      ERROR_LOG("Insufficient PING params...");
      return;
    }
    iterator++;
    if (*iterator != "*")
    {
      std::string nodeId = *iterator;
      iterator++;
      std::string pingMessage = *iterator;
      SendPing(nodeId, pingMessage);
    }
    else
    {
      iterator++;
      std::string pingMessage = *iterator;
      std::map<uint32_t, Ipv4Address>::iterator iter;
      for (iter = m_nodeAddressMap.begin(); iter != m_nodeAddressMap.end(); iter++)
      {
        std::ostringstream sin;
        uint32_t nodeNumber = iter->first;
        sin << nodeNumber;
        std::string nodeId = sin.str();
        SendPing(nodeId, pingMessage);
      }
    }
  }
  else
  {
    if (command == "PUBLISH")
    {
      // std::cout << "----------------------------PUBLISH----------------------------" << std::endl;
      // std::cout << *iterator << std::endl;
      // int now_id = 0;
      // for (std::string &s : tokens)
      // {
      //   std::cout << "token【"<<now_id<<"】" << s<<std::endl;
      //   now_id+=1;
      // }
      // std::cout << "----------------------------PUBLISH----------------------------" << std::endl;
      std::string filename = tokens.at(1);
      PublishUse(filename);
    }
    else if(command=="SEARCH"){

      SearchUse(tokens);
    }
  }
}

void PennSearch::SendPing(std::string nodeId, std::string pingMessage)
{
  // Send Ping Via-Chord layer
  SEARCH_LOG("Sending Ping via Chord Layer to node: " << nodeId << " Message: " << pingMessage);
  Ipv4Address destAddress = ResolveNodeIpAddress(nodeId);
  m_chord->SendPing(destAddress, pingMessage);
}

void PennSearch::SendPennSearchPing(Ipv4Address destAddress, std::string pingMessage)
{
  if (destAddress != Ipv4Address::GetAny())
  {
    uint32_t transactionId = GetNextTransactionId();
    SEARCH_LOG("Sending PING_REQ to Node: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << pingMessage << " transactionId: " << transactionId);
    Ptr<PingRequest> pingRequest = Create<PingRequest>(transactionId, Simulator::Now(), destAddress, pingMessage);
    // Add to ping-tracker
    m_pingTracker.insert(std::make_pair(transactionId, pingRequest));
    Ptr<Packet> packet = Create<Packet>();
    PennSearchMessage message = PennSearchMessage(PennSearchMessage::PING_REQ, transactionId);
    message.SetPingReq(pingMessage);
    packet->AddHeader(message);
    m_socket->SendTo(packet, 0, InetSocketAddress(destAddress, m_appPort));
  }
}

void PennSearch::RecvMessage(Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom(sourceAddr);
  InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom(sourceAddr);
  Ipv4Address sourceAddress = inetSocketAddr.GetIpv4();
  uint16_t sourcePort = inetSocketAddr.GetPort();
  PennSearchMessage message;
  packet->RemoveHeader(message);

  switch (message.GetMessageType())
  {
  case PennSearchMessage::PING_REQ:
    ProcessPingReq(message, sourceAddress, sourcePort);
    break;
  case PennSearchMessage::PING_RSP:
    ProcessPingRsp(message, sourceAddress, sourcePort);
    break;
  default:
    ERROR_LOG("Unknown Message Type!");
    break;
  }
}

void PennSearch::ProcessPingReq(PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{

  // Use reverse lookup for ease of debug
  std::string fromNode = ReverseLookup(sourceAddress);
  SEARCH_LOG("Received PING_REQ, From Node: " << fromNode << ", Message: " << message.GetPingReq().pingMessage);
  // Send Ping Response
  PennSearchMessage resp = PennSearchMessage(PennSearchMessage::PING_RSP, message.GetTransactionId());
  resp.SetPingRsp(message.GetPingReq().pingMessage);
  Ptr<Packet> packet = Create<Packet>();
  packet->AddHeader(resp);
  m_socket->SendTo(packet, 0, InetSocketAddress(sourceAddress, sourcePort));
}

void PennSearch::ProcessPingRsp(PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  // Remove from pingTracker
  std::map<uint32_t, Ptr<PingRequest>>::iterator iter;
  iter = m_pingTracker.find(message.GetTransactionId());
  if (iter != m_pingTracker.end())
  {
    std::string fromNode = ReverseLookup(sourceAddress);
    SEARCH_LOG("Received PING_RSP, From Node: " << fromNode << ", Message: " << message.GetPingRsp().pingMessage);
    m_pingTracker.erase(iter);
  }
  else
  {
    DEBUG_LOG("Received invalid PING_RSP!");
  }
}

void PennSearch::AuditPings()
{
  std::map<uint32_t, Ptr<PingRequest>>::iterator iter;
  for (iter = m_pingTracker.begin(); iter != m_pingTracker.end();)
  {
    Ptr<PingRequest> pingRequest = iter->second;
    if (pingRequest->GetTimestamp().GetMilliSeconds() + m_pingTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
    {
      DEBUG_LOG("Ping expired. Message: " << pingRequest->GetPingMessage() << " Timestamp: " << pingRequest->GetTimestamp().GetMilliSeconds() << " CurrentTime: " << Simulator::Now().GetMilliSeconds());
      // Remove stale entries
      m_pingTracker.erase(iter++);
    }
    else
    {
      ++iter;
    }
  }
  // Rechedule timer
  m_auditPingsTimer.Schedule(m_pingTimeout);
}

uint32_t
PennSearch::GetNextTransactionId()
{
  return m_currentTransactionId++;
}

// Handle Chord Callbacks

void PennSearch::HandleChordPingFailure(Ipv4Address destAddress, std::string message)
{
  SEARCH_LOG("Chord Ping Expired! Destination nodeId: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << message);
}

void PennSearch::HandleChordPingSuccess(Ipv4Address destAddress, std::string message)
{
  SEARCH_LOG("Chord Ping Success! Destination nodeId: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << message);
  // Send ping via search layer
  SendPennSearchPing(destAddress, message);
}

void PennSearch::HandleChordPingRecv(Ipv4Address destAddress, std::string message)
{
  SEARCH_LOG("Chord Layer Received Ping! Source nodeId: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << message);
}

// Override PennLog

void PennSearch::SetTrafficVerbose(bool on)
{
  m_chord->SetTrafficVerbose(on);
  g_trafficVerbose = on;
}

void PennSearch::SetErrorVerbose(bool on)
{
  m_chord->SetErrorVerbose(on);
  g_errorVerbose = on;
}

void PennSearch::SetDebugVerbose(bool on)
{
  m_chord->SetDebugVerbose(on);
  g_debugVerbose = on;
}

void PennSearch::SetStatusVerbose(bool on)
{
  m_chord->SetStatusVerbose(on);
  g_statusVerbose = on;
}

void PennSearch::SetChordVerbose(bool on)
{
  m_chord->SetChordVerbose(on);
  g_chordVerbose = on;
}

void PennSearch::SetSearchVerbose(bool on)
{
  m_chord->SetSearchVerbose(on);
  g_searchVerbose = on;
}

void PennSearch::PublishUse(std::string filename)
{
  std::vector<Document> docs;
  std::ifstream f(filename, std::ios_base::in);
  std::string line;

  while (std::getline(f, line))
  {
    std::istringstream iss(line);
    Document doc;
    iss >> doc.name;
    m_termList.push_back(doc.name);
    std::string term;
    // std::cout<<"----------------------------PUBLISH Function----------------------------" << std::endl;
    // std::cout<<"doc.name: "<<doc.name<<std::endl;
    while (iss >> term)
    {
      doc.terms.push_back(term);
      m_invertedLists[term].push_back(doc.name);
      // GraderLogs::Publish(doc.name, term);
      // 第一个参数是Keyword 第二个参数是文档名
      SEARCH_LOG(GraderLogs::GetPublishLogStr(term,doc.name));

      // std::cout << "term: " << term << std::endl;
    }

    // std::cout<<"----------------------------PUBLISH Function----------------------------" << std::endl;
  }

  for(std::map<std::string, std::vector<std::string>>::iterator it = m_invertedLists.begin(); it != m_invertedLists.end(); ++it)
  {
    // uint32_t hash_use = PennKeyHelper::CreateShaKey( it->first);
    // std::cout << "Inverted List: " << it->first <<"("<<hash_use<<")"<< " -> ";
    m_chord->ProcessPublish(it->first, it->second);
    // for (const auto &docName : it->second)
    // {
    //   std::cout << docName << " ";
    // }
    // std::cout << std::endl;
  }

}


void PennSearch::SearchUse(std::vector<std::string>tokens)
{
// token【0】SEARCH
// token【1】17
// token【2】George-Clooney
// token【3】Brad-Pitt
// token【4】Matt-Damon
  // std::cout << "----------------------------SEARCH----------------------------" << std::endl;
  // std::vector<std::string>::iterator iterator = tokens.begin();
  // std::cout << *iterator << std::endl;
  // int now_id = 0;
  // for (std::string &s : tokens)
  // {
  //   std::cout << "token【"<<now_id<<"】" << s<<std::endl;
  //   now_id+=1;
  // }
  uint32_t send_id = std::stoi(tokens.at(1));
  // 将2到末尾的元素重新放到一个vector中
  std::vector<std::string> findterms(tokens.begin() + 2, tokens.end());
  m_chord->ProcessSearch(send_id,findterms);
  // 输出重构后的vector
  // std::cout << "重构后的vector: ";
  // for (const auto &term : findterms)
  // {
  //   std::cout << term << " ";
  // }
// std::cout << "----------------------------SEARCH----------------------------" << std::endl;
}