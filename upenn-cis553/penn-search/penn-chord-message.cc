/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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

#include "penn-chord-message.h"
#include "ns3/log.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("PennChordMessage");
NS_OBJECT_ENSURE_REGISTERED(PennChordMessage);

PennChordMessage::PennChordMessage()
    : Header(), m_messageType(MessageType(0)), m_transactionId(0), m_message()
{
}

PennChordMessage::~PennChordMessage()
{
}

PennChordMessage::PennChordMessage(PennChordMessage::MessageType messageType, uint32_t transactionId)
    : Header(), m_messageType(messageType), m_transactionId(transactionId), m_message()
{
}

TypeId
PennChordMessage::GetTypeId(void)
{
  static TypeId tid = TypeId("PennChordMessage")
                          .SetParent<Header>()
                          .AddConstructor<PennChordMessage>();
  return tid;
}

TypeId
PennChordMessage::GetInstanceTypeId(void) const
{
  return GetTypeId();
}

uint32_t
PennChordMessage::GetSerializedSize(void) const
{
  // size of messageType, transaction id
  uint32_t size = sizeof(uint8_t) + sizeof(uint32_t);
  switch (m_messageType)
  {
  case PING_REQ:
    size += m_message.pingReq.GetSerializedSize();
    break;
  case PING_RSP:
    size += m_message.pingRsp.GetSerializedSize();
    break;
  case LOOK_UP:
    size += m_message.lookUpMessage.GetSerializedSize();
    break;
  case RING_STATE:
    size += m_message.ringState.GetSerializedSize();
    break;
  case PENNSEARCH:
    size += m_message.pennSearch.GetSerializedSize();
    break;
  default:
    NS_ASSERT(false);
  }
  return size;
}

void PennChordMessage::Print(std::ostream &os) const
{
  os << "\n****PennChordMessage Dump****\n";
  os << "messageType: " << m_messageType << "\n";
  os << "transactionId: " << m_transactionId << "\n";
  os << "PAYLOAD:: \n";

  switch (m_messageType)
  {
  case PING_REQ:
    m_message.pingReq.Print(os);
    break;
  case PING_RSP:
    m_message.pingRsp.Print(os);
    break;
  case LOOK_UP:
    m_message.lookUpMessage.Print(os);
    break;
  case RING_STATE:
    m_message.ringState.Print(os);
    break;
  case PENNSEARCH:
    m_message.pennSearch.Print(os);
    break;
  default:
    break;
  }
  os << "\n****END OF MESSAGE****\n";
}

void PennChordMessage::Serialize(Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteU8(m_messageType);
  i.WriteHtonU32(m_transactionId);

  switch (m_messageType)
  {
  case PING_REQ:
    m_message.pingReq.Serialize(i);
    break;
  case PING_RSP:
    m_message.pingRsp.Serialize(i);
    break;
  case LOOK_UP:
    m_message.lookUpMessage.Serialize(i);
    break;
  case RING_STATE:
    m_message.ringState.Serialize(i);
    break;
  case PENNSEARCH:
    m_message.pennSearch.Serialize(i);
    break;
  // case UPDATE_NEIGHBORS:
  //   m_message.updateNeighbors.Serialize (i);
  //   break;
  // case UODATE_ID_IP_AP:
  //   m_message.updateIdIpMap.Serialize (i);
  //   break;
  default:
    NS_ASSERT(false);
  }
}

uint32_t
PennChordMessage::Deserialize(Buffer::Iterator start)
{
  uint32_t size;
  Buffer::Iterator i = start;
  m_messageType = (MessageType)i.ReadU8();
  m_transactionId = i.ReadNtohU32();

  size = sizeof(uint8_t) + sizeof(uint32_t);

  switch (m_messageType)
  {
  case PING_REQ:
    size += m_message.pingReq.Deserialize(i);
    break;
  case PING_RSP:
    size += m_message.pingRsp.Deserialize(i);
    break;
  case LOOK_UP:
    size += m_message.lookUpMessage.Deserialize(i);
    break;
  case RING_STATE:
    size += m_message.ringState.Deserialize(i);
    break;
  case PENNSEARCH:
    size += m_message.pennSearch.Deserialize(i);
    break;
  // case UPDATE_NEIGHBORS:
  //   size += m_message.updateNeighbors.Deserialize (i);
  //   break;
  // case UODATE_ID_IP_AP:
  //   size += m_message.updateIdIpMap.Deserialize (i);
  //   break;
  default:
    NS_ASSERT(false);
  }
  return size;
}

/* UPDATE_ID_IP_MAP */

uint32_t
PennChordMessage::UpdataIdIpMap::GetSerializedSize(void) const
{
  uint32_t size = sizeof(uint32_t);                                         // Size of map
  size += (sizeof(uint32_t) + IPV4_ADDRESS_SIZE) * m_nodeAddressMap.size(); // Each entry has nodeId and ipAddr
  return size;
}

void PennChordMessage::UpdataIdIpMap::Print(std::ostream &os) const
{
  os << "UpdateIdIpMap:: Map Size: " << m_nodeAddressMap.size() << "\n";
  for (const auto &pair : m_nodeAddressMap)
  {
    os << "NodeID: " << pair.first << ", IP: " << pair.second << "\n";
  }
}

void PennChordMessage::UpdataIdIpMap::Serialize(Buffer::Iterator &start) const
{
  start.WriteHtonU32(m_nodeAddressMap.size());
  for (const auto &pair : m_nodeAddressMap)
  {
    start.WriteHtonU32(pair.first);
    uint8_t ipBuffer[IPV4_ADDRESS_SIZE];
    pair.second.Serialize(ipBuffer);
    start.Write(ipBuffer, IPV4_ADDRESS_SIZE);
  }
}

uint32_t
PennChordMessage::UpdataIdIpMap::Deserialize(Buffer::Iterator &start)
{
  uint32_t mapSize = start.ReadNtohU32();
  m_nodeAddressMap.clear();

  for (uint32_t i = 0; i < mapSize; ++i)
  {
    uint32_t nodeId = start.ReadNtohU32();
    uint8_t ipBuffer[IPV4_ADDRESS_SIZE];
    start.Read(ipBuffer, IPV4_ADDRESS_SIZE);
    Ipv4Address ipAddr;
    ipAddr.Deserialize(ipBuffer);
    m_nodeAddressMap[nodeId] = ipAddr;
  }

  return GetSerializedSize();
}

/* RING_STATE */

uint32_t
PennChordMessage::RingState::GetSerializedSize(void) const
{
  uint32_t size = IPV4_ADDRESS_SIZE * 2; // originatorNode and targetNode
  return size;
}

void PennChordMessage::RingState::Print(std::ostream &os) const
{
  os << "RingState:: Originator Node: " << originatorNode
     << ", Target Node: " << targetNode << "\n";
}

void PennChordMessage::RingState::Serialize(Buffer::Iterator &start) const
{
  uint8_t ipBuffer[IPV4_ADDRESS_SIZE];
  originatorNode.Serialize(ipBuffer);
  start.Write(ipBuffer, IPV4_ADDRESS_SIZE);
  targetNode.Serialize(ipBuffer);
  start.Write(ipBuffer, IPV4_ADDRESS_SIZE);
}

uint32_t
PennChordMessage::RingState::Deserialize(Buffer::Iterator &start)
{
  uint8_t ipBuffer[IPV4_ADDRESS_SIZE];
  start.Read(ipBuffer, IPV4_ADDRESS_SIZE);
  originatorNode.Deserialize(ipBuffer);
  start.Read(ipBuffer, IPV4_ADDRESS_SIZE);
  targetNode.Deserialize(ipBuffer);
  return GetSerializedSize();
}

/* UPDATE_NEIGHBORS */

uint32_t
PennChordMessage::UpdateNeighbors::GetSerializedSize(void) const
{
  uint32_t size = IPV4_ADDRESS_SIZE * 3; // targetNode, newSuccessor, newPredecessor
  return size;
}

void PennChordMessage::UpdateNeighbors::Print(std::ostream &os) const
{
  os << "UpdateNeighbors:: Target Node: " << targetNode
     << ", New Successor: " << newSuccessor
     << ", New Predecessor: " << newPredecessor << "\n";
}

void PennChordMessage::UpdateNeighbors::Serialize(Buffer::Iterator &start) const
{
  uint8_t ipBuffer[IPV4_ADDRESS_SIZE];

  targetNode.Serialize(ipBuffer);
  start.Write(ipBuffer, IPV4_ADDRESS_SIZE);

  newSuccessor.Serialize(ipBuffer);
  start.Write(ipBuffer, IPV4_ADDRESS_SIZE);

  newPredecessor.Serialize(ipBuffer);
  start.Write(ipBuffer, IPV4_ADDRESS_SIZE);
}

uint32_t
PennChordMessage::UpdateNeighbors::Deserialize(Buffer::Iterator &start)
{
  uint8_t ipBuffer[IPV4_ADDRESS_SIZE];

  start.Read(ipBuffer, IPV4_ADDRESS_SIZE);
  targetNode.Deserialize(ipBuffer);

  start.Read(ipBuffer, IPV4_ADDRESS_SIZE);
  newSuccessor.Deserialize(ipBuffer);

  start.Read(ipBuffer, IPV4_ADDRESS_SIZE);
  newPredecessor.Deserialize(ipBuffer);

  return GetSerializedSize();
}

/* PING_REQ */

uint32_t
PennChordMessage::PingReq::GetSerializedSize(void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + pingMessage.length();
  return size;
}

void PennChordMessage::PingReq::Print(std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void PennChordMessage::PingReq::Serialize(Buffer::Iterator &start) const
{
  start.WriteU16(pingMessage.length());
  start.Write((uint8_t *)(const_cast<char *>(pingMessage.c_str())), pingMessage.length());
}

uint32_t
PennChordMessage::PingReq::Deserialize(Buffer::Iterator &start)
{
  uint16_t length = start.ReadU16();
  char *str = (char *)malloc(length);
  start.Read((uint8_t *)str, length);
  pingMessage = std::string(str, length);
  free(str);
  return PingReq::GetSerializedSize();
}

void PennChordMessage::SetPingReq(std::string pingMessage)
{
  if (m_messageType == 0)
  {
    m_messageType = PING_REQ;
  }
  else
  {
    NS_ASSERT(m_messageType == PING_REQ);
  }
  m_message.pingReq.pingMessage = pingMessage;
}

PennChordMessage::PingReq
PennChordMessage::GetPingReq()
{
  return m_message.pingReq;
}

/* PING_RSP */

uint32_t
PennChordMessage::PingRsp::GetSerializedSize(void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + pingMessage.length();
  return size;
}

void PennChordMessage::PingRsp::Print(std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void PennChordMessage::PingRsp::Serialize(Buffer::Iterator &start) const
{
  start.WriteU16(pingMessage.length());
  start.Write((uint8_t *)(const_cast<char *>(pingMessage.c_str())), pingMessage.length());
}

uint32_t
PennChordMessage::PingRsp::Deserialize(Buffer::Iterator &start)
{
  uint16_t length = start.ReadU16();
  char *str = (char *)malloc(length);
  start.Read((uint8_t *)str, length);
  pingMessage = std::string(str, length);
  free(str);
  return PingRsp::GetSerializedSize();
}

void PennChordMessage::SetPingRsp(std::string pingMessage)
{
  if (m_messageType == 0)
  {
    m_messageType = PING_RSP;
  }
  else
  {
    NS_ASSERT(m_messageType == PING_RSP);
  }
  m_message.pingRsp.pingMessage = pingMessage;
}

PennChordMessage::PingRsp
PennChordMessage::GetPingRsp()
{
  return m_message.pingRsp;
}

void PennChordMessage::SetMessageType(MessageType messageType)
{
  m_messageType = messageType;
}

PennChordMessage::MessageType
PennChordMessage::GetMessageType() const
{
  return m_messageType;
}

void PennChordMessage::SetTransactionId(uint32_t transactionId)
{
  m_transactionId = transactionId;
}

uint32_t
PennChordMessage::GetTransactionId(void) const
{
  return m_transactionId;
}

/* LOOK_UP */

uint32_t
PennChordMessage::LookUp::GetSerializedSize(void) const
{
  // Calculate total byte size required for serialization
  const uint32_t ipv4AddressSize = sizeof(uint32_t);
  const uint32_t stringHeaderSize = sizeof(uint16_t);

  uint32_t totalSize = 0;
  totalSize += ipv4AddressSize * 3;                     // For JoinNode and ThoughNode and FromNode
  totalSize += stringHeaderSize + key.size();           // For key and its length
  totalSize += stringHeaderSize + lookupMessage.size(); // For lookupMessage and its length
  totalSize += sizeof(int) * 2;                         // maxDiff和Id
  return totalSize;
}

uint32_t
PennChordMessage::LookUp::Deserialize(Buffer::Iterator &start)
{
  // Extract ThoughNode IP address
  uint32_t thoughtNodeRaw = start.ReadNtohU32();
  ThoughNode = Ipv4Address(thoughtNodeRaw);

  // Extract JoinNode IP address
  uint32_t joinNodeRaw = start.ReadNtohU32();
  JoinNode = Ipv4Address(joinNodeRaw);

  // Extract FromNode IP address
  uint32_t fromNodeRaw = start.ReadNtohU32();
  FromNode = Ipv4Address(fromNodeRaw);

  // Extract key string
  uint16_t keyLength = start.ReadU16();
  std::vector<char> keyBuffer(keyLength);
  start.Read(reinterpret_cast<uint8_t *>(keyBuffer.data()), keyLength);
  key.assign(keyBuffer.data(), keyLength);

  // Extract lookup message string
  uint16_t msgLength = start.ReadU16();
  std::vector<char> msgBuffer(msgLength);
  start.Read(reinterpret_cast<uint8_t *>(msgBuffer.data()), msgLength);
  lookupMessage.assign(msgBuffer.data(), msgLength);
  // 新增字段反序列化
  finger_query_index = start.ReadNtohU32();
  Id = start.ReadNtohU32();

  return GetSerializedSize();
}

void PennChordMessage::LookUp::Serialize(Buffer::Iterator &start) const
{
  // Write the IP addresses
  start.WriteHtonU32(ThoughNode.Get());
  start.WriteHtonU32(JoinNode.Get());
  start.WriteHtonU32(FromNode.Get());
  // Write the key with its length
  const uint16_t keySize = static_cast<uint16_t>(key.size());
  start.WriteU16(keySize);
  if (keySize > 0)
  {
    const uint8_t *keyData = reinterpret_cast<const uint8_t *>(key.data());
    start.Write(keyData, keySize);
  }

  // Write the lookup message with its length
  const uint16_t msgSize = static_cast<uint16_t>(lookupMessage.size());
  start.WriteU16(msgSize);
  if (msgSize > 0)
  {
    const uint8_t *msgData = reinterpret_cast<const uint8_t *>(lookupMessage.data());
    start.Write(msgData, msgSize);
  }
  start.WriteHtonU32(finger_query_index);
  start.WriteHtonU32(Id);
}

void PennChordMessage::LookUp::Print(std::ostream &os) const
{
  os << "LookUp:: Content: " << lookupMessage;
  os << " [Key: " << key << ", ";
  os << "Join: " << JoinNode << ", ";
  os << "Through: " << ThoughNode << "]" << std::endl;
}

uint32_t GetAbsDiffHash(Ipv4Address ipAddr1, Ipv4Address ipAddr2)
{
  uint32_t hash1 = PennKeyHelper::CreateShaKey(ipAddr1);
  uint32_t hash2 = PennKeyHelper::CreateShaKey(ipAddr2);
  return std::abs(static_cast<int>(hash1) - static_cast<int>(hash2));
}
// // Getter和Setter for finger_query_index
// void SetLookUpMaxDiff(int finger_query_index);
// int GetLookUpMaxDiff();

// // Getter和Setter for Id
// void SetLookUpId(int id);
// int GetLookUpId();
void PennChordMessage::SetFingerQueryIndex(int index)
{
    m_message.lookUpMessage.finger_query_index = index;
}
void PennChordMessage::SetFromNode(Ipv4Address fromNode)
{
    m_message.lookUpMessage.FromNode = fromNode;
}
void PennChordMessage::SetFingerTableNode(Ipv4Address node)
{
    m_message.lookUpMessage.JoinNode = node;
}
Ipv4Address PennChordMessage::GetFingerTableNode()
{
    return m_message.lookUpMessage.JoinNode;
}
uint32_t PennChordMessage::GetFingerQueryIndex()
{
    return m_message.lookUpMessage.finger_query_index;
}

void PennChordMessage::SetFingerTablePredecessor(Ipv4Address prenode)
{
    m_message.lookUpMessage.ThoughNode = prenode;
}

Ipv4Address PennChordMessage::GetFingerTablePredecessor()
{
    return m_message.lookUpMessage.ThoughNode;
}
Ipv4Address PennChordMessage::GetFromNode()
{
    return m_message.lookUpMessage.FromNode;
}
void PennChordMessage::SetLookUpMaxDiff(int finger_query_index)
{
  m_message.lookUpMessage.finger_query_index = finger_query_index;
}

int PennChordMessage::GetLookUpMaxDiff()
{
  return m_message.lookUpMessage.finger_query_index;
}

// void PennChordMessage::SetLookUpId(int id)
// {
//   m_message.lookUpMessage.Id = id;
// }

// int PennChordMessage::GetLookUpId()
// {
//   return m_message.lookUpMessage.Id;
// }

/* PENNSEARCH */

uint32_t
PennChordMessage::PennSearch::GetSerializedSize(void) const
{
  uint32_t size = 0;
  size += sizeof(uint32_t);  // NowHops
  size += sizeof(uint16_t) + operation.length();  // operation字符串长度
  size += sizeof(uint16_t) + documentPath.length();  // documentPath字符串长度
  size += IPV4_ADDRESS_SIZE;  // originNode的IP地址
  
  // currentResults向量
  size += sizeof(uint32_t);  // 向量大小
  for (const auto& result : currentResults)
  {
    size += sizeof(uint16_t) + result.length();
  }
  
  // remainingQueries向量
  size += sizeof(uint32_t);  // 向量大小
  for (const auto& query : remainingQueries)
  {
    size += sizeof(uint16_t) + query.length();
  }
  
  return size;
}

void
PennChordMessage::PennSearch::Print(std::ostream &os) const
{
  os << "PennSearch:: Operation: " << operation
     << ", Document Path: " << documentPath 
     << ", Origin Node: " << originNode << "\n";
  
  os << "Current Results: [";
  for (const auto& result : currentResults)
  {
    os << result << ", ";
  }
  os << "]\n";
  
  os << "Remaining Queries: [";
  for (const auto& query : remainingQueries)
  {
    os << query << ", ";
  }
  os << "]\n";
}

void
PennChordMessage::PennSearch::Serialize(Buffer::Iterator &start) const
{
  // 序列化NowHops
  start.WriteHtonU32(NowHops);
  // 序列化operation
  start.WriteU16(operation.length());
  start.Write((uint8_t*)(const_cast<char*>(operation.c_str())), operation.length());

  // 序列化documentPath
  start.WriteU16(documentPath.length());
  start.Write((uint8_t*)(const_cast<char*>(documentPath.c_str())), documentPath.length());

  // 序列化originNode
  uint8_t ipBuffer[IPV4_ADDRESS_SIZE];
  originNode.Serialize(ipBuffer);
  //std::cout<<"序列化前的IP"<<originNode<<std::endl;
  start.Write(ipBuffer, IPV4_ADDRESS_SIZE);

  // 序列化currentResults
  start.WriteHtonU32(currentResults.size());
  for (const auto& result : currentResults)
  {
    start.WriteU16(result.length());
    start.Write((uint8_t*)(const_cast<char*>(result.c_str())), result.length());
  }

  // 序列化remainingQueries
  start.WriteHtonU32(remainingQueries.size());
  for (const auto& query : remainingQueries)
  {
    start.WriteU16(query.length());
    start.Write((uint8_t*)(const_cast<char*>(query.c_str())), query.length());
  }
}

uint32_t
PennChordMessage::PennSearch::Deserialize(Buffer::Iterator &start)
{
  // 反序列化NowHops
  NowHops = start.ReadNtohU32();
  // 反序列化operation
  uint16_t operationLength = start.ReadU16();
  char* operationStr = (char*)malloc(operationLength);
  start.Read((uint8_t*)operationStr, operationLength);
  operation = std::string(operationStr, operationLength);
  free(operationStr);

  // 反序列化documentPath
  uint16_t pathLength = start.ReadU16();
  char* pathStr = (char*)malloc(pathLength);
  start.Read((uint8_t*)pathStr, pathLength);
  documentPath = std::string(pathStr, pathLength);
  free(pathStr);

  // 反序列化originNode
  //uint8_t ipBuffer[IPV4_ADDRESS_SIZE];
  //start.Read(ipBuffer, IPV4_ADDRESS_SIZE);
  //originNode.Deserialize(ipBuffer);
  uint32_t originNodeRaw = start.ReadNtohU32();
  originNode = Ipv4Address(originNodeRaw);

  //std::cout<<"解析后的序列化后的IP"<<originNode<<std::endl;
  // 反序列化currentResults
  uint32_t resultsSize = start.ReadNtohU32();
  currentResults.clear();
  for (uint32_t i = 0; i < resultsSize; ++i)
  {
    uint16_t length = start.ReadU16();
    char* str = (char*)malloc(length);
    start.Read((uint8_t*)str, length);
    currentResults.push_back(std::string(str, length));
    free(str);
  }

  // 反序列化remainingQueries
  uint32_t queriesSize = start.ReadNtohU32();
  remainingQueries.clear();
  for (uint32_t i = 0; i < queriesSize; ++i)
  {
    uint16_t length = start.ReadU16();
    char* str = (char*)malloc(length);
    start.Read((uint8_t*)str, length);
    remainingQueries.push_back(std::string(str, length));
    free(str);
  }

  return GetSerializedSize();
}
