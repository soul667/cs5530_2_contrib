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

#ifndef PENN_CHORD_MESSAGE_H
#define PENN_CHORD_MESSAGE_H

#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/penn-key-helper.h"

using namespace ns3;

#define IPV4_ADDRESS_SIZE 4

class PennChordMessage : public Header
{
public:
  PennChordMessage();
  virtual ~PennChordMessage();
  // Getter和Setter for finger_query_index
  void SetLookUpMaxDiff(int finger_query_index);
  
  void SetFingerQueryIndex(int index);
  void SetFromNode(Ipv4Address fromNode);
  void SetFingerTableNode(Ipv4Address node);
  void SetFingerTablePredecessor(Ipv4Address prenode);


  // SetFingerTablePredecessor
  Ipv4Address GetFingerTableNode();
  uint32_t GetFingerQueryIndex();
  // Ipv4Address SetFingetTablePredecessor(Ipv4Address prenode); 
  Ipv4Address GetFingerTablePredecessor();

  Ipv4Address GetFromNode();

  int GetLookUpMaxDiff();

  // Getter和Setter for Id
  // void SetLookUpId(int id);
  // int GetLookUpId();
  enum MessageType
  {
    PING_REQ = 1,
    PING_RSP = 2,
    LOOK_UP = 3,
    RING_STATE = 4,
    PENNSEARCH = 5
    // UPDATE_NEIGHBORS = 6,  // 新增消息类型用于更新前驱和后继节点
    // UODATE_ID_IP_AP = 7
  };

  PennChordMessage(PennChordMessage::MessageType messageType, uint32_t transactionId);

  /**
   *  \brief Sets message type
   *  \param messageType message type
   */
  void SetMessageType(MessageType messageType);

  /**
   *  \returns message type
   */
  MessageType GetMessageType() const;

  /**
   *  \brief Sets Transaction Id
   *  \param transactionId Transaction Id of the request
   */
  void SetTransactionId(uint32_t transactionId);

  /**
   *  \returns Transaction Id
   */
  uint32_t GetTransactionId() const;

private:
  /**
   *  \cond
   */
  MessageType m_messageType;
  uint32_t m_transactionId;
  /**
   *  \endcond
   */

public:
  static TypeId GetTypeId(void);
  virtual TypeId GetInstanceTypeId(void) const;
  void Print(std::ostream &os) const;
  uint32_t GetSerializedSize(void) const;
  void Serialize(Buffer::Iterator start) const;
  uint32_t Deserialize(Buffer::Iterator start);

  void SetLookUpType()
  {
    if (m_messageType == 0)
      m_messageType = PING_RSP;
    else
      NS_ASSERT(m_messageType == PING_RSP);
  };

  
  struct chord_table {
    uint32_t id;
    Ipv4Address ipAddr;
    uint32_t hash_key;
    Ipv4Address successor;
    Ipv4Address predecessor;

    chord_table() 
        : id(0)
        , ipAddr(Ipv4Address::GetAny())
        , hash_key(0)
        , successor(Ipv4Address::GetAny())
        , predecessor(Ipv4Address::GetAny())
    { }

    chord_table(uint32_t id, Ipv4Address ipAddr) 
        : id(id)
        , ipAddr(ipAddr)
        , hash_key(PennKeyHelper::CreateShaKey(ipAddr))
        , successor(Ipv4Address::GetAny())
        , predecessor(Ipv4Address::GetAny())
    { }
  };
  void SetLookUpFromNode(Ipv4Address FromNode)
  {
    m_message.lookUpMessage.FromNode = FromNode;
  };
  void SetLookUpJoinNode(Ipv4Address JoinNode)
  {
    m_message.lookUpMessage.JoinNode = JoinNode;
  };
  void SetLookUpMessage(std::string message)
  {
    m_message.lookUpMessage.lookupMessage = message;
  };
  void SetLookUpThoughNode(Ipv4Address ThroughNode)
  {
    m_message.lookUpMessage.ThoughNode = ThroughNode;
    // std::cout << "设置的ThroughNode: " <<  m_message.lookUpMessage.ThroughNode << std::endl;
  };
  void SetLookUpKey(std::string key)
  {
    m_message.lookUpMessage.key = key;
  };
  void SetLookUpMessageType(std::string message)
  {
    m_message.lookUpMessage.lookupMessage = message;
  };
  void SetLookUpId(int id)
  {
    m_message.lookUpMessage.Id = id;
  };
  int GetLookUpId()
  {
    return m_message.lookUpMessage.Id;
  };
  void SetLookUpPreIp(Ipv4Address message)
  {
    m_message.lookUpMessage.JoinNode = message;
  };
  
  Ipv4Address GetLookUpPreIp()
  {
    return m_message.lookUpMessage.JoinNode;
  }

  void SetLookUpSuccIp(Ipv4Address message)
  {
    m_message.lookUpMessage.ThoughNode = message;
  };
  
  Ipv4Address GetLookUpSuccIp()
  {
    return m_message.lookUpMessage.ThoughNode;
  };
    

  // void Set
  // void SerChordTable(chord_table chord_table_)
  // {
  //   m_message.lookUpMessage.chord_table_ = chord_table_;
  // };
  // void SetNodenumber(uint32_t nodenumber)
  // {
  //   m_message.lookUpMessage.nodenumber = nodenumber;
  //   std::cout<<"设置的节点ID: " <<  m_message.lookUpMessage.nodenumber << std::endl;
  // };

  struct PingReq
  {
    PingReq() : pingMessage("") { }
    void Print(std::ostream &os) const;
    uint32_t GetSerializedSize(void) const;
    void Serialize(Buffer::Iterator &start) const;
    uint32_t Deserialize(Buffer::Iterator &start);
    // Payload
    std::string pingMessage;
  };

  struct PingRsp
  {
    PingRsp() : pingMessage("") { }
    void Print(std::ostream &os) const;
    uint32_t GetSerializedSize(void) const;
    void Serialize(Buffer::Iterator &start) const;
    uint32_t Deserialize(Buffer::Iterator &start);
    // Payload
    std::string pingMessage;
  };

  struct LookUp
  {
    void Print (std::ostream &os) const;
    uint32_t GetSerializedSize (void) const;
    void Serialize (Buffer::Iterator &start) const;
    uint32_t Deserialize (Buffer::Iterator &start);
    // Payload
    Ipv4Address ThoughNode;   
    Ipv4Address JoinNode;
    Ipv4Address FromNode; // 一开始的发起请求的节点

    std::string key;
    std::string lookupMessage;

    // FingerTableUse
    int finger_query_index=0; //The index for initiating finger query
    int Id=-1;

    uint32_t GetFingerStart(uint32_t a, uint32_t k) {
      if (k >= 32) {
          throw std::out_of_range("k must be less than 32");
      }
      return a + (1u << k);
  }
    // 这里返回的是查询的Key
    uint32_t GetQueryKey(){
      uint32_t Key=PennKeyHelper::CreateShaKey(FromNode);
      return GetFingerStart(Key,finger_query_index);
    }


    // 下面是给FingerTable查询专用的Set和Get函数，就不用别的变量名了
  
    //------------------------------------------------------------
  };

  struct RingState {
    RingState() 
        : originatorNode(Ipv4Address::GetAny())
        , targetNode(Ipv4Address::GetAny())
    { }
    
    void Print(std::ostream &os) const;
    uint32_t GetSerializedSize(void) const;
    void Serialize(Buffer::Iterator &start) const;
    uint32_t Deserialize(Buffer::Iterator &start);
    
    Ipv4Address originatorNode;  // 发起环状态请求的节点
    Ipv4Address targetNode;      // 消息当前的目标节点
  };

  void SetRingStateOriginator(Ipv4Address originator)
  {
    m_message.ringState.originatorNode = originator;
  }
  void SetRingStateTarget(Ipv4Address target)
  {
    m_message.ringState.targetNode = target;
  }
  Ipv4Address GetRingStateOriginator()
  {
    return m_message.ringState.originatorNode;
  }
  Ipv4Address GetRingStateTarget()
  {
    return m_message.ringState.targetNode;
  }
  struct UpdateNeighbors {
    UpdateNeighbors()
      : targetNode(Ipv4Address::GetAny())
      , newSuccessor(Ipv4Address::GetAny())
      , newPredecessor(Ipv4Address::GetAny())
    { }
    
    void Print(std::ostream &os) const;
    uint32_t GetSerializedSize(void) const;
    void Serialize(Buffer::Iterator &start) const;
    uint32_t Deserialize(Buffer::Iterator &start);

    Ipv4Address targetNode;      // 需要更新的目标节点
    Ipv4Address newSuccessor;    // 新的后继节点
    Ipv4Address newPredecessor;  // 新的前驱节点
  };

  struct UpdataIdIpMap
  {
    std::map<uint32_t, Ipv4Address> m_nodeAddressMap; // key: node_id, value: ip_address
    
    void Print(std::ostream &os) const;
    uint32_t GetSerializedSize(void) const;
    void Serialize(Buffer::Iterator &start) const;
    uint32_t Deserialize(Buffer::Iterator &start);
  };

  struct PennSearch {
    PennSearch()
      : operation("")
      , documentPath("")
      , originNode(Ipv4Address::GetAny())
    { }
    
    void Print(std::ostream &os) const;
    uint32_t GetSerializedSize(void) const;
    void Serialize(Buffer::Iterator &start) const;
    uint32_t Deserialize(Buffer::Iterator &start);

    uint32_t NowHops = 0;  // 当前跳数
    std::string operation;  // "PUBLISH" 或 "SEARCH"
    std::string documentPath;  // metadata文件路径
    std::vector<std::string> currentResults;  // 存储倒排列表或搜索结果
    std::vector<std::string> remainingQueries;  // 存储剩余的查询词
    Ipv4Address originNode;  // 发起节点地址
  };

  struct Messages
  {
    Messages() 
      : pingReq()
      , pingRsp()
      , lookUpMessage()
      , ringState()
      , pennSearch()
    { }

    PingReq pingReq;
    PingRsp pingRsp;
    LookUp lookUpMessage;
    RingState ringState;
    PennSearch pennSearch;
  };


private:
  Messages m_message;

public:
  /**
   *  \returns PingReq Struct
   */
  PingReq GetPingReq();

  /**
   *  \brief Sets PingReq message params
   *  \param message Payload String
   */

  void SetPingReq(std::string message);

  /**
   * \returns PingRsp Struct
   */
  PingRsp GetPingRsp();
  /**
   *  \brief Sets PingRsp message params
   *  \param message Payload String
   */
  void SetPingRsp(std::string message);

  /**
   * \returns LookUp Struct
   */
  LookUp GetLookUp()
  {
    return m_message.lookUpMessage;
  }

  void SetRingState(Ipv4Address originator, Ipv4Address target)
  {
    m_message.ringState.originatorNode = originator;
    m_message.ringState.targetNode = target;
  }

  RingState GetRingState()
  {
    return m_message.ringState;
  }

  /**
   * \brief Sets PennSearch params
   */
  void SetPennSearchOperation(std::string operation)
  {
    m_message.pennSearch.operation = operation;
  }

  void SetPennSearchDocumentPath(std::string path)
  {
    m_message.pennSearch.documentPath = path;
  }

  void SetPennSearchOriginNode(Ipv4Address node)
  {
    m_message.pennSearch.originNode = node;
    //std::cout << "设置的originNode: " << m_message.pennSearch.originNode << std::endl;
  }

  void SetPennSearchCurrentResults(std::vector<std::string> results)
  {
    m_message.pennSearch.currentResults = results;
  }

  void SetPennSearchRemainingQueries(std::vector<std::string> queries)
  {
    m_message.pennSearch.remainingQueries = queries;
  }

  void SetPennSearchNowHops(uint32_t hops) {
    m_message.pennSearch.NowHops = hops;
  }
  
  uint32_t GetPennSearchNowHops() {
    return m_message.pennSearch.NowHops;
  }

  /**
   * \returns PennSearch Struct
   */
  PennSearch GetPennSearch()
  {
    return m_message.pennSearch;
  }

  void SetUpdateIdIpMap(std::map<uint32_t, Ipv4Address> nodeAddressMap);
  UpdataIdIpMap GetUpdateIdIpMap();


}; // class PennChordMessage

static inline std::ostream &operator<<(std::ostream &os, const PennChordMessage &message)
{
  message.Print(os);
  return os;
}

uint32_t GetAbsDiffHash(Ipv4Address ipAddr1, Ipv4Address ipAddr2);
#endif
