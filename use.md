## 设置消息的一些函数
```c++
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
  }

  void SetPennSearchCurrentResults(std::vector<std::string> results)
  {
    m_message.pennSearch.currentResults = results;
  }

  void SetPennSearchRemainingQueries(std::vector<std::string> queries)
  {
    m_message.pennSearch.remainingQueries = queries;
  }
```