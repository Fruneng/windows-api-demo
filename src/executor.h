#include <json/json.h>

#include <iostream>

class ExecutorInterface {
 public:
  virtual ~ExecutorInterface(){};
  virtual bool Execute(Json::Value &req, Json::Value &rep) = 0;
};

class WindowsLogonUserExecutor : public ExecutorInterface {
 public:
  WindowsLogonUserExecutor();
  ~WindowsLogonUserExecutor();

  bool Execute(Json::Value &req, Json::Value &rep);
};