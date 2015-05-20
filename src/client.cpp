
#include <ola/Callback.h>
#include <ola/Logging.h>
#include <ola/base/Flags.h>
#include <ola/base/Init.h>
#include <ola/base/SysExits.h>
#include <ola/io/SelectServer.h>

#include <memory>
#include <vector>

#include "DiscoveryAgent.h"
#include "MasterEntry.h"

DEFINE_string(scope, "default", "The scope to use.");

using ola::io::SelectServer;
using ola::network::IPV4Address;
using ola::network::IPV4SocketAddress;
using std::auto_ptr;
using std::vector;
using std::set;

class Client {
 public:
  Client() {}

  bool Init() {
    // Start the agent.
    DiscoveryAgentFactory factory;
    DiscoveryAgentInterface::Options options;
    options.scope = FLAGS_scope.str();
    options.watch_masters = true;
    auto_ptr<DiscoveryAgentInterface> agent(factory.New(options));

    if (!agent->Start()) {
      return false;
    }

    agent->WatchMasters(ola::NewCallback(this, &Client::MasterChanged));
    m_discovery_agent.reset(agent.release());
    return true;
  }

  void Stop() {
    m_ss.Terminate();
  }

  void Run() {
    m_ss.Run();
  }

  // This is called within the Discovery thread.
  void MasterChanged(DiscoveryAgentInterface::MasterEvent event,
                     const MasterEntry &entry) {
    UpdateMasterList(event, entry);
    OLA_INFO << "Have " << m_masters.size() << " masters";

    uint8_t priority = 0;
    Master *preferred_master = NULL;
    vector<Master>::iterator iter = m_masters.begin();
    for (; iter != m_masters.end(); ++iter) {
      if (iter->priority > priority) {
        preferred_master = &(*iter);
        priority = iter->priority;
      }
    }
    OLA_INFO << "Would have picked " << preferred_master->name << " @ "
             << preferred_master->address;
  }

 private:
  struct Master {
    std::string name;
    ola::network::IPV4SocketAddress address;
    uint8_t priority;
  };

  std::vector<Master> m_masters;
  ola::io::SelectServer m_ss;

  // Accessed by the discovery thread.
  std::auto_ptr<DiscoveryAgentInterface> m_discovery_agent;

  void UpdateMasterList(DiscoveryAgentInterface::MasterEvent event,
                        const MasterEntry &entry) {
    vector<Master>::iterator iter = m_masters.begin();
    for (; iter != m_masters.end(); ++iter) {
      if (iter->name == entry.service_name) {
        if (event == DiscoveryAgentInterface::MASTER_REMOVED) {
          m_masters.erase(iter);
        } else {
          iter->priority = entry.priority;
          iter->address = entry.address;
        }
        return;
      }
    }
    // not in the list.
    Master master = {
      entry.service_name,
      entry.address,
      entry.priority
    };
    m_masters.push_back(master);
  }
};

Client *g_client = NULL;

static void InteruptSignal(OLA_UNUSED int signal) {
  if (g_client) {
    g_client->Stop();
  }
}

int main(int argc, char *argv[]) {
  ola::AppInit(&argc, argv, "[options]", "Dummy Master");

  Client client;
  if (!client.Init()) {
    exit(ola::EXIT_UNAVAILABLE);
  }

  g_client = &client;
  ola::InstallSignal(SIGINT, InteruptSignal);
  client.Run();
  g_client = NULL;
}
